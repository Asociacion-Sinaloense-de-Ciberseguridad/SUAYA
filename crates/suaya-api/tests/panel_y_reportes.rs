//! Puntos de la API de 1.7: perfiles incluidos, contexto de la organización,
//! reportes en otros formatos, resumen, comparación, tendencias, OpenAPI y
//! panel web.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use suaya_api::{AppState, Config, Credential, router};
use tower::ServiceExt;

const ALICE: &str = "alice-test-012345678901234567890123456789";
const BOB: &str = "bob-test-01234567890123456789012345678901";

fn demo(ruta: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../pruebas/fixtures/sistema-demo")
        .join(ruta)
}

fn app(organizacion: Option<std::path::PathBuf>) -> axum::Router {
    let credenciales = [
        ("alice", ALICE, Some(vec!["legado".to_string()])),
        ("bob", BOB, None),
    ]
    .into_iter()
    .map(|(user, token, targets)| Credential {
        user: user.into(),
        token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        admin: false,
        targets,
    })
    .collect();
    let config = Config {
        credentials: credenciales,
        targets: std::collections::HashMap::from([
            ("legado".into(), demo("legado")),
            ("app".into(), demo("srv/app")),
        ]),
        network_targets: Default::default(),
        organization: organizacion,
    };
    router(AppState::new(config, Connection::open_in_memory().unwrap()).unwrap())
}

async fn llamar(
    app: &axum::Router,
    metodo: &str,
    ruta: &str,
    token: Option<&str>,
    cuerpo: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder()
        .method(metodo)
        .uri(ruta)
        .header("Content-Type", "application/json");
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let r = app
        .clone()
        .oneshot(req.body(Body::from(cuerpo.to_string())).unwrap())
        .await
        .unwrap();
    let (partes, cuerpo) = r.into_parts();
    let bytes = cuerpo.collect().await.unwrap().to_bytes().to_vec();
    (partes.status, partes.headers, bytes)
}

fn json(b: &[u8]) -> serde_json::Value {
    serde_json::from_slice(b).unwrap()
}

#[tokio::test]
async fn panel_y_openapi_publicos_con_su_politica() {
    let app = app(None);
    let (estado, cab, cuerpo) = llamar(&app, "GET", "/panel", None, "").await;
    assert_eq!(estado, StatusCode::OK);
    let csp = cab["content-security-policy"].to_str().unwrap();
    assert!(
        csp.contains("script-src 'self'") && !csp.contains("unsafe"),
        "{csp}"
    );
    let html = String::from_utf8(cuerpo).unwrap();
    assert!(html.contains("/panel/app.js") && !html.contains("<script>"));
    let (estado, cab, _) = llamar(&app, "GET", "/panel/app.js", None, "").await;
    assert_eq!(estado, StatusCode::OK);
    assert!(
        cab["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/javascript")
    );
    let (estado, _, cuerpo) = llamar(&app, "GET", "/api/v1/openapi.json", None, "").await;
    assert_eq!(estado, StatusCode::OK);
    assert_eq!(json(&cuerpo)["openapi"], "3.1.0");
    // Lo demás exige credencial.
    for ruta in ["/api/v1/profiles", "/api/v1/targets", "/api/v1/trends"] {
        assert_eq!(
            llamar(&app, "GET", ruta, None, "").await.0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn perfiles_solo_incluidos_y_alias_visibles() {
    let app = app(None);
    let (_, _, cuerpo) = llamar(&app, "GET", "/api/v1/profiles", Some(ALICE), "").await;
    let perfiles = json(&cuerpo);
    assert!(
        perfiles
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["id"] == "cnsa-2.0")
    );
    let (_, _, cuerpo) = llamar(&app, "GET", "/api/v1/targets", Some(ALICE), "").await;
    assert_eq!(json(&cuerpo)["targets"], serde_json::json!(["legado"]));
    let (_, _, cuerpo) = llamar(&app, "GET", "/api/v1/targets", Some(BOB), "").await;
    assert_eq!(
        json(&cuerpo)["targets"],
        serde_json::json!(["app", "legado"])
    );
    // Un perfil que no está incluido (o una ruta) se rechaza.
    for perfil in ["/etc/passwd", "../perfil.toml", "inexistente"] {
        let cuerpo = serde_json::json!({"target": "legado", "profile": perfil}).to_string();
        assert_eq!(
            llamar(&app, "POST", "/api/v1/scan", Some(ALICE), &cuerpo)
                .await
                .0,
            StatusCode::BAD_REQUEST,
            "{perfil}"
        );
    }
}

#[tokio::test]
async fn reportes_resumen_comparacion_y_tendencias() {
    let dir = std::env::temp_dir().join(format!("suaya-api-org-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let org = dir.join("organizacion.toml");
    std::fs::write(
        &org,
        "[organizacion]\nhorizonte_cuantico = 2035\n\n[[sistema]]\nnombre = \"Heredados\"\nresponsable = \"ops@ejemplo.mx\"\ncriticidad = \"baja\"\nrutas = [\"legado/**\"]\n",
    )
    .unwrap();
    let app = app(Some(org));
    let mut ids = Vec::new();
    for perfil in ["cnsa-2.0", "pci-dss-4"] {
        let cuerpo = serde_json::json!({"target": "legado", "profile": perfil}).to_string();
        let (estado, _, r) = llamar(&app, "POST", "/api/v1/scan", Some(ALICE), &cuerpo).await;
        assert_eq!(estado, StatusCode::OK, "{}", String::from_utf8_lossy(&r));
        ids.push(json(&r)["id"].as_str().unwrap().to_string());
    }
    let (_, _, cbom) = llamar(
        &app,
        "GET",
        &format!("/api/v1/scan/{}", ids[0]),
        Some(ALICE),
        "",
    )
    .await;
    let cbom = String::from_utf8(cbom).unwrap();
    assert!(
        cbom.contains("suaya:perfil-politica") && cbom.contains("suaya:sistema"),
        "falta perfil o contexto"
    );

    for (formato, tipo) in [
        ("html", "text/html"),
        ("md", "text/markdown"),
        ("pci", "text/markdown"),
        ("sarif", "application/sarif+json"),
        ("csv", "text/csv"),
        ("jsonl", "application/x-ndjson"),
        ("tickets", "application/json"),
    ] {
        let ruta = format!("/api/v1/scan/{}/report?format={formato}", ids[0]);
        let (estado, cab, cuerpo) = llamar(&app, "GET", &ruta, Some(ALICE), "").await;
        assert_eq!(estado, StatusCode::OK, "{formato}");
        assert!(
            cab["content-type"].to_str().unwrap().starts_with(tipo),
            "{formato}"
        );
        assert!(
            cab["content-disposition"]
                .to_str()
                .unwrap()
                .contains("attachment")
        );
        assert!(!cuerpo.is_empty());
        if formato == "html" {
            let csp = cab["content-security-policy"].to_str().unwrap();
            assert!(
                csp.contains("style-src 'unsafe-inline'") && !csp.contains("script-src"),
                "{csp}"
            );
            assert!(!String::from_utf8_lossy(&cuerpo).contains("<script"));
        }
    }
    let ruta = format!("/api/v1/scan/{}/report?format=exe", ids[0]);
    assert_eq!(
        llamar(&app, "GET", &ruta, Some(ALICE), "").await.0,
        StatusCode::BAD_REQUEST
    );
    // Bob no puede leer el escaneo de Alice en ningún formato.
    let ruta = format!("/api/v1/scan/{}/report?format=csv", ids[0]);
    assert_eq!(
        llamar(&app, "GET", &ruta, Some(BOB), "").await.0,
        StatusCode::NOT_FOUND
    );

    let (_, _, r) = llamar(
        &app,
        "GET",
        &format!("/api/v1/scan/{}/summary", ids[0]),
        Some(ALICE),
        "",
    )
    .await;
    let resumen = json(&r);
    assert_eq!(resumen["system"], "legado");
    assert!(resumen["totals"]["total"].as_u64().unwrap() > 0);
    assert!(!resumen["urgent"].as_array().unwrap().is_empty());

    let (estado, _, r) = llamar(
        &app,
        "GET",
        &format!("/api/v1/compare/{}/{}", ids[0], ids[1]),
        Some(ALICE),
        "",
    )
    .await;
    assert_eq!(estado, StatusCode::OK);
    assert_eq!(json(&r)["regression"], false);
    assert_eq!(
        llamar(
            &app,
            "GET",
            &format!("/api/v1/compare/{}/{}", ids[0], ids[1]),
            Some(BOB),
            ""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    let (_, _, r) = llamar(&app, "GET", "/api/v1/trends?target=legado", Some(ALICE), "").await;
    assert_eq!(json(&r)["escaneos"].as_array().unwrap().len(), 2);
    let (_, _, r) = llamar(&app, "GET", "/api/v1/trends", Some(BOB), "").await;
    assert!(json(&r)["escaneos"].as_array().unwrap().is_empty());
    assert_eq!(
        llamar(
            &app,
            "GET",
            "/api/v1/trends?target=x&ruta=/etc",
            Some(ALICE),
            ""
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let _ = std::fs::remove_dir_all(&dir);
}

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rusqlite::{Connection, params};
use serde_json::json;
use sha2::{Digest, Sha256};
use suaya_api::{AppState, Config, Credential, router};
use tower::ServiceExt;
const ALICE: &str = "alice-test-012345678901234567890123456789";
const BOB: &str = "bob-test-01234567890123456789012345678901";
const ADMIN: &str = "admin-test-012345678901234567890123456789";
fn app() -> axum::Router {
    let credentials = [
        ("alice", ALICE, false),
        ("bob", BOB, false),
        ("admin", ADMIN, true),
    ]
    .into_iter()
    .map(|(user, token, admin)| Credential {
        user: user.into(),
        token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
        expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        admin,
        targets: None,
    })
    .collect();
    let db = Connection::open_in_memory().unwrap();
    let config = Config {
        credentials,
        targets: Default::default(),
        network_targets: Default::default(),
    };
    let state = AppState::new(config, db).unwrap();
    router(state)
}
async fn call(
    app: axum::Router,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("Content-Type", "application/json");
    if let Some(token) = token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    app.oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap()
}
#[tokio::test]
async fn credentials_required_and_admin_role_enforced() {
    for method_path in [
        ("GET", "/api/v1/scans"),
        ("POST", "/api/v1/scan"),
        ("GET", "/api/v1/config"),
        (
            "DELETE",
            "/api/v1/scan/00000000-0000-0000-0000-000000000001",
        ),
    ] {
        for token in [
            None,
            Some("inventado"),
            Some("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        ] {
            assert_eq!(
                call(app(), method_path.0, method_path.1, token, "{}")
                    .await
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
    }
    assert_eq!(
        call(app(), "GET", "/api/v1/scans", Some(ALICE), "")
            .await
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        call(app(), "GET", "/api/v1/config", Some(ALICE), "")
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(app(), "GET", "/api/v1/config", Some(ADMIN), "")
            .await
            .status(),
        StatusCode::OK
    );
}
#[tokio::test]
async fn rejects_arbitrary_paths_urls_and_unknown_fields() {
    for target in [
        "/etc",
        "../secret",
        "http://127.0.0.1",
        "https://169.254.169.254",
    ] {
        assert_eq!(
            call(
                app(),
                "POST",
                "/api/v1/scan",
                Some(ALICE),
                &json!({"target":target}).to_string()
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        call(
            app(),
            "POST",
            "/api/v1/scan",
            Some(ALICE),
            r#"{"target":"demo","owner":"admin"}"#
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
}
#[tokio::test]
async fn ownership_checked_on_read_delete_and_list() {
    let file = std::env::temp_dir().join(format!("suaya-api-test-{}.db", uuid::Uuid::new_v4()));
    let config = Config {
        credentials: vec![Credential {
            user: "bob".into(),
            token_sha256: hex::encode(Sha256::digest(BOB)),
            expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 60,
            admin: false,
            targets: None,
        }],
        targets: Default::default(),
        network_targets: Default::default(),
    };
    let state = AppState::new(config, Connection::open(&file).unwrap()).unwrap();
    let db = Connection::open(&file).unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    db.execute(
        "INSERT INTO scans VALUES(?1,'alice','2026-01-01','completed','{}')",
        params![id],
    )
    .unwrap();
    let app = router(state);
    for method in ["GET", "DELETE"] {
        assert_eq!(
            call(
                app.clone(),
                method,
                &format!("/api/v1/scan/{id}"),
                Some(BOB),
                ""
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }
    let count: i64 = db
        .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    use http_body_util::BodyExt;
    let bytes = call(app.clone(), "GET", "/api/v1/scans", Some(BOB), "")
        .await
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(&bytes[..], b"[]");
    drop(app);
    drop(db);
    std::fs::remove_file(file).unwrap();
}
#[tokio::test]
async fn request_budget_and_response_headers() {
    let app = app();
    for _ in 0..60 {
        assert_eq!(
            call(app.clone(), "GET", "/api/v1/scans", Some(ALICE), "")
                .await
                .status(),
            StatusCode::OK
        );
    }
    let response = call(app, "GET", "/api/v1/scans", Some(ALICE), "").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["cache-control"], "no-store");
}
#[test]
fn rejects_expired_config_and_duplicate_tokens() {
    let c = Credential {
        user: "a".into(),
        token_sha256: hex::encode(Sha256::digest(ALICE)),
        expires_at: 0,
        admin: false,
        targets: None,
    };
    assert!(
        AppState::new(
            Config {
                credentials: vec![c],
                targets: Default::default(),
                network_targets: Default::default(),
            },
            Connection::open_in_memory().unwrap()
        )
        .is_err()
    );
}

#[tokio::test]
async fn real_scan_persists_and_is_readable_by_owner() {
    use http_body_util::BodyExt;
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../pruebas/fixtures/sistema-demo/etc/ssh/sshd_config");
    let target = if target.exists() {
        target
    } else {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../pruebas/fixtures/sistema-demo/srv/app.pub.pem")
    };
    let credential = Credential {
        user: "alice".into(),
        token_sha256: hex::encode(Sha256::digest(ALICE)),
        expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
        admin: false,
        targets: None,
    };
    let config = Config {
        credentials: vec![credential],
        targets: std::collections::HashMap::from([("fixture".into(), target)]),
        network_targets: Default::default(),
    };
    let app = router(AppState::new(config, Connection::open_in_memory().unwrap()).unwrap());
    let response = call(
        app.clone(),
        "POST",
        "/api/v1/scan",
        Some(ALICE),
        r#"{"target":"fixture"}"#,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let scan: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(scan["status"], "completed");
    assert!(scan["files"].as_u64().unwrap() > 0);
    let path = format!("/api/v1/scan/{}", scan["id"].as_str().unwrap());
    let response = call(app.clone(), "GET", &path, Some(ALICE), "").await;
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let cbom: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(cbom["bomFormat"], "CycloneDX");
    assert!(!cbom["components"].as_array().unwrap().is_empty());
    assert_eq!(
        call(app.clone(), "DELETE", &path, Some(ALICE), "")
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(app, "GET", &path, Some(ALICE), "").await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn anonymous_flood_preserves_authenticated_budgets() {
    let app = app();
    for _ in 0..650 {
        call(app.clone(), "GET", "/api/v1/scans", None, "").await;
    }
    for token in [ALICE, BOB] {
        let response = call(app.clone(), "GET", "/api/v1/scans", Some(token), "").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("x-request-id"));
    }
}

#[test]
fn duplicate_tokens_rejected_including_hex_case() {
    let first = Credential {
        user: "first".into(),
        token_sha256: hex::encode(Sha256::digest(ALICE)),
        expires_at: i64::MAX,
        admin: false,
        targets: None,
    };
    let mut second = first.clone();
    second.user = "second".into();
    second.token_sha256.make_ascii_uppercase();
    assert!(
        AppState::new(
            Config {
                credentials: vec![first, second],
                targets: Default::default(),
                network_targets: Default::default(),
            },
            Connection::open_in_memory().unwrap()
        )
        .is_err()
    );
}

#[tokio::test]
async fn reload_revokes_old_token_and_accepts_new_token() {
    let credential = |token: &str| Credential {
        user: "alice".into(),
        token_sha256: hex::encode(Sha256::digest(token)),
        expires_at: i64::MAX,
        admin: false,
        targets: None,
    };
    let config = |token: &str| Config {
        credentials: vec![credential(token)],
        targets: Default::default(),
        network_targets: Default::default(),
    };
    let state = AppState::new(config(ALICE), Connection::open_in_memory().unwrap()).unwrap();
    let app = router(state.clone());
    assert_eq!(
        call(app.clone(), "GET", "/api/v1/scans", Some(ALICE), "")
            .await
            .status(),
        StatusCode::OK
    );
    state.reload_credentials(config(BOB)).unwrap();
    assert_eq!(
        call(app.clone(), "GET", "/api/v1/scans", Some(ALICE), "")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(app, "GET", "/api/v1/scans", Some(BOB), "")
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn scoped_credential_cannot_scan_another_alias() {
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../pruebas/fixtures/sistema-demo");
    let credential = Credential {
        user: "alice".into(),
        token_sha256: hex::encode(Sha256::digest(ALICE)),
        expires_at: i64::MAX,
        admin: false,
        targets: Some(vec![]),
    };
    let state = AppState::new(
        Config {
            credentials: vec![credential],
            targets: std::collections::HashMap::from([("fixture".into(), target)]),
            network_targets: Default::default(),
        },
        Connection::open_in_memory().unwrap(),
    )
    .unwrap();
    assert_eq!(
        call(
            router(state),
            "POST",
            "/api/v1/scan",
            Some(ALICE),
            r#"{"target":"fixture"}"#
        )
        .await
        .status(),
        StatusCode::FORBIDDEN
    );
}

#[test]
fn retention_removes_expired_records_without_new_scans() {
    let file = std::env::temp_dir().join(format!("suaya-retention-{}.db", uuid::Uuid::new_v4()));
    let c = Credential {
        user: "alice".into(),
        token_sha256: hex::encode(Sha256::digest(ALICE)),
        expires_at: i64::MAX,
        admin: false,
        targets: None,
    };
    let state = AppState::new(
        Config {
            credentials: vec![c],
            targets: Default::default(),
            network_targets: Default::default(),
        },
        Connection::open(&file).unwrap(),
    )
    .unwrap();
    let db = Connection::open(&file).unwrap();
    db.execute(
        "INSERT INTO scans VALUES('old','alice','2000-01-01','completed','{}')",
        [],
    )
    .unwrap();
    state.maintenance().unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    drop(db);
    drop(state);
    std::fs::remove_file(file).unwrap();
}

fn app_with_network(target: &str, scope: Option<Vec<String>>) -> axum::Router {
    let credentials = [("alice", ALICE, false, scope), ("admin", ADMIN, true, None)]
        .into_iter()
        .map(|(user, token, admin, targets)| Credential {
            user: user.into(),
            token_sha256: hex::encode(Sha256::digest(token.as_bytes())),
            expires_at: time::OffsetDateTime::now_utc().unix_timestamp() + 3600,
            admin,
            targets,
        })
        .collect();
    let config = Config {
        credentials,
        targets: Default::default(),
        network_targets: std::collections::HashMap::from([("web".into(), target.into())]),
    };
    router(AppState::new(config, Connection::open_in_memory().unwrap()).unwrap())
}

#[tokio::test]
async fn diagnose_uses_only_preconfigured_network_aliases() {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let target = format!("tls://127.0.0.1:{port}");

    // Sin credencial, no hay diagnóstico.
    let r = call(
        app_with_network(&target, None),
        "POST",
        "/api/v1/diagnose",
        None,
        r#"{"target":"web"}"#,
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // El cliente no puede dar una URL ni un alias desconocido.
    for body in [
        r#"{"target":"tls://evil.example:443"}"#,
        r#"{"target":"web","host":"x"}"#,
    ] {
        let r = call(
            app_with_network(&target, None),
            "POST",
            "/api/v1/diagnose",
            Some(ALICE),
            body,
        )
        .await;
        assert!(r.status().is_client_error(), "{body}: {}", r.status());
    }

    // Un alcance de alias que no incluye el servicio se rechaza.
    let r = call(
        app_with_network(&target, Some(vec![])),
        "POST",
        "/api/v1/diagnose",
        Some(ALICE),
        r#"{"target":"web"}"#,
    )
    .await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Diagnóstico real contra un puerto cerrado: hallazgo crítico, no error del servidor.
    let r = call(
        app_with_network(&target, None),
        "POST",
        "/api/v1/diagnose",
        Some(ALICE),
        r#"{"target":"web"}"#,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let body = http_body_util::BodyExt::collect(r.into_body())
        .await
        .unwrap()
        .to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["target"], "web");
    assert_eq!(v["worst"], "critico");
    assert_eq!(v["diagnosis"]["hallazgos"][0]["codigo"], "CON-TCP");

    // La configuración lista los alias de red solo a administradores.
    let r = call(
        app_with_network(&target, None),
        "GET",
        "/api/v1/config",
        Some(ADMIN),
        "",
    )
    .await;
    let body = http_body_util::BodyExt::collect(r.into_body())
        .await
        .unwrap()
        .to_bytes();
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["network_targets"], json!(["web"]));
}

#[test]
fn invalid_network_targets_are_rejected_at_startup() {
    for (alias, target) in [
        ("web", "ftp://x"),
        ("bad alias", "tls://x:443"),
        ("web", "x:puerto"),
    ] {
        let config = Config {
            credentials: vec![Credential {
                user: "admin".into(),
                token_sha256: hex::encode(Sha256::digest(ADMIN.as_bytes())),
                expires_at: i64::MAX,
                admin: true,
                targets: None,
            }],
            targets: Default::default(),
            network_targets: std::collections::HashMap::from([(alias.into(), target.into())]),
        };
        assert!(
            AppState::new(config, Connection::open_in_memory().unwrap()).is_err(),
            "{alias}={target}"
        );
    }
}

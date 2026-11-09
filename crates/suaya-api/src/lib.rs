//! API local: tokens opacos con expiración, autorización por propietario,
//! objetivos preconfigurados y persistencia SQLite. Nunca acepta rutas o URLs del cliente:
//! los escaneos usan alias de rutas, los diagnósticos de red alias de servicios y los
//! perfiles, solo los incluidos en Suaya. El contexto de la organización lo fija el
//! operador en la configuración. Sirve además un panel web estático (`/panel`).
use axum::{
    Extension, Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::sync::Semaphore;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub user: String,
    pub token_sha256: String,
    pub expires_at: i64,
    pub admin: bool,
    /// None conserva acceso a todos los alias; Some restringe explícitamente.
    #[serde(default)]
    pub targets: Option<Vec<String>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub credentials: Vec<Credential>,
    pub targets: HashMap<String, PathBuf>,
    /// Servicios de red autorizados para diagnóstico: alias → `tls://host:puerto`, `ssh://...`.
    #[serde(default)]
    pub network_targets: HashMap<String, String>,
    /// Contexto de la organización (TOML) que se aplica a todos los escaneos.
    #[serde(default)]
    pub organization: Option<PathBuf>,
}
#[derive(Clone)]
pub struct Principal {
    pub user: String,
    pub admin: bool,
    pub targets: Option<Vec<String>>,
}
#[derive(Hash, PartialEq, Eq)]
enum Bucket {
    Anonymous,
    User(String),
}
struct Budget {
    since: Instant,
    count: u32,
}
#[derive(Clone)]
pub struct AppState {
    credentials: Arc<RwLock<Vec<Credential>>>,
    targets: Arc<HashMap<String, PathBuf>>,
    network_targets: Arc<HashMap<String, suaya_red::Objetivo>>,
    organization: Arc<Option<suaya_core::contexto::ArchivoContexto>>,
    db: Arc<Mutex<Connection>>,
    scans: Arc<Semaphore>,
    requests: Arc<Mutex<HashMap<Bucket, Budget>>>,
}

impl AppState {
    pub fn new(mut config: Config, db: Connection) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !config.credentials.is_empty() && config.credentials.len() <= 100,
            "Se requieren 1..100 credenciales"
        );
        let mut users = std::collections::HashSet::new();
        let mut hashes = std::collections::HashSet::new();
        for c in &mut config.credentials {
            c.token_sha256.make_ascii_lowercase();
            if let Some(allowed) = &c.targets {
                anyhow::ensure!(
                    allowed.iter().all(|a| config.targets.contains_key(a)
                        || config.network_targets.contains_key(a)),
                    "Alias de credencial desconocido"
                );
            }
            anyhow::ensure!(
                !c.user.is_empty()
                    && c.user.len() <= 64
                    && c.user
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "Identidad inválida"
            );
            anyhow::ensure!(
                users.insert(c.user.clone()) && hashes.insert(c.token_sha256.clone()),
                "Identidad o token duplicado"
            );
            anyhow::ensure!(
                hex::decode(&c.token_sha256).is_ok_and(|h| h.len() == 32),
                "Hash de token inválido"
            );
            anyhow::ensure!(
                c.expires_at > time::OffsetDateTime::now_utc().unix_timestamp(),
                "Credencial expirada"
            );
        }
        let valid_alias = |name: &str| {
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        };
        anyhow::ensure!(
            config.network_targets.len() <= 256,
            "Se admiten hasta 256 servicios de red"
        );
        let mut network_targets = HashMap::new();
        for (name, target) in config.network_targets {
            anyhow::ensure!(
                valid_alias(&name) && !config.targets.contains_key(&name),
                "Servicio de red inválido o con alias repetido"
            );
            let objetivo = suaya_red::Objetivo::interpretar(&target)
                .map_err(|e| anyhow::anyhow!("Servicio de red {name}: {e}"))?;
            network_targets.insert(name, objetivo);
        }
        let organization = match &config.organization {
            Some(path) => Some(
                suaya_core::contexto::ArchivoContexto::cargar(path)
                    .map_err(|e| anyhow::anyhow!("Contexto de la organización: {e}"))?,
            ),
            None => None,
        };
        let mut targets = HashMap::new();
        for (name, path) in config.targets {
            anyhow::ensure!(valid_alias(&name), "Objetivo inválido");
            let path = path.canonicalize()?;
            anyhow::ensure!(path.is_dir() || path.is_file(), "Objetivo no regular");
            targets.insert(name, path);
        }
        db.busy_timeout(Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA max_page_count=147456;
          CREATE TABLE IF NOT EXISTS scans(id TEXT PRIMARY KEY, owner TEXT NOT NULL,
          created_at TEXT NOT NULL, status TEXT NOT NULL, cbom TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS scan_owner ON scans(owner);",
        )?;
        Ok(Self {
            credentials: Arc::new(RwLock::new(config.credentials)),
            targets: Arc::new(targets),
            network_targets: Arc::new(network_targets),
            organization: Arc::new(organization),
            db: Arc::new(Mutex::new(db)),
            scans: Arc::new(Semaphore::new(2)),
            requests: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    /// Purga también en períodos sin nuevos escaneos; invocada por el supervisor horario.
    pub fn maintenance(&self) -> anyhow::Result<()> {
        let db = self.db.lock().map_err(|_| anyhow::anyhow!("lock"))?;
        db.execute(
            "DELETE FROM scans WHERE julianday(created_at) < julianday('now','-30 days')",
            [],
        )?;
        Ok(())
    }
    /// Recarga validada y atómica. Cambiar alias requiere reiniciar la instancia.
    pub fn reload_credentials(&self, config: Config) -> anyhow::Result<()> {
        let candidate = Self::new(config, Connection::open_in_memory()?)?;
        anyhow::ensure!(
            *self.targets == *candidate.targets
                && *self.network_targets == *candidate.network_targets,
            "Cambiar objetivos requiere reiniciar"
        );
        let credentials = candidate
            .credentials
            .read()
            .map_err(|_| anyhow::anyhow!("lock"))?
            .clone();
        *self
            .credentials
            .write()
            .map_err(|_| anyhow::anyhow!("lock"))? = credentials;
        self.requests
            .lock()
            .map_err(|_| anyhow::anyhow!("lock"))?
            .clear();
        Ok(())
    }
    fn budget(&self, user: Bucket, limit: u32) -> bool {
        let Ok(mut budgets) = self.requests.lock() else {
            return false;
        };
        let budget = budgets.entry(user).or_insert(Budget {
            since: Instant::now(),
            count: 0,
        });
        if budget.since.elapsed() >= Duration::from_secs(60) {
            budget.since = Instant::now();
            budget.count = 0;
        }
        budget.count = budget.count.saturating_add(1);
        budget.count <= limit
    }
}

#[derive(Debug)]
pub struct ApiError(StatusCode);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(json!({"error": self.0.canonical_reason().unwrap_or("Error")})),
        )
            .into_response()
    }
}
fn internal(_: impl std::fmt::Display) -> ApiError {
    eprintln!(
        "{}",
        json!({"event":"api_internal_error", "at":time::OffsetDateTime::now_utc().unix_timestamp()})
    );
    ApiError(StatusCode::INTERNAL_SERVER_ERROR)
}

fn authenticate(state: &AppState, request: &Request) -> Result<Principal, ApiError> {
    let token = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| (32..=256).contains(&s.len()));
    let digest = token.map(|s| Sha256::digest(s.as_bytes()));
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let credentials = state.credentials.read().map_err(internal)?;
    let mut principal = None;
    if let Some(digest) = digest {
        for credential in credentials.iter() {
            let expected = hex::decode(&credential.token_sha256).unwrap_or_default();
            if expected.as_slice().ct_eq(digest.as_slice()).unwrap_u8() == 1
                && credential.expires_at > now
            {
                principal = Some(Principal {
                    user: credential.user.clone(),
                    admin: credential.admin,
                    targets: credential.targets.clone(),
                });
            }
        }
    }
    drop(credentials);
    let Some(principal) = principal else {
        // Un único bucket anónimo acotado no afecta a los usuarios autenticados.
        let status = if state.budget(Bucket::Anonymous, 600) {
            StatusCode::UNAUTHORIZED
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        return Err(ApiError(status));
    };
    if !state.budget(Bucket::User(principal.user.clone()), 60) {
        return Err(ApiError(StatusCode::TOO_MANY_REQUESTS));
    }
    Ok(principal)
}
async fn auth(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let id = uuid::Uuid::new_v4().to_string();
    let route = request
        .extensions()
        .get::<axum::extract::MatchedPath>()
        .map(|p| p.as_str())
        .unwrap_or("unknown")
        .to_string();
    let object = request
        .uri()
        .path()
        .rsplit('/')
        .next()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .map(|id| id.to_string());
    let method = request.method().to_string();
    let start = Instant::now();
    let mut user = None;
    let mut response = match authenticate(&state, &request) {
        Ok(principal) => {
            user = Some(principal.user.clone());
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    };
    response
        .headers_mut()
        .insert("x-request-id", id.parse().unwrap());
    eprintln!(
        "{}",
        json!({"event":"api_request", "request_id":id, "user":user,
        "method":method, "route":route, "object":object, "status":response.status().as_u16(),
        "duration_ms":start.elapsed().as_millis(), "at":time::OffsetDateTime::now_utc().unix_timestamp()})
    );
    response
}
async fn headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let h = response.headers_mut();
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; frame-ancestors 'none'"
                .parse()
                .unwrap(),
        );
    }
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/scan", post(scan))
        .route("/api/v1/diagnose", post(diagnose))
        .route("/api/v1/scans", get(list))
        .route("/api/v1/scan/{id}", get(read).delete(delete))
        .route("/api/v1/config", get(config))
        .route("/api/v1/targets", get(targets))
        .route("/api/v1/profiles", get(profiles))
        .route("/api/v1/scan/{id}/report", get(report))
        .route("/api/v1/scan/{id}/summary", get(summary))
        .route("/api/v1/compare/{a}/{b}", get(compare))
        .route("/api/v1/trends", get(trends))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth));
    Router::new()
        .merge(protected)
        .route(
            "/api/v1/health",
            get(|| async { Json(json!({"status":"ok", "version":env!("CARGO_PKG_VERSION")})) }),
        )
        .route("/api/v1/openapi.json", get(openapi))
        .route(
            "/",
            get(|| async { axum::response::Redirect::to("/panel") }),
        )
        .route("/panel", get(panel_html))
        .route("/panel/app.js", get(panel_js))
        .route("/panel/app.css", get(panel_css))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn(headers))
        .with_state(state)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScanRequest {
    target: String,
    /// Identificador de un perfil incluido en Suaya (nunca una ruta).
    #[serde(default)]
    profile: Option<String>,
}
async fn scan(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Json(input): Json<ScanRequest>,
) -> Result<Json<Value>, ApiError> {
    if !user.admin
        && user
            .targets
            .as_ref()
            .is_some_and(|targets| !targets.contains(&input.target))
    {
        return Err(ApiError(StatusCode::FORBIDDEN));
    }
    let path = state
        .targets
        .get(&input.target)
        .cloned()
        .ok_or(ApiError(StatusCode::BAD_REQUEST))?;
    let permit = state
        .scans
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS))?;
    let profile = match &input.profile {
        Some(id) => Some(
            suaya_core::Perfil::incluidos()
                .into_iter()
                .find(|p| p.perfil.id == *id)
                .ok_or(ApiError(StatusCode::BAD_REQUEST))?,
        ),
        None => None,
    };
    let name = input.target;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let knowledge = suaya_core::Conocimiento::embebido();
        let mut result = suaya_escaneo::escanear(&[path], &knowledge, &suaya_escaneo::Opciones { hilos: 2, ..Default::default() });
        if result.archivos_revisados == 0 && !result.avisos.is_empty() { return Err(ApiError(StatusCode::UNPROCESSABLE_ENTITY)); }
        let status = if result.avisos.is_empty() && result.archivos_omitidos == 0 { "completed" } else { "partial" };
        // Como en el CLI: el contexto va antes del perfil.
        if let Some(ctx) = state.organization.as_ref() {
            ctx.aplicar(&mut result.inventario, &suaya_escaneo::api::hoy());
        }
        let anio = time::OffsetDateTime::now_utc().year();
        if let Some(p) = &profile {
            p.evaluar(&mut result.inventario, &knowledge, anio);
        }
        let mut cbom = suaya_cbom::generar(&result.inventario, &knowledge, &suaya_cbom::OpcionesCbom {
            nombre_sistema: Some(name),
            perfil: profile.as_ref().map(|p| (p.perfil.nombre.clone(), p.perfil.referencia.clone())),
            declaraciones: profile.clone().map(|p| (p, anio)),
            ..Default::default()
        });
        if let Some(props) = cbom["metadata"]["properties"].as_array_mut() {
            props.push(json!({"name":"suaya:estado", "value":status}));
            if let Some(ctx) = state.organization.as_ref() {
                props.push(json!({"name":"suaya:horizonte-cuantico", "value":ctx.horizonte().to_string()}));
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let created = time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).map_err(internal)?;
        let text = serde_json::to_string(&cbom).map_err(internal)?;
        let db = state.db.lock().map_err(internal)?;
        // Retención 30 días, máximo 16 MiB por documento, 128 MiB por usuario, 512 MiB total.
        if text.len() > 16 * 1024 * 1024 { return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE)); }
        db.execute("DELETE FROM scans WHERE julianday(created_at) < julianday('now','-30 days')", []).map_err(internal)?;
        let used: i64 = db.query_row("SELECT COALESCE(SUM(length(CAST(cbom AS BLOB))),0) FROM scans WHERE owner=?1", [&user.user], |r| r.get(0)).map_err(internal)?;
        let total: i64 = db.query_row("SELECT COALESCE(SUM(length(CAST(cbom AS BLOB))),0) FROM scans", [], |r| r.get(0)).map_err(internal)?;
        if used + text.len() as i64 > 128 * 1024 * 1024 || total + text.len() as i64 > 512 * 1024 * 1024 { return Err(ApiError(StatusCode::CONFLICT)); }
        let count: i64 = db.query_row("SELECT COUNT(*) FROM scans WHERE owner=?1", [&user.user], |r| r.get(0)).map_err(internal)?;
        if count >= 1000 { return Err(ApiError(StatusCode::CONFLICT)); }
        db.execute("INSERT INTO scans VALUES(?1,?2,?3,?4,?5)", params![id,user.user,created,status,text]).map_err(internal)?;
        Ok(Json(json!({"id":id,"status":status,"created_at":created,"files":result.archivos_revisados,"skipped":result.archivos_omitidos,"warnings":result.avisos.len()})))
    }).await.map_err(internal)?
}
/// Diagnóstico de conectividad e intercambio de llaves y certificados de un
/// servicio preconfigurado. No se persiste: el resultado describe un instante.
async fn diagnose(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Json(input): Json<ScanRequest>,
) -> Result<Json<Value>, ApiError> {
    if !user.admin
        && user
            .targets
            .as_ref()
            .is_some_and(|targets| !targets.contains(&input.target))
    {
        return Err(ApiError(StatusCode::FORBIDDEN));
    }
    let objetivo = state
        .network_targets
        .get(&input.target)
        .cloned()
        .ok_or(ApiError(StatusCode::BAD_REQUEST))?;
    let permit = state
        .scans
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError(StatusCode::TOO_MANY_REQUESTS))?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let knowledge = suaya_core::Conocimiento::embebido();
        let diagnostico = suaya_red::diagnosticar(
            std::slice::from_ref(&objetivo),
            &knowledge,
            &suaya_red::Opciones::default(),
        )
        .pop()
        .ok_or_else(|| internal("sin diagnóstico"))?;
        let created = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(internal)?;
        Ok(Json(json!({
            "target": input.target,
            "created_at": created,
            "worst": diagnostico.peor().map(suaya_red::Nivel::como_texto),
            "diagnosis": diagnostico,
        })))
    })
    .await
    .map_err(internal)?
}
async fn list(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    tokio::task::spawn_blocking(move || {
    let db = state.db.lock().map_err(internal)?;
    let mut stmt = db.prepare("SELECT id,created_at,status FROM scans WHERE owner=?1 OR ?2 ORDER BY created_at DESC LIMIT 1000").map_err(internal)?;
    let rows = stmt.query_map(params![user.user,user.admin], |r| Ok(json!({"id":r.get::<_,String>(0)?,"created_at":r.get::<_,String>(1)?,"status":r.get::<_,String>(2)?}))).map_err(internal)?;
    Ok(Json(Value::Array(
        rows.collect::<Result<Vec<_>, _>>().map_err(internal)?,
    )))
    }).await.map_err(internal)?
}
fn validate_id(id: &str) -> Result<(), ApiError> {
    uuid::Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| ApiError(StatusCode::NOT_FOUND))
}
/// CBOM de un escaneo del usuario (o de cualquiera, si es administrador).
fn load_cbom(state: &AppState, user: &Principal, id: &str) -> Result<String, ApiError> {
    validate_id(id)?;
    let db = state.db.lock().map_err(internal)?;
    db.query_row(
        "SELECT cbom FROM scans WHERE id=?1 AND (owner=?2 OR ?3)",
        params![id, user.user, user.admin],
        |r| r.get(0),
    )
    .optional()
    .map_err(internal)?
    .ok_or(ApiError(StatusCode::NOT_FOUND))
}
fn parse_cbom(text: &str) -> Result<suaya_cbom::CbomLeido, ApiError> {
    suaya_cbom::leer(text).map_err(internal)
}
async fn read(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validate_id(&id)?;
    tokio::task::spawn_blocking(move || {
        let text = load_cbom(&state, &user, &id)?;
        Ok(Json(serde_json::from_str(&text).map_err(internal)?))
    })
    .await
    .map_err(internal)?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportQuery {
    #[serde(default)]
    format: Option<String>,
}
/// Reporte de un escaneo: md, html, pci, sarif, csv, jsonl o tickets.
async fn report(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Path(id): Path<String>,
    Query(q): Query<ReportQuery>,
) -> Result<Response, ApiError> {
    validate_id(&id)?;
    let format = q.format.unwrap_or_else(|| "html".into());
    let (content_type, extension) = match format.as_str() {
        "html" => ("text/html; charset=utf-8", "html"),
        "md" | "pci" => ("text/markdown; charset=utf-8", "md"),
        "sarif" => ("application/sarif+json", "sarif"),
        "csv" => ("text/csv; charset=utf-8", "csv"),
        "jsonl" => ("application/x-ndjson", "jsonl"),
        "tickets" => ("application/json", "json"),
        _ => return Err(ApiError(StatusCode::BAD_REQUEST)),
    };
    tokio::task::spawn_blocking(move || {
        let text = load_cbom(&state, &user, &id)?;
        let cbom = parse_cbom(&text)?;
        let c = suaya_core::Conocimiento::embebido();
        use suaya_cbom::formatos;
        let body = match format.as_str() {
            "html" => suaya_cbom::reporte_html(&cbom, &c),
            "md" => suaya_cbom::reporte_markdown(&cbom, &c),
            "pci" => formatos::pci(&cbom, &c),
            "sarif" => serde_json::to_string_pretty(&formatos::sarif(&cbom, &c)).map_err(internal)?,
            "csv" => formatos::csv(&cbom, &c),
            "jsonl" => formatos::jsonl(&cbom, &c),
            _ => serde_json::to_string_pretty(&formatos::tickets(&cbom, &c)).map_err(internal)?,
        };
        let mut response = body.into_response();
        let h = response.headers_mut();
        h.insert(header::CONTENT_TYPE, content_type.parse().map_err(internal)?);
        h.insert(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"suaya-{id}.{extension}\"").parse().map_err(internal)?,
        );
        if format == "html" {
            // El reporte HTML trae su propio estilo y ningún script.
            h.insert(
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'none'"
                    .parse()
                    .map_err(internal)?,
            );
        }
        Ok(response)
    })
    .await
    .map_err(internal)?
}
/// Resumen de un escaneo: totales por prioridad y lo más urgente.
async fn summary(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    validate_id(&id)?;
    tokio::task::spawn_blocking(move || {
        let cbom = parse_cbom(&load_cbom(&state, &user, &id)?)?;
        let punto = suaya_cbom::tendencias::tendencias(std::slice::from_ref(&cbom)).pop();
        let mut urgentes: Vec<&suaya_cbom::lectura::Registro> =
            cbom.registros.iter().filter(|r| r.prioridad <= 2).collect();
        urgentes.sort_by_key(|r| (r.prioridad, r.nombre.clone()));
        let urgentes: Vec<Value> = urgentes
            .iter()
            .take(25)
            .map(|r| {
                json!({
                    "name": suaya_core::idioma::traducir(&r.nombre),
                    "priority": r.prioridad,
                    "action": r.accion,
                    "location": r.ubicaciones.first(),
                    "exception": r.excepcion.as_ref().filter(|e| e.2).map(|e| e.0.clone()),
                })
            })
            .collect();
        Ok(Json(json!({
            "system": cbom.sistema,
            "created_at": cbom.fecha,
            "status": cbom.estado,
            "profile": cbom.perfil.as_ref().map(|p| p.0.clone()),
            "totals": punto,
            "urgent": urgentes,
        })))
    })
    .await
    .map_err(internal)?
}
/// Diferencias entre dos escaneos del usuario.
async fn compare(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Path((a, b)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    validate_id(&a)?;
    validate_id(&b)?;
    tokio::task::spawn_blocking(move || {
        let anterior = parse_cbom(&load_cbom(&state, &user, &a)?)?;
        let actual = parse_cbom(&load_cbom(&state, &user, &b)?)?;
        let d = suaya_cbom::comparar(&anterior, &actual);
        Ok(Json(json!({
            "previous": a,
            "current": b,
            "regression": d.hay_regresion(),
            "text": d.como_texto(&anterior, &actual),
        })))
    })
    .await
    .map_err(internal)?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrendsQuery {
    /// Alias del objetivo (nombre del sistema escaneado).
    #[serde(default)]
    target: Option<String>,
}
/// Evolución de los últimos 100 escaneos del usuario, opcionalmente de un alias.
async fn trends(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Query(q): Query<TrendsQuery>,
) -> Result<Json<Value>, ApiError> {
    if q.target.as_ref().is_some_and(|t| t.len() > 64) {
        return Err(ApiError(StatusCode::BAD_REQUEST));
    }
    tokio::task::spawn_blocking(move || {
        let textos: Vec<String> = {
            let db = state.db.lock().map_err(internal)?;
            let mut stmt = db
                .prepare("SELECT cbom FROM scans WHERE owner=?1 OR ?2 ORDER BY created_at DESC LIMIT 100")
                .map_err(internal)?;
            let filas = stmt
                .query_map(params![user.user, user.admin], |r| r.get::<_, String>(0))
                .map_err(internal)?;
            filas.collect::<Result<Vec<_>, _>>().map_err(internal)?
        };
        let cboms: Vec<suaya_cbom::CbomLeido> = textos
            .iter()
            .filter_map(|t| suaya_cbom::leer(t).ok())
            .filter(|c| q.target.as_ref().is_none_or(|t| c.sistema == *t))
            .collect();
        let serie = suaya_cbom::tendencias::tendencias(&cboms);
        Ok(Json(suaya_cbom::tendencias::como_json(&serie)))
    })
    .await
    .map_err(internal)?
}
/// Alias que el usuario puede escanear o diagnosticar.
async fn targets(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
) -> Json<Value> {
    let visible =
        |name: &String| user.admin || user.targets.as_ref().is_none_or(|t| t.contains(name));
    let mut targets: Vec<&String> = state.targets.keys().filter(|n| visible(n)).collect();
    targets.sort();
    let mut network_targets: Vec<&String> = state
        .network_targets
        .keys()
        .filter(|n| visible(n))
        .collect();
    network_targets.sort();
    Json(
        json!({"targets": targets, "network_targets": network_targets, "organization": state.organization.is_some()}),
    )
}
/// Perfiles de política incluidos.
async fn profiles() -> Json<Value> {
    Json(Value::Array(
        suaya_core::Perfil::incluidos()
            .iter()
            .map(|p| json!({"id": p.perfil.id, "name": p.perfil.nombre, "reference": p.perfil.referencia}))
            .collect(),
    ))
}
async fn openapi() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        include_str!("../openapi.json"),
    )
        .into_response()
}
/// Política del panel: solo recursos propios y llamadas a esta misma API.
const CSP_PANEL: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";
fn static_file(content_type: &'static str, body: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CONTENT_SECURITY_POLICY, CSP_PANEL),
        ],
        body,
    )
        .into_response()
}
async fn panel_html() -> Response {
    static_file(
        "text/html; charset=utf-8",
        include_str!("../panel/index.html"),
    )
}
async fn panel_js() -> Response {
    static_file(
        "text/javascript; charset=utf-8",
        include_str!("../panel/app.js"),
    )
}
async fn panel_css() -> Response {
    static_file("text/css; charset=utf-8", include_str!("../panel/app.css"))
}
async fn delete(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    validate_id(&id)?;
    tokio::task::spawn_blocking(move || {
        let db = state.db.lock().map_err(internal)?;
        let n = db
            .execute(
                "DELETE FROM scans WHERE id=?1 AND (owner=?2 OR ?3)",
                params![id, user.user, user.admin],
            )
            .map_err(internal)?;
        if n == 0 {
            Err(ApiError(StatusCode::NOT_FOUND))
        } else {
            Ok(StatusCode::NO_CONTENT)
        }
    })
    .await
    .map_err(internal)?
}
async fn config(
    State(state): State<AppState>,
    Extension(user): Extension<Principal>,
) -> Result<Json<Value>, ApiError> {
    if !user.admin {
        return Err(ApiError(StatusCode::FORBIDDEN));
    }
    let mut targets = state.targets.keys().cloned().collect::<Vec<_>>();
    targets.sort();
    let mut network_targets = state.network_targets.keys().cloned().collect::<Vec<_>>();
    network_targets.sort();
    Ok(Json(
        json!({"targets":targets,"network_targets":network_targets,"configuration":"SIGHUP reloads credentials; restart to change targets", "scan_concurrency":2, "max_document_bytes":16777216, "max_owner_bytes":134217728, "max_total_bytes":536870912, "retention_days":30}),
    ))
}

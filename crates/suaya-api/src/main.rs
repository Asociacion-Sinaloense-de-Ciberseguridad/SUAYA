use clap::Parser;
use std::{net::SocketAddr, path::PathBuf};
#[derive(Parser)]
#[command(
    version,
    about = "API local de SUAYA: configurar TLS en un proxy antes de exponerla"
)]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    database: PathBuf,
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    anyhow::ensure!(
        args.listen.ip().is_loopback(),
        "La API solo escucha loopback; use un proxy TLS para acceso remoto"
    );
    let config = read_config(&args.config)?;
    // El directorio de datos debe ser exclusivo de la cuenta del servicio.
    let parent = args
        .database
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let dir = std::fs::metadata(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        anyhow::ensure!(
            dir.permissions().mode() & 0o077 == 0,
            "El directorio de datos requiere permisos 0700"
        );
        if !args.database.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&args.database)?;
        }
        let meta = std::fs::symlink_metadata(&args.database)?;
        anyhow::ensure!(
            meta.is_file() && meta.permissions().mode() & 0o077 == 0,
            "Base de datos no regular o permisos inseguros"
        );
    }
    let state = suaya_api::AppState::new(config, rusqlite::Connection::open(&args.database)?)?;
    #[cfg(unix)]
    {
        let state_reload = state.clone();
        let path = args.config.clone();
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::spawn(async move {
            while signal.recv().await.is_some() {
                let ok = read_config(&path)
                    .and_then(|c| state_reload.reload_credentials(c))
                    .is_ok();
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"credentials_reload", "success":ok})
                );
            }
        });
    }
    let maintenance = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let state = maintenance.clone();
            let ok = tokio::task::spawn_blocking(move || state.maintenance().is_ok())
                .await
                .unwrap_or(false);
            eprintln!(
                "{}",
                serde_json::json!({"event":"retention_cleanup", "success":ok})
            );
        }
    });
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    eprintln!("SUAYA API {} en {}", env!("CARGO_PKG_VERSION"), args.listen);
    axum::serve(listener, suaya_api::router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

fn read_config(path: &std::path::Path) -> anyhow::Result<suaya_api::Config> {
    let meta = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        meta.is_file() && meta.len() <= 65536,
        "Configuración no regular o demasiado grande"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "La configuración requiere permisos 0600"
        );
    }
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

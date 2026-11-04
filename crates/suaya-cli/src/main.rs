//! Suaya: interfaz de línea de comandos.
//!
//! Suaya ("cuidar, proteger" en yoremnokki, la lengua yoreme mayo de Sinaloa)
//! inventaría los activos criptográficos de un sistema, los exporta como CBOM
//! CycloneDX 1.7 y evalúa su preparación poscuántica.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{ArgAction, Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use suaya_cbom::{OpcionesCbom, comparar, generar, leer, reporte_html, reporte_markdown};
use suaya_core::{
    Conocimiento, EstadoCumplimiento, Inventario, Perfil, clasificar, etiqueta_prioridad,
};
use suaya_escaneo::{Opciones, escanear_con_imagenes};
use suaya_red::{Objetivo, registro, sondear};

/// `println!` en el idioma actual.
macro_rules! decir {
    ($es:literal, $en:literal $(, $a:expr)* $(,)?) => {
        println!("{}", suaya_core::t!($es, $en $(, $a)*))
    };
}

/// `eprintln!` en el idioma actual.
macro_rules! decir_err {
    ($es:literal, $en:literal $(, $a:expr)* $(,)?) => {
        eprintln!("{}", suaya_core::t!($es, $en $(, $a)*))
    };
}

/// `bail!` en el idioma actual.
macro_rules! fallar {
    ($es:literal, $en:literal $(, $a:expr)* $(,)?) => {
        anyhow::bail!("{}", suaya_core::t!($es, $en $(, $a)*))
    };
}

#[derive(Parser)]
#[command(
    name = "suaya",
    version,
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    subcommand_help_heading = "Órdenes",
    subcommand_value_name = "ORDEN",
    about = "Suaya: protege lo que sostiene tu criptografía.",
    long_about = "Inventario criptográfico abierto (CBOM CycloneDX 1.7) con evaluación de preparación poscuántica.\n\
                  «Suaya» significa cuidar, proteger, en yoremnokki, la lengua yoreme mayo de Sinaloa.",
    after_help = "Códigos de salida: 0 éxito; 1 error; 2 se alcanzó el umbral de --fallar-en o --fallar-si-empeora; 3 firma no válida; 4 inventario incompleto."
)]
struct Cli {
    #[command(subcommand)]
    orden: Orden,
    /// Muestra la ayuda.
    #[arg(short = 'h', long = "ayuda", visible_alias = "help", action = ArgAction::Help, global = true, display_order = 1000)]
    ayuda: Option<bool>,
    /// Muestra la versión.
    #[arg(short = 'V', long = "version", action = ArgAction::Version)]
    version: Option<bool>,
    /// Idioma de la interfaz y de los reportes: es o en (también SUAYA_IDIOMA).
    #[arg(long, global = true, value_name = "es|en", value_parser = ["es", "en"], hide_possible_values = true, display_order = 999)]
    idioma: Option<String>,
}

const PLANTILLA_AYUDA: &str =
    "{before-help}{about-with-newline}\nUso: {usage}\n\n{all-args}{after-help}";
const PLANTILLA_AYUDA_EN: &str =
    "{before-help}{about-with-newline}\nUsage: {usage}\n\n{all-args}{after-help}";

/// Construye la interfaz con encabezados de ayuda en el idioma elegido.
fn interfaz() -> clap::Command {
    let en = suaya_core::idioma::es_ingles();
    let tr =
        |t: &clap::builder::StyledStr| suaya_core::idioma::traducir(&t.to_string()).into_owned();
    let ajustar = move |c: clap::Command| {
        let mut c = c.help_template(if en {
            PLANTILLA_AYUDA_EN
        } else {
            PLANTILLA_AYUDA
        });
        if en {
            if let Some(t) = c.get_about().map(tr) {
                c = c.about(t);
            }
            if let Some(t) = c.get_long_about().map(tr) {
                c = c.long_about(t);
            }
            if let Some(t) = c.get_after_help().map(tr) {
                c = c.after_help(t);
            }
            c = c.subcommand_help_heading("Commands");
        }
        c.mut_args(move |a| {
            let a = if a.is_positional() {
                a.help_heading(if en { "Arguments" } else { "Argumentos" })
            } else {
                a.help_heading(if en { "Options" } else { "Opciones" })
            };
            if !en {
                return a;
            }
            let a = match a.get_help().map(tr) {
                Some(h) => a.help(h),
                None => a,
            };
            match a.get_long_help().map(tr) {
                Some(h) => a.long_help(h),
                None => a,
            }
        })
    };
    ajustar(Cli::command()).mut_subcommands(ajustar)
}

#[derive(Subcommand)]
enum Orden {
    /// Escanea archivos y directorios (y, opcionalmente, servicios de red) y genera el CBOM.
    #[command(
        visible_alias = "scan",
        override_usage = "suaya escanear [OPCIONES] <RUTAS>..."
    )]
    Escanear {
        /// Archivos o directorios a escanear.
        #[arg(help_heading = "Argumentos")]
        rutas: Vec<PathBuf>,
        /// Servicio de red a sondear además de los archivos (repetible): tls://, ssh://, smtp://, imap://, pop3://, ldap://, postgres:// o mysql://host:puerto.
        #[arg(long = "objetivo", value_name = "OBJETIVO")]
        objetivos: Vec<String>,
        /// Imagen de contenedor (repetible): archivo tar de «docker save», «podman save» u OCI, o docker://registro/repositorio:etiqueta para descargarla del registro.
        #[arg(long = "imagen", value_name = "IMAGEN")]
        imagenes: Vec<String>,
        /// CBOM CycloneDX de otra herramienta que se une a este inventario (repetible).
        #[arg(long = "importar", value_name = "CBOM.json")]
        importados: Vec<PathBuf>,
        /// Plataforma a descargar de una imagen multiplataforma (predeterminado: la de este equipo, p. ej. linux/amd64).
        #[arg(long, value_name = "SO/ARQ")]
        plataforma: Option<String>,
        /// Autoridad certificadora adicional (PEM) para un registro privado.
        #[arg(long, value_name = "ARCHIVO.pem")]
        ca_registro: Option<PathBuf>,
        /// Permite HTTP de desarrollo únicamente para registros loopback.
        #[arg(long)]
        registro_http_local: bool,
        /// Autoriza un origen de tokens por registro: REGISTRO=https://auth.example (repetible).
        #[arg(long)]
        registro_token_origen: Vec<String>,
        #[command(flatten)]
        salida: ArgsSalida,
        #[command(flatten)]
        red: ArgsRed,
        /// Sigue enlaces simbólicos.
        #[arg(long)]
        seguir_enlaces: bool,
        /// Revisa también ejecutables grandes (hasta 512 MiB) en busca de su biblioteca criptográfica y su versión.
        #[arg(long)]
        binarios: bool,
        /// Hilos de análisis (predeterminado: todos los núcleos).
        #[arg(long, default_value_t = 0, hide_default_value = true)]
        hilos: usize,
        /// Tamaño máximo de archivo, en MiB (predeterminado: 5).
        #[arg(long, default_value_t = 5, hide_default_value = true)]
        tamano_maximo: u64,
    },
    /// Sondea servicios TLS, STARTTLS y SSH en la red y genera el CBOM.
    #[command(
        visible_alias = "probe",
        override_usage = "suaya sondear [OPCIONES] <OBJETIVOS>...",
        long_about = "Sondea servicios TLS y SSH para observar la criptografía que ofrecen realmente: \
                      versiones de TLS, grupos de intercambio de llaves (incluidos los híbridos con ML-KEM), \
                      algoritmos SSH y la cadena de certificados.\n\n\
                      Uso responsable: sondee solo sistemas que administre o que tenga autorización expresa \
                      para evaluar. Cada objetivo recibe unas veinte conexiones breves y secuenciales."
    )]
    Sondear {
        /// Servicios a sondear: tls://, ssh://, smtp://, imap://, pop3://, ldap://, postgres:// o mysql://host:puerto, o host:puerto.
        #[arg(required = true, help_heading = "Argumentos")]
        objetivos: Vec<String>,
        #[command(flatten)]
        salida: ArgsSalida,
        #[command(flatten)]
        red: ArgsRed,
    },
    /// Inventaría un clúster de Kubernetes en vivo (Secrets, Ingress y cert-manager), solo con lecturas.
    #[command(
        visible_alias = "k8s",
        override_usage = "suaya kubernetes [OPCIONES]",
        long_about = "Lee por la API del clúster los Secrets, los Ingress y, si existe, los Certificates de cert-manager. \
                      Solo hace lecturas (GET) y analiza el contenido de los Secrets en memoria; nunca lo guarda.\n\n\
                      Requiere permiso «list» sobre secrets e ingresses. Usa el kubeconfig (contexto actual o --contexto) \
                      o la cuenta de servicio cuando se ejecuta dentro del clúster."
    )]
    Kubernetes {
        /// Ruta del kubeconfig (predeterminada: $KUBECONFIG o ~/.kube/config).
        #[arg(long)]
        kubeconfig: Option<PathBuf>,
        /// Contexto del kubeconfig (predeterminado: current-context).
        #[arg(long)]
        contexto: Option<String>,
        /// Espacio de nombres a leer (repetible; predeterminado: todos).
        #[arg(long = "espacio", value_name = "ESPACIO")]
        espacios: Vec<String>,
        /// Sondea además por TLS los hosts publicados en los Ingress.
        #[arg(long)]
        sondear_ingress: bool,
        #[command(flatten)]
        salida: ArgsSalida,
        #[command(flatten)]
        red: ArgsRed,
    },
    /// Genera el reporte ejecutivo a partir de un CBOM de Suaya.
    #[command(
        visible_alias = "report",
        override_usage = "suaya reporte [OPCIONES] <CBOM>"
    )]
    Reporte {
        /// CBOM generado por Suaya.
        #[arg(help_heading = "Argumentos")]
        cbom: PathBuf,
        /// Archivo de salida (.md o .html); si se omite, se imprime en pantalla.
        #[arg(short = 'o', long)]
        salida: Option<PathBuf>,
        /// Formato: md o html (predeterminado: según la extensión de la salida).
        #[arg(long, value_parser = ["md", "html"], hide_possible_values = true)]
        formato: Option<String>,
        /// Directorio con algoritmos.toml y madurez.toml que sustituye a la base incrustada.
        #[arg(long)]
        base_conocimiento: Option<PathBuf>,
    },
    /// Compara dos CBOM para seguir el avance de una migración.
    #[command(
        visible_alias = "diff",
        override_usage = "suaya comparar [OPCIONES] <ANTERIOR> <ACTUAL>"
    )]
    Comparar {
        /// CBOM del escaneo anterior.
        #[arg(help_heading = "Argumentos", display_order = 1)]
        anterior: PathBuf,
        /// CBOM del escaneo actual.
        #[arg(help_heading = "Argumentos", display_order = 2)]
        actual: PathBuf,
        /// Termina con código 2 si aparecen hallazgos críticos o altos, o si algo empeora.
        #[arg(long)]
        fallar_si_empeora: bool,
    },
    /// Importa CBOM CycloneDX de otras herramientas (p. ej. CBOMkit) y los clasifica con el criterio de Suaya.
    #[command(
        visible_alias = "import",
        override_usage = "suaya importar [OPCIONES] <CBOM>..."
    )]
    Importar {
        /// CBOM CycloneDX (JSON) a importar.
        #[arg(required = true, help_heading = "Argumentos")]
        cboms: Vec<PathBuf>,
        #[command(flatten)]
        salida: ArgsSalida,
    },
    /// Lista los perfiles de política incluidos.
    #[command(visible_alias = "profiles", override_usage = "suaya perfiles")]
    Perfiles,
    /// Genera un par de llaves de firma híbrida (ML-DSA-65 y Ed25519) para firmar CBOM.
    #[command(
        visible_alias = "keygen",
        override_usage = "suaya llaves [OPCIONES] <PREFIJO>"
    )]
    Llaves {
        /// Prefijo de los archivos: crea <PREFIJO>.privada.json y <PREFIJO>.publica.json.
        #[arg(help_heading = "Argumentos")]
        prefijo: PathBuf,
        /// Variable de entorno con la frase de paso que cifra la llave privada.
        #[arg(
            long,
            value_name = "VARIABLE",
            default_value = "SUAYA_CLAVE_FIRMA",
            hide_default_value = true
        )]
        clave_env: String,
    },
    /// Firma un CBOM con ML-DSA-65 y Ed25519 (firma en un archivo aparte).
    #[command(
        visible_alias = "sign",
        override_usage = "suaya firmar [OPCIONES] <CBOM> --llave <PRIVADA>"
    )]
    Firmar {
        /// CBOM a firmar.
        #[arg(help_heading = "Argumentos")]
        cbom: PathBuf,
        /// Llave privada de Suaya (<PREFIJO>.privada.json).
        #[arg(long)]
        llave: PathBuf,
        /// Archivo de la firma (predeterminado: <CBOM>.firma).
        #[arg(short = 'o', long)]
        salida: Option<PathBuf>,
        /// Variable de entorno con la frase de paso de la llave privada.
        #[arg(
            long,
            value_name = "VARIABLE",
            default_value = "SUAYA_CLAVE_FIRMA",
            hide_default_value = true
        )]
        clave_env: String,
    },
    /// Verifica la firma híbrida de un CBOM: deben ser válidas ML-DSA-65 y Ed25519.
    #[command(
        visible_alias = "verify",
        override_usage = "suaya verificar [OPCIONES] <CBOM> --llave-publica <PUBLICA>"
    )]
    Verificar {
        /// CBOM firmado.
        #[arg(help_heading = "Argumentos")]
        cbom: PathBuf,
        /// Llave pública de Suaya (<PREFIJO>.publica.json).
        #[arg(long)]
        llave_publica: PathBuf,
        /// Archivo de la firma (predeterminado: <CBOM>.firma).
        #[arg(long)]
        firma: Option<PathBuf>,
    },
    /// Imprime el autocompletado para un intérprete de órdenes (bash, zsh, fish, powershell o elvish).
    #[command(hide = true, override_usage = "suaya completado <INTERPRETE>")]
    Completado {
        /// Intérprete de órdenes.
        #[arg(help_heading = "Argumentos")]
        interprete: clap_complete::Shell,
    },
    /// Imprime la página de manual (roff).
    #[command(hide = true, override_usage = "suaya manual")]
    Manual,
    /// Muestra la base de conocimiento y la tabla de madurez del ecosistema.
    #[command(
        visible_alias = "knowledge",
        override_usage = "suaya conocimiento [OPCIONES]"
    )]
    Conocimiento {
        /// Directorio con algoritmos.toml y madurez.toml que sustituye a la base incrustada.
        #[arg(long)]
        base_conocimiento: Option<PathBuf>,
    },
}

/// Opciones comunes de salida.
#[derive(Args)]
struct ArgsSalida {
    /// Devuelve código 4 si hay avisos o archivos omitidos; conserva el resultado parcial.
    #[arg(long)]
    fallar_si_incompleto: bool,
    /// Archivo CBOM de salida, JSON CycloneDX 1.7 (predeterminado: suaya-cbom.json).
    #[arg(
        short = 'o',
        long,
        default_value = "suaya-cbom.json",
        hide_default_value = true
    )]
    salida: PathBuf,
    /// Genera además el reporte ejecutivo: HTML si termina en .html, Markdown en otro caso.
    #[arg(short, long)]
    reporte: Option<PathBuf>,
    /// Nombre del sistema evaluado.
    #[arg(short, long)]
    nombre: Option<String>,
    /// Perfil de política para evaluar el cumplimiento: nist-ir-8547, cnsa-2.0 o un archivo TOML propio.
    #[arg(long)]
    perfil: Option<String>,
    /// Año de evaluación del perfil (predeterminado: el actual).
    #[arg(long)]
    anio: Option<i32>,
    /// Directorio con algoritmos.toml y madurez.toml que sustituye a la base incrustada.
    #[arg(long)]
    base_conocimiento: Option<PathBuf>,
    /// Termina con código 2 si hay hallazgos de esta prioridad o más grave (1 = crítica ... 4 = baja).
    #[arg(long, value_parser = clap::value_parser!(u8).range(1..=4))]
    fallar_en: Option<u8>,
    /// Muestra los avisos de lo que no se pudo interpretar o alcanzar.
    #[arg(short, long)]
    detallado: bool,
    /// Firma el CBOM generado con esta llave privada de Suaya (crea <SALIDA>.firma).
    #[arg(long, value_name = "PRIVADA.json")]
    firmar_con: Option<PathBuf>,
}

/// Opciones del sondeo de red.
#[derive(Args)]
struct ArgsRed {
    /// Capacidad tecnológica de los servicios TLS, p. ej. vpn-cifrado-red o conectividad-nube (predeterminada: servidores-web).
    #[arg(long, default_value = "servidores-web", hide_default_value = true)]
    capacidad_tls: String,
    /// No obtiene la cadena de certificados.
    #[arg(long)]
    sin_certificados: bool,
    /// Tiempo límite por conexión, en segundos (predeterminado: 5).
    #[arg(long, default_value_t = 5, hide_default_value = true)]
    tiempo_limite: u64,
}

impl ArgsRed {
    fn opciones(&self, c: &Conocimiento) -> Result<suaya_red::Opciones> {
        if c.capacidad(&self.capacidad_tls).is_none() {
            let validas: Vec<&str> = c.capacidades.iter().map(|x| x.id.as_str()).collect();
            fallar!(
                "capacidad desconocida: {} (válidas: {})",
                "unknown capability: {} (valid: {})",
                self.capacidad_tls,
                validas.join(", ")
            );
        }
        Ok(suaya_red::Opciones {
            tiempo_limite: std::time::Duration::from_secs(self.tiempo_limite.max(1)),
            capacidad_tls: self.capacidad_tls.clone(),
            certificados: !self.sin_certificados,
        })
    }
}

fn interpretar_objetivos(textos: &[String]) -> Result<Vec<Objetivo>> {
    textos
        .iter()
        .map(|t| Objetivo::interpretar(t).map_err(anyhow::Error::msg))
        .collect()
}

/// Escribe el CBOM y el reporte, imprime el resumen y decide el código de salida.
fn finalizar(
    inventario: &mut Inventario,
    c: &Conocimiento,
    a: &ArgsSalida,
    raices: Vec<String>,
    avisos: &[String],
    linea_resumen: &str,
) -> Result<ExitCode> {
    let perfil = match &a.perfil {
        Some(p) => Some(Perfil::cargar(p).map_err(anyhow::Error::msg)?),
        None => None,
    };
    let anio = a
        .anio
        .unwrap_or_else(|| time::OffsetDateTime::now_utc().year());
    if let Some(p) = &perfil {
        p.evaluar(inventario, c, anio);
    }
    let mut documento = generar(
        inventario,
        c,
        &OpcionesCbom {
            nombre_sistema: a.nombre.clone(),
            raices,
            perfil: perfil
                .as_ref()
                .map(|p| (p.perfil.nombre.clone(), p.perfil.referencia.clone())),
            declaraciones: perfil.as_ref().map(|p| (p.clone(), anio)),
        },
    );
    if let Some(props) = documento["metadata"]["properties"].as_array_mut() {
        props.push(serde_json::json!({"name":"suaya:estado", "value":if avisos.is_empty() {"completed"} else {"partial"}}));
        props.push(serde_json::json!({"name":"suaya:avisos", "value":avisos.len().to_string()}));
    }
    let texto = serde_json::to_string_pretty(&documento)?;
    escribir_atomico(&a.salida, &texto)
        .with_context(|| suaya_core::t!("al escribir {}", "writing {}", a.salida.display()))?;
    if let Some(llave) = &a.firmar_con {
        firmar_archivo(
            &a.salida,
            llave,
            "SUAYA_CLAVE_FIRMA",
            &con_sufijo(&a.salida, ".firma"),
        )?;
    }
    if let Some(ruta_reporte) = &a.reporte {
        let leido = leer(&texto).map_err(anyhow::Error::msg)?;
        escribir_atomico(ruta_reporte, texto_reporte(&leido, c, ruta_reporte, None)).with_context(
            || suaya_core::t!("al escribir {}", "writing {}", ruta_reporte.display()),
        )?;
    }

    let activos = &inventario.activos;
    let prioridad =
        |x: &suaya_core::Activo| x.clasificacion.as_ref().map(|k| k.prioridad).unwrap_or(9);
    println!(
        "Suaya {} · {}",
        suaya_core::VERSION,
        suaya_core::idioma::traducir(&c.procedencia())
    );
    decir!(
        "{linea_resumen} · activos criptográficos: {}",
        "{linea_resumen} · cryptographic assets: {}",
        activos.len()
    );
    println!();
    for p in 1..=5u8 {
        println!(
            "  {:<12} {:>4}",
            etiqueta_prioridad(p),
            activos.iter().filter(|x| prioridad(x) == p).count()
        );
    }
    if let Some(p) = &perfil {
        let n = |e: EstadoCumplimiento| {
            activos
                .iter()
                .filter(|x| x.cumplimiento.as_ref().is_some_and(|k| k.estado == e))
                .count()
        };
        println!();
        let sin_evaluar = n(EstadoCumplimiento::SinEvaluar);
        decir!(
            "  {}: {} no conformes · {} en transición · {} conformes{}",
            "  {}: {} non-compliant · {} in transition · {} compliant{}",
            suaya_core::idioma::traducir(&p.perfil.nombre),
            n(EstadoCumplimiento::NoConforme),
            n(EstadoCumplimiento::Transicion),
            n(EstadoCumplimiento::Conforme),
            if sin_evaluar > 0 {
                suaya_core::t!(
                    " · {sin_evaluar} sin evaluar",
                    " · {sin_evaluar} not evaluated"
                )
            } else {
                String::new()
            }
        );
    }
    let urgentes: Vec<_> = activos.iter().filter(|x| prioridad(x) <= 2).collect();
    if !urgentes.is_empty() {
        println!();
        decir!("Atención prioritaria:", "Priority attention:");
        for x in urgentes.iter().take(12) {
            let cl = x.clasificacion.as_ref().expect("clasificado");
            let donde = x.ubicaciones.first().map(|u| u.ruta.as_str()).unwrap_or("");
            println!(
                "  [{}] {} · {} · {}",
                etiqueta_prioridad(cl.prioridad),
                suaya_core::idioma::traducir(&x.nombre),
                cl.accion.etiqueta(),
                donde
            );
        }
        if urgentes.len() > 12 {
            decir!(
                "  ... y {} más (ver el reporte)",
                "  ... and {} more (see the report)",
                urgentes.len() - 12
            );
        }
    }
    if !avisos.is_empty() {
        println!();
        if a.detallado {
            println!("{}", suaya_core::idioma::tx("Avisos:", "Notices:"));
            for x in avisos {
                println!("  - {}", suaya_core::idioma::traducir(x));
            }
        } else {
            decir!(
                "{} avisos (use --detallado para verlos).",
                "{} notices (use --detallado to see them).",
                avisos.len()
            );
        }
    }
    println!();
    println!("CBOM: {}", a.salida.display());
    if let Some(r) = &a.reporte {
        println!(
            "{}: {}",
            suaya_core::idioma::tx("Reporte", "Report"),
            r.display()
        );
    }
    if a.fallar_si_incompleto && !avisos.is_empty() {
        return Ok(ExitCode::from(4));
    }
    if let Some(umbral) = a.fallar_en
        && activos.iter().any(|x| prioridad(x) <= umbral)
    {
        decir_err!(
            "Hay hallazgos de prioridad {} o más grave.",
            "There are findings of priority {} or worse.",
            etiqueta_prioridad(umbral).to_lowercase()
        );
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}

fn con_sufijo(ruta: &std::path::Path, sufijo: &str) -> PathBuf {
    let mut s = ruta.as_os_str().to_os_string();
    s.push(sufijo);
    PathBuf::from(s)
}

/// Crea un archivo nuevo legible solo por su dueño (no sobrescribe).
fn escribir_privado(ruta: &std::path::Path, datos: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opciones = std::fs::OpenOptions::new();
    opciones.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opciones.mode(0o600);
    }
    let mut f = opciones.open(ruta).with_context(|| {
        suaya_core::t!(
            "al crear {} (¿ya existe?)",
            "creating {} (does it already exist?)",
            ruta.display()
        )
    })?;
    f.write_all(datos)?;
    Ok(())
}

fn firmar_archivo(
    cbom: &std::path::Path,
    llave: &std::path::Path,
    clave_env: &str,
    destino: &std::path::Path,
) -> Result<()> {
    let texto = leer_limitado(llave)
        .with_context(|| suaya_core::t!("al leer {}", "reading {}", llave.display()))?;
    let v: serde_json::Value = serde_json::from_slice(&texto)
        .with_context(|| suaya_core::t!("{} no es JSON", "{} is not JSON", llave.display()))?;
    let clave = std::env::var(clave_env).ok().filter(|c| !c.is_empty());
    let llaves =
        suaya_cbom::firma::Llaves::desde_json(&v, clave.as_deref()).map_err(anyhow::Error::msg)?;
    let documento = leer_limitado(cbom)
        .with_context(|| suaya_core::t!("al leer {}", "reading {}", cbom.display()))?;
    let fecha = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default();
    let firma =
        suaya_cbom::firma::firmar(&documento, &llaves, &fecha).map_err(anyhow::Error::msg)?;
    escribir_atomico(destino, serde_json::to_vec_pretty(&firma)?)
        .with_context(|| suaya_core::t!("al escribir {}", "writing {}", destino.display()))?;
    Ok(())
}

/// Reporte en HTML si la extensión es .html o .htm (o si se pide), en
/// Markdown en otro caso.
fn texto_reporte(
    leido: &suaya_cbom::CbomLeido,
    c: &Conocimiento,
    ruta: &std::path::Path,
    formato: Option<&str>,
) -> String {
    let html = match formato {
        Some(f) => f.eq_ignore_ascii_case("html"),
        None => ruta
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("html") || e.eq_ignore_ascii_case("htm")),
    };
    if html {
        reporte_html(leido, c)
    } else {
        reporte_markdown(leido, c)
    }
}

/// Importa CBOM de otras herramientas al inventario; devuelve cuántos activos agregó.
fn importar_archivos(
    archivos: &[PathBuf],
    c: &Conocimiento,
    inventario: &mut Inventario,
    avisos: &mut Vec<String>,
) -> Result<usize> {
    let mut total = 0;
    for archivo in archivos {
        let texto = leer_texto_limitado(archivo).with_context(|| {
            suaya_core::t!("no se pudo leer {}", "could not read {}", archivo.display())
        })?;
        let nombre = archivo
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| archivo.display().to_string());
        let r = suaya_escaneo::importar_cbom(&texto, &nombre, c)
            .map_err(|e| anyhow::anyhow!("{}: {e}", archivo.display()))?;
        total += r.activos.len();
        inventario.extender(r.activos);
        avisos.extend(r.avisos);
    }
    Ok(total)
}

fn cargar_conocimiento(dir: Option<&PathBuf>) -> Result<Conocimiento> {
    match dir {
        Some(d) => {
            let c = Conocimiento::desde_directorio(d).with_context(|| {
                suaya_core::t!(
                    "al cargar la base de conocimiento de {}",
                    "loading the knowledge base from {}",
                    d.display()
                )
            })?;
            suaya_escaneo::api::validar_reglas(&c).map_err(anyhow::Error::msg)?;
            Ok(c)
        }
        None => Ok(Conocimiento::embebido()),
    }
}

fn main() -> ExitCode {
    suaya_core::idioma::fijar(suaya_core::idioma::desde_entorno(std::env::args()));
    // Los errores de uso salen con código 1, no con el 2 de clap, que Suaya
    // reserva para el umbral de --fallar-en y --fallar-si-empeora.
    let cli = match interfaz()
        .try_get_matches()
        .and_then(|m| Cli::from_arg_matches(&m))
    {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    match ejecutar(cli) {
        Ok(codigo) => codigo,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn ejecutar(cli: Cli) -> Result<ExitCode> {
    match cli.orden {
        Orden::Escanear {
            rutas,
            objetivos,
            imagenes,
            importados,
            plataforma,
            ca_registro,
            registro_http_local,
            registro_token_origen,
            salida,
            red,
            seguir_enlaces,
            binarios,
            hilos,
            tamano_maximo,
        } => {
            if rutas.is_empty()
                && objetivos.is_empty()
                && imagenes.is_empty()
                && importados.is_empty()
            {
                fallar!(
                    "indique al menos una ruta, un --objetivo, una --imagen o un --importar",
                    "give at least one path, --objetivo, --imagen or --importar"
                );
            }
            let (remotas, imagenes): (Vec<String>, Vec<String>) = imagenes
                .into_iter()
                .partition(|i| i.starts_with("docker://"));
            let imagenes: Vec<PathBuf> = imagenes.into_iter().map(PathBuf::from).collect();
            for r in rutas.iter().chain(&imagenes) {
                if !r.exists() {
                    fallar!(
                        "la ruta no existe: {}",
                        "path does not exist: {}",
                        r.display()
                    );
                }
            }
            let objetivos = interpretar_objetivos(&objetivos)?;
            let c = cargar_conocimiento(salida.base_conocimiento.as_ref())?;
            let opciones_red = red.opciones(&c)?;
            let opciones = Opciones {
                tamano_maximo: tamano_maximo.clamp(1, 512) * 1024 * 1024,
                seguir_enlaces,
                binarios,
                hilos,
                ..Opciones::default()
            };
            let mut resultado = escanear_con_imagenes(&rutas, &imagenes, &c, &opciones);
            let mut raices: Vec<String> = rutas
                .iter()
                .chain(&imagenes)
                .map(|r| r.display().to_string())
                .collect();
            if !remotas.is_empty() {
                let op_registro = registro::Opciones {
                    tiempo_limite: opciones_red.tiempo_limite,
                    plataforma: plataforma.unwrap_or_else(registro::plataforma_local),
                    autoridad_pem: match &ca_registro {
                        Some(r) => Some(leer_limitado(r).with_context(|| {
                            suaya_core::t!("no se pudo leer {}", "could not read {}", r.display())
                        })?),
                        None => None,
                    },
                    config_docker: None,
                    permitir_http_local: registro_http_local,
                    origenes_token: registro_token_origen,
                };
                let escaneres = suaya_escaneo::escaneres_predeterminados();
                for imagen in &remotas {
                    decir_err!(
                        "Descargando y analizando {imagen} ({})...",
                        "Pulling and analyzing {imagen} ({})...",
                        op_registro.plataforma
                    );
                    registro::inventariar_imagen(
                        imagen,
                        &escaneres,
                        &c,
                        &opciones,
                        &op_registro,
                        &mut resultado,
                    )
                    .map_err(|e| anyhow::anyhow!("{imagen}: {e}"))?;
                    raices.push(imagen.clone());
                }
                suaya_escaneo::api::resolver_certificados_referenciados(&mut resultado.inventario);
                clasificar(&mut resultado.inventario, &c);
            }
            if !importados.is_empty() {
                let n = importar_archivos(
                    &importados,
                    &c,
                    &mut resultado.inventario,
                    &mut resultado.avisos,
                )?;
                decir_err!(
                    "Importados {n} activos de {} CBOM.",
                    "Imported {n} assets from {} CBOM(s).",
                    importados.len()
                );
                raices.extend(importados.iter().map(|r| r.display().to_string()));
                clasificar(&mut resultado.inventario, &c);
            }
            if !objetivos.is_empty() {
                let r = sondear(&objetivos, &c, &opciones_red);
                resultado.inventario.extender(r.activos);
                resultado.avisos.extend(r.avisos);
                clasificar(&mut resultado.inventario, &c);
                raices.extend(objetivos.iter().map(Objetivo::ubicacion));
            }
            if resultado.archivos_omitidos > 0 {
                resultado.avisos.push(format!(
                    "{} archivos omitidos por tamaño: inventario parcial",
                    resultado.archivos_omitidos
                ));
            }
            let linea = suaya_core::t!(
                "Archivos revisados: {} · omitidos por tamaño: {} · servicios sondeados: {}",
                "Files reviewed: {} · skipped for size: {} · services probed: {}",
                resultado.archivos_revisados,
                resultado.archivos_omitidos,
                objetivos.len()
            );
            finalizar(
                &mut resultado.inventario,
                &c,
                &salida,
                raices,
                &resultado.avisos,
                &linea,
            )
        }

        Orden::Importar { cboms, salida } => {
            let c = cargar_conocimiento(salida.base_conocimiento.as_ref())?;
            let mut inventario = Inventario::default();
            let mut avisos = Vec::new();
            let n = importar_archivos(&cboms, &c, &mut inventario, &mut avisos)?;
            clasificar(&mut inventario, &c);
            let linea = suaya_core::t!(
                "CBOM importados: {} · activos importados: {n}",
                "CBOMs imported: {} · assets imported: {n}",
                cboms.len()
            );
            let raices = cboms.iter().map(|r| r.display().to_string()).collect();
            finalizar(&mut inventario, &c, &salida, raices, &avisos, &linea)
        }

        Orden::Sondear {
            objetivos,
            salida,
            red,
        } => {
            let objetivos = interpretar_objetivos(&objetivos)?;
            let c = cargar_conocimiento(salida.base_conocimiento.as_ref())?;
            let r = sondear(&objetivos, &c, &red.opciones(&c)?);
            let mut inventario = Inventario::default();
            inventario.extender(r.activos);
            clasificar(&mut inventario, &c);
            let alcanzados = inventario
                .activos
                .iter()
                .filter(|a| a.referencia.starts_with("protocolo:"))
                .count();
            let linea = suaya_core::t!(
                "Servicios sondeados: {} · alcanzados: {alcanzados}",
                "Services probed: {} · reached: {alcanzados}",
                objetivos.len()
            );
            let raices = objetivos.iter().map(Objetivo::ubicacion).collect();
            finalizar(&mut inventario, &c, &salida, raices, &r.avisos, &linea)
        }

        Orden::Kubernetes {
            kubeconfig,
            contexto,
            espacios,
            sondear_ingress,
            salida,
            red,
        } => {
            let c = cargar_conocimiento(salida.base_conocimiento.as_ref())?;
            let opciones_red = red.opciones(&c)?;
            let conexion = match (
                kubeconfig.as_ref(),
                contexto.as_ref(),
                suaya_red::kubernetes::dentro_del_cluster(),
            ) {
                (None, None, Some(dentro)) => dentro.map_err(anyhow::Error::msg)?,
                _ => {
                    let ruta = suaya_red::kubernetes::ruta_kubeconfig(kubeconfig.as_deref())
                        .context("no se encontró un kubeconfig; indique --kubeconfig")?;
                    suaya_red::kubernetes::desde_kubeconfig(&ruta, contexto.as_deref())
                        .map_err(anyhow::Error::msg)?
                }
            };
            if conexion.confianza.sin_verificar {
                decir_err!(
                    "Advertencia: el kubeconfig desactiva la verificación TLS del servidor (insecure-skip-tls-verify).",
                    "Warning: the kubeconfig disables TLS verification of the server (insecure-skip-tls-verify)."
                );
            }
            let opciones = suaya_red::kubernetes::Opciones {
                espacios,
                tiempo: opciones_red.tiempo_limite * 2,
            };
            let r = suaya_red::kubernetes::inventariar(&conexion, &c, &opciones)
                .map_err(anyhow::Error::msg)?;
            let mut inventario = Inventario::default();
            inventario.extender(r.activos);
            let mut avisos = r.avisos;
            let mut sondeados = 0;
            if sondear_ingress && !r.hosts_ingress.is_empty() {
                let objetivos: Vec<Objetivo> = r
                    .hosts_ingress
                    .iter()
                    .filter_map(|h| Objetivo::interpretar(&format!("tls://{h}:443")).ok())
                    .collect();
                sondeados = objetivos.len();
                let rs = sondear(&objetivos, &c, &opciones_red);
                inventario.extender(rs.activos);
                avisos.extend(rs.avisos);
            }
            clasificar(&mut inventario, &c);
            let linea = suaya_core::t!(
                "Clúster: {} ({}) · Secrets revisados: {} · hosts de Ingress: {} · sondeados: {sondeados}",
                "Cluster: {} ({}) · Secrets reviewed: {} · Ingress hosts: {} · probed: {sondeados}",
                conexion.contexto,
                conexion.servidor.host,
                r.secretos_revisados,
                r.hosts_ingress.len()
            );
            finalizar(
                &mut inventario,
                &c,
                &salida,
                vec![format!("k8s://{}", conexion.contexto)],
                &avisos,
                &linea,
            )
        }

        Orden::Reporte {
            cbom,
            salida,
            formato,
            base_conocimiento,
        } => {
            let c = cargar_conocimiento(base_conocimiento.as_ref())?;
            let texto = leer_texto_limitado(&cbom)
                .with_context(|| suaya_core::t!("al leer {}", "reading {}", cbom.display()))?;
            let leido = leer(&texto).map_err(anyhow::Error::msg)?;
            match salida {
                Some(s) => escribir_atomico(&s, texto_reporte(&leido, &c, &s, formato.as_deref()))
                    .with_context(|| suaya_core::t!("al escribir {}", "writing {}", s.display()))?,
                None => print!(
                    "{}",
                    texto_reporte(&leido, &c, std::path::Path::new("-"), formato.as_deref())
                ),
            }
            Ok(ExitCode::SUCCESS)
        }

        Orden::Comparar {
            anterior,
            actual,
            fallar_si_empeora,
        } => {
            let a =
                leer(&leer_texto_limitado(&anterior).with_context(|| {
                    suaya_core::t!("al leer {}", "reading {}", anterior.display())
                })?)
                .map_err(anyhow::Error::msg)?;
            let b =
                leer(&leer_texto_limitado(&actual).with_context(|| {
                    suaya_core::t!("al leer {}", "reading {}", actual.display())
                })?)
                .map_err(anyhow::Error::msg)?;
            let d = comparar(&a, &b);
            print!("{}", d.como_texto(&a, &b));
            if fallar_si_empeora && d.hay_regresion() {
                return Ok(ExitCode::from(2));
            }
            Ok(ExitCode::SUCCESS)
        }

        Orden::Perfiles => {
            decir!(
                "Perfiles de política incluidos (use --perfil <id> o --perfil <archivo.toml>):",
                "Bundled policy profiles (use --perfil <id> or --perfil <file.toml>):"
            );
            println!();
            for p in Perfil::incluidos() {
                println!(
                    "  {:<14} {}",
                    p.perfil.id,
                    suaya_core::idioma::traducir(&p.perfil.nombre)
                );
                println!(
                    "  {:<14} {}",
                    "",
                    suaya_core::idioma::traducir(&p.perfil.referencia)
                );
            }
            println!();
            decir!(
                "Para un marco propio, copie conocimiento/perfiles/plantilla.toml y ajuste sus reglas.",
                "For your own framework, copy conocimiento/perfiles/plantilla.toml and adjust its rules."
            );
            Ok(ExitCode::SUCCESS)
        }

        Orden::Llaves { prefijo, clave_env } => {
            let llaves = suaya_cbom::firma::Llaves::generar().map_err(anyhow::Error::msg)?;
            let clave = std::env::var(&clave_env).ok().filter(|c| !c.is_empty());
            let privada = con_sufijo(&prefijo, ".privada.json");
            let publica = con_sufijo(&prefijo, ".publica.json");
            let json_privada = llaves
                .a_json(clave.as_deref())
                .map_err(anyhow::Error::msg)?;
            escribir_privado(&privada, &serde_json::to_vec_pretty(&json_privada)?)?;
            escribir_atomico(
                &publica,
                serde_json::to_vec_pretty(&llaves.publica().a_json())?,
            )
            .with_context(|| suaya_core::t!("al escribir {}", "writing {}", publica.display()))?;
            println!(
                "{}",
                suaya_core::t!(
                    "Llave privada: {} ({})\nLlave pública: {}\nHuella: {}",
                    "Private key: {} ({})\nPublic key: {}\nFingerprint: {}",
                    privada.display(),
                    if clave.is_some() {
                        suaya_core::idioma::tx(
                            "cifrada con la frase de paso",
                            "encrypted with the passphrase",
                        )
                    } else {
                        suaya_core::idioma::tx(
                            "sin cifrar: protéjala o defina la variable de la frase de paso",
                            "unencrypted: protect it or set the passphrase variable",
                        )
                    },
                    publica.display(),
                    llaves.publica().huella()
                )
            );
            Ok(ExitCode::SUCCESS)
        }

        Orden::Firmar {
            cbom,
            llave,
            salida,
            clave_env,
        } => {
            let destino = salida.unwrap_or_else(|| con_sufijo(&cbom, ".firma"));
            firmar_archivo(&cbom, &llave, &clave_env, &destino)?;
            println!(
                "{}",
                suaya_core::t!("Firma: {}", "Signature: {}", destino.display())
            );
            Ok(ExitCode::SUCCESS)
        }

        Orden::Verificar {
            cbom,
            llave_publica,
            firma,
        } => {
            let ruta_firma = firma.unwrap_or_else(|| con_sufijo(&cbom, ".firma"));
            let documento = leer_limitado(&cbom)
                .with_context(|| suaya_core::t!("al leer {}", "reading {}", cbom.display()))?;
            let leer_json = |r: &PathBuf| -> Result<serde_json::Value> {
                let t = leer_limitado(r)
                    .with_context(|| suaya_core::t!("al leer {}", "reading {}", r.display()))?;
                serde_json::from_slice(&t)
                    .with_context(|| suaya_core::t!("{} no es JSON", "{} is not JSON", r.display()))
            };
            let publica = suaya_cbom::firma::LlavePublica::desde_json(&leer_json(&llave_publica)?)
                .map_err(anyhow::Error::msg)?;
            match suaya_cbom::firma::verificar(&documento, &leer_json(&ruta_firma)?, &publica) {
                Ok(()) => {
                    println!(
                        "{}",
                        suaya_core::t!(
                            "Firma válida ({}, llave {}).",
                            "Valid signature ({}, key {}).",
                            suaya_cbom::firma::ALGORITMO,
                            publica.huella()
                        )
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        suaya_core::t!("Firma NO válida: {e}", "INVALID signature: {e}")
                    );
                    Ok(ExitCode::from(3))
                }
            }
        }

        Orden::Completado { interprete } => {
            let mut c = interfaz();
            clap_complete::generate(interprete, &mut c, "suaya", &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }

        Orden::Manual => {
            clap_mangen::Man::new(interfaz())
                .render(&mut std::io::stdout())
                .context("al generar la página de manual")?;
            Ok(ExitCode::SUCCESS)
        }

        Orden::Conocimiento { base_conocimiento } => {
            let c = cargar_conocimiento(base_conocimiento.as_ref())?;
            decir!(
                "Base de conocimiento: {}",
                "Knowledge base: {}",
                suaya_core::idioma::traducir(&c.procedencia())
            );
            decir!(
                "Algoritmos registrados: {}",
                "Registered algorithms: {}",
                c.algoritmos.len()
            );
            if let Some(p) = &c.politica {
                decir!(
                    "Política de transición: retiro {} · prohibición {} ({})",
                    "Transition policy: deprecation {} · prohibition {} ({})",
                    p.anio_retiro_vulnerables,
                    p.anio_prohibicion_vulnerables,
                    suaya_core::idioma::traducir(&p.referencia)
                );
            }
            println!();
            println!(
                "{:<44} {:<26} {:<26}",
                suaya_core::idioma::tx("Capacidad", "Capability"),
                suaya_core::idioma::tx("Confidencialidad", "Confidentiality"),
                suaya_core::idioma::tx("Autenticación", "Authentication")
            );
            for cap in &c.capacidades {
                println!(
                    "{:<44} {:<26} {:<26}",
                    suaya_core::idioma::traducir(&cap.nombre),
                    cap.confidencialidad.etiqueta(),
                    cap.autenticacion.etiqueta()
                );
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}

// Todos los documentos externos se leen con un límite, incluso si crecen durante la lectura.
fn leer_limitado(ruta: impl AsRef<std::path::Path>) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    const MAX: u64 = 256 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(ruta)?
        .take(MAX + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX {
        return Err(std::io::Error::other("documento mayor de 256 MiB"));
    }
    Ok(bytes)
}
fn leer_texto_limitado(ruta: impl AsRef<std::path::Path>) -> std::io::Result<String> {
    String::from_utf8(leer_limitado(ruta)?).map_err(|_| std::io::Error::other("UTF-8 inválido"))
}
fn escribir_atomico(
    ruta: impl AsRef<std::path::Path>,
    datos: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    use std::io::Write;
    let ruta = ruta.as_ref();
    let parent = ruta
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(datos.as_ref())?;
    file.as_file().sync_all()?;
    file.persist(ruta).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod pruebas {
    use super::*;

    /// Textos de ayuda de la interfaz: about de cada orden y help de cada opción.
    fn textos_de_ayuda() -> Vec<String> {
        fn recorrer(c: &clap::Command, v: &mut Vec<String>) {
            for t in [c.get_about(), c.get_long_about()].into_iter().flatten() {
                v.push(t.to_string());
            }
            for a in c.get_arguments() {
                for t in [a.get_help(), a.get_long_help()].into_iter().flatten() {
                    v.push(t.to_string());
                }
            }
            for s in c.get_subcommands() {
                recorrer(s, v);
            }
        }
        let mut v = Vec::new();
        recorrer(&Cli::command(), &mut v);
        v.sort();
        v.dedup();
        v
    }

    #[test]
    fn ayuda_traducida_al_ingles() {
        if let Ok(ruta) = std::env::var("SUAYA_VOLCAR_AYUDA") {
            escribir_atomico(ruta, textos_de_ayuda().join("\n---\n")).unwrap();
        }
        let faltan: Vec<String> = textos_de_ayuda()
            .into_iter()
            .filter(|t| suaya_core::idioma::al_ingles(t).is_none())
            .collect();
        assert!(
            faltan.is_empty(),
            "ayuda sin traducir:\n{}",
            faltan.join("\n")
        );
    }
}

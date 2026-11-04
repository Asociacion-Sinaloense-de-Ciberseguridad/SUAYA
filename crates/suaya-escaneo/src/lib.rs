//! # suaya-escaneo
//!
//! Escáneres de Suaya. Cada escáner implementa el rasgo [`Escaner`] y se
//! registra en [`escaneres_predeterminados`]. Para contribuir un escáner nuevo
//! basta con implementar el rasgo; el núcleo no necesita cambios.
//!
//! Principios de seguridad:
//!
//! - Suaya **nunca** copia material secreto al inventario: de una llave privada
//!   registra su tipo, tamaño, protección y ubicación, jamás su contenido.
//! - No sigue enlaces simbólicos por defecto y omite archivos grandes.
//! - Un archivo malformado produce un aviso, nunca detiene el escaneo.

mod bibliotecas;
mod cert_manager;
mod codigo;
mod comun;
mod config_haproxy;
mod config_java;
mod config_mysql;
mod config_postfix;
mod config_postgresql;
mod config_ssh;
mod config_tls;
mod contenedores;
mod crypttab;
mod identidad;
mod imagen;
mod importar;
mod incrustados;
mod llaves_ssh;
mod pem;
mod vpn;

use std::path::{Path, PathBuf};

use suaya_core::{Conocimiento, Garantia, Inventario};
use walkdir::WalkDir;

pub use comun::Archivo;
pub use imagen::AnalizadorImagen;
pub use importar::{Importado, importar_cbom};

/// Funciones para escáneres externos a este paquete (por ejemplo, el sondeo
/// de red), de modo que todos produzcan activos con las mismas reglas.
pub mod api {
    pub use crate::cert_manager::activos_certificado;
    pub use crate::codigo::validar_reglas;
    pub use crate::comun::resolver_certificados_referenciados;
    pub use crate::comun::{activo_algoritmo, id_corto, por_alias};
    pub use crate::config_ssh::riesgo_kex_ssh;
    pub use crate::pem::{
        ResumenCertificado, analizar_texto_pem, certificado_en_contexto, resumen_certificado,
    };
}

/// Un escáner analiza archivos y devuelve activos criptográficos.
pub trait Escaner: Send + Sync {
    /// Nombre corto, en español, para avisos y metadatos.
    fn nombre(&self) -> &'static str;
    /// Decide de forma barata si el archivo le interesa.
    fn aplica(&self, archivo: &Archivo) -> bool;
    /// Analiza el archivo. Los errores se reportan como avisos.
    fn analizar(
        &self,
        archivo: &Archivo,
        conocimiento: &Conocimiento,
    ) -> Result<Vec<suaya_core::Activo>, String>;
}

pub fn escaneres_predeterminados() -> Vec<Box<dyn Escaner>> {
    vec![
        Box::new(pem::EscanerPem),
        Box::new(llaves_ssh::EscanerLlavesSsh),
        Box::new(config_ssh::EscanerConfigSsh),
        Box::new(config_tls::EscanerConfigTls),
        Box::new(config_haproxy::EscanerConfigHaproxy),
        Box::new(config_postgresql::EscanerConfigPostgresql),
        Box::new(config_mysql::EscanerConfigMysql),
        Box::new(config_java::EscanerConfigJava),
        Box::new(config_postfix::EscanerConfigPostfix),
        Box::new(crypttab::EscanerCrypttab),
        Box::new(vpn::EscanerWireGuard),
        Box::new(vpn::EscanerOpenVpn),
        Box::new(vpn::EscanerStrongSwan),
        Box::new(contenedores::EscanerContenedores),
        Box::new(incrustados::EscanerIncrustados),
        Box::new(cert_manager::EscanerCertManager),
        Box::new(codigo::EscanerCodigo::default()),
        Box::new(bibliotecas::EscanerBibliotecas),
    ]
}

/// Opciones de recorrido del sistema de archivos.
#[derive(Debug, Clone)]
pub struct Opciones {
    /// Tamaño máximo de archivo en bytes.
    pub tamano_maximo: u64,
    pub seguir_enlaces: bool,
    /// Revisa también ejecutables grandes (hasta 512 MiB) en busca de la
    /// versión de su biblioteca criptográfica.
    pub binarios: bool,
    /// Hilos de análisis (0 = todos los núcleos).
    pub hilos: usize,
    /// Nombres de directorio que se omiten.
    pub excluir: Vec<String>,
}

impl Default for Opciones {
    fn default() -> Self {
        Self {
            tamano_maximo: 5 * 1024 * 1024,
            seguir_enlaces: false,
            binarios: false,
            hilos: 0,
            excluir: [
                ".git",
                "node_modules",
                "target",
                ".venv",
                "venv",
                "__pycache__",
                ".cache",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

/// Resultado de un escaneo.
#[derive(Debug, Default)]
pub struct Resultado {
    pub inventario: Inventario,
    pub archivos_revisados: usize,
    pub archivos_omitidos: usize,
    pub avisos: Vec<String>,
}

/// Escanea una lista de rutas (archivos o directorios).
pub fn escanear(rutas: &[PathBuf], conocimiento: &Conocimiento, opciones: &Opciones) -> Resultado {
    escanear_con_imagenes(rutas, &[], conocimiento, opciones)
}

/// Escanea rutas del sistema de archivos e imágenes de contenedor
/// (archivos `docker save`, `podman save` u OCI en formato tar).
pub fn escanear_con_imagenes(
    rutas: &[PathBuf],
    imagenes: &[PathBuf],
    conocimiento: &Conocimiento,
    opciones: &Opciones,
) -> Resultado {
    let escaneres = escaneres_predeterminados();
    let mut resultado = Resultado::default();

    for imagen in imagenes {
        if let Err(e) =
            imagen::escanear_imagen(imagen, &escaneres, conocimiento, opciones, &mut resultado)
        {
            resultado.avisos.push(format!("{}: {e}", imagen.display()));
        }
    }

    // Primero se recorre el árbol (rápido y en orden); después los archivos
    // se analizan en paralelo y sus resultados se unen en el orden del
    // recorrido, de modo que el inventario no depende del número de hilos.
    enum Tarea {
        Archivo(usize, PathBuf),
        Error(String),
    }
    let mut tareas: Vec<Tarea> = Vec::new();
    for (indice, raiz) in rutas.iter().enumerate() {
        let recorrido = WalkDir::new(raiz)
            .follow_links(opciones.seguir_enlaces)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                !(e.file_type().is_dir()
                    && e.depth() > 0
                    && opciones
                        .excluir
                        .iter()
                        .any(|x| e.file_name().to_string_lossy() == x.as_str()))
            });
        for entrada in recorrido {
            if tareas.len() >= 100_000 {
                resultado
                    .avisos
                    .push("Límite de 100000 entradas alcanzado; escaneo parcial".into());
                break;
            }
            match entrada {
                Ok(e) if e.file_type().is_file() => {
                    tareas.push(Tarea::Archivo(indice, e.into_path()))
                }
                Ok(_) => {}
                Err(e) => tareas.push(Tarea::Error(format!("No se pudo recorrer: {e}"))),
            }
        }
    }
    let parciales = en_paralelo(&tareas, opciones.hilos, |t| {
        let mut parcial = Resultado::default();
        match t {
            Tarea::Archivo(i, ruta) => analizar_ruta(
                &rutas[*i],
                ruta,
                &escaneres,
                conocimiento,
                opciones,
                &mut parcial,
            ),
            Tarea::Error(e) => parcial.avisos.push(e.clone()),
        }
        parcial
    });
    for p in parciales {
        resultado.archivos_revisados += p.archivos_revisados;
        resultado.archivos_omitidos += p.archivos_omitidos;
        resultado.avisos.extend(p.avisos);
        resultado.inventario.extender(p.inventario.activos);
    }

    comun::resolver_certificados_referenciados(&mut resultado.inventario);
    suaya_core::clasificar(&mut resultado.inventario, conocimiento);
    resultado
}

fn analizar_ruta(
    raiz: &Path,
    ruta: &Path,
    escaneres: &[Box<dyn Escaner>],
    conocimiento: &Conocimiento,
    opciones: &Opciones,
    resultado: &mut Resultado,
) {
    let metadatos = match std::fs::metadata(ruta) {
        Ok(m) => m,
        Err(e) => {
            resultado.avisos.push(format!("{}: {e}", ruta.display()));
            return;
        }
    };
    if metadatos.len() > opciones.tamano_maximo {
        analizar_grande(raiz, ruta, &metadatos, conocimiento, opciones, resultado);
        return;
    }
    // Verificar el descriptor abierto y acotar lectura protege frente a crecimiento del archivo.
    let leer = || -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut op = std::fs::OpenOptions::new();
        op.read(true);
        #[cfg(unix)]
        if !opciones.seguir_enlaces {
            use std::os::unix::fs::OpenOptionsExt;
            op.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = op.open(ruta)?;
        if !file.metadata()?.is_file() {
            return Err(std::io::Error::other("archivo no regular"));
        }
        let max = opciones.tamano_maximo.min(512 * 1024 * 1024);
        let mut data = Vec::new();
        file.take(max + 1).read_to_end(&mut data)?;
        if data.len() as u64 > max {
            return Err(std::io::Error::other("archivo excede el límite"));
        }
        Ok(data)
    };
    let contenido = match leer() {
        Ok(c) => c,
        Err(e) => {
            resultado.avisos.push(format!("{}: {e}", ruta.display()));
            return;
        }
    };
    resultado.archivos_revisados += 1;

    let texto_ruta = ruta.display().to_string();
    let mut archivo = Archivo::nuevo(&texto_ruta, ruta, &contenido, comun::modo(&metadatos));
    if let Ok(relativa) = ruta.strip_prefix(raiz)
        && !relativa.as_os_str().is_empty()
    {
        archivo.ruta_estable = relativa.to_string_lossy().replace('\\', "/");
    }
    let activos = aplicar_escaneres(&archivo, escaneres, conocimiento, &mut resultado.avisos);
    resultado.inventario.extender(activos);
}

/// Aplica `f` a cada elemento con varios hilos y devuelve los resultados en
/// el orden de entrada. `hilos == 0` usa todos los núcleos disponibles.
pub fn en_paralelo<T: Sync, R: Send>(
    items: &[T],
    hilos: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let hilos = if hilos == 0 {
        std::thread::available_parallelism().map_or(1, |n| n.get())
    } else {
        hilos
    }
    .clamp(1, 64)
    .min(items.len().max(1));
    if hilos == 1 {
        return items.iter().map(f).collect();
    }
    let siguiente = AtomicUsize::new(0);
    let mut partes: Vec<Vec<(usize, R)>> = std::thread::scope(|s| {
        let trabajadores: Vec<_> = (0..hilos)
            .map(|_| {
                s.spawn(|| {
                    let mut propios = Vec::new();
                    loop {
                        let i = siguiente.fetch_add(1, Ordering::Relaxed);
                        if i >= items.len() {
                            break;
                        }
                        propios.push((i, f(&items[i])));
                    }
                    propios
                })
            })
            .collect();
        trabajadores
            .into_iter()
            .map(|t| t.join().expect("un hilo de análisis falló"))
            .collect()
    });
    let mut todos: Vec<(usize, R)> = partes.drain(..).flatten().collect();
    todos.sort_by_key(|(i, _)| *i);
    todos.into_iter().map(|(_, r)| r).collect()
}

/// Archivo mayor que el límite general: solo se revisa si es una biblioteca
/// criptográfica compartida, un JAR conocido (por su nombre, sin leerlo) o,
/// con `binarios`, un ejecutable.
fn analizar_grande(
    raiz: &Path,
    ruta: &Path,
    metadatos: &std::fs::Metadata,
    conocimiento: &Conocimiento,
    opciones: &Opciones,
    resultado: &mut Resultado,
) {
    let nombre = ruta
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let texto_ruta = ruta.display().to_string();
    let estable = ruta
        .strip_prefix(raiz)
        .ok()
        .filter(|r| !r.as_os_str().is_empty())
        .map(|r| r.to_string_lossy().replace('\\', "/"));
    if bibliotecas::jar_por_nombre(&nombre).is_some() {
        let mut a = Archivo::nuevo(&texto_ruta, ruta, &[], comun::modo(metadatos));
        if let Some(e) = &estable {
            a.ruta_estable = e.clone();
        }
        resultado.archivos_revisados += 1;
        resultado
            .inventario
            .extender(bibliotecas::analizar_grande(&a, conocimiento));
        return;
    }
    let ejecutable = comun::modo(metadatos).is_some_and(|m| m & 0o111 != 0);
    let candidato = bibliotecas::es_biblioteca_compartida(&nombre)
        || (opciones.binarios
            && (ejecutable || nombre.ends_with(".exe") || nombre.ends_with(".dll")));
    if !candidato || metadatos.len() > bibliotecas::MAXIMO_BINARIO {
        resultado.archivos_omitidos += 1;
        return;
    }
    let abrir = || -> std::io::Result<std::fs::File> {
        let mut open = std::fs::OpenOptions::new();
        open.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(
                libc::O_NONBLOCK
                    | if opciones.seguir_enlaces {
                        0
                    } else {
                        libc::O_NOFOLLOW
                    },
            );
        }
        let file = open.open(ruta)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() > bibliotecas::MAXIMO_BINARIO {
            return Err(std::io::Error::other(
                "archivo no regular o demasiado grande",
            ));
        }
        Ok(file)
    };
    let archivo = match abrir() {
        Ok(f) => f,
        Err(e) => {
            resultado.avisos.push(format!("{}: {e}", ruta.display()));
            return;
        }
    };
    let mut a = Archivo::nuevo(&texto_ruta, ruta, &[], comun::modo(metadatos));
    if let Some(e) = &estable {
        a.ruta_estable = e.clone();
    }
    match bibliotecas::binario_por_partes(std::io::BufReader::new(archivo), &a, conocimiento) {
        Ok(activos) => {
            resultado.archivos_revisados += 1;
            resultado.inventario.extender(activos);
        }
        Err(e) => resultado.avisos.push(format!("{}: {e}", ruta.display())),
    }
}

/// Ejecuta los escáneres que aplican a un archivo y devuelve sus activos.
pub(crate) fn aplicar_escaneres(
    archivo: &Archivo,
    escaneres: &[Box<dyn Escaner>],
    conocimiento: &Conocimiento,
    avisos: &mut Vec<String>,
) -> Vec<suaya_core::Activo> {
    let mut activos = Vec::new();
    for escaner in escaneres {
        if !escaner.aplica(archivo) {
            continue;
        }
        match escaner.analizar(archivo, conocimiento) {
            Ok(v) => activos.extend(v),
            Err(e) => avisos.push(format!("{} [{}]: {e}", archivo.ruta, escaner.nombre())),
        }
    }
    activos
}

/// Garantía predeterminada al no tener contexto de uso.
pub(crate) fn garantia_de(def: Option<&suaya_core::AlgoritmoDef>) -> Garantia {
    def.map(|d| d.garantia).unwrap_or(Garantia::Autenticacion)
}

//! Imágenes de contenedor en formato tar (`docker save`, `podman save` u
//! OCI image layout).
//!
//! Cada capa se recorre en orden y sus archivos pasan por los mismos
//! escáneres que el sistema de archivos. Nada se extrae a disco.
//!
//! Hallazgo propio de las imágenes: un secreto que una capa agrega y una capa
//! posterior borra (con un archivo `.wh.`) desaparece del contenedor en
//! ejecución, pero **sigue dentro de la imagen** y cualquiera que la descargue
//! puede extraerlo.
//!
//! El recorrido de capas vive en [`AnalizadorImagen`], que recibe cada capa
//! como un flujo de lectura; así lo usan igual el archivo tar local y la
//! descarga desde un registro OCI (paquete `suaya-red`).

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek};
use std::path::Path;

use suaya_core::{Activo, Conocimiento, Detalles};

use crate::comun::Archivo;
use crate::{Escaner, Opciones, Resultado, aplicar_escaneres};

/// Límite de metadatos (manifiestos e índices) que se cargan en memoria.
const MAXIMO_METADATO: u64 = 1024 * 1024;
/// Límite de bytes descomprimidos por imagen, contra bombas de compresión.
const MAXIMO_DESCOMPRIMIDO: u64 = 16 * 1024 * 1024 * 1024;
const MAXIMO_ENTRADAS: usize = 100_000;

/// Capas en orden y nombre de la imagen.
struct Estructura {
    capas: Vec<String>,
    nombre: String,
    tamanos: BTreeMap<String, u64>,
}

fn leer_estructura(file: &mut File) -> Result<Estructura, String> {
    let mut metadatos: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut archivo = tar::Archive::new(file);
    let mut total_metadatos = 0u64;
    let mut entradas = 0usize;
    let mut nombres = BTreeSet::new();
    for entrada in archivo
        .entries()
        .map_err(|e| format!("no es un archivo tar: {e}"))?
    {
        let mut entrada = entrada
            .map_err(|e| format!("no parece un archivo tar de imagen de contenedor ({e})"))?;
        let nombre = entrada
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        entradas += 1;
        if entradas > 100_000 || !nombres.insert(nombre.clone()) {
            return Err("demasiadas entradas o entrada duplicada en imagen".into());
        }
        if !entrada.header().entry_type().is_file() {
            continue;
        }
        let es_metadato =
            nombre == "manifest.json" || nombre == "index.json" || nombre.starts_with("blobs/");
        if es_metadato && entrada.size() <= MAXIMO_METADATO {
            total_metadatos += entrada.size();
            if total_metadatos > 32 * 1024 * 1024 {
                return Err("metadatos exceden 32 MiB".into());
            }
            let mut b = Vec::new();
            entrada.read_to_end(&mut b).map_err(|e| e.to_string())?;
            if b.first() == Some(&b'{') || b.first() == Some(&b'[') {
                metadatos.insert(nombre, b);
            }
        }
    }
    let json = |n: &str| {
        metadatos
            .get(n)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
    };
    let blob = |digest: &str| -> Result<serde_json::Value, String> {
        let path = ruta_digest(digest)?;
        let bytes = metadatos.get(&path).ok_or("manifiesto OCI ausente")?;
        if format!("sha256:{:x}", Sha256::digest(bytes)) != digest {
            return Err("digest de manifiesto OCI incorrecto".into());
        }
        serde_json::from_slice(bytes).map_err(|e| format!("manifiesto OCI inválido: {e}"))
    };

    // docker save / podman save (docker-archive).
    if let Some(m) = json("manifest.json").and_then(|v| v.get(0).cloned()) {
        let capas: Vec<String> = m
            .get("Layers")
            .and_then(|l| l.as_array())
            .map(|l| {
                l.iter()
                    .map(|x| {
                        x.as_str()
                            .map(str::to_string)
                            .ok_or("nombre de capa inválido")
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .ok_or("manifiesto sin Layers")??;
        if !capas.is_empty() {
            let nombre = m
                .pointer("/RepoTags/0")
                .and_then(|t| t.as_str())
                .map(str::to_string)
                .unwrap_or_default();
            return Ok(Estructura {
                capas,
                nombre,
                tamanos: BTreeMap::new(),
            });
        }
    }

    // OCI image layout (oci-archive): index.json -> manifiesto -> capas.
    if let Some(indice) = json("index.json") {
        let mut manifiesto = indice.pointer("/manifests/0").cloned();
        let nombre = manifiesto
            .as_ref()
            .and_then(|m| m.pointer("/annotations/org.opencontainers.image.ref.name"))
            .and_then(|t| t.as_str())
            .unwrap_or_default()
            .to_string();
        for _ in 0..3 {
            let Some(m) = manifiesto.clone() else { break };
            let digest = m
                .get("digest")
                .and_then(|d| d.as_str())
                .ok_or("descriptor OCI sin digest")?;
            let contenido = blob(digest)?;
            if let Some(capas) = contenido.get("layers").and_then(|l| l.as_array()) {
                let mut tamanos = BTreeMap::new();
                let capas = capas
                    .iter()
                    .map(|c| {
                        let path = ruta_digest(c["digest"].as_str().ok_or("capa sin digest")?)?;
                        tamanos.insert(path.clone(), c["size"].as_u64().ok_or("capa sin tamaño")?);
                        Ok(path)
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                return Ok(Estructura {
                    capas,
                    nombre,
                    tamanos,
                });
            }
            // Índice anidado (imágenes multiplataforma): se toma el primero.
            manifiesto = contenido.pointer("/manifests/0").cloned();
        }
    }
    Err("no se reconoce como imagen docker save ni OCI (falta manifest.json o index.json)".into())
}

fn ruta_digest(digest: &str) -> Result<String, String> {
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or("digest OCI no soportado")?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("digest OCI inválido".into());
    }
    Ok(format!("blobs/sha256/{hex}"))
}

struct VerificarCapa<R> {
    reader: R,
    hash: Sha256,
    bytes: u64,
}
impl<R: Read> Read for VerificarCapa<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.bytes += n as u64;
        self.hash.update(&buf[..n]);
        Ok(n)
    }
}

/// Lector de capa que detecta gzip o zstd por sus primeros bytes.
fn descomprimir<'a>(r: impl Read + 'a) -> Result<Box<dyn Read + 'a>, String> {
    let mut b = BufReader::new(r);
    let inicio = b.fill_buf().map_err(|e| e.to_string())?;
    if inicio.starts_with(&[0x1F, 0x8B]) {
        Ok(Box::new(flate2::read::GzDecoder::new(b)))
    } else if inicio.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        Ok(Box::new(
            ruzstd::decoding::StreamingDecoder::new(b).map_err(|e| format!("zstd: {e}"))?,
        ))
    } else {
        Ok(Box::new(b))
    }
}

// Cuenta bytes reales, incluyendo padding y entradas que el analizador omite.
struct Presupuesto<'a, R> {
    reader: R,
    total: &'a mut u64,
    inicio: std::time::Instant,
}
impl<R: Read> Read for Presupuesto<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inicio.elapsed() > std::time::Duration::from_secs(120) {
            return Err(std::io::Error::other("tiempo máximo de imagen excedido"));
        }
        let n = self.reader.read(buf)?;
        *self.total = self.total.saturating_add(n as u64);
        if *self.total > MAXIMO_DESCOMPRIMIDO {
            return Err(std::io::Error::other("límite descomprimido excedido"));
        }
        Ok(n)
    }
}

/// Un hallazgo con la capa y la ruta interna donde apareció.
struct Hallazgo {
    capa: usize,
    ruta: String,
    activos: Vec<Activo>,
}

/// Recorre las capas de una imagen, en orden, sin escribir nada a disco.
///
/// Los activos solo se agregan al resultado en [`AnalizadorImagen::terminar`],
/// de modo que una imagen que falla a medias (por ejemplo, una capa cuyo
/// resumen no coincide) no deja hallazgos parciales.
pub struct AnalizadorImagen {
    /// Nombre de la imagen (etiqueta o referencia) para rutas estables.
    etiqueta: String,
    /// Prefijo visible de las ubicaciones (archivo tar o referencia remota).
    origen: String,
    hallazgos: Vec<Hallazgo>,
    /// Rutas borradas (whiteout) por capa: (capa, ruta borrada, es directorio opaco).
    borrados: Vec<(usize, String, bool)>,
    descomprimido: u64,
    entradas: usize,
    inicio: std::time::Instant,
    pub archivos_revisados: usize,
    pub archivos_omitidos: usize,
    pub avisos: Vec<String>,
}

impl AnalizadorImagen {
    pub fn nuevo(etiqueta: &str, origen: &str) -> Self {
        Self {
            etiqueta: etiqueta.to_string(),
            origen: origen.to_string(),
            hallazgos: Vec::new(),
            borrados: Vec::new(),
            descomprimido: 0,
            entradas: 0,
            inicio: std::time::Instant::now(),
            archivos_revisados: 0,
            archivos_omitidos: 0,
            avisos: Vec::new(),
        }
    }

    /// Analiza una capa (tar, tar+gzip o tar+zstd). `capa` empieza en 0.
    pub fn capa(
        &mut self,
        capa: usize,
        lector: &mut dyn Read,
        escaneres: &[Box<dyn Escaner>],
        c: &Conocimiento,
        op: &Opciones,
    ) -> Result<(), String> {
        let limitado = Presupuesto {
            reader: descomprimir(lector)?,
            total: &mut self.descomprimido,
            inicio: self.inicio,
        };
        let mut interno = tar::Archive::new(limitado);
        let lista = match interno.entries() {
            Ok(l) => l,
            Err(e) => {
                self.avisos
                    .push(format!("{}: capa {}: {e}", self.origen, capa + 1));
                return Ok(());
            }
        };
        for e in lista {
            let mut e = match e {
                Ok(e) => e,
                Err(err) => {
                    self.avisos
                        .push(format!("{}: capa {}: {err}", self.origen, capa + 1));
                    break;
                }
            };
            self.entradas += 1;
            if self.entradas > MAXIMO_ENTRADAS {
                return Err("la imagen excede el número máximo de entradas".into());
            }
            let interna = match e.path() {
                Ok(p) => format!(
                    "/{}",
                    p.to_string_lossy()
                        .trim_start_matches("./")
                        .trim_start_matches('/')
                ),
                Err(_) => continue,
            };
            let (directorio, archivo) = interna.rsplit_once('/').unwrap_or(("", interna.as_str()));
            if archivo == ".wh..wh..opq" {
                self.borrados.push((capa, format!("{directorio}/"), true));
                continue;
            }
            if let Some(borrado) = archivo.strip_prefix(".wh.") {
                self.borrados
                    .push((capa, format!("{directorio}/{borrado}"), false));
                continue;
            }
            if !e.header().entry_type().is_file() {
                continue;
            }
            let tamano = e.size();
            if tamano > MAXIMO_DESCOMPRIMIDO {
                return Err("la imagen excede el límite de datos descomprimidos".into());
            }
            if tamano > op.tamano_maximo {
                self.archivos_omitidos += 1;
                continue;
            }
            let mut contenido = Vec::with_capacity(tamano as usize);
            e.read_to_end(&mut contenido)
                .map_err(|e| format!("capa truncada: {e}"))?;
            self.archivos_revisados += 1;
            let modo = e.header().mode().ok();
            let visible = format!("{}@capa{}:{interna}", self.origen, capa + 1);
            let mut a = Archivo::nuevo(&visible, Path::new(&interna), &contenido, modo);
            a.ruta_estable = format!("imagen:{}:{interna}", self.etiqueta);
            let activos = aplicar_escaneres(&a, escaneres, c, &mut self.avisos);
            if !activos.is_empty() {
                self.hallazgos.push(Hallazgo {
                    capa,
                    ruta: interna,
                    activos,
                });
            }
        }
        Ok(())
    }

    /// Marca los secretos borrados en capas posteriores y agrega los activos.
    pub fn terminar(self, resultado: &mut Resultado) {
        let Self {
            etiqueta,
            origen,
            hallazgos,
            borrados,
            archivos_revisados,
            archivos_omitidos,
            avisos,
            ..
        } = self;
        resultado.archivos_revisados += archivos_revisados;
        resultado.archivos_omitidos += archivos_omitidos;
        resultado.avisos.extend(avisos);

        let mut ultima_aparicion: BTreeMap<String, usize> = BTreeMap::new();
        for h in &hallazgos {
            let v = ultima_aparicion.entry(h.ruta.clone()).or_insert(h.capa);
            *v = (*v).max(h.capa);
        }
        let borrado_despues = |ruta: &str, capa: usize| {
            borrados.iter().any(|(cb, b, opaco)| {
                *cb > capa
                    && if *opaco {
                        ruta.starts_with(b.as_str())
                    } else {
                        ruta == b || ruta.starts_with(&format!("{b}/"))
                    }
            })
        };
        let mut rutas_borradas: BTreeSet<String> = BTreeSet::new();
        for h in hallazgos {
            let reemplazado = ultima_aparicion
                .get(h.ruta.as_str())
                .is_some_and(|&u| u > h.capa);
            let borrado = borrado_despues(&h.ruta, h.capa);
            for mut a in h.activos {
                let es_material_secreto = matches!(&a.detalles, Detalles::Material { tipo_material, .. } if tipo_material == "private-key" || tipo_material == "secret-key");
                if es_material_secreto && (borrado || reemplazado) {
                    rutas_borradas.insert(h.ruta.clone());
                    a.advertir(format!(
                        "{} en una capa posterior, pero sigue dentro de la imagen (capa {}) y cualquiera que la descargue puede extraerla. Reconstruya la imagen sin el secreto y revóquelo.",
                        if borrado { "Se borró" } else { "Se reemplazó" },
                        h.capa + 1
                    ));
                }
                if es_material_secreto {
                    a.advertir(format!(
                        "Llave privada dentro de la imagen de contenedor «{etiqueta}»: queda expuesta en cada registro y equipo donde se copie la imagen. Móntela en tiempo de ejecución desde un gestor de secretos."
                    ));
                }
                resultado.inventario.agregar(a);
            }
        }
        if !rutas_borradas.is_empty() {
            resultado.avisos.push(format!(
                "{origen}: {} secreto(s) borrados en capas posteriores siguen dentro de la imagen",
                rutas_borradas.len()
            ));
        }
    }
}

pub(crate) fn escanear_imagen(
    ruta: &Path,
    escaneres: &[Box<dyn Escaner>],
    c: &Conocimiento,
    op: &Opciones,
    resultado: &mut Resultado,
) -> Result<(), String> {
    let mut open = std::fs::OpenOptions::new();
    open.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = open.open(ruta).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 * 1024 {
        return Err("imagen no regular o mayor de 64 GiB".into());
    }
    let estructura = leer_estructura(&mut file)?;
    file.rewind().map_err(|e| e.to_string())?;
    let esperadas: BTreeSet<_> = estructura.capas.iter().cloned().collect();
    if esperadas.len() != estructura.capas.len() || esperadas.len() > 1000 {
        return Err("manifiesto con capas duplicadas o demasiadas capas".into());
    }
    let mut vistas = BTreeSet::new();
    let archivo_tar = ruta
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let etiqueta = if estructura.nombre.is_empty() {
        archivo_tar.clone()
    } else {
        estructura.nombre.clone()
    };
    let mut analizador = AnalizadorImagen::nuevo(&etiqueta, &archivo_tar);

    let mut externo = tar::Archive::new(file.take(meta.len() + 1));
    for entrada in externo.entries().map_err(|e| e.to_string())? {
        let mut entrada = entrada.map_err(|e| format!("tar dañado: {e}"))?;
        let nombre = entrada
            .path()
            .map_err(|e| e.to_string())?
            .to_string_lossy()
            .trim_start_matches("./")
            .to_string();
        let Some(capa) = estructura.capas.iter().position(|c| *c == nombre) else {
            continue;
        };
        if !entrada.header().entry_type().is_file() || !vistas.insert(nombre.clone()) {
            return Err("capa no regular o repetida".into());
        }
        let mut verificado = VerificarCapa {
            reader: &mut entrada,
            hash: Sha256::new(),
            bytes: 0,
        };
        analizador.capa(capa, &mut verificado, escaneres, c, op)?;
        std::io::copy(&mut verificado, &mut std::io::sink()).map_err(|e| e.to_string())?;
        if let Some(tamano) = estructura.tamanos.get(&nombre) {
            let digest = format!("blobs/sha256/{:x}", verificado.hash.finalize());
            if verificado.bytes != *tamano || digest != nombre {
                return Err("digest o tamaño de capa OCI incorrecto".into());
            }
        }
    }
    if vistas != esperadas {
        return Err("faltan capas declaradas en el manifiesto".into());
    }
    analizador.terminar(resultado);
    Ok(())
}

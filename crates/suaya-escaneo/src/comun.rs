//! Utilidades compartidas por los escáneres.

use std::path::Path;

use sha2::{Digest, Sha256};
use suaya_core::{Activo, AlgoritmoDef, Conocimiento, Detalles, Garantia, Inventario};

/// Archivo en análisis.
pub struct Archivo<'a> {
    /// Ruta tal como se mostrará en el inventario.
    pub ruta: &'a str,
    /// Ruta relativa a la raíz escaneada. Se usa para derivar referencias
    /// estables, de modo que dos escaneos del mismo sistema sean comparables
    /// aunque se lancen desde directorios distintos.
    pub ruta_estable: String,
    /// Nombre del archivo, en minúsculas.
    pub nombre: String,
    /// Extensión, en minúsculas y sin punto.
    pub extension: String,
    pub contenido: &'a [u8],
    /// Permisos Unix, si están disponibles.
    pub modo: Option<u32>,
    /// Descripción del contenedor cuando el contenido viene incrustado en
    /// otro archivo (por ejemplo, «un Secret de Kubernetes»).
    pub incrustado_en: Option<String>,
    /// Marcas conocidas presentes en el contenido (ver [`MARCAS`]), calculadas
    /// una sola vez y bajo demanda.
    marcas: std::cell::OnceCell<u64>,
}

/// Cadenas que los escáneres buscan en el contenido para decidir si un
/// archivo les interesa. Se buscan todas en una sola pasada (Aho-Corasick)
/// en lugar de recorrer el archivo una vez por escáner.
pub const MARCAS: &[&[u8]] = &[
    b"-----BEGIN ",
    b"LS0tLS1CRUdJTi",
    b"ssl_certificate",
    b"ssl_protocols",
    b"SSLProtocol",
    b"SSLCertificateFile",
    b"SSLEngine",
    b"jdk.tls.disabledAlgorithms",
    b"JAVA_VERSION=",
    b"cert-manager.io/",
    b"Certificate",
    b"[Interface]",
    b"PrivateKey",
    b"[Peer]",
    b"\ndev tun",
    b"\ndev tap",
    b"[mysqld",
    b"[mariadb",
    b"[server]",
];

fn automata() -> &'static aho_corasick::AhoCorasick {
    static A: std::sync::OnceLock<aho_corasick::AhoCorasick> = std::sync::OnceLock::new();
    A.get_or_init(|| aho_corasick::AhoCorasick::new(MARCAS).expect("marcas válidas"))
}

impl<'a> Archivo<'a> {
    pub fn nuevo(ruta: &'a str, camino: &Path, contenido: &'a [u8], modo: Option<u32>) -> Self {
        let nombre = camino
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let extension = camino
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        Self {
            ruta,
            ruta_estable: ruta.to_string(),
            nombre,
            extension,
            contenido,
            modo,
            incrustado_en: None,
            marcas: std::cell::OnceCell::new(),
        }
    }

    /// Describe dónde está incrustado el contenido, si aplica: por origen
    /// explícito o porque el archivo es de configuración (YAML, JSON, etc.).
    pub fn origen_incrustado(&self) -> Option<String> {
        if let Some(o) = &self.incrustado_en {
            return Some(o.clone());
        }
        match self.extension.as_str() {
            "yaml" | "yml" => Some("un archivo YAML".into()),
            "json" => Some("un archivo JSON".into()),
            "tf" | "tfvars" | "tfstate" | "hcl" => Some("un archivo de Terraform".into()),
            "env" => Some("un archivo de variables de entorno".into()),
            "toml" | "ini" | "properties" => Some("un archivo de configuración".into()),
            _ if self.nombre == ".env" => Some("un archivo de variables de entorno".into()),
            _ => None,
        }
    }

    pub fn texto(&self) -> Option<&'a str> {
        std::str::from_utf8(self.contenido).ok()
    }

    pub fn contiene(&self, aguja: &[u8]) -> bool {
        match MARCAS.iter().position(|m| *m == aguja) {
            Some(i) => self.marcas() & (1 << i) != 0,
            None => memchr::memmem::find(self.contenido, aguja).is_some(),
        }
    }

    fn marcas(&self) -> u64 {
        *self.marcas.get_or_init(|| {
            let todas = (1u64 << MARCAS.len()) - 1;
            let mut b = 0u64;
            for m in automata().find_overlapping_iter(self.contenido) {
                b |= 1 << m.pattern().as_usize();
                if b == todas {
                    break;
                }
            }
            b
        })
    }
}

#[cfg(unix)]
pub fn modo(m: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(m.permissions().mode())
}

#[cfg(not(unix))]
pub fn modo(_m: &std::fs::Metadata) -> Option<u32> {
    None
}

pub fn huella_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Identificador corto y determinista derivado de un texto.
pub fn id_corto(texto: &str) -> String {
    huella_sha256(texto.as_bytes())[..16].to_string()
}

/// Número de línea (desde 1) correspondiente a un desplazamiento en bytes.
pub fn linea_de(contenido: &[u8], desplazamiento: usize) -> u32 {
    let fin = desplazamiento.min(contenido.len());
    1 + contenido[..fin].iter().filter(|&&b| b == b'\n').count() as u32
}

/// Bits significativos de un entero sin signo en big-endian (p. ej. un módulo RSA).
pub fn bits_de_entero(bytes: &[u8]) -> u32 {
    let sin_ceros: &[u8] = match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => return 0,
    };
    (sin_ceros.len() as u32) * 8 - sin_ceros[0].leading_zeros()
}

/// Crea el activo de un algoritmo a partir de la base de conocimiento.
///
/// Si `def` es `None`, se crea un activo "desconocido" con el nombre de respaldo,
/// para que el inventario nunca oculte lo que Suaya no reconoce.
pub fn activo_algoritmo(
    def: Option<&AlgoritmoDef>,
    respaldo: &str,
    tamano: Option<u32>,
    capacidad: &str,
    garantia: Option<Garantia>,
    ruta: &str,
    linea: Option<u32>,
) -> Activo {
    match def {
        Some(d) => {
            // El tamaño solo distingue algoritmos de tamaño variable (RSA, DSA);
            // en curvas y conjuntos de parámetros ya está implícito.
            let implicito =
                d.tamano_llave.is_some() || d.curva.is_some() || d.conjunto_parametros.is_some();
            let tamano = if implicito { None } else { tamano };
            let (referencia, nombre) = match tamano {
                Some(t) => (
                    format!("algoritmo:{}-{t}", d.id),
                    format!("{}-{t}", d.nombre),
                ),
                None => (format!("algoritmo:{}", d.id), d.nombre.clone()),
            };
            let mut a = Activo::nuevo(
                referencia,
                nombre,
                Detalles::Algoritmo {
                    algoritmo_id: Some(d.id.clone()),
                    tamano_llave: tamano,
                },
            )
            .con_contexto(capacidad, garantia.unwrap_or(d.garantia))
            .con_ubicacion(ruta, linea);
            if let Some(adv) = &d.advertencia {
                a.advertir(adv.clone());
            }
            a
        }
        None => {
            let limpio = respaldo.trim().to_lowercase();
            let mut a = Activo::nuevo(
                format!("algoritmo:desconocido:{limpio}"),
                respaldo.trim(),
                Detalles::Algoritmo {
                    algoritmo_id: None,
                    tamano_llave: tamano,
                },
            )
            .con_contexto(capacidad, garantia.unwrap_or(Garantia::Autenticacion))
            .con_ubicacion(ruta, linea);
            a.advertir(format!(
                "Algoritmo no reconocido por la base de conocimiento: «{}». Considere agregarlo a conocimiento/algoritmos.toml.",
                respaldo.trim()
            ));
            a
        }
    }
}

/// Atajo: busca un algoritmo por alias y crea su activo.
pub fn por_alias(
    c: &Conocimiento,
    espacio: &str,
    nombre: &str,
    capacidad: &str,
    garantia: Option<Garantia>,
    ruta: &str,
    linea: Option<u32>,
) -> Activo {
    activo_algoritmo(
        c.por_alias(espacio, nombre),
        nombre,
        None,
        capacidad,
        garantia,
        ruta,
        linea,
    )
}

/// Tipo de relación provisional que emiten las configuraciones TLS para
/// enlazar certificados por ruta; se resuelve al final del escaneo.
pub const REL_RUTA_CERTIFICADO: &str = "ruta-certificado";

/// Sustituye las relaciones por ruta de certificado por la referencia del
/// certificado hallado en esa ruta, y le agrega el contexto de uso.
pub fn resolver_certificados_referenciados(inv: &mut Inventario) {
    let certificados: Vec<(String, Vec<String>)> = inv
        .activos
        .iter()
        .filter(|a| matches!(a.detalles, Detalles::Certificado { .. }))
        .map(|a| {
            (
                a.referencia.clone(),
                a.ubicaciones.iter().map(|u| u.ruta.clone()).collect(),
            )
        })
        .collect();

    let mut nuevos_contextos: Vec<(String, String)> = Vec::new();

    for activo in inv.activos.iter_mut() {
        let capacidad = activo.contextos.first().map(|c| c.capacidad.clone());
        let mut pendientes = Vec::new();
        activo.relaciones.retain(|r| {
            if r.tipo == REL_RUTA_CERTIFICADO {
                pendientes.push(r.referencia.clone());
                false
            } else {
                true
            }
        });
        for ruta_config in pendientes {
            let objetivo = ruta_config.trim_start_matches('/');
            let directorio = format!("{}/", objetivo.trim_end_matches('/'));
            let hallados: Vec<&String> = certificados
                .iter()
                .filter(|(_, rutas)| {
                    rutas.iter().any(|r| {
                        let r = r.trim_start_matches("./");
                        r == ruta_config
                            || r.ends_with(objetivo)
                            || objetivo.ends_with(r)
                            // Un directorio de certificados (p. ej. `crt /etc/haproxy/certs/`).
                            || (ruta_config.ends_with('/') && r.contains(&directorio))
                    })
                })
                .map(|(referencia, _)| referencia)
                .collect();
            if hallados.is_empty() {
                activo.advertir(format!(
                    "Certificado referenciado que no se encontró en el escaneo: {ruta_config}. Inclúyalo para evaluarlo."
                ));
            }
            for referencia in hallados {
                activo.relacionar("certificate", referencia);
                if let Some(cap) = &capacidad {
                    nuevos_contextos.push((referencia.clone(), cap.clone()));
                }
            }
        }
    }

    for (referencia, capacidad) in nuevos_contextos {
        if let Some(cert) = inv.activos.iter_mut().find(|a| a.referencia == referencia) {
            cert.agregar_contexto(&capacidad, Garantia::Autenticacion);
        }
    }
}

#[cfg(test)]
mod pruebas {
    use super::*;

    #[test]
    fn bits() {
        assert_eq!(bits_de_entero(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(bits_de_entero(&[0x01, 0x00]), 9);
        assert_eq!(bits_de_entero(&[0x00]), 0);
    }

    #[test]
    fn lineas() {
        assert_eq!(linea_de(b"a\nb\nc", 0), 1);
        assert_eq!(linea_de(b"a\nb\nc", 4), 3);
    }
}

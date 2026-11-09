//! Modelo de datos de Suaya.
//!
//! Un [`Activo`] es cualquier cosa criptográfica que un escáner encuentra:
//! un algoritmo, un certificado, una llave o una configuración de protocolo.
//! El modelo es independiente de CycloneDX; el exportador lo traduce a CBOM.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::clasificacion::Clasificacion;

/// Riesgo de un activo frente a la criptografía clásica y cuántica.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Riesgo {
    /// Ya es inseguro hoy, sin computadora cuántica (MD5, SHA-1 en firmas, RSA < 2048).
    RotoClasico,
    /// No está roto, pero está retirado o en retiro por los estándares.
    Obsoleto,
    /// Vulnerable a un ataque cuántico con el algoritmo de Shor (RSA, ECC, DH).
    VulnerableCuantico,
    /// Margen reducido por el algoritmo de Grover; revisar el tamaño de llave.
    DebilitadoGrover,
    /// Combina un algoritmo clásico con uno poscuántico.
    HibridoPq,
    /// Resistente a los ataques cuánticos conocidos.
    ResistenteCuantico,
    /// Suaya no tiene información suficiente para decidir.
    Desconocido,
}

impl Riesgo {
    pub const TODOS: [Riesgo; 7] = [
        Riesgo::RotoClasico,
        Riesgo::Obsoleto,
        Riesgo::VulnerableCuantico,
        Riesgo::DebilitadoGrover,
        Riesgo::HibridoPq,
        Riesgo::ResistenteCuantico,
        Riesgo::Desconocido,
    ];

    /// Interpreta el texto de [`Riesgo::como_texto`] (p. ej. de un CBOM).
    pub fn desde_texto(t: &str) -> Option<Self> {
        Self::TODOS.into_iter().find(|r| r.como_texto() == t)
    }

    pub fn como_texto(self) -> &'static str {
        match self {
            Riesgo::RotoClasico => "roto-clasico",
            Riesgo::Obsoleto => "obsoleto",
            Riesgo::VulnerableCuantico => "vulnerable-cuantico",
            Riesgo::DebilitadoGrover => "debilitado-grover",
            Riesgo::HibridoPq => "hibrido-pq",
            Riesgo::ResistenteCuantico => "resistente-cuantico",
            Riesgo::Desconocido => "desconocido",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        match self {
            Riesgo::RotoClasico => crate::idioma::tx("Roto (clásico)", "Broken (classical)"),
            Riesgo::Obsoleto => crate::idioma::tx("Obsoleto", "Deprecated"),
            Riesgo::VulnerableCuantico => {
                crate::idioma::tx("Vulnerable a cómputo cuántico", "Quantum-vulnerable")
            }
            Riesgo::DebilitadoGrover => {
                crate::idioma::tx("Debilitado por Grover", "Weakened by Grover")
            }
            Riesgo::HibridoPq => crate::idioma::tx("Híbrido poscuántico", "Post-quantum hybrid"),
            Riesgo::ResistenteCuantico => {
                crate::idioma::tx("Resistente a cómputo cuántico", "Quantum-resistant")
            }
            Riesgo::Desconocido => crate::idioma::tx("Desconocido", "Unknown"),
        }
    }

    /// Gravedad para ordenar: menor número, más grave.
    pub fn gravedad(self) -> u8 {
        match self {
            Riesgo::RotoClasico => 0,
            Riesgo::Obsoleto => 1,
            Riesgo::VulnerableCuantico => 2,
            Riesgo::Desconocido => 3,
            Riesgo::DebilitadoGrover => 4,
            Riesgo::HibridoPq => 5,
            Riesgo::ResistenteCuantico => 6,
        }
    }
}

impl fmt::Display for Riesgo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.como_texto())
    }
}

/// Tipo de garantía de seguridad que el activo aporta.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Garantia {
    Confidencialidad,
    Autenticacion,
    Integridad,
}

impl Garantia {
    /// Interpreta el texto de [`Garantia::como_texto`] (p. ej. de un CBOM).
    pub fn desde_texto(t: &str) -> Option<Self> {
        [
            Garantia::Confidencialidad,
            Garantia::Autenticacion,
            Garantia::Integridad,
        ]
        .into_iter()
        .find(|g| g.como_texto() == t)
    }

    pub fn como_texto(self) -> &'static str {
        match self {
            Garantia::Confidencialidad => "confidencialidad",
            Garantia::Autenticacion => "autenticacion",
            Garantia::Integridad => "integridad",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        match self {
            Garantia::Confidencialidad => crate::idioma::tx("Confidencialidad", "Confidentiality"),
            Garantia::Autenticacion => crate::idioma::tx("Autenticación", "Authentication"),
            Garantia::Integridad => crate::idioma::tx("Integridad", "Integrity"),
        }
    }
}

/// Nivel de madurez del ecosistema para adoptar PQC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NivelMadurez {
    NoAplica,
    Bloqueado,
    Habilitado,
    ComponentesDisponibles,
    IntegracionPreliminar,
    Integracion,
    IntegracionValidada,
    Desconocido,
}

impl NivelMadurez {
    /// Posición en la escala (0 = no aplica, 6 = integración validada).
    pub fn rango(self) -> u8 {
        match self {
            NivelMadurez::NoAplica | NivelMadurez::Desconocido => 0,
            NivelMadurez::Bloqueado => 1,
            NivelMadurez::Habilitado => 2,
            NivelMadurez::ComponentesDisponibles => 3,
            NivelMadurez::IntegracionPreliminar => 4,
            NivelMadurez::Integracion => 5,
            NivelMadurez::IntegracionValidada => 6,
        }
    }

    pub fn como_texto(self) -> &'static str {
        match self {
            NivelMadurez::NoAplica => "no-aplica",
            NivelMadurez::Bloqueado => "bloqueado",
            NivelMadurez::Habilitado => "habilitado",
            NivelMadurez::ComponentesDisponibles => "componentes-disponibles",
            NivelMadurez::IntegracionPreliminar => "integracion-preliminar",
            NivelMadurez::Integracion => "integracion",
            NivelMadurez::IntegracionValidada => "integracion-validada",
            NivelMadurez::Desconocido => "desconocido",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        match self {
            NivelMadurez::NoAplica => crate::idioma::tx("No aplica", "Not applicable"),
            NivelMadurez::Bloqueado => crate::idioma::tx("Bloqueado", "Blocked"),
            NivelMadurez::Habilitado => crate::idioma::tx("Habilitado", "Enabled"),
            NivelMadurez::ComponentesDisponibles => {
                crate::idioma::tx("Componentes disponibles", "Components available")
            }
            NivelMadurez::IntegracionPreliminar => {
                crate::idioma::tx("Integración preliminar", "Preliminary integration")
            }
            NivelMadurez::Integracion => crate::idioma::tx("Integración", "Integration"),
            NivelMadurez::IntegracionValidada => {
                crate::idioma::tx("Integración validada", "Validated integration")
            }
            NivelMadurez::Desconocido => crate::idioma::tx("Desconocido", "Unknown"),
        }
    }
}

/// Dónde se encontró un activo.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ubicacion {
    pub ruta: String,
    pub linea: Option<u32>,
}

/// Contexto de uso: en qué capacidad tecnológica y para qué garantía.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Contexto {
    /// Identificador de capacidad en `madurez.toml` (p. ej. `servidores-web`).
    pub capacidad: String,
    pub garantia: Garantia,
}

/// Relación con otro activo del inventario (por su referencia).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Relacion {
    /// Tipo de relación, con los nombres sugeridos por CycloneDX:
    /// `algorithm`, `publicKey`, `privateKey`, `signature`.
    pub tipo: String,
    pub referencia: String,
}

/// Detalles específicos según el tipo de activo.
///
/// La **identidad de llave** es el SHA-256 (hexadecimal) de la llave pública
/// en su forma canónica: `RSAPublicKey` en DER para RSA, el punto sin
/// comprimir para curvas NIST y los 32 bytes para Ed25519. Es la misma sin
/// importar si la llave viene de un certificado, un PKCS#8, un PKCS#1, un
/// SEC1 o un archivo OpenSSH, y permite enlazar unos con otros.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "tipo", rename_all = "kebab-case")]
pub enum Detalles {
    Algoritmo {
        /// Identificador en `algoritmos.toml`, si se reconoció.
        algoritmo_id: Option<String>,
        tamano_llave: Option<u32>,
    },
    Certificado {
        sujeto: String,
        emisor: String,
        serie: String,
        no_antes: String,
        no_despues: String,
        /// Huella SHA-256 del TBSCertificate, en hexadecimal.
        huella_sha256: String,
        extension_archivo: Option<String>,
        vencido: bool,
        /// Identidad de la llave pública del certificado (ver [`Detalles`]).
        #[serde(default)]
        identidad_llave: Option<String>,
    },
    Material {
        /// Tipo según CycloneDX: `private-key`, `public-key`, `secret-key`...
        tipo_material: String,
        tamano: Option<u32>,
        formato: String,
        /// Descripción de la protección en reposo, si la hay (p. ej. cifrado PBES2).
        protegido_por: Option<String>,
        huella_sha256: Option<String>,
        /// Identidad de la llave pública correspondiente, si se pudo derivar.
        #[serde(default)]
        identidad_llave: Option<String>,
    },
    Protocolo {
        /// Tipo según CycloneDX: `tls`, `ssh`, `ipsec`...
        tipo_protocolo: String,
        versiones: Vec<String>,
        /// Grupos o algoritmos de intercambio de llaves declarados.
        grupos: Vec<String>,
        cifrados: Vec<String>,
    },
    /// Biblioteca o entorno criptográfico (se exporta como componente `library`).
    Biblioteca {
        /// Identificador en `bibliotecas.toml`.
        biblioteca_id: String,
        version: Option<String>,
        /// Identificador de paquete (purl), si se conoce.
        purl: Option<String>,
    },
}

/// Criticidad de un sistema para la organización.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Criticidad {
    Alta,
    Media,
    Baja,
}

impl Criticidad {
    pub fn como_texto(self) -> &'static str {
        match self {
            Criticidad::Alta => "alta",
            Criticidad::Media => "media",
            Criticidad::Baja => "baja",
        }
    }

    pub fn etiqueta(self) -> &'static str {
        match self {
            Criticidad::Alta => crate::idioma::tx("Alta", "High"),
            Criticidad::Media => crate::idioma::tx("Media", "Medium"),
            Criticidad::Baja => crate::idioma::tx("Baja", "Low"),
        }
    }
}

/// Desde dónde se puede alcanzar un sistema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Exposicion {
    Internet,
    Interna,
}

impl Exposicion {
    pub fn como_texto(self) -> &'static str {
        match self {
            Exposicion::Internet => "internet",
            Exposicion::Interna => "interna",
        }
    }
}

/// Evaluación de la desigualdad de Mosca (x + y > z): los datos deben seguir
/// confidenciales `x` años, la migración tarda `y` y el horizonte de una
/// computadora cuántica relevante es `z` años desde hoy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mosca {
    pub vida_datos: u32,
    pub migracion: u32,
    /// Año que se supone para una computadora cuántica relevante.
    pub horizonte: i32,
    /// Años de margen: z - (x + y). Negativo significa exposición.
    pub holgura: i32,
}

impl Mosca {
    /// Los datos capturados hoy seguirán siendo valiosos cuando se puedan descifrar.
    pub fn expuesto(&self) -> bool {
        self.holgura < 0
    }
}

/// Riesgo aceptado formalmente, con vencimiento.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Excepcion {
    pub id: String,
    pub justificacion: String,
    #[serde(default)]
    pub aprobada_por: Option<String>,
    /// Fecha AAAA-MM-DD a partir de la cual deja de valer.
    pub vence: String,
    pub vigente: bool,
}

/// A qué sistemas pertenece un activo, quién responde por él y cuánto tiempo
/// deben protegerse sus datos (archivo de contexto, `--organizacion`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContextoOrganizacional {
    pub sistemas: Vec<String>,
    pub responsables: Vec<String>,
    /// La más alta de sus sistemas.
    pub criticidad: Option<Criticidad>,
    /// `internet` si alguno de sus sistemas lo está.
    pub exposicion: Option<Exposicion>,
    pub mosca: Option<Mosca>,
    pub excepcion: Option<Excepcion>,
}

/// Un activo criptográfico del inventario.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Activo {
    /// Referencia estable y determinista (sirve para comparar escaneos).
    pub referencia: String,
    pub nombre: String,
    pub detalles: Detalles,
    pub contextos: Vec<Contexto>,
    pub ubicaciones: Vec<Ubicacion>,
    pub relaciones: Vec<Relacion>,
    /// Riesgo fijado por el escáner cuando no se deriva de un solo algoritmo
    /// (por ejemplo, una configuración TLS cuyo riesgo depende de sus grupos).
    pub riesgo_fijado: Option<Riesgo>,
    pub advertencias: Vec<String>,
    pub clasificacion: Option<Clasificacion>,
    /// Cumplimiento con un perfil de política, si se evaluó.
    #[serde(default)]
    pub cumplimiento: Option<crate::politica::Cumplimiento>,
    /// Contexto de la organización, si se proporcionó.
    #[serde(default)]
    pub organizacion: Option<ContextoOrganizacional>,
}

impl Activo {
    pub fn nuevo(
        referencia: impl Into<String>,
        nombre: impl Into<String>,
        detalles: Detalles,
    ) -> Self {
        Self {
            referencia: referencia.into(),
            nombre: nombre.into(),
            detalles,
            contextos: Vec::new(),
            ubicaciones: Vec::new(),
            relaciones: Vec::new(),
            riesgo_fijado: None,
            advertencias: Vec::new(),
            clasificacion: None,
            cumplimiento: None,
            organizacion: None,
        }
    }

    pub fn con_contexto(mut self, capacidad: &str, garantia: Garantia) -> Self {
        self.agregar_contexto(capacidad, garantia);
        self
    }

    pub fn con_ubicacion(mut self, ruta: &str, linea: Option<u32>) -> Self {
        self.agregar_ubicacion(ruta, linea);
        self
    }

    pub fn agregar_contexto(&mut self, capacidad: &str, garantia: Garantia) {
        let c = Contexto {
            capacidad: capacidad.to_string(),
            garantia,
        };
        if !self.contextos.contains(&c) {
            self.contextos.push(c);
        }
    }

    pub fn agregar_ubicacion(&mut self, ruta: &str, linea: Option<u32>) {
        let u = Ubicacion {
            ruta: ruta.to_string(),
            linea,
        };
        if !self.ubicaciones.contains(&u) {
            self.ubicaciones.push(u);
        }
    }

    pub fn relacionar(&mut self, tipo: &str, referencia: &str) {
        let r = Relacion {
            tipo: tipo.to_string(),
            referencia: referencia.to_string(),
        };
        if !self.relaciones.contains(&r) {
            self.relaciones.push(r);
        }
    }

    pub fn advertir(&mut self, texto: impl Into<String>) {
        let t = texto.into();
        if !self.advertencias.contains(&t) {
            self.advertencias.push(t);
        }
    }

    /// Identificador de algoritmo, si el activo es un algoritmo reconocido.
    pub fn algoritmo_id(&self) -> Option<&str> {
        match &self.detalles {
            Detalles::Algoritmo { algoritmo_id, .. } => algoritmo_id.as_deref(),
            _ => None,
        }
    }

    /// Fusiona otro activo con la misma referencia (ubicaciones, contextos, etc.).
    pub fn fusionar(&mut self, otro: Activo) {
        for c in otro.contextos {
            self.agregar_contexto(&c.capacidad, c.garantia);
        }
        for u in otro.ubicaciones {
            self.agregar_ubicacion(&u.ruta, u.linea);
        }
        for r in otro.relaciones {
            self.relacionar(&r.tipo, &r.referencia);
        }
        for a in otro.advertencias {
            self.advertir(a);
        }
        if self.riesgo_fijado.is_none() {
            self.riesgo_fijado = otro.riesgo_fijado;
        }
    }
}

/// Inventario: colección de activos sin duplicados por referencia.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Inventario {
    pub activos: Vec<Activo>,
}

impl Inventario {
    pub fn agregar(&mut self, activo: Activo) {
        if let Some(existente) = self
            .activos
            .iter_mut()
            .find(|a| a.referencia == activo.referencia)
        {
            existente.fusionar(activo);
        } else {
            self.activos.push(activo);
        }
    }

    pub fn extender(&mut self, activos: impl IntoIterator<Item = Activo>) {
        for a in activos {
            self.agregar(a);
        }
    }

    /// Ordena de forma estable: primero por prioridad, luego por referencia.
    pub fn ordenar(&mut self) {
        self.activos.sort_by(|a, b| {
            let pa = a.clasificacion.as_ref().map(|c| c.prioridad).unwrap_or(9);
            let pb = b.clasificacion.as_ref().map(|c| c.prioridad).unwrap_or(9);
            pa.cmp(&pb).then_with(|| a.referencia.cmp(&b.referencia))
        });
        for a in &mut self.activos {
            a.ubicaciones
                .sort_by(|x, y| x.ruta.cmp(&y.ruta).then(x.linea.cmp(&y.linea)));
        }
    }
}

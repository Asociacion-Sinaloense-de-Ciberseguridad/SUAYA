//! Escáner de configuración de OpenSSH (`sshd_config`, `ssh_config` y sus
//! fragmentos en `*.d/*.conf`).
//!
//! Evalúa si el intercambio de llaves declarado incluye un híbrido
//! poscuántico (`mlkem768x25519-sha256`) y si quedan algoritmos rotos.

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, id_corto, linea_de, por_alias};

const CAPACIDAD: &str = "vpn-cifrado-red";

pub struct EscanerConfigSsh;

impl Escaner for EscanerConfigSsh {
    fn nombre(&self) -> &'static str {
        "configuración SSH"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "sshd_config"
            || a.nombre == "ssh_config"
            || (a.extension == "conf"
                && (a.ruta.contains("sshd_config.d") || a.ruta.contains("ssh_config.d")))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut activos = Vec::new();
        let mut kex: Vec<String> = Vec::new();
        let mut cifrados: Vec<String> = Vec::new();
        let mut kex_declarado = false;
        let mut kex_modificado = false;
        let mut desplazamiento = 0usize;
        let mut algoritmos: Vec<Activo> = Vec::new();

        for linea in texto.split_inclusive('\n') {
            let numero = Some(linea_de(a.contenido, desplazamiento));
            desplazamiento += linea.len();
            let l = linea.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut partes = l.splitn(2, |ch: char| ch.is_whitespace() || ch == '=');
            let clave = partes.next().unwrap_or("").to_lowercase();
            let valor = partes
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches('=')
                .trim();

            let (espacio, garantia) = match clave.as_str() {
                "kexalgorithms" => ("ssh-kex", Garantia::Confidencialidad),
                "ciphers" => ("ssh-cifrado", Garantia::Confidencialidad),
                "macs" => ("ssh-mac", Garantia::Integridad),
                "hostkeyalgorithms"
                | "pubkeyacceptedalgorithms"
                | "pubkeyacceptedkeytypes"
                | "casignaturealgorithms"
                | "hostbasedacceptedalgorithms" => ("ssh", Garantia::Autenticacion),
                _ => continue,
            };

            let modificador = valor.starts_with(['+', '-', '^']);
            let lista: Vec<&str> = valor
                .trim_start_matches(['+', '-', '^'])
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();

            if espacio == "ssh-kex" {
                kex_declarado = true;
                kex_modificado |= modificador;
                if !valor.starts_with('-') {
                    kex.extend(lista.iter().map(|s| s.to_string()));
                }
            }
            if espacio == "ssh-cifrado" && !valor.starts_with('-') {
                cifrados.extend(lista.iter().map(|s| s.to_string()));
            }
            // Los algoritmos que se quitan (prefijo '-') no se inventarían.
            if valor.starts_with('-') {
                continue;
            }
            for nombre in lista {
                algoritmos.push(por_alias(
                    c,
                    espacio,
                    nombre,
                    CAPACIDAD,
                    Some(garantia),
                    a.ruta,
                    numero,
                ));
            }
        }

        if algoritmos.is_empty() && !kex_declarado {
            return Ok(activos);
        }

        let mut protocolo = Activo::nuevo(
            format!("protocolo:ssh:{}", id_corto(&a.ruta_estable)),
            format!("Configuración SSH ({})", a.nombre),
            Detalles::Protocolo {
                tipo_protocolo: "ssh".into(),
                versiones: vec!["2".into()],
                grupos: kex.clone(),
                cifrados,
            },
        )
        .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
        .con_ubicacion(a.ruta, None);

        protocolo.riesgo_fijado = Some(if !kex_declarado || kex_modificado {
            protocolo.advertir(
                "KexAlgorithms no se declara de forma explícita: el resultado depende de la versión de OpenSSH (10.0 o posterior prefiere mlkem768x25519-sha256). Verificar con «suaya sondear».",
            );
            Riesgo::Desconocido
        } else {
            let (riesgo, advertencias) = riesgo_kex_ssh(&kex, c);
            for a in advertencias {
                protocolo.advertir(a);
            }
            riesgo
        });

        for alg in &algoritmos {
            protocolo.relacionar("algorithm", &alg.referencia);
        }
        activos.extend(algoritmos);
        activos.push(protocolo);
        Ok(activos)
    }
}

/// Riesgo de una lista explícita de intercambios de llaves SSH.
///
/// En SSH se negocia el primer algoritmo del cliente que el servidor acepta,
/// así que importa qué acepta el servidor, no su orden.
pub fn riesgo_kex_ssh(kex: &[String], c: &Conocimiento) -> (Riesgo, Vec<String>) {
    let riesgos: Vec<Riesgo> = kex
        .iter()
        .map(|k| {
            c.por_alias("ssh-kex", k)
                .map(|d| d.riesgo)
                .unwrap_or(Riesgo::Desconocido)
        })
        .collect();
    let hay_hibrido = riesgos
        .iter()
        .any(|r| matches!(r, Riesgo::HibridoPq | Riesgo::ResistenteCuantico));
    let hay_clasico = riesgos.contains(&Riesgo::VulnerableCuantico);
    let mut adv = Vec::new();
    let riesgo = if riesgos.contains(&Riesgo::RotoClasico) {
        adv.push("El intercambio de llaves acepta algoritmos rotos; deshabilitarlos.".to_string());
        Riesgo::RotoClasico
    } else if riesgos.contains(&Riesgo::Obsoleto) {
        adv.push("El intercambio de llaves acepta algoritmos obsoletos.".to_string());
        Riesgo::Obsoleto
    } else if hay_hibrido {
        if hay_clasico {
            adv.push(
                "También acepta intercambios clásicos: los clientes antiguos negociarán sin protección poscuántica."
                    .to_string(),
            );
        }
        Riesgo::HibridoPq
    } else if riesgos.is_empty() {
        Riesgo::Desconocido
    } else {
        Riesgo::VulnerableCuantico
    };
    (riesgo, adv)
}

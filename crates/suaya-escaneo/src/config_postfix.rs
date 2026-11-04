//! Escáner de configuración de Postfix (`main.cf`).
//!
//! Evalúa el TLS del servidor SMTP (`smtpd_tls_*`): nivel de seguridad,
//! versiones, curvas (`tls_eecdh_auto_curves`) y certificados. El cliente
//! saliente (`smtp_tls_security_level`) se reporta como advertencia.

use std::collections::BTreeMap;

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{Archivo, REL_RUTA_CERTIFICADO, id_corto, linea_de, por_alias};
use crate::config_tls::evaluar_tls;

/// Decisión de Suaya: el correo entre servidores es tráfico de red entre
/// organizaciones, terminado por un servidor; se evalúa con la madurez de
/// `servidores-web` (documentado en docs/metodologia.md).
const CAPACIDAD: &str = "servidores-web";
const VERSIONES: [&str; 6] = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
const SIN_GRUPOS: &str = "No declara tls_eecdh_auto_curves: Postfix usa sus curvas predeterminadas, que son clásicas salvo que su versión y OpenSSL (3.5 o posterior) agreguen X25519MLKEM768. Verifique la versión de OpenSSL enlazada.";

pub struct EscanerConfigPostfix;

/// Versiones permitidas por una lista de Postfix (`>=TLSv1.2`, `!SSLv3`, ...).
fn versiones_permitidas(lista: &str) -> Vec<String> {
    let mut desde = 0usize;
    let mut hasta = VERSIONES.len() - 1;
    let mut incluidas: Vec<usize> = Vec::new();
    let mut excluidas: Vec<usize> = Vec::new();
    let pos = |v: &str| VERSIONES.iter().position(|x| x.eq_ignore_ascii_case(v));
    for t in lista
        .split([',', ' ', ':', '\t'])
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        if let Some(v) = t.strip_prefix(">=").and_then(pos) {
            desde = v;
        } else if let Some(v) = t.strip_prefix("<=").and_then(pos) {
            hasta = v;
        } else if let Some(v) = t.strip_prefix('!').and_then(pos) {
            excluidas.push(v);
        } else if let Some(v) = pos(t) {
            incluidas.push(v);
        }
    }
    // Postfix ya no implementa SSLv2: solo se considera si se lista.
    (desde..=hasta)
        .filter(|i| !excluidas.contains(i))
        .filter(|i| incluidas.is_empty() || incluidas.contains(i))
        .filter(|&i| i != 0 || incluidas.contains(&0))
        .map(|i| VERSIONES[i].to_string())
        .collect()
}

impl Escaner for EscanerConfigPostfix {
    fn nombre(&self) -> &'static str {
        "configuración de Postfix"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "main.cf"
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        // Parámetros con su línea; una línea que empieza con espacio continúa
        // la anterior.
        let mut valores: BTreeMap<String, (String, u32)> = BTreeMap::new();
        let mut ultima: Option<String> = None;
        let mut desplazamiento = 0usize;
        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            if linea.trim().is_empty() || linea.trim_start().starts_with('#') {
                continue;
            }
            if linea.starts_with([' ', '\t']) {
                if let Some(v) = ultima.as_ref().and_then(|k| valores.get_mut(k)) {
                    v.0.push(' ');
                    v.0.push_str(linea.trim());
                }
                continue;
            }
            if let Some((k, v)) = linea.split_once('=') {
                let k = k.trim().to_string();
                valores.insert(k.clone(), (v.trim().to_string(), numero));
                ultima = Some(k);
            }
        }
        if !valores
            .keys()
            .any(|k| k.contains("tls") || k == "myhostname")
        {
            return Ok(Vec::new());
        }
        // Expansión simple de $parametro y ${parametro}.
        let expandir = |v: &str| -> String {
            let mut s = v.to_string();
            for _ in 0..4 {
                let mut cambio = false;
                for (k, (valor, _)) in &valores {
                    for patron in [format!("${{{k}}}"), format!("${k}")] {
                        if s.contains(&patron) {
                            s = s.replace(&patron, valor);
                            cambio = true;
                        }
                    }
                }
                if !s.contains('$') || !cambio {
                    break;
                }
            }
            s.replace("$config_directory", "/etc/postfix")
                .replace("${config_directory}", "/etc/postfix")
        };
        let valor = |k: &str| valores.get(k).map(|(v, n)| (expandir(v), *n));

        let interfaces = valor("inet_interfaces")
            .map(|(v, _)| v.to_lowercase())
            .unwrap_or_else(|| "all".into());
        let solo_local = interfaces
            .split([',', ' '])
            .filter(|x| !x.is_empty())
            .all(|i| matches!(i, "loopback-only" | "localhost" | "127.0.0.1" | "[::1]"));

        let nivel = valor("smtpd_tls_security_level")
            .map(|(v, n)| (v.to_lowercase(), Some(n)))
            .or_else(|| {
                valor("smtpd_use_tls")
                    .filter(|(v, _)| v.eq_ignore_ascii_case("yes"))
                    .map(|(_, n)| ("may".to_string(), Some(n)))
            })
            .unwrap_or(("none".to_string(), None));

        let referencia = format!("protocolo:tls:{}", id_corto(&a.ruta_estable));
        let nombre = format!("Postfix SMTP ({})", a.nombre);
        let protocolo_vacio = |versiones: Vec<String>, grupos: Vec<String>, linea| {
            Activo::nuevo(
                referencia.clone(),
                nombre.clone(),
                Detalles::Protocolo {
                    tipo_protocolo: "tls".into(),
                    versiones,
                    grupos,
                    cifrados: Vec::new(),
                },
            )
            .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
            .con_ubicacion(a.ruta, linea)
        };

        if nivel.0 == "none" {
            if solo_local {
                return Ok(Vec::new());
            }
            let mut p = protocolo_vacio(Vec::new(), Vec::new(), nivel.1);
            p.riesgo_fijado = Some(Riesgo::RotoClasico);
            p.advertir(
                "El servidor SMTP no ofrece STARTTLS (smtpd_tls_security_level=none): el correo y las credenciales SMTP AUTH viajan sin cifrar.",
            );
            return Ok(vec![p]);
        }

        let obligatorio = matches!(nivel.0.as_str(), "encrypt");
        let parametro = if obligatorio {
            "smtpd_tls_mandatory_protocols"
        } else {
            "smtpd_tls_protocols"
        };
        let (versiones, linea_versiones) = match valor(parametro) {
            Some((v, n)) => (versiones_permitidas(&v), Some(n)),
            // Predeterminado de Postfix 3.6 y posteriores: >=TLSv1.
            None => (versiones_permitidas(">=TLSv1"), None),
        };
        let (grupos, linea_grupos) = match valor("tls_eecdh_auto_curves") {
            Some((v, n)) => (
                Some(
                    v.split([',', ' ', ':'])
                        .filter(|x| !x.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                ),
                Some(n),
            ),
            None => (None, None),
        };
        let mut protocolo = protocolo_vacio(
            versiones.clone(),
            grupos.clone().unwrap_or_default(),
            linea_versiones.or(nivel.1),
        );
        let mut activos = Vec::new();
        for g in grupos.iter().flatten() {
            let alg = por_alias(
                c,
                "tls-grupo",
                g,
                CAPACIDAD,
                Some(Garantia::Confidencialidad),
                a.ruta,
                linea_grupos,
            );
            protocolo.relacionar("algorithm", &alg.referencia);
            activos.push(alg);
        }
        evaluar_tls(
            &mut protocolo,
            &versiones,
            grupos.as_deref(),
            SIN_GRUPOS,
            Riesgo::Desconocido,
            c,
        );
        if !obligatorio {
            protocolo.advertir(
                "TLS oportunista (smtpd_tls_security_level=may): un atacante en la red puede suprimir STARTTLS y forzar texto claro. Para el intercambio entre sistemas propios exija TLS (encrypt) o publique DANE o MTA-STS.",
            );
        }
        let saliente = valor("smtp_tls_security_level")
            .map(|(v, _)| v.to_lowercase())
            .unwrap_or_else(|| "none".into());
        if saliente == "none" {
            protocolo.advertir(
                "El envío saliente no usa TLS (smtp_tls_security_level=none): el correo hacia otros servidores viaja sin cifrar. Use al menos «may», o «dane» con DNSSEC.",
            );
        }

        let mut certificados: Vec<String> = Vec::new();
        for k in ["smtpd_tls_cert_file", "smtpd_tls_eccert_file"] {
            if let Some((v, _)) = valor(k).filter(|(v, _)| !v.is_empty()) {
                certificados.push(v);
            }
        }
        if let Some((v, _)) = valor("smtpd_tls_chain_files") {
            certificados.extend(
                v.split([',', ' '])
                    .filter(|x| !x.is_empty())
                    .map(str::to_string),
            );
        }
        for cert in certificados {
            protocolo.relacionar(REL_RUTA_CERTIFICADO, &cert);
        }
        activos.push(protocolo);
        Ok(activos)
    }
}

#[cfg(test)]
mod pruebas {
    use super::versiones_permitidas;

    #[test]
    fn listas_de_protocolos() {
        assert_eq!(versiones_permitidas(">=TLSv1.2"), ["TLSv1.2", "TLSv1.3"]);
        assert_eq!(
            versiones_permitidas("!SSLv2, !SSLv3"),
            ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
        );
        assert_eq!(
            versiones_permitidas("!SSLv2, !SSLv3, !TLSv1, !TLSv1.1"),
            ["TLSv1.2", "TLSv1.3"]
        );
        assert_eq!(versiones_permitidas("TLSv1.3"), ["TLSv1.3"]);
    }
}

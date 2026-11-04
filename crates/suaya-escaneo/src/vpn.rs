//! Escáneres de VPN: WireGuard, OpenVPN y strongSwan (IKEv2/IPsec).

use suaya_core::{Activo, Conocimiento, Detalles, Garantia, Riesgo};

use crate::Escaner;
use crate::comun::{
    Archivo, REL_RUTA_CERTIFICADO, activo_algoritmo, id_corto, linea_de, por_alias,
};
use crate::config_tls::evaluar_tls;

const CAPACIDAD: &str = "vpn-cifrado-red";

fn protocolo(
    a: &Archivo,
    tipo: &str,
    nombre: String,
    versiones: Vec<String>,
    grupos: Vec<String>,
    cifrados: Vec<String>,
) -> Activo {
    Activo::nuevo(
        format!("protocolo:{tipo}:{}", id_corto(&a.ruta_estable)),
        nombre,
        Detalles::Protocolo {
            tipo_protocolo: tipo.into(),
            versiones,
            grupos,
            cifrados,
        },
    )
    .con_contexto(CAPACIDAD, Garantia::Confidencialidad)
    .con_ubicacion(a.ruta, None)
}

/// El riesgo más grave entre los indicados.
fn peor(riesgos: impl IntoIterator<Item = Riesgo>) -> Option<Riesgo> {
    riesgos.into_iter().min_by_key(|r| r.gravedad())
}

// ---------------------------------------------------------------------------
// WireGuard
// ---------------------------------------------------------------------------

pub struct EscanerWireGuard;

impl Escaner for EscanerWireGuard {
    fn nombre(&self) -> &'static str {
        "configuración de WireGuard"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.extension == "conf"
            && a.contiene(b"[Interface]")
            && (a.contiene(b"PrivateKey") || a.contiene(b"[Peer]"))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut pares = 0usize;
        let mut pares_con_psk = 0usize;
        let mut linea_privada = None;
        let mut seccion = String::new();
        let mut desplazamiento = 0usize;
        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let l = linea.trim();
            if l.starts_with('[') {
                seccion = l.to_lowercase();
                if seccion == "[peer]" {
                    pares += 1;
                }
                continue;
            }
            let clave = l.split('=').next().unwrap_or("").trim().to_lowercase();
            match (seccion.as_str(), clave.as_str()) {
                ("[interface]", "privatekey") => linea_privada = Some(numero),
                ("[peer]", "presharedkey") => pares_con_psk += 1,
                _ => {}
            }
        }

        // La suite de WireGuard es fija: Noise_IKpsk2 con X25519, ChaCha20-Poly1305 y BLAKE2s.
        let algoritmos = vec![
            activo_algoritmo(
                c.por_id("x25519"),
                "X25519",
                None,
                CAPACIDAD,
                Some(Garantia::Confidencialidad),
                a.ruta,
                None,
            )
            .con_contexto(CAPACIDAD, Garantia::Autenticacion),
            activo_algoritmo(
                c.por_id("chacha20-poly1305"),
                "ChaCha20-Poly1305",
                None,
                CAPACIDAD,
                Some(Garantia::Confidencialidad),
                a.ruta,
                None,
            ),
            activo_algoritmo(
                c.por_alias("wireguard", "blake2s"),
                "BLAKE2s",
                None,
                CAPACIDAD,
                Some(Garantia::Integridad),
                a.ruta,
                None,
            ),
        ];
        let mut p = protocolo(
            a,
            "other",
            format!("WireGuard ({})", a.nombre),
            vec!["Noise_IKpsk2".into()],
            vec!["x25519".into()],
            vec!["ChaCha20-Poly1305".into()],
        );
        p.riesgo_fijado = Some(if pares > 0 && pares_con_psk == pares {
            p.advertir(
                "Todos los pares usan PresharedKey, que añade una capa simétrica con resistencia poscuántica a la confidencialidad, siempre que esa llave se haya distribuido por un canal seguro distinto de la propia VPN.",
            );
            Riesgo::HibridoPq
        } else {
            if pares > 0 {
                p.advertir(format!(
                    "{} de {pares} pares no usan PresharedKey: su tráfico depende solo de X25519 y puede guardarse para descifrarse en el futuro.",
                    pares - pares_con_psk
                ));
            }
            Riesgo::VulnerableCuantico
        });
        p.advertir(
            "La autenticación de los pares sigue basada en X25519. Para un intercambio poscuántico completo, considere Rosenpass, que renueva la PresharedKey con ML-KEM y Classic McEliece.",
        );
        for alg in &algoritmos {
            p.relacionar("algorithm", &alg.referencia);
        }

        let mut activos = algoritmos;
        if let Some(linea) = linea_privada {
            let mut llave = Activo::nuevo(
                format!("llave:{}", id_corto(&format!("{}#{linea}", a.ruta_estable))),
                "Llave privada WireGuard (X25519)",
                Detalles::Material {
                    tipo_material: "private-key".into(),
                    tamano: Some(256),
                    formato: "WireGuard (base64)".into(),
                    protegido_por: None,
                    huella_sha256: None,
                    identidad_llave: None,
                },
            )
            .con_contexto(CAPACIDAD, Garantia::Autenticacion)
            .con_ubicacion(a.ruta, Some(linea));
            llave.relacionar("algorithm", &activos[0].referencia);
            if a.modo.is_some_and(|m| m & 0o077 != 0) {
                llave.advertir(format!(
                    "Llave privada de WireGuard legible por grupo u otros ({:o}). Restringir a 600.",
                    a.modo.unwrap_or(0) & 0o777
                ));
            }
            p.relacionar("privateKey", &llave.referencia);
            activos.push(llave);
        }
        activos.push(p);
        Ok(activos)
    }
}

// ---------------------------------------------------------------------------
// OpenVPN
// ---------------------------------------------------------------------------

pub struct EscanerOpenVpn;

impl Escaner for EscanerOpenVpn {
    fn nombre(&self) -> &'static str {
        "configuración de OpenVPN"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.extension == "ovpn"
            || (a.extension == "conf"
                && (a.ruta.contains("openvpn")
                    || a.contiene(b"\ndev tun")
                    || a.contiene(b"\ndev tap"))
                && !a.contiene(b"[Interface]"))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut cifrados: Vec<(String, u32)> = Vec::new();
        let mut autenticacion: Option<(String, u32)> = None;
        let mut minima: Option<String> = None;
        let mut maxima: Option<String> = None;
        let mut grupos: Option<(Vec<String>, u32)> = None;
        let mut dh: Option<String> = None;
        let mut tls_crypt = false;
        let mut rutas_cert = Vec::new();
        let mut desplazamiento = 0usize;

        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let l = linea.trim();
            if l.is_empty() || l.starts_with('#') || l.starts_with(';') || l.starts_with('<') {
                continue;
            }
            let mut partes = l.split_whitespace();
            let directiva = partes.next().unwrap_or("").to_lowercase();
            let arg = partes.next().unwrap_or("").to_string();
            match directiva.as_str() {
                "data-ciphers" | "ncp-ciphers" => {
                    cifrados = arg.split(':').map(|x| (x.to_lowercase(), numero)).collect();
                }
                "cipher" | "data-ciphers-fallback" => {
                    if !cifrados.iter().any(|(x, _)| *x == arg.to_lowercase()) {
                        cifrados.push((arg.to_lowercase(), numero));
                    }
                }
                "auth" => autenticacion = Some((arg.to_lowercase(), numero)),
                "tls-version-min" => minima = Some(arg),
                "tls-version-max" => maxima = Some(arg),
                "tls-groups" => {
                    grupos = Some((arg.split(':').map(str::to_lowercase).collect(), numero))
                }
                "ecdh-curve" => grupos = Some((vec![arg.to_lowercase()], numero)),
                "dh" => dh = Some(arg),
                "tls-crypt" | "tls-crypt-v2" => tls_crypt = true,
                "cert" | "ca" => rutas_cert.push(arg),
                _ => {}
            }
        }

        let mut p = protocolo(
            a,
            "tls",
            format!("OpenVPN ({})", a.nombre),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        let mut activos = Vec::new();

        // Canal de datos.
        if cifrados.is_empty() {
            p.advertir("No declara data-ciphers: OpenVPN 2.5 o posterior usa AES-256-GCM, AES-128-GCM y CHACHA20-POLY1305 por omisión.");
        }
        let mut riesgos_datos = Vec::new();
        for (cif, n) in &cifrados {
            let alg = por_alias(
                c,
                "openvpn-cifrado",
                cif,
                CAPACIDAD,
                Some(Garantia::Confidencialidad),
                a.ruta,
                Some(*n),
            );
            riesgos_datos.push(
                c.por_alias("openvpn-cifrado", cif)
                    .map(|d| d.riesgo)
                    .unwrap_or(Riesgo::Desconocido),
            );
            p.relacionar("algorithm", &alg.referencia);
            activos.push(alg);
        }
        if let Some((au, n)) = &autenticacion {
            let alg = por_alias(
                c,
                "openvpn-auth",
                au,
                CAPACIDAD,
                Some(Garantia::Integridad),
                a.ruta,
                Some(*n),
            );
            riesgos_datos.push(
                c.por_alias("openvpn-auth", au)
                    .map(|d| d.riesgo)
                    .unwrap_or(Riesgo::Desconocido),
            );
            p.relacionar("algorithm", &alg.referencia);
            activos.push(alg);
        }

        // Canal de control (TLS).
        const VERSIONES: [&str; 4] = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"];
        let posicion = |v: &str| match v {
            "1.0" => Some(0),
            "1.1" => Some(1),
            "1.2" => Some(2),
            "1.3" => Some(3),
            _ => None,
        };
        if minima.is_none() {
            p.advertir("tls-version-min no se declara: se asume TLS 1.2, el mínimo predeterminado de OpenVPN 2.6.");
        }
        let desde = minima.as_deref().and_then(posicion).unwrap_or(2);
        let hasta = maxima.as_deref().and_then(posicion).unwrap_or(3).max(desde);
        let versiones: Vec<String> = VERSIONES[desde..=hasta]
            .iter()
            .map(|s| s.to_string())
            .collect();

        let lista_grupos = grupos.as_ref().map(|(g, _)| g.clone());
        if let Some((gs, n)) = &grupos {
            for g in gs {
                let alg = por_alias(
                    c,
                    "tls-grupo",
                    g,
                    CAPACIDAD,
                    Some(Garantia::Confidencialidad),
                    a.ruta,
                    Some(*n),
                );
                p.relacionar("algorithm", &alg.referencia);
                activos.push(alg);
            }
        }
        // Los nombres de grupo de OpenVPN coinciden con los de OpenSSL.
        let grupos_tls: Option<Vec<String>> = lista_grupos.clone();
        evaluar_tls(
            &mut p,
            &versiones,
            grupos_tls.as_deref(),
            "No declara tls-groups: OpenVPN usa los grupos predeterminados de OpenSSL (con OpenSSL 3.5 o posterior incluyen X25519MLKEM768). Verificar la versión o sondear el servicio.",
            Riesgo::Desconocido,
            c,
        );
        if let Some(d) = &dh
            && d != "none"
        {
            p.advertir(format!(
                    "Usa parámetros Diffie-Hellman de campo finito ({d}) para TLS 1.2; con TLS 1.3 se usan los grupos de tls-groups."
                ));
        }
        if tls_crypt {
            p.advertir(
                "tls-crypt cifra el canal de control con una llave simétrica compartida: si esa llave no se expone, dificulta capturar el intercambio de llaves para descifrarlo en el futuro.",
            );
        }
        if let Some(r) = peor(
            riesgos_datos
                .iter()
                .copied()
                .filter(|r| matches!(r, Riesgo::RotoClasico | Riesgo::Obsoleto)),
        ) {
            p.advertir("El canal de datos acepta cifradores o MAC rotos u obsoletos.");
            p.riesgo_fijado = peor(p.riesgo_fijado.into_iter().chain([r]));
        }
        if let Detalles::Protocolo {
            versiones: v,
            grupos: g,
            cifrados: cf,
            ..
        } = &mut p.detalles
        {
            *v = versiones;
            *g = lista_grupos.unwrap_or_default();
            *cf = cifrados.iter().map(|(x, _)| x.to_uppercase()).collect();
        }
        for r in rutas_cert {
            if r != "[inline]" {
                p.relacionar(REL_RUTA_CERTIFICADO, &r);
            }
        }
        activos.push(p);
        Ok(activos)
    }
}

// ---------------------------------------------------------------------------
// strongSwan
// ---------------------------------------------------------------------------

pub struct EscanerStrongSwan;

/// Fichas que no son algoritmos en una propuesta de strongSwan.
fn ignorable(f: &str) -> bool {
    f.starts_with("prf") || matches!(f, "esn" | "noesn" | "default" | "")
}

impl Escaner for EscanerStrongSwan {
    fn nombre(&self) -> &'static str {
        "configuración de strongSwan"
    }

    fn aplica(&self, a: &Archivo) -> bool {
        a.nombre == "swanctl.conf"
            || a.nombre == "ipsec.conf"
            || (a.extension == "conf"
                && (a.ruta.contains("swanctl") || a.ruta.contains("strongswan")))
    }

    fn analizar(&self, a: &Archivo, c: &Conocimiento) -> Result<Vec<Activo>, String> {
        let texto = a.texto().ok_or("el archivo no es texto UTF-8")?;
        let mut propuestas_ike: Vec<(String, u32)> = Vec::new();
        let mut propuestas_esp: Vec<(String, u32)> = Vec::new();
        let mut ikev1 = false;
        let mut desplazamiento = 0usize;
        for linea in texto.split_inclusive('\n') {
            let numero = linea_de(a.contenido, desplazamiento);
            desplazamiento += linea.len();
            let l = linea.split('#').next().unwrap_or("").trim();
            let Some((clave, valor)) = l.split_once('=') else {
                continue;
            };
            let clave = clave.trim();
            if (clave == "keyexchange" && valor.trim() == "ikev1")
                || (clave == "version" && valor.trim() == "1")
            {
                ikev1 = true;
            }
            let destino = match clave {
                "proposals" | "ike" => &mut propuestas_ike,
                "esp_proposals" | "ah_proposals" | "esp" | "ah" => &mut propuestas_esp,
                _ => continue,
            };
            for propuesta in valor.split(',') {
                let propuesta = propuesta.trim().trim_end_matches('!').to_lowercase();
                if !propuesta.is_empty() {
                    destino.push((propuesta, numero));
                }
            }
        }
        if propuestas_ike.is_empty() && propuestas_esp.is_empty() {
            return Ok(Vec::new());
        }

        let mut activos = Vec::new();
        let mut p = protocolo(
            a,
            "ipsec",
            format!("strongSwan ({})", a.nombre),
            vec![if ikev1 {
                "IKEv1".into()
            } else {
                "IKEv2".into()
            }],
            Vec::new(),
            propuestas_esp.iter().map(|(x, _)| x.clone()).collect(),
        );

        // Riesgo del intercambio de llaves de cada propuesta IKE.
        let mut riesgos_ke: Vec<Riesgo> = Vec::new();
        let mut otros_rotos = Vec::new();
        let mut hay_hibrida = false;
        let mut hay_clasica = false;
        let mut grupos = Vec::new();
        for (lista, es_ike) in [(&propuestas_ike, true), (&propuestas_esp, false)] {
            for (propuesta, n) in lista {
                let mut ke_propuesta: Vec<Riesgo> = Vec::new();
                for ficha in propuesta.split('-') {
                    // RFC 9370: intercambios adicionales como «ke1_mlkem768».
                    let (adicional, nombre) = match ficha.split_once('_') {
                        Some((pre, resto)) if pre.starts_with("ke") => (true, resto),
                        _ => (false, ficha),
                    };
                    if ignorable(nombre) {
                        continue;
                    }
                    let def = c.por_alias("ipsec", nombre);
                    let garantia = def
                        .map(|d| d.garantia)
                        .unwrap_or(Garantia::Confidencialidad);
                    let alg = por_alias(
                        c,
                        "ipsec",
                        nombre,
                        CAPACIDAD,
                        Some(garantia),
                        a.ruta,
                        Some(*n),
                    );
                    p.relacionar("algorithm", &alg.referencia);
                    activos.push(alg);
                    let riesgo = def.map(|d| d.riesgo).unwrap_or(Riesgo::Desconocido);
                    let es_ke =
                        def.is_some_and(|d| matches!(d.primitiva.as_str(), "key-agree" | "kem"));
                    if es_ke {
                        ke_propuesta.push(riesgo);
                        if !grupos.contains(&nombre.to_string()) {
                            grupos.push(if adicional {
                                ficha.to_string()
                            } else {
                                nombre.to_string()
                            });
                        }
                    } else if matches!(riesgo, Riesgo::RotoClasico | Riesgo::Obsoleto) {
                        otros_rotos.push(riesgo);
                    }
                }
                if es_ike && !ke_propuesta.is_empty() {
                    let pq = ke_propuesta
                        .iter()
                        .any(|r| matches!(r, Riesgo::ResistenteCuantico | Riesgo::HibridoPq));
                    if pq {
                        hay_hibrida = true;
                    } else {
                        hay_clasica = true;
                    }
                    riesgos_ke.extend(
                        ke_propuesta
                            .iter()
                            .copied()
                            .filter(|r| matches!(r, Riesgo::RotoClasico | Riesgo::Obsoleto)),
                    );
                }
            }
        }
        let riesgo_ke = if propuestas_ike.is_empty() {
            p.advertir("No declara propuestas IKE: se usan las predeterminadas de strongSwan. Verifique si incluyen ML-KEM en su versión.");
            Riesgo::Desconocido
        } else if hay_hibrida {
            if hay_clasica {
                p.advertir("También acepta propuestas IKE sin ML-KEM: los pares antiguos negociarán sin protección poscuántica.");
            }
            Riesgo::HibridoPq
        } else {
            p.advertir("Ninguna propuesta IKE incluye ML-KEM. strongSwan 6 admite intercambios adicionales (RFC 9370), por ejemplo «aes256gcm16-sha384-x25519-ke1_mlkem768».");
            Riesgo::VulnerableCuantico
        };
        if !otros_rotos.is_empty() || !riesgos_ke.is_empty() {
            p.advertir("Las propuestas incluyen algoritmos rotos u obsoletos (3DES, MD5, SHA-1 o grupos DH menores a 2048 bits).");
        }
        if ikev1 {
            p.advertir("Usa IKEv1, retirado por RFC 9395; migre a IKEv2, que además admite intercambios adicionales con ML-KEM.");
            otros_rotos.push(Riesgo::Obsoleto);
        }
        p.riesgo_fijado = peor(riesgos_ke.into_iter().chain(otros_rotos).chain([riesgo_ke]));
        if let Detalles::Protocolo { grupos: g, .. } = &mut p.detalles {
            *g = grupos;
        }
        activos.push(p);
        Ok(activos)
    }
}

#[cfg(test)]
mod pruebas {
    use super::ignorable;

    #[test]
    fn fichas_ignorables() {
        assert!(ignorable("prfsha384"));
        assert!(ignorable("esn"));
        assert!(!ignorable("aes256gcm16"));
    }
}

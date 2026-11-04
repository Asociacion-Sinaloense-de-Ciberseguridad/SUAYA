//! Robustez de los analizadores de protocolo ante respuestas arbitrarias.

use suaya_red::http::{Servidor, interpretar_respuesta};
use suaya_red::registro::Referencia;
use suaya_red::{KexInit, Objetivo, leer_respuesta};

struct Azar(u64);

impl Azar {
    fn siguiente(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = (self.siguiente() % (max as u64 + 1)) as usize;
        (0..n).map(|_| self.siguiente() as u8).collect()
    }
}

#[test]
fn respuestas_arbitrarias() {
    let mut r = Azar(7);
    let prefijos: [&[u8]; 6] = [
        b"",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999\r\n\r\n",
        b"\x16\x03\x03\x00\x30\x02\x00\x00\x2c\x03\x03",
        b"\x15\x03\x03\x00\x02",
        b"\x14\x00\x00\x00",
    ];
    for i in 0..4000 {
        let mut b = prefijos[i % prefijos.len()].to_vec();
        b.extend(r.bytes(300));
        let _ = interpretar_respuesta(&b);
        let _ = leer_respuesta(&mut std::io::Cursor::new(b.clone()));
        let _ = KexInit::desde_carga(&b);
    }
}

#[test]
fn textos_arbitrarios() {
    let mut r = Azar(11);
    let piezas = [
        "docker://",
        "tls://",
        "smtp://",
        "[",
        "]",
        ":",
        "@sha256:",
        "/",
        "..",
        "%",
        "ñ",
        "localhost",
        "999999",
        "a",
        "1",
        "-",
        "_",
        "https://",
        "?",
        "#",
    ];
    for _ in 0..5000 {
        let n = (r.siguiente() % 8) as usize;
        let t: String = (0..n)
            .map(|_| piezas[(r.siguiente() % piezas.len() as u64) as usize])
            .collect();
        let _ = Objetivo::interpretar(&t);
        let _ = Referencia::interpretar(&t);
        let _ = Servidor::interpretar(&t);
    }
}

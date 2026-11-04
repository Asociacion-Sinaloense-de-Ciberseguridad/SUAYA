//! Robustez del núcleo: traducción, versiones y perfiles con entradas arbitrarias.

use suaya_core::idioma::{Idioma, con_idioma, traducir};
use suaya_core::{Perfil, comparar_versiones};

#[test]
fn entradas_arbitrarias() {
    let mut x: u64 = 99;
    let mut azar = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let piezas = [
        "La rama ",
        "{}",
        " de ",
        "1.2.3",
        "v",
        "go",
        "+",
        ".",
        "ñ",
        "«",
        "»",
        "Llave privada ",
        "(",
        ")",
        "[línea ",
        "]",
        " ",
        "\n",
        "x",
        "{",
    ];
    con_idioma(Idioma::En, || {
        for _ in 0..5000 {
            let n = (azar() % 10) as usize;
            let t: String = (0..n)
                .map(|_| piezas[(azar() % piezas.len() as u64) as usize])
                .collect();
            let _ = traducir(&t);
            let _ = comparar_versiones(&t, "3.5.0");
            let _ = Perfil::desde_texto(&t);
        }
    });
}

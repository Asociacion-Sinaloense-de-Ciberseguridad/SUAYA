use serde_json::json;
use suaya_cbom::{
    firma::{Llaves, firmar, verificar},
    leer, reporte_html, reporte_markdown,
};
use suaya_core::Conocimiento;
#[test]
fn signature_binds_timestamp_and_rejects_legacy_prefix() {
    let keys = Llaves::generar().unwrap();
    let doc = b"fixture";
    let mut signature = firmar(doc, &keys, "2026-10-19T00:00:00Z").unwrap();
    verificar(doc, &signature, &keys.publica()).unwrap();
    signature["fecha"] = json!("2026-10-20T00:00:00Z");
    assert!(verificar(doc, &signature, &keys.publica()).is_err());
    assert!(verificar(doc, &json!("sig_inventada"), &keys.publica()).is_err());
}
#[test]
fn rejects_hostile_kdf_parameters_before_work() {
    let keys = Llaves::generar().unwrap();
    let original = keys.a_json(Some("test-passphrase")).unwrap();
    for n in [0u64, 99_999, 1_000_001, u32::MAX as u64, u64::MAX] {
        let mut key = original.clone();
        key["cifrado"]["iteraciones"] = json!(n);
        assert!(Llaves::desde_json(&key, Some("test-passphrase")).is_err());
    }
}
#[test]
fn hostile_strings_are_text_and_critical_is_counted() {
    let payload =
        "</title><script>document.title='SUAYA_TEST'</script><img src=x onerror=alert(1)>";
    let cbom = json!({"bomFormat":"CycloneDX","metadata":{"component":{"name":payload}},"components":[{
        "type":"cryptographic-asset","bom-ref":"test","name":payload,
        "properties":[{"name":"suaya:prioridad","value":"1"},{"name":"suaya:riesgo","value":"roto-clasico"},{"name":"suaya:justificacion","value":payload}]
    }]});
    let parsed = leer(&cbom.to_string()).unwrap();
    let c = Conocimiento::embebido();
    let html = reporte_html(&parsed, &c);
    assert!(!html.contains("<script>"));
    assert!(!html.contains("<img src=x"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(html.contains("Content-Security-Policy"));
    assert_eq!(suaya_cbom::reporte::Modelo::desde(&parsed, &c).criticos, 1);
    let md = reporte_markdown(&parsed, &c);
    assert!(!md.contains("<script>"));
}

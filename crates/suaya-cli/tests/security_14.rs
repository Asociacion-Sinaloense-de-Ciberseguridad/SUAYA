use std::process::Command;
#[test]
fn incomplete_scan_is_machine_readable_and_can_fail_gate() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input");
    std::fs::create_dir(&input).unwrap();
    let big = std::fs::File::create(input.join("large.txt")).unwrap();
    big.set_len(6 * 1024 * 1024).unwrap();
    let output = dir.path().join("cbom.json");
    let status = Command::new(env!("CARGO_BIN_EXE_suaya"))
        .args(["escanear", "--fallar-si-incompleto", "-o"])
        .arg(&output)
        .arg(input)
        .output()
        .unwrap();
    assert_eq!(status.status.code(), Some(4));
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&output).unwrap()).unwrap();
    assert!(
        v["metadata"]["properties"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["name"] == "suaya:estado" && p["value"] == "partial")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(output).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

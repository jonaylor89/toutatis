use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("toutatis").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Instagram information gathering tool"))
        .stdout(predicate::str::contains("--sessionid"))
        .stdout(predicate::str::contains("--username"))
        .stdout(predicate::str::contains("--id"));
}

#[test]
fn test_cli_missing_sessionid() {
    let mut cmd = Command::cargo_bin("toutatis").unwrap();
    cmd.arg("-u").arg("testuser");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required"));
}

#[test]
fn test_cli_missing_target() {
    let mut cmd = Command::cargo_bin("toutatis").unwrap();
    cmd.arg("-s").arg("test_session");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Either username or ID must be provided"));
}

#[test]
fn test_cli_conflicting_args() {
    let mut cmd = Command::cargo_bin("toutatis").unwrap();
    cmd.arg("-s").arg("test_session")
        .arg("-u").arg("user")
        .arg("-i").arg("123");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used"));
}

#[test]
fn test_cli_invalid_id() {
    let mut cmd = Command::cargo_bin("toutatis").unwrap();
    cmd.arg("-s").arg("test_session")
        .arg("-i").arg("not_a_number");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Invalid ID format"));
}
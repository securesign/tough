// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;

use crate::test_utils::days;
use assert_cmd::Command;
use chrono::Utc;
use serial_test::serial;
use std::path::PathBuf;
use std::{fs, io::Write, path::Path};
use test_utils::dir_url;
use tough::{RepositoryLoader, TargetName};

struct TestRepoCleanup {
    path: PathBuf,
}

impl TestRepoCleanup {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for TestRepoCleanup {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir_all(&self.path) {
            eprintln!(
                "Failed to clean up test directory {}: {}",
                self.path.display(),
                e
            );
        }
    }
}

fn create_repo<P: AsRef<Path>>(repo_dir: P) {
    let timestamp_expiration = Utc::now().checked_add_signed(days(1)).unwrap();
    let timestamp_version: u64 = 1;
    let snapshot_expiration = Utc::now().checked_add_signed(days(2)).unwrap();
    let snapshot_version: u64 = 1;
    let targets_expiration = Utc::now().checked_add_signed(days(3)).unwrap();
    let targets_version: u64 = 1;
    let targets_input_dir = test_utils::test_data()
        .join("tuf-reference-impl")
        .join("targets");
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");

    // Create a repository
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "create",
            "-t",
            targets_input_dir.to_str().unwrap(),
            "-o",
            repo_dir.as_ref().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--targets-expires",
            targets_expiration.to_rfc3339().as_str(),
            "--targets-version",
            format!("{}", targets_version).as_str(),
            "--snapshot-expires",
            snapshot_expiration.to_rfc3339().as_str(),
            "--snapshot-version",
            format!("{}", snapshot_version).as_str(),
            "--timestamp-expires",
            timestamp_expiration.to_rfc3339().as_str(),
            "--timestamp-version",
            format!("{}", timestamp_version).as_str(),
        ])
        .assert()
        .success();
}

#[tokio::test]
#[serial]
async fn rhtas_command_add_new_target() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = test_utils::test_data().join("rhtas_tmp");

    // Ensure the test directory gets cleaned up even if the test fails.
    let _cleanup = TestRepoCleanup::new(repo_dir.clone());

    // Create a repository
    create_repo(repo_dir.clone());

    let new_targets_expiration = Utc::now().checked_add_signed(days(6)).unwrap();
    let new_targets_input_dir = test_utils::test_data()
        .join("rhtas-targets")
        .join("ctfe.pub");
    let metadata_base_url = &dir_url(&repo_dir);

    // Add new target
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-ctlog-target",
            new_targets_input_dir.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--targets-expires",
            new_targets_expiration.to_rfc3339().as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo.
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json.clone()).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the targets (new and existing) are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 6);

    // Ensure we can read the newly added targets
    let ctfe = TargetName::new("ctfe.pub").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&ctfe).await.unwrap().unwrap()).await,
        &b"-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3Pyu\n\
        dDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==\n\
        -----END PUBLIC KEY-----"[..]
    );
    // Ensure trusted_root.json was created as a target and non-empty
    let trusted_root = TargetName::new("trusted_root.json").unwrap();
    let target_content =
        test_utils::read_to_end(repo.read_target(&trusted_root).await.unwrap().unwrap()).await;
    assert!(!target_content.is_empty(), "trusted_root is empty");

    // Test: Allow changing expiration on only subset of metadata files
    assert_eq!(repo.targets().signed.expires, new_targets_expiration);

    // Test: Automatically calculate new versions of metadata files
    assert_eq!(repo.targets().signed.version.get(), 2);
    assert_eq!(repo.snapshot().signed.version.get(), 2);
    assert_eq!(repo.timestamp().signed.version.get(), 2);
}

#[tokio::test]
#[serial]
async fn rhtas_command_update_target() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = test_utils::test_data().join("rhtas_tmp");

    // Ensure the test directory gets cleaned up even if the test fails.
    let _cleanup = TestRepoCleanup::new(repo_dir.clone());

    create_repo(repo_dir.clone());

    let new_targets_input_dir = test_utils::test_data()
        .join("rhtas-targets")
        .join("ctfe.pub");
    let metadata_base_url = &dir_url(&repo_dir);

    // Add target
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-ctlog-target",
            new_targets_input_dir.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo.
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json.clone()).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the targets (new and existing) are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 6);

    // // Ensure we can read the newly added targets
    let ctfe = TargetName::new("ctfe.pub").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&ctfe).await.unwrap().unwrap()).await,
        &b"-----BEGIN PUBLIC KEY-----\n\
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3Pyu\n\
        dDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==\n\
        -----END PUBLIC KEY-----"[..]
    );

    // Update the target
    let target_input = fs::File::create(new_targets_input_dir.clone());
    assert!(target_input.is_ok());
    let new_content = "-----BEGIN PUBLIC KEY-----\n\
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNK\n\
    AaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==\n\
    -----END PUBLIC KEY-----";
    assert!(target_input
        .as_ref()
        .unwrap()
        .write_all(new_content.as_bytes())
        .is_ok());

    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-ctlog-target",
            new_targets_input_dir.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo.
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json.clone()).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.join("targets")),
    )
    .load()
    .await
    .unwrap();

    let ctfe = TargetName::new("ctfe.pub").unwrap();
    assert_eq!(
        test_utils::read_to_end(repo.read_target(&ctfe).await.unwrap().unwrap()).await,
        &new_content.as_bytes().to_vec()[..]
    );

    // Ensure targets count is unchanged
    assert_eq!(repo.targets().signed.targets.len(), 6);

    // Revert the target file content to its original state.
    let target_input = fs::File::create(new_targets_input_dir.clone());
    let new_target = "-----BEGIN PUBLIC KEY-----\n\
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3Pyu\n\
    dDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==\n\
    -----END PUBLIC KEY-----";
    assert!(target_input.is_ok());
    assert!(target_input
        .as_ref()
        .unwrap()
        .write_all(new_target.as_bytes())
        .is_ok());
}

#[tokio::test]
#[serial]
async fn rhtas_command_delete_target() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = test_utils::test_data().join("rhtas_tmp");

    // Ensure the test directory gets cleaned up even if the test fails.
    let _cleanup = TestRepoCleanup::new(repo_dir.clone());

    create_repo(repo_dir.clone());

    let new_targets_input_dir = test_utils::test_data()
        .join("rhtas-targets")
        .join("ctfe.pub");
    let metadata_base_url = &dir_url(&repo_dir);

    // Add target
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-ctlog-target",
            new_targets_input_dir.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo.
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json.clone()).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the targets (new and existing) are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 6);

    // Delete the target
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--delete-ctlog-target",
            "ctfe.pub",
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo.
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json.clone()).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure that one target has been removed
    assert_eq!(repo.targets().signed.targets.len(), 5);

    // Ensure that the target was removed from repository
    let ctfe = TargetName::new("ctfe.pub").unwrap();
    let target_content = repo.read_target(&ctfe).await.unwrap();
    assert!(
        target_content.is_none(),
        "Expected `None`, but target was found."
    );
}

#[tokio::test]
#[serial]
async fn rhtas_command_argument_validation() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = test_utils::test_data().join("rhtas_tmp");

    // Ensure the test directory gets cleaned up even if the test fails.
    let _cleanup = TestRepoCleanup::new(repo_dir.clone());

    create_repo(repo_dir.clone());

    // Set new expiration dates and version numbers for the update command
    let new_targets_input_dir = test_utils::test_data()
        .join("rhtas-targets")
        .join("ctfe.pub");
    let metadata_base_url = &dir_url(&repo_dir);

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-ctlog-target",
            new_targets_input_dir.to_str().unwrap(),
            "--fulcio-uri",
            "https://fulcio.sigstore.dev",
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .failure();

    // oidc-uri with ctlog-target should also fail (oidc is only valid with fulcio-target)
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-ctlog-target",
            new_targets_input_dir.to_str().unwrap(),
            "--oidc-uri",
            "https://oauth2.sigstore.dev/auth",
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .failure();
}

#[tokio::test]
#[serial]
async fn rhtas_command_force_metadata_version() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = test_utils::test_data().join("rhtas_tmp");

    // Ensure the test directory gets cleaned up even if the test fails.
    let _cleanup = TestRepoCleanup::new(repo_dir.clone());

    create_repo(repo_dir.clone());

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(days(4)).unwrap();
    let new_timestamp_version: u64 = 310;
    let new_snapshot_expiration = Utc::now().checked_add_signed(days(5)).unwrap();
    let new_snapshot_version: u64 = 250;
    let new_targets_expiration = Utc::now().checked_add_signed(days(6)).unwrap();
    let new_targets_version: u64 = 170;
    let new_targets_input_dir = test_utils::test_data()
        .join("rhtas-targets")
        .join("ctfe.pub");
    let metadata_base_url = &dir_url(&repo_dir);

    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-ctlog-target",
            new_targets_input_dir.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--targets-expires",
            new_targets_expiration.to_rfc3339().as_str(),
            "--targets-version",
            format!("{}", new_targets_version).as_str(),
            "--snapshot-expires",
            new_snapshot_expiration.to_rfc3339().as_str(),
            "--snapshot-version",
            format!("{}", new_snapshot_version).as_str(),
            "--timestamp-expires",
            new_timestamp_expiration.to_rfc3339().as_str(),
            "--timestamp-version",
            format!("{}", new_timestamp_version).as_str(),
            "--force-version",
        ])
        .assert()
        .success();

    // Load the updated repo.
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json.clone()).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the metadata has been updated
    assert_eq!(repo.targets().signed.expires, new_targets_expiration);
    assert_eq!(repo.targets().signed.version.get(), new_targets_version);
    assert_eq!(repo.snapshot().signed.expires, new_snapshot_expiration);
    assert_eq!(repo.snapshot().signed.version.get(), new_snapshot_version);
    assert_eq!(repo.timestamp().signed.expires, new_timestamp_expiration);
    assert_eq!(repo.timestamp().signed.version.get(), new_timestamp_version);
}

#[tokio::test]
#[serial]
async fn rhtas_command_fulcio_oidc_signing_config() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = test_utils::test_data().join("rhtas_tmp");

    let _cleanup = TestRepoCleanup::new(repo_dir.clone());

    create_repo(repo_dir.clone());

    let mut fulcio_cert = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fulcio_cert.pop();
    fulcio_cert.push("rhtas/test/fulcio-cert");
    let metadata_base_url = &dir_url(&repo_dir);

    // Add Fulcio target with OIDC URI - this should populate signing_config with oidcUrls
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "rhtas",
            "-o",
            repo_dir.to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--set-fulcio-target",
            fulcio_cert.to_str().unwrap(),
            "--fulcio-uri",
            "https://fulcio.test.example",
            "--oidc-uri",
            "https://oauth2.test.example/auth",
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .success();

    // Load the repo and verify signing_config contains oidcUrls
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json.clone()).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Find signing_config target (may be hashed or direct)
    let signing_config_name = repo
        .targets()
        .signed
        .targets
        .keys()
        .find(|k| k.raw().contains("signing_config"))
        .expect("signing_config target should exist");

    let signing_config_data = test_utils::read_to_end(
        repo.read_target(signing_config_name)
            .await
            .unwrap()
            .unwrap(),
    )
    .await;
    let signing_config: serde_json::Value =
        serde_json::from_slice(&signing_config_data).expect("signing_config should be valid JSON");

    let oidc_urls = signing_config
        .get("oidcUrls")
        .expect("signing_config should contain oidcUrls");
    let oidc_urls = oidc_urls.as_array().expect("oidcUrls should be an array");
    assert!(!oidc_urls.is_empty(), "oidcUrls should not be empty");
    let first_oidc = &oidc_urls[0];
    assert_eq!(
        first_oidc.get("url").and_then(|v| v.as_str()),
        Some("https://oauth2.test.example/auth"),
        "OIDC URL should match"
    );
}

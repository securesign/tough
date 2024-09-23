// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

mod test_utils;

use crate::test_utils::days;
use assert_cmd::assert::Assert;
use assert_cmd::Command;
use chrono::{DateTime, Utc};
use std::path::Path;
use tempfile::TempDir;
use test_utils::dir_url;
use tough::{RepositoryLoader, TargetName};

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

    // Create a repo using tuftool and the reference tuf implementation data
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
// Ensure a repo updates correctly when only updating `timestamp` and preserves all other data
async fn update_command_timestamp_only() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_json2 = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Load the created repo
    let create_repo = RepositoryLoader::new(
        &tokio::fs::read(root_json2).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Set new expiration dates and version numbers for the update command
    let new_timestamp_expiration = Utc::now().checked_add_signed(days(4)).unwrap();
    let metadata_base_url = &dir_url(&repo_dir);
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "-o",
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--timestamp-expires",
            new_timestamp_expiration.to_rfc3339().as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(&update_out),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the existing targets are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 3);

    // Ensure all the metadata has been updated
    assert_eq!(
        repo.targets().signed.expires,
        create_repo.targets().signed.expires
    );
    assert_eq!(repo.targets().signatures, create_repo.targets().signatures);
    assert_eq!(repo.targets().signed.version.get(), 1);
    assert_eq!(
        repo.snapshot().signed.expires,
        create_repo.snapshot().signed.expires
    );
    assert_eq!(
        repo.snapshot().signatures,
        create_repo.snapshot().signatures
    );
    assert_eq!(repo.snapshot().signed.version.get(), 1);
    assert_eq!(repo.timestamp().signed.expires, new_timestamp_expiration);
    assert_ne!(
        repo.timestamp().signatures,
        create_repo.timestamp().signatures
    );
    assert_eq!(repo.timestamp().signed.version.get(), 2);
}

#[tokio::test]
// Ensure a repo updates correctly when only updating `snapshot`, also resigns timestamp as it
// relies on snapshot, but preserves all other data
async fn update_command_snapshot_only() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_json2 = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Load the created repo
    let create_repo = RepositoryLoader::new(
        &tokio::fs::read(root_json2).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Set new expiration dates and version numbers for the update command
    let new_snapshot_expiration = Utc::now().checked_add_signed(days(4)).unwrap();
    let metadata_base_url = &dir_url(&repo_dir);
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "-o",
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--snapshot-expires",
            new_snapshot_expiration.to_rfc3339().as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(&update_out),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the existing targets are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 3);

    // Ensure all the metadata has been updated
    assert_eq!(
        repo.targets().signed.expires,
        create_repo.targets().signed.expires
    );
    assert_eq!(repo.targets().signatures, create_repo.targets().signatures);
    assert_eq!(repo.targets().signed.version.get(), 1);
    assert_eq!(repo.snapshot().signed.expires, new_snapshot_expiration);
    assert_ne!(
        repo.snapshot().signatures,
        create_repo.snapshot().signatures
    );
    assert_eq!(repo.snapshot().signed.version.get(), 2);
    assert_eq!(
        repo.timestamp().signed.expires,
        create_repo.timestamp().signed.expires
    );
    assert_ne!(
        repo.timestamp().signatures,
        create_repo.timestamp().signatures
    );
    assert_eq!(repo.timestamp().signed.version.get(), 2);
}

#[tokio::test]
// Ensure a repo updates correctly when only updating `target`, also resigns timestamp and snapshot as it
// relies on target, but preserves all other data
async fn update_command_target_only() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_json2 = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Load the created repo
    let create_repo = RepositoryLoader::new(
        &tokio::fs::read(root_json2).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Set new expiration dates and version numbers for the update command
    let new_target_expiration = Utc::now().checked_add_signed(days(4)).unwrap();
    let metadata_base_url = &dir_url(&repo_dir);
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "-o",
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--targets-expires",
            new_target_expiration.to_rfc3339().as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(&update_out),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the existing targets are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 3);

    // Ensure all the metadata has been updated
    assert_eq!(repo.targets().signed.expires, new_target_expiration);
    assert_ne!(repo.targets().signatures, create_repo.targets().signatures);
    assert_eq!(repo.targets().signed.version.get(), 2);
    assert_eq!(
        repo.snapshot().signed.expires,
        create_repo.snapshot().signed.expires
    );
    assert_ne!(
        repo.snapshot().signatures,
        create_repo.snapshot().signatures
    );
    assert_eq!(repo.snapshot().signed.version.get(), 2);
    assert_eq!(
        repo.timestamp().signed.expires,
        create_repo.timestamp().signed.expires
    );
    assert_ne!(
        repo.timestamp().signatures,
        create_repo.timestamp().signatures
    );
    assert_eq!(repo.timestamp().signed.version.get(), 2);
}

#[tokio::test]
// Makes sure all data is preserved if the user is merely updating the root, and does not resign
// everything needlessly
async fn update_command_without_metadata_flags() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_json2 = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Load the created repo
    let create_repo = RepositoryLoader::new(
        &tokio::fs::read(root_json2).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url = &dir_url(&repo_dir);
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "-o",
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
        ])
        .assert()
        .success();

    // Load the updated repo
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(&update_out),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the existing targets are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 3);

    // Ensure all the metadata has been updated
    assert_eq!(
        repo.targets().signed.expires,
        create_repo.targets().signed.expires
    );
    assert_eq!(repo.targets().signatures, create_repo.targets().signatures);
    assert_eq!(repo.targets().signed.version.get(), 1);
    assert_eq!(
        repo.snapshot().signed.expires,
        create_repo.snapshot().signed.expires
    );
    assert_eq!(
        repo.snapshot().signatures,
        create_repo.snapshot().signatures
    );
    assert_eq!(repo.snapshot().signed.version.get(), 1);
    assert_eq!(
        repo.timestamp().signed.expires,
        create_repo.timestamp().signed.expires
    );
    assert_eq!(
        repo.timestamp().signatures,
        create_repo.timestamp().signatures
    );
    assert_eq!(repo.timestamp().signed.version.get(), 1);
}

#[tokio::test]
// Makes use of the --force-version flag to forcefully change version of timestamp metadata while
// preserving all other
async fn update_command_force_flag() {
    let root_json = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_json2 = test_utils::test_data().join("simple-rsa").join("root.json");
    let root_key = test_utils::test_data().join("snakeoil.pem");
    let repo_dir = TempDir::new().unwrap();

    // Create a repo using tuftool and the reference tuf implementation data
    create_repo(repo_dir.path());

    // Load the created repo
    let create_repo = RepositoryLoader::new(
        &tokio::fs::read(root_json2).await.unwrap(),
        dir_url(&repo_dir),
        dir_url(repo_dir.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    let metadata_base_url = &dir_url(&repo_dir);
    let update_out = TempDir::new().unwrap();

    // Update the repo we just created
    Command::cargo_bin("tuftool")
        .unwrap()
        .args([
            "update",
            "-o",
            update_out.path().to_str().unwrap(),
            "-k",
            root_key.to_str().unwrap(),
            "--root",
            root_json.to_str().unwrap(),
            "--metadata-url",
            metadata_base_url.as_str(),
            "--force-version",
            "--timestamp-version",
            "5",
        ])
        .assert()
        .success();

    // Load the updated repo
    let repo = RepositoryLoader::new(
        &tokio::fs::read(root_json).await.unwrap(),
        dir_url(&update_out),
        dir_url(update_out.path().join("targets")),
    )
    .load()
    .await
    .unwrap();

    // Ensure all the existing targets are accounted for
    assert_eq!(repo.targets().signed.targets.len(), 3);

    // Ensure all the metadata has been updated
    assert_eq!(
        repo.targets().signed.expires,
        create_repo.targets().signed.expires
    );
    assert_eq!(repo.targets().signatures, create_repo.targets().signatures);
    assert_eq!(repo.targets().signed.version.get(), 1);
    assert_eq!(
        repo.snapshot().signed.expires,
        create_repo.snapshot().signed.expires
    );
    assert_eq!(
        repo.snapshot().signatures,
        create_repo.snapshot().signatures
    );
    assert_eq!(repo.snapshot().signed.version.get(), 1);
    assert_eq!(
        repo.timestamp().signed.expires,
        create_repo.timestamp().signed.expires
    );
    assert_ne!(
        repo.timestamp().signatures,
        create_repo.timestamp().signatures
    );
    assert_eq!(repo.timestamp().signed.version.get(), 5);
}

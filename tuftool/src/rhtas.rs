// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::common::UNUSED_URL;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use crate::TargetName;
use chrono::{DateTime, Utc};
use clap::Parser;
use prost_types::Timestamp;
use serde_json::from_reader;
use serde_json::json;
use sha2::{Digest, Sha256};
use sigstore::trust::sigstore::{SigstoreTrustRoot, Target, TargetType};
use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::{
        DistinguishedName, LogId, PublicKey, TimeRange, X509Certificate, X509CertificateChain,
    },
    trustroot::v1::{CertificateAuthority, TransparencyLogInstance, TrustedRoot},
};
use snafu::{OptionExt, ResultExt};
use std::fs::{self, File};
use std::io::{self, Read};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tough::editor::signed::{PathExists, SignedRepository};
use tough::editor::RepositoryEditor;
use tough::{ExpirationEnforcement, RepositoryLoader};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct RhtasArgs {
    /// Allow repo download for expired metadata
    #[arg(long)]
    allow_expired_repo: bool,

    /// Follow symbolic links in the given directory when adding targets
    #[arg(short, long)]
    follow: bool,

    /// Incoming metadata from delegatee
    #[arg(short, long = "incoming-metadata")]
    indir: Option<Url>,

    /// Key files to sign with
    #[arg(short, long = "key", required = true)]
    keys: Vec<String>,

    /// TUF repository metadata base URL
    #[arg(short, long = "metadata-url")]
    metadata_base_url: Url,

    /// The directory where the updated repository will be written
    #[arg(short, long)]
    outdir: PathBuf,

    /// Path to root.json file for the repository
    #[arg(short, long)]
    root: PathBuf,

    /// Role of incoming metadata
    #[arg(long)]
    role: Option<String>,

    /// Expiration of snapshot.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long, value_parser = parse_datetime)]
    snapshot_expires: Option<DateTime<Utc>>,

    /// Behavior when a target exists with the same name and hash in the targets directory,
    /// for example from another repository when they share a targets directory.
    /// Options are "replace", "fail", and "skip"
    #[arg(long, default_value = "skip")]
    target_path_exists: PathExists,

    #[arg(long = "delete-fulcio-target")]
    delete_fulcio_targets: Vec<TargetName>,

    #[arg(long = "delete-ctlog-target")]
    delete_ctlog_targets: Vec<TargetName>,

    #[arg(long = "delete-rekor-target")]
    delete_rekor_targets: Vec<TargetName>,

    #[arg(long = "delete-tsa-target")]
    delete_tsa_targets: Vec<TargetName>,

    /// Path to the new Fulcio target file to add to the targets
    #[arg(long = "set-fulcio-target")]
    fulcio_target: Option<PathBuf>,

    /// Status for the Fulcio target
    #[arg(long)]
    fulcio_status: Option<String>,

    /// URI for the Fulcio target.
    /// Example: <https://fulcio.sigstore.dev>
    #[arg(long)]
    fulcio_uri: Option<String>,

    /// Path to the new Ctlog target file
    #[arg(long = "set-ctlog-target")]
    ctlog_target: Option<PathBuf>,

    /// Status for the Ctlog certificate
    #[arg(long)]
    ctlog_status: Option<String>,

    /// URI for the Ctlog certificate.
    /// Example: <https://ctfe.sigstore.dev/test>
    #[arg(long)]
    ctlog_uri: Option<String>,

    /// Path to the new rekor target file
    #[arg(long = "set-rekor-target")]
    rekor_target: Option<PathBuf>,

    /// Status for the rekor certificate
    #[arg(long)]
    rekor_status: Option<String>,

    /// URI for the rekor certificate.
    /// Example: <https://rekor.sigstore.dev>
    #[arg(long)]
    rekor_uri: Option<String>,

    /// Path to the new Timestamp Authority target file
    #[arg(long = "set-tsa-target")]
    tsa_target: Option<PathBuf>,

    /// Status for the tsa certificate
    #[arg(long)]
    tsa_status: Option<String>,

    /// URI for the tsa certificate
    #[arg(long)]
    tsa_uri: Option<String>,

    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long, value_parser = parse_datetime)]
    targets_expires: Option<DateTime<Utc>>,

    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long, value_parser = parse_datetime)]
    timestamp_expires: Option<DateTime<Utc>>,

    /// Forcibly update metadata version, usage not recommended
    #[arg(long)]
    force_version: bool,

    /// Version of snapshot.json
    #[arg(long)]
    snapshot_version: Option<NonZeroU64>,

    /// Version of targets.json
    #[arg(long)]
    targets_version: Option<NonZeroU64>,

    /// Version of timestamp.json
    #[arg(long)]
    timestamp_version: Option<NonZeroU64>,
}

fn expired_repo_warning<P: AsRef<Path>>(path: P) {
    #[rustfmt::skip]
    eprintln!("\
=================================================================
Updating repo at {}
WARNING: `--allow-expired-repo` was passed; this is unsafe and will not establish trust, use only for testing!
=================================================================",
              path.as_ref().display());
}

impl RhtasArgs {
    pub(crate) async fn run(&mut self) -> Result<()> {
        self.validate_and_set_defaults()?;
        let expiration_enforcement = if self.allow_expired_repo {
            expired_repo_warning(&self.outdir);
            ExpirationEnforcement::Unsafe
        } else {
            ExpirationEnforcement::Safe
        };
        let repository = RepositoryLoader::new(
            &tokio::fs::read(&self.root)
                .await
                .context(error::OpenRootSnafu { path: &self.root })?,
            self.metadata_base_url.clone(),
            Url::parse(UNUSED_URL).context(error::UrlParseSnafu { url: UNUSED_URL })?,
        )
        .expiration_enforcement(expiration_enforcement)
        .load()
        .await
        .context(error::RepoLoadSnafu)?;
        self.update_metadata(
            RepositoryEditor::from_repo(&self.root, repository)
                .await
                .context(error::EditorFromRepoSnafu { path: &self.root })?,
        )
        .await
    }

    #[allow(clippy::too_many_lines)]
    async fn update_metadata(&self, mut editor: RepositoryEditor) -> Result<()> {
        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        self.update_repository_metadata(&mut editor)?;

        let trusted_root_path = self.outdir.join("targets").join("trusted_root.json");
        // Create temporary targets/trusted_root.json
        // check if a <sha256>.trusted_root.json was already created
        let latest_trusted_root = self.get_latest_trusted_root();
        if trusted_root_path != latest_trusted_root {
            fs::copy(latest_trusted_root.clone(), &trusted_root_path).context(
                error::FileCopySnafu {
                    src: latest_trusted_root,
                    destination: trusted_root_path.clone(),
                },
            )?;
        }

        let mut sigstore_trust_root = RhtasArgs::load_trusted_root(&trusted_root_path)?;

        // If the "remove-<target>-target" argument was passed, remove the targets from the repository.
        self.delete_targets(&mut editor, &mut sigstore_trust_root)
            .await?;

        self.set_all_targets(&mut editor, &mut sigstore_trust_root)
            .await?;

        // If a `Targets` metadata needs to be updated
        if self.role.is_some() && self.indir.is_some() {
            editor
                .sign_targets_editor(&keys)
                .await
                .context(error::DelegationStructureSnafu)?
                .update_delegated_targets(
                    self.role.as_ref().context(error::MissingSnafu {
                        what: "delegated role",
                    })?,
                    self.indir
                        .as_ref()
                        .context(error::MissingSnafu {
                            what: "delegated role metadata url",
                        })?
                        .as_str(),
                )
                .await
                .context(error::DelegateeNotFoundSnafu {
                    role: self.role.as_ref().unwrap().clone(),
                })?;
        }

        let signed_repo = editor.sign(&keys).await.context(error::SignRepoSnafu)?;

        self.copy_target_files(&signed_repo).await?;

        signed_repo
            .write(&self.outdir)
            .await
            .context(error::WriteRepoSnafu {
                directory: &self.outdir,
            })?;

        // delete targets/trusted_root.json
        if trusted_root_path.exists() {
            fs::remove_file(&trusted_root_path).context(error::FileDeleteSnafu {
                file: trusted_root_path.clone(),
            })?;
        }

        Ok(())
    }

    async fn delete_targets(
        &self,
        editor: &mut RepositoryEditor,
        sigstore_trust_root: &mut SigstoreTrustRoot,
    ) -> Result<()> {
        for target_name in &self.delete_fulcio_targets {
            editor
                .remove_target(target_name)
                .context(error::RemoveTargetSnafu {
                    name: target_name.raw(),
                })?;
            self.remove_target_file(
                target_name.raw(),
                sigstore_trust_root,
                Target::CertificateAuthority,
            )
            .await?;
        }

        for target_name in &self.delete_ctlog_targets {
            editor
                .remove_target(target_name)
                .context(error::RemoveTargetSnafu {
                    name: target_name.raw(),
                })?;
            self.remove_target_file(target_name.raw(), sigstore_trust_root, Target::Ctlog)
                .await?;
        }

        for target_name in &self.delete_rekor_targets {
            editor
                .remove_target(target_name)
                .context(error::RemoveTargetSnafu {
                    name: target_name.raw(),
                })?;
            self.remove_target_file(target_name.raw(), sigstore_trust_root, Target::Tlog)
                .await?;
        }

        for target_name in &self.delete_tsa_targets {
            editor
                .remove_target(target_name)
                .context(error::RemoveTargetSnafu {
                    name: target_name.raw(),
                })?;
            self.remove_target_file(
                target_name.raw(),
                sigstore_trust_root,
                Target::TimestampAuthority,
            )
            .await?;
        }

        Ok(())
    }

    fn update_repository_metadata(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if self.force_version {
            self.update_metadata_version(editor);
        } else if self.snapshot_version.is_some()
            || self.targets_version.is_some()
            || self.timestamp_version.is_some()
        {
            return error::ForceVersionMissingSnafu {}.fail();
        }

        if let Some(_expires) = self.targets_expires {
            let _ = editor.targets_expires(self.targets_expires.unwrap());
        }

        if let Some(_expires) = self.snapshot_expires {
            let _ = editor.snapshot_expires(self.snapshot_expires.unwrap());
        }

        if let Some(_expires) = self.timestamp_expires {
            let _ = editor.timestamp_expires(self.timestamp_expires.unwrap());
        };
        Ok(())
    }

    fn load_trusted_root(trusted_root_path: &PathBuf) -> Result<SigstoreTrustRoot> {
        if Path::new(&trusted_root_path).exists() {
            let file = File::open(trusted_root_path).context(error::FileOpenSnafu {
                path: trusted_root_path.clone(),
            })?;
            let trusted_root: TrustedRoot =
                from_reader(file).context(error::FileParseJsonSnafu {
                    path: trusted_root_path.clone(),
                })?;
            Ok(SigstoreTrustRoot::from_trusted_root(trusted_root))
        } else {
            Ok(RhtasArgs::new_trusted_root())
        }
    }

    pub fn new_trusted_root() -> SigstoreTrustRoot {
        let trusted_root = TrustedRoot {
            media_type: "application/vnd.dev.sigstore.trustedroot+json;version=0.1".to_string(),
            tlogs: Vec::new(),
            certificate_authorities: Vec::new(),
            ctlogs: Vec::new(),
            timestamp_authorities: Vec::new(),
        };

        SigstoreTrustRoot::from_trusted_root(trusted_root)
    }

    async fn set_all_targets(
        &self,
        editor: &mut RepositoryEditor,
        sigstore_trust_root: &mut SigstoreTrustRoot,
    ) -> Result<()> {
        // If the "set-fulcio-target" argument was passed, build a target
        // and add it to the repository.
        self.set_fulcio_target(editor, sigstore_trust_root).await?;

        // If the "set-ctlog-target" argument was passed, build a target
        // and add it to the repository.
        self.set_ctlog_target(editor, sigstore_trust_root).await?;

        // If the "set-rekor-target" argument was passed, build a target
        // and add it to the repository.
        self.set_rekor_target(editor, sigstore_trust_root).await?;

        // If the "set-tsa-target" argument was passed, build a target
        // and add it to the repository.
        self.set_tsa_target(editor, sigstore_trust_root).await?;

        // Save then set trust_root
        let trusted_root_path = self.outdir.join("targets").join("trusted_root.json");
        match SigstoreTrustRoot::save_to_file(
            sigstore_trust_root,
            trusted_root_path.clone().as_path(),
        ) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("Error saving to file: {e}");
            }
        }
        self.set_trust_root_target(editor).await?;
        Ok(())
    }

    async fn copy_target_files(&self, signed_repo: &SignedRepository) -> Result<()> {
        let targets_outdir = &self.outdir.join("targets");

        // Handle trusted_root target
        let trusted_root_path = self.outdir.join("targets").join("trusted_root.json");
        if fs::metadata(&trusted_root_path).is_ok() {
            let resolved_trusted_root_path = if self.follow {
                tokio::fs::canonicalize(&trusted_root_path).await.context(
                    error::ResolveSymlinkSnafu {
                        path: &trusted_root_path,
                    },
                )?
            } else {
                trusted_root_path.clone()
            };
            let symlink_name = trusted_root_path.file_name().unwrap();
            let target_name = symlink_name.to_string_lossy().to_string();
            let target_name = TargetName::new(target_name);
            signed_repo
                .copy_target(
                    &resolved_trusted_root_path,
                    targets_outdir,
                    self.target_path_exists,
                    Some(&target_name.unwrap()),
                )
                .await
                .context(error::LinkTargetsSnafu {
                    indir: &trusted_root_path,
                    outdir: targets_outdir,
                })?;
        }

        // Handle the rest of the targets
        let mut target_path: Option<&PathBuf> = None;

        if let Some(ref fulcio_target_path) = self.fulcio_target {
            target_path = Some(fulcio_target_path);
        }
        if let Some(ref ctlog_target_path) = self.ctlog_target {
            target_path = Some(ctlog_target_path);
        }
        if let Some(ref rekor_target_path) = self.rekor_target {
            target_path = Some(rekor_target_path);
        }
        if let Some(ref tsa_target_path) = self.tsa_target {
            target_path = Some(tsa_target_path);
        }

        if let Some(path) = target_path {
            // let targets_outdir = &self.outdir.join("targets");
            let resolved_target_path = if self.follow {
                tokio::fs::canonicalize(path)
                    .await
                    .context(error::ResolveSymlinkSnafu { path })?
            } else {
                path.clone()
            };
            let symlink_name = path.file_name().unwrap();
            let target_name = symlink_name.to_string_lossy().to_string();
            let target_name = TargetName::new(target_name);
            signed_repo
                .copy_target(
                    &resolved_target_path,
                    targets_outdir,
                    self.target_path_exists,
                    Some(&target_name.unwrap()),
                )
                .await
                .context(error::LinkTargetsSnafu {
                    indir: path,
                    outdir: targets_outdir,
                })?;
        }
        Ok(())
    }

    async fn set_trust_root_target(&self, editor: &mut RepositoryEditor) -> Result<()> {
        let trusted_root_path = self.outdir.join("targets").join("trusted_root.json");
        // Check if the trusted_root.json exists
        if tokio::fs::metadata(&trusted_root_path).await.is_ok() {
            let mut trusted_root_target = build_targets(&trusted_root_path, self.follow).await?;
            // Add trusted_root as a target
            if let Some((target_name, target)) = trusted_root_target.iter_mut().next() {
                // Add the trusted root target
                editor
                    .add_target(target_name.clone(), target.clone())
                    .context(error::DelegationStructureSnafu)?;
            }
        }
        Ok(())
    }

    async fn set_fulcio_target(
        &self,
        editor: &mut RepositoryEditor,
        trusted_root: &mut SigstoreTrustRoot,
    ) -> Result<()> {
        if let Some(ref fulcio_target_path) = self.fulcio_target {
            let mut fulcio_target = build_targets(fulcio_target_path, self.follow).await?;

            if !matches!(self.fulcio_status.as_deref(), Some("Active" | "Expired")) {
                return error::NoValidTargetStatusSnafu {}.fail();
            }
            let custom_sigstore_metadata = json!({
                "status": self.fulcio_status,
                "uri": self.fulcio_uri,
                "usage": "Fulcio"
            });

            if let Some((target_name, target)) = fulcio_target.iter_mut().next() {
                target
                    .custom
                    .insert("sigstore".to_string(), custom_sigstore_metadata);
                editor
                    .add_target(target_name.clone(), target.clone())
                    .context(error::DelegationStructureSnafu)?;
            }

            // TrustedRoot
            let certificate_raw_bytes =
                RhtasArgs::load_target_bytes(fulcio_target_path).context(error::FileReadSnafu {
                    path: fulcio_target_path.clone(),
                })?;

            #[allow(clippy::cast_possible_wrap)]
            let current_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let timestamp: Option<Timestamp> = Some(Timestamp {
                seconds: current_timestamp,
                nanos: 0,
            });

            let mut start = timestamp.clone();
            let mut end: Option<Timestamp> = None;

            if self.fulcio_status.clone().unwrap() == "Expired" {
                end = timestamp;
                start = None;
            }
            let new_ca = CertificateAuthority {
                subject: Some(DistinguishedName {
                    organization: "sigstore.dev".to_string(),
                    common_name: "sigstore".to_string(),
                }),
                uri: self.fulcio_uri.clone().unwrap(),
                cert_chain: Some(X509CertificateChain {
                    certificates: vec![X509Certificate {
                        raw_bytes: certificate_raw_bytes,
                    }],
                }),
                valid_for: Some(TimeRange { start, end }),
            };

            match trusted_root
                .set_target(TargetType::Authority(new_ca), Target::CertificateAuthority)
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trusted_root");
                }
            }
        }
        Ok(())
    }

    async fn set_ctlog_target(
        &self,
        editor: &mut RepositoryEditor,
        trusted_root: &mut SigstoreTrustRoot,
    ) -> Result<()> {
        if let Some(ref ctlog_target_path) = self.ctlog_target {
            let mut ctlog_target = build_targets(ctlog_target_path, self.follow).await?;

            if !matches!(self.ctlog_status.as_deref(), Some("Active" | "Expired")) {
                return error::NoValidTargetStatusSnafu {}.fail();
            }
            let custom_sigstore_metadata = json!({
                "status": self.ctlog_status,
                "uri": self.ctlog_uri,
                "usage": "CTFE"
            });

            if let Some((target_name, target)) = ctlog_target.iter_mut().next() {
                target
                    .custom
                    .insert("sigstore".to_string(), custom_sigstore_metadata);
                editor
                    .add_target(target_name.clone(), target.clone())
                    .context(error::DelegationStructureSnafu)?;
            }

            // TrustedRoot
            let ctlog_raw_bytes =
                RhtasArgs::load_target_bytes(ctlog_target_path).context(error::FileReadSnafu {
                    path: ctlog_target_path.clone(),
                })?;

            let mut hasher = Sha256::new();
            hasher.update(&ctlog_raw_bytes);
            let hash_result = hasher.finalize();
            let key_id = hash_result.to_vec();

            #[allow(clippy::cast_possible_wrap)]
            let current_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let timestamp: Option<Timestamp> = Some(Timestamp {
                seconds: current_timestamp,
                nanos: 0,
            });

            let mut start = timestamp.clone();
            let mut end: Option<Timestamp> = None;

            if self.ctlog_status.clone().unwrap() == "Expired" {
                end = timestamp;
                start = None;
            }
            let new_ctlog = TransparencyLogInstance {
                base_url: self.ctlog_uri.clone().unwrap(),
                hash_algorithm: 1, // Sha2256 = 1 => HashAlgorithm::Sha2256 => "SHA2_256"
                public_key: Some(PublicKey {
                    raw_bytes: Some(ctlog_raw_bytes),
                    key_details: 5, // PkixEcdsaP256Sha256 = 5 => PKIX_ECDSA_P256_SHA_256
                    valid_for: Some(TimeRange { start, end }),
                }),
                log_id: Some(LogId { key_id }),
                checkpoint_key_id: None,
            };

            match trusted_root.set_target(TargetType::Log(new_ctlog), Target::Ctlog) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trusted_root");
                }
            }
        }
        Ok(())
    }

    async fn set_rekor_target(
        &self,
        editor: &mut RepositoryEditor,
        trusted_root: &mut SigstoreTrustRoot,
    ) -> Result<()> {
        if let Some(ref rekor_target_path) = self.rekor_target {
            let mut rekor_target = build_targets(rekor_target_path, self.follow).await?;

            if !matches!(self.rekor_status.as_deref(), Some("Active" | "Expired")) {
                return error::NoValidTargetStatusSnafu {}.fail();
            }
            let custom_sigstore_metadata = json!({
                "status": self.rekor_status,
                "uri": self.rekor_uri,
                "usage": "Rekor"
            });

            if let Some((target_name, target)) = rekor_target.iter_mut().next() {
                target
                    .custom
                    .insert("sigstore".to_string(), custom_sigstore_metadata);
                editor
                    .add_target(target_name.clone(), target.clone())
                    .context(error::DelegationStructureSnafu)?;
            }

            // TrustedRoot
            let rekor_raw_bytes =
                RhtasArgs::load_target_bytes(rekor_target_path).context(error::FileReadSnafu {
                    path: rekor_target_path.clone(),
                })?;

            let mut hasher = Sha256::new();
            hasher.update(&rekor_raw_bytes);
            let hash_result = hasher.finalize();
            let key_id = hash_result.to_vec();

            #[allow(clippy::cast_possible_wrap)]
            let current_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let timestamp: Option<Timestamp> = Some(Timestamp {
                seconds: current_timestamp,
                nanos: 0,
            });

            let mut start = timestamp.clone();
            let mut end: Option<Timestamp> = None;

            if self.rekor_status.clone().unwrap() == "Expired" {
                end = timestamp;
                start = None;
            }
            let new_tlog = TransparencyLogInstance {
                base_url: self.rekor_uri.clone().unwrap(),
                hash_algorithm: 1, // Sha2256 = 1 => HashAlgorithm::Sha2256 => "SHA2_256"
                public_key: Some(PublicKey {
                    raw_bytes: Some(rekor_raw_bytes),
                    key_details: 5, // PkixEcdsaP256Sha256 = 5 => PKIX_ECDSA_P256_SHA_256
                    valid_for: Some(TimeRange { start, end }),
                }),
                log_id: Some(LogId { key_id }),
                checkpoint_key_id: None,
            };

            match trusted_root.set_target(TargetType::Log(new_tlog), Target::Tlog) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trusted_root");
                }
            }
        }
        Ok(())
    }

    async fn set_tsa_target(
        &self,
        editor: &mut RepositoryEditor,
        trusted_root: &mut SigstoreTrustRoot,
    ) -> Result<()> {
        if let Some(ref tsa_target_path) = self.tsa_target {
            let mut tsa_target = build_targets(tsa_target_path, self.follow).await?;

            if !matches!(self.tsa_status.as_deref(), Some("Active" | "Expired")) {
                return error::NoValidTargetStatusSnafu {}.fail();
            }
            let custom_sigstore_metadata = json!({
                "status": self.tsa_status,
                "uri": self.tsa_uri,
                "usage": "TSA"
            });

            if let Some((target_name, target)) = tsa_target.iter_mut().next() {
                target
                    .custom
                    .insert("sigstore".to_string(), custom_sigstore_metadata);
                editor
                    .add_target(target_name.clone(), target.clone())
                    .context(error::DelegationStructureSnafu)?;
            }

            // TrustedRoot
            let certificate_raw_bytes =
                RhtasArgs::load_target_bytes(tsa_target_path).context(error::FileReadSnafu {
                    path: tsa_target_path.clone(),
                })?;

            #[allow(clippy::cast_possible_wrap)]
            let current_timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;

            let timestamp: Option<Timestamp> = Some(Timestamp {
                seconds: current_timestamp,
                nanos: 0,
            });

            let mut start = timestamp.clone();
            let mut end: Option<Timestamp> = None;

            if self.tsa_status.clone().unwrap() == "Expired" {
                end = timestamp;
                start = None;
            }
            let new_tsa = CertificateAuthority {
                subject: Some(DistinguishedName {
                    organization: "sigstore.dev".to_string(),
                    common_name: "sigstore".to_string(),
                }),
                uri: self.tsa_uri.clone().unwrap(),
                cert_chain: Some(X509CertificateChain {
                    certificates: vec![X509Certificate {
                        raw_bytes: certificate_raw_bytes,
                    }],
                }),
                valid_for: Some(TimeRange { start, end }),
            };

            match trusted_root
                .set_target(TargetType::Authority(new_tsa), Target::TimestampAuthority)
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trusted_root");
                }
            }
        }
        Ok(())
    }

    async fn remove_target_file(
        &self,
        target_name: &str,
        sigstore_trust_root: &mut SigstoreTrustRoot,
        target_type: Target,
    ) -> Result<()> {
        let targets_dir = self.outdir.join("targets");

        if !targets_dir.exists() {
            return error::TargetFileDoesNotExistSnafu {}.fail();
        }

        let mut dir_entries =
            tokio::fs::read_dir(&targets_dir)
                .await
                .context(error::ReadDirSnafu {
                    path: targets_dir.clone(),
                })?;

        let mut target_found = false;
        while let Some(entry) = dir_entries
            .next_entry()
            .await
            .context(error::DirEntrySnafu {
                path: targets_dir.clone(),
            })?
        {
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            if file_name_str.contains(target_name) {
                target_found = true;
                let file_path = entry.path();

                let identifier =
                    RhtasArgs::load_target_bytes(&file_path).context(error::FileReadSnafu {
                        path: file_path.clone(),
                    })?;

                // Remove target file
                tokio::fs::remove_file(&file_path)
                    .await
                    .context(error::RemoveTargetPathSnafu {
                        path: file_path.clone(),
                    })?;
                // Remove target from TrustedRoot
                match sigstore_trust_root.delete_target(&target_type, &identifier) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("Failed to delete target: {e:?} from trusted_root");
                    }
                }
            }
        }
        if !target_found {
            return error::TargetFileDoesNotExistSnafu {}.fail();
        }
        Ok(())
    }

    fn update_metadata_version(&self, editor: &mut RepositoryEditor) {
        if self.snapshot_version.is_some() {
            let _ = editor.snapshot_version(self.snapshot_version.unwrap());
        }
        if self.targets_version.is_some() {
            let _ = editor.targets_version(self.targets_version.unwrap());
        }
        if self.timestamp_version.is_some() {
            let _ = editor.timestamp_version(self.timestamp_version.unwrap());
        }
    }

    fn validate_and_set_defaults(&mut self) -> Result<()> {
        // Validate
        if self.fulcio_target.is_some()
            && (self.ctlog_uri.is_some()
                || self.rekor_uri.is_some()
                || self.tsa_uri.is_some()
                || self.ctlog_status.is_some()
                || self.rekor_status.is_some()
                || self.tsa_status.is_some())
        {
            return error::InvalidArgumentCombinationSnafu {
                msg: "--set-fulcio-target only accepts --fulcio-uri and --fulcio-status."
                    .to_string(),
            }
            .fail();
        }

        if self.ctlog_target.is_some()
            && (self.fulcio_uri.is_some()
                || self.rekor_uri.is_some()
                || self.tsa_uri.is_some()
                || self.fulcio_status.is_some()
                || self.rekor_status.is_some()
                || self.tsa_status.is_some())
        {
            return error::InvalidArgumentCombinationSnafu {
                msg: "--set-ctlog-target only accepts --ctlog-uri and --ctlog-status.".to_string(),
            }
            .fail();
        }

        if self.rekor_target.is_some()
            && (self.fulcio_uri.is_some()
                || self.ctlog_uri.is_some()
                || self.tsa_uri.is_some()
                || self.fulcio_status.is_some()
                || self.ctlog_status.is_some()
                || self.tsa_status.is_some())
        {
            return error::InvalidArgumentCombinationSnafu {
                msg: "--set-rekor-target only accepts --rekor-uri and --rekor-status.".to_string(),
            }
            .fail();
        }

        if self.tsa_target.is_some()
            && (self.fulcio_uri.is_some()
                || self.ctlog_uri.is_some()
                || self.rekor_uri.is_some()
                || self.fulcio_status.is_some()
                || self.ctlog_status.is_some()
                || self.rekor_status.is_some())
        {
            return error::InvalidArgumentCombinationSnafu {
                msg: "--set-tsa-target only accepts --tsa-uri and --tsa-status.".to_string(),
            }
            .fail();
        }
        // Set Default parameters
        if self.fulcio_target.is_some() {
            if self.fulcio_uri.is_none() {
                self.fulcio_uri = Some(String::from("https://fulcio.sigstore.dev"));
            }
            if self.fulcio_status.is_none() {
                self.fulcio_status = Some(String::from("Active"));
            }
        }
        if self.ctlog_target.is_some() {
            if self.ctlog_uri.is_none() {
                self.ctlog_uri = Some(String::from("https://ctfe.sigstore.dev/test"));
            }
            if self.ctlog_status.is_none() {
                self.ctlog_status = Some(String::from("Active"));
            }
        }

        if self.rekor_target.is_some() {
            if self.rekor_uri.is_none() {
                self.rekor_uri = Some(String::from("https://rekor.sigstore.dev"));
            }
            if self.rekor_status.is_none() {
                self.rekor_status = Some(String::from("Active"));
            }
        }

        if self.tsa_target.is_some() && self.tsa_status.is_none() {
            self.tsa_status = Some(String::from("Active"));
        }
        Ok(())
    }

    fn load_target_bytes(target_path: &std::path::Path) -> io::Result<Vec<u8>> {
        let mut file = File::open(target_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    fn get_latest_trusted_root(&self) -> PathBuf {
        let targets_dir = self.outdir.join("targets");
        let mut sha256_trusted_root_files: Vec<PathBuf> = Vec::new();
        if let Ok(entries) = fs::read_dir(&targets_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(extension) = path.extension() {
                    if extension == "json"
                        && path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .ends_with(".trusted_root.json")
                    {
                        sha256_trusted_root_files.push(path);
                    }
                }
            }
        }
        // get the latest file based on update time
        if !sha256_trusted_root_files.is_empty() {
            let latest_trusted_root = sha256_trusted_root_files.into_iter().max_by_key(|path| {
                fs::metadata(path)
                    .and_then(|metadata| metadata.modified())
                    .map(|time| time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO))
                    .unwrap_or(Duration::ZERO)
            });
            if let Some(latest_file) = latest_trusted_root {
                return latest_file;
            }
        }
        // return the default "trusted_root.json" path
        targets_dir.join("trusted_root.json")
    }
}

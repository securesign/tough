// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::common::UNUSED_URL;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
#[cfg(feature = "sigstore-trust-root")]
use crate::sigstore_trust::trust::sigstore::{SigstoreTrustBundle, Target, TargetType};
use crate::source::parse_key_source;
use crate::TargetName;
use chrono::{DateTime, Utc};
use clap::Parser;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sha::sha256;
use prost_types::Timestamp;
use serde_json::json;
use serde_json::Value;
use sigstore_protobuf_specs::dev::sigstore::{
    common::v1::{
        DistinguishedName, LogId, PublicKey, TimeRange, X509Certificate, X509CertificateChain,
    },
    trustroot::v1::{
        CertificateAuthority, ServiceConfiguration, SigningConfig, TransparencyLogInstance,
        TrustedRoot,
    },
};
use snafu::{OptionExt, ResultExt};
use std::fs::{self, File};
use std::io::BufReader;
use std::io::{self, Read};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
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

    /// URI for the OIDC provider (used with Fulcio).
    /// Example: <https://oauth2.sigstore.dev/auth>
    #[arg(long)]
    oidc_uri: Option<String>,

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

    /// Operator name for the signing config services
    #[arg(long, default_value = "sigstore.dev")]
    operator: String,

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

    /// Default checksum algorithm > sha256
    #[arg(long)]
    checksum_algo: Option<String>,
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

#[allow(deprecated)]
#[allow(clippy::clone_on_copy)]
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
        let trusted_root_path = self.outdir.join("targets").join("trusted_root.json");
        let signing_config_path = self.outdir.join("targets").join("signing_config.v0.2.json");

        let result = async {
            let mut keys = Vec::new();
            for source in &self.keys {
                let key_source = parse_key_source(source)?;
                keys.push(key_source);
            }

            self.update_repository_metadata(&mut editor)?;

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

            let latest_signing_config = self.get_latest_signing_config();
            if latest_signing_config != signing_config_path {
                fs::copy(latest_signing_config.clone(), &signing_config_path).context(
                    error::FileCopySnafu {
                        src: latest_signing_config,
                        destination: signing_config_path.clone(),
                    },
                )?;
            }

            let mut sigstore_trust_bundle =
                RhtasArgs::load_trust_bundle(&trusted_root_path, &signing_config_path)?;
            // If the "remove-<target>-target" argument was passed, remove the targets from the repository.
            self.delete_targets(&mut editor, &mut sigstore_trust_bundle)
                .await?;

            self.set_all_targets(&mut editor, &mut sigstore_trust_bundle)
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

            Ok::<(), error::Error>(())
        }
        .await;

        // delete targets/trusted_root.json & targets/signing_config.v0.2.json
        if trusted_root_path.exists() {
            fs::remove_file(&trusted_root_path).context(error::FileDeleteSnafu {
                file: trusted_root_path.clone(),
            })?;
        }

        if signing_config_path.exists() {
            fs::remove_file(&signing_config_path).context(error::FileDeleteSnafu {
                file: signing_config_path.clone(),
            })?;
        }

        result
    }

    async fn delete_targets(
        &self,
        editor: &mut RepositoryEditor,
        sigstore_trust_bundle: &mut SigstoreTrustBundle,
    ) -> Result<()> {
        for target_name in &self.delete_fulcio_targets {
            editor
                .remove_target(target_name)
                .context(error::RemoveTargetSnafu {
                    name: target_name.raw(),
                })?;
            self.remove_target_file(
                target_name.raw(),
                sigstore_trust_bundle,
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
            self.remove_target_file(target_name.raw(), sigstore_trust_bundle, Target::Ctlog)
                .await?;
        }

        for target_name in &self.delete_rekor_targets {
            editor
                .remove_target(target_name)
                .context(error::RemoveTargetSnafu {
                    name: target_name.raw(),
                })?;
            self.remove_target_file(target_name.raw(), sigstore_trust_bundle, Target::Tlog)
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
                sigstore_trust_bundle,
                Target::TimestampAuthority,
            )
            .await?;
        }

        Ok(())
    }

    fn update_repository_metadata(&self, editor: &mut RepositoryEditor) -> Result<()> {
        self.update_all_metadata(editor)?;

        if self.force_version {
            let _ = self.update_metadata_version(editor);
        } else if self.snapshot_version.is_some()
            || self.targets_version.is_some()
            || self.timestamp_version.is_some()
        {
            return error::ForceVersionMissingSnafu {}.fail();
        }
        Ok(())
    }

    fn load_trust_bundle(
        trusted_root_path: &PathBuf,
        signing_config_path: &PathBuf,
    ) -> Result<SigstoreTrustBundle> {
        if Path::new(trusted_root_path).exists() {
            let file = File::open(trusted_root_path).context(error::FileOpenSnafu {
                path: trusted_root_path.clone(),
            })?;
            let trusted_root: TrustedRoot = serde_json::from_reader(BufReader::new(file)).context(
                error::FileParseJsonSnafu {
                    path: trusted_root_path.clone(),
                },
            )?;

            let signing_config = if signing_config_path.exists() {
                let file = File::open(signing_config_path).context(error::FileOpenSnafu {
                    path: signing_config_path.clone(),
                })?;
                Some(serde_json::from_reader(BufReader::new(file)).context(
                    error::FileParseJsonSnafu {
                        path: signing_config_path,
                    },
                )?)
            } else {
                None
            };

            Ok(SigstoreTrustBundle::from_trust_bundle(
                trusted_root,
                signing_config,
            ))
        } else {
            Ok(RhtasArgs::new_trust_bundle())
        }
    }

    pub fn new_trust_bundle() -> SigstoreTrustBundle {
        let trusted_root = TrustedRoot {
            media_type: "application/vnd.dev.sigstore.trustedroot+json;version=0.1".to_string(),
            tlogs: Vec::new(),
            certificate_authorities: Vec::new(),
            ctlogs: Vec::new(),
            timestamp_authorities: Vec::new(),
        };

        let signing_config = SigningConfig {
            media_type: "application/vnd.dev.sigstore.signingconfig.v0.2+json".to_string(),
            ca_urls: Vec::new(),
            oidc_urls: Vec::new(),
            rekor_tlog_urls: Vec::new(),
            tsa_urls: Vec::new(),
            rekor_tlog_config: Some(ServiceConfiguration {
                selector: 2,
                count: 0,
            }),
            tsa_config: Some(ServiceConfiguration {
                selector: 2,
                count: 0,
            }),
        };

        SigstoreTrustBundle::from_trust_bundle(trusted_root, Some(signing_config))
    }

    async fn set_all_targets(
        &self,
        editor: &mut RepositoryEditor,
        sigstore_trust_bundle: &mut SigstoreTrustBundle,
    ) -> Result<()> {
        // If the "set-fulcio-target" argument was passed, build a target
        // and add it to the repository.
        self.set_fulcio_target(editor, sigstore_trust_bundle)
            .await?;

        // If the "set-ctlog-target" argument was passed, build a target
        // and add it to the repository.
        self.set_ctlog_target(editor, sigstore_trust_bundle).await?;

        // If the "set-rekor-target" argument was passed, build a target
        // and add it to the repository.
        self.set_rekor_target(editor, sigstore_trust_bundle).await?;

        // If the "set-tsa-target" argument was passed, build a target
        // and add it to the repository.
        self.set_tsa_target(editor, sigstore_trust_bundle).await?;

        // Save then set trust_root
        let trusted_root_path = self.outdir.join("targets").join("trusted_root.json");
        sigstore_trust_bundle
            .save_trusted_root_to_file(&trusted_root_path)
            .map_err(|e| error::Error::FileOpen {
                source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
                path: trusted_root_path.clone(),
                backtrace: snafu::Backtrace::new(),
            })?;

        let signing_config_path = self.outdir.join("targets").join("signing_config.v0.2.json");
        sigstore_trust_bundle
            .save_signing_config_to_file(&signing_config_path)
            .map_err(|e| error::Error::FileOpen {
                source: std::io::Error::new(std::io::ErrorKind::Other, e.to_string()),
                path: signing_config_path.clone(),
                backtrace: snafu::Backtrace::new(),
            })?;

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

        // Handle signing_config.v0.2.json
        let signing_config_path = self.outdir.join("targets").join("signing_config.v0.2.json");
        if fs::metadata(&signing_config_path).is_ok() {
            let resolved_signing_config_path = if self.follow {
                tokio::fs::canonicalize(&signing_config_path)
                    .await
                    .context(error::ResolveSymlinkSnafu {
                        path: &signing_config_path,
                    })?
            } else {
                signing_config_path.clone()
            };
            let target_name =
                TargetName::new("signing_config.v0.2.json").context(error::RemoveTargetSnafu {
                    name: "signing_config.v0.2.json".to_string(),
                })?;
            signed_repo
                .copy_target(
                    &resolved_signing_config_path,
                    targets_outdir,
                    self.target_path_exists,
                    Some(&target_name),
                )
                .await
                .context(error::LinkTargetsSnafu {
                    indir: &signing_config_path,
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
        if tokio::fs::metadata(&trusted_root_path).await.is_ok() {
            let mut trusted_root_target = build_targets(&trusted_root_path, self.follow).await?;
            if let Some((target_name, target)) = trusted_root_target.iter_mut().next() {
                editor
                    .add_target(target_name.clone(), target.clone())
                    .context(error::DelegationStructureSnafu)?;
            }
        }

        let signing_config_path = self.outdir.join("targets").join("signing_config.v0.2.json");
        if tokio::fs::metadata(&signing_config_path).await.is_ok() {
            let mut signing_config_target =
                build_targets(&signing_config_path, self.follow).await?;
            if let Some((target_name, target)) = signing_config_target.iter_mut().next() {
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
        trust_bundle: &mut SigstoreTrustBundle,
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
            let certificate_raw_bytes_vec = RhtasArgs::load_target_der_bytes(fulcio_target_path)
                .context(error::FileReadSnafu {
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

            let valid_for = Some(TimeRange {
                start: start.clone(),
                end: end.clone(),
            });

            let mut certificates: Vec<X509Certificate> = Vec::new();
            for item in certificate_raw_bytes_vec {
                certificates.push(X509Certificate { raw_bytes: item });
            }

            let new_ca = CertificateAuthority {
                subject: Some(DistinguishedName {
                    organization: self.operator.clone(),
                    common_name: self.operator.clone(),
                }),
                uri: self.fulcio_uri.clone().unwrap(),
                cert_chain: Some(X509CertificateChain { certificates }),
                valid_for: valid_for.clone(),
                operator: self.operator.clone(),
            };

            match trust_bundle
                .set_target(TargetType::Authority(new_ca), Target::CertificateAuthority)
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trust_bundle");
                }
            }

            if let Some(ref oidc_uri) = self.oidc_uri {
                if let Err(e) = trust_bundle.add_oidc_url_to_signing_config(
                    oidc_uri.clone(),
                    valid_for,
                    self.operator.clone(),
                ) {
                    eprintln!("Failed to add OIDC URL to signing_config: {e:?}");
                }
            }
        }
        Ok(())
    }

    async fn set_ctlog_target(
        &self,
        editor: &mut RepositoryEditor,
        trust_bundle: &mut SigstoreTrustBundle,
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
            let ctlog_raw_bytes_vec = RhtasArgs::load_target_der_bytes(ctlog_target_path).context(
                error::FileReadSnafu {
                    path: ctlog_target_path.clone(),
                },
            )?;

            let key_details = RhtasArgs::detect_public_key_details(
                ctlog_target_path,
                self.checksum_algo.as_deref(),
            );
            if key_details.is_err() {
                return error::InvalidPublicKeySnafu {}.fail();
            }

            let ctlog_raw_bytes = ctlog_raw_bytes_vec[0].clone();

            let key_id = sha256(&ctlog_raw_bytes).to_vec();

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
                    key_details: key_details.unwrap(),
                    valid_for: Some(TimeRange { start, end }),
                }),
                log_id: Some(LogId { key_id }),
                checkpoint_key_id: None,
                operator: self.operator.clone(),
            };

            match trust_bundle.set_target(TargetType::Log(new_ctlog), Target::Ctlog) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trust_bundle");
                }
            }
        }
        Ok(())
    }

    async fn set_rekor_target(
        &self,
        editor: &mut RepositoryEditor,
        trust_bundle: &mut SigstoreTrustBundle,
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
            let rekor_raw_bytes_vec = RhtasArgs::load_target_der_bytes(rekor_target_path).context(
                error::FileReadSnafu {
                    path: rekor_target_path.clone(),
                },
            )?;

            let key_details = RhtasArgs::detect_public_key_details(
                rekor_target_path,
                self.checksum_algo.as_deref(),
            );
            if key_details.is_err() {
                return error::InvalidPublicKeySnafu {}.fail();
            }

            let rekor_raw_bytes = rekor_raw_bytes_vec[0].clone();

            let key_id = sha256(&rekor_raw_bytes).to_vec();

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
                    key_details: key_details.unwrap(),
                    valid_for: Some(TimeRange { start, end }),
                }),
                log_id: Some(LogId { key_id }),
                checkpoint_key_id: None,
                operator: self.operator.clone(),
            };

            match trust_bundle.set_target(TargetType::Log(new_tlog), Target::Tlog) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trust_bundle");
                }
            }
        }
        Ok(())
    }

    async fn set_tsa_target(
        &self,
        editor: &mut RepositoryEditor,
        trust_bundle: &mut SigstoreTrustBundle,
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
            let certificate_raw_bytes_vec = RhtasArgs::load_target_der_bytes(tsa_target_path)
                .context(error::FileReadSnafu {
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

            let mut certificates: Vec<X509Certificate> = Vec::new();
            for item in certificate_raw_bytes_vec {
                certificates.push(X509Certificate { raw_bytes: item });
            }

            let new_tsa = CertificateAuthority {
                subject: Some(DistinguishedName {
                    organization: self.operator.clone(),
                    common_name: self.operator.clone(),
                }),
                uri: self.tsa_uri.clone().unwrap(),
                cert_chain: Some(X509CertificateChain { certificates }),
                valid_for: Some(TimeRange { start, end }),
                operator: self.operator.clone(),
            };

            match trust_bundle
                .set_target(TargetType::Authority(new_tsa), Target::TimestampAuthority)
            {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Failed to set target: {e:?} in trust_bundle");
                }
            }
        }
        Ok(())
    }

    async fn remove_target_file(
        &self,
        target_name: &str,
        sigstore_trust_bundle: &mut SigstoreTrustBundle,
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
                    RhtasArgs::load_target_der_bytes(&file_path).context(error::FileReadSnafu {
                        path: file_path.clone(),
                    })?;

                // Remove target file
                // Used by delete_signing_config_target
                let target_uri =
                    sigstore_trust_bundle.get_uri_for_target(&target_type, &identifier[0]);

                tokio::fs::remove_file(&file_path)
                    .await
                    .context(error::RemoveTargetPathSnafu {
                        path: file_path.clone(),
                    })?;
                // Remove target from TrustedRoot
                match sigstore_trust_bundle.delete_target(&target_type, &identifier[0]) {
                    Ok(()) => {}
                    Err(e) => {
                        eprintln!("Failed to delete target: {e:?} from trusted_root");
                    }
                }

                // Remove target config from SigningConfig
                if let Some(uri) = target_uri {
                    match sigstore_trust_bundle.delete_signing_config_target(&target_type, &uri) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("Failed to delete {uri} from signing_config: {e:?}");
                        }
                    }
                }
            }
        }
        if !target_found {
            return error::TargetFileDoesNotExistSnafu {}.fail();
        }
        Ok(())
    }

    fn update_metadata_version(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if self.snapshot_version.is_some() {
            editor.snapshot_version(self.snapshot_version.unwrap());
        }
        if self.targets_version.is_some() {
            editor
                .targets_version(self.targets_version.unwrap())
                .context(error::DelegationStructureSnafu)?;
        }
        if self.timestamp_version.is_some() {
            editor.timestamp_version(self.timestamp_version.unwrap());
        }
        Ok(())
    }

    fn update_all_metadata(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if self.fulcio_target.is_some()
            || self.ctlog_target.is_some()
            || self.rekor_target.is_some()
            || self.tsa_target.is_some()
            || !self.delete_fulcio_targets.is_empty()
            || !self.delete_tsa_targets.is_empty()
            || !self.delete_ctlog_targets.is_empty()
            || !self.delete_rekor_targets.is_empty()
        {
            if self.targets_expires.is_some() {
                editor
                    .targets_expires(self.targets_expires.unwrap())
                    .context(error::DelegationStructureSnafu)?;
            }
            editor
                .bump_targets_version()
                .context(error::DelegationStructureSnafu)?;

            if self.snapshot_expires.is_some() {
                editor.snapshot_expires(self.snapshot_expires.unwrap());
            }

            editor.bump_snapshot_version();

            if self.timestamp_expires.is_some() {
                editor.timestamp_expires(self.timestamp_expires.unwrap());
            }

            editor.bump_timestamp_version();
        }
        Ok(())
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
                msg: "--set-fulcio-target only accepts --fulcio-uri, --fulcio-status, and --oidc-uri."
                    .to_string(),
            }
            .fail();
        }

        if self.ctlog_target.is_some()
            && (self.fulcio_uri.is_some()
                || self.oidc_uri.is_some()
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
                || self.oidc_uri.is_some()
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
                || self.oidc_uri.is_some()
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
            if self.oidc_uri.is_none() {
                self.oidc_uri = Some(String::from("https://oauth2.sigstore.dev/auth"));
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

    pub fn detect_public_key_details(
        key_path: &Path,
        checksum_algo: Option<&str>,
    ) -> io::Result<i32> {
        let raw_algo_string = checksum_algo.unwrap_or("sha256");
        let algo_to_use = raw_algo_string.to_lowercase();
        let mut file = File::open(key_path)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;

        if let Ok(ec_key) = EcKey::public_key_from_pem(buffer.as_bytes()) {
            let group = ec_key.group();
            let curve = group.curve_name();
            let key_type_id = match curve {
                Some(Nid::X9_62_PRIME256V1) => {
                    if algo_to_use == "sha256" {
                        Ok(5)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "EC P-256 curve requires 'sha256' checksum,
                                but '{algo_to_use}' was provided"
                            ),
                        ))
                    }
                }
                Some(Nid::SECP384R1) => {
                    if algo_to_use == "sha384" {
                        Ok(12)
                    } else if algo_to_use == "sha256" {
                        Ok(19)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "EC P-384 curve requires 'sha384' or 'sha256' checksum,
                                but '{algo_to_use}' was provided"
                            ),
                        ))
                    }
                }
                Some(Nid::SECP521R1) => {
                    if algo_to_use == "sha512" {
                        Ok(13)
                    } else if algo_to_use == "sha256" {
                        Ok(20)
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "EC P-521 curve requires 'sha512' or 'sha256' checksum,
                                but '{algo_to_use}' was provided"
                            ),
                        ))
                    }
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unknown or unsupported EC curve",
                )),
            };
            return key_type_id;
        }
        if let Ok(rsa_key) = Rsa::public_key_from_pem(buffer.as_bytes())
            .or_else(|_| Rsa::public_key_from_pem_pkcs1(buffer.as_bytes()))
        {
            let key_size = rsa_key.size() * 8;
            let key_type_id = match key_size {
                2048 => Ok(9),
                3072 => Ok(10),
                4096 => Ok(11),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unknown RSA key size",
                )),
            };
            return key_type_id;
        }

        if let Ok(pkey) = PKey::public_key_from_pem(buffer.as_bytes()) {
            if pkey.id() == openssl::pkey::Id::ED25519 {
                return Ok(7);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid public key format or unsupported key type",
        ))
    }

    fn load_target_der_bytes(target_path: &Path) -> io::Result<Vec<Vec<u8>>> {
        let mut file = File::open(target_path)?;
        let mut buffer = String::new();
        file.read_to_string(&mut buffer)?;

        let pems = pem::parse_many(buffer).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("PEM parse error: {err}"),
            )
        })?;

        Ok(pems.into_iter().map(pem::Pem::into_contents).collect())
    }

    fn get_latest_trusted_root(&self) -> PathBuf {
        let repo_dir = &self.outdir;
        let targets_dir = repo_dir.join("targets");

        // Find the latest target metadata file: N.targets.json
        let mut latest_targets: Option<PathBuf> = None;
        let mut latest_version: u64 = 0;

        if let Ok(entries) = fs::read_dir(repo_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(version_str) = file_name.strip_suffix(".targets.json") {
                        if let Ok(version) = version_str.parse::<u64>() {
                            if version > latest_version {
                                latest_version = version;
                                latest_targets = Some(path);
                            }
                        }
                    }
                }
            }
        }

        // Parse latest targets.json to identify latest trusted_root reference
        if let Some(targets_path) = latest_targets {
            if let Ok(data) = fs::read_to_string(&targets_path) {
                if let Ok(json) = serde_json::from_str::<Value>(&data) {
                    if let Some(hash_val) = json
                        .get("signed")
                        .and_then(|s| s.get("targets"))
                        .and_then(|t| t.get("trusted_root.json"))
                        .and_then(|t| t.get("hashes"))
                        .and_then(|h| h.get("sha256"))
                        .and_then(|v| v.as_str())
                    {
                        let hashed_path = targets_dir.join(format!("{hash_val}.trusted_root.json"));
                        if hashed_path.exists() {
                            return hashed_path;
                        }
                    }
                }
            }
        }

        // fallback: return the default "trusted_root.json" path
        targets_dir.join("trusted_root.json")
    }

    fn get_latest_signing_config(&self) -> PathBuf {
        let repo_dir = &self.outdir;
        let targets_dir = repo_dir.join("targets");

        // Find the latest target metadata file: N.targets.json
        let mut latest_targets: Option<PathBuf> = None;
        let mut latest_version: u64 = 0;

        if let Ok(entries) = fs::read_dir(repo_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Some(version_str) = file_name.strip_suffix(".targets.json") {
                        if let Ok(version) = version_str.parse::<u64>() {
                            if version > latest_version {
                                latest_version = version;
                                latest_targets = Some(path);
                            }
                        }
                    }
                }
            }
        }

        // Parse latest targets.json to identify latest signing_config reference
        if let Some(targets_path) = latest_targets {
            if let Ok(data) = fs::read_to_string(&targets_path) {
                if let Ok(json) = serde_json::from_str::<Value>(&data) {
                    if let Some(hash_val) = json
                        .get("signed")
                        .and_then(|s| s.get("targets"))
                        .and_then(|t| t.get("signing_config.v0.2.json"))
                        .and_then(|t| t.get("hashes"))
                        .and_then(|h| h.get("sha256"))
                        .and_then(|v| v.as_str())
                    {
                        let hashed_path =
                            targets_dir.join(format!("{hash_val}.signing_config.v0.2.json"));
                        if hashed_path.exists() {
                            return hashed_path;
                        }
                    }
                }
            }
        }

        // fallback: return the default "signing_config.v0.2.json" path
        targets_dir.join("signing_config.v0.2.json")
    }
}

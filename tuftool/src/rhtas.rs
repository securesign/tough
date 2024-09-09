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
use serde_json::json;
use snafu::{OptionExt, ResultExt};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tough::editor::signed::PathExists;
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

    #[arg(long = "delete-target")]
    delete_targets: Vec<TargetName>,

    /// Path to the new Fulcio target file to add to the targets
    #[arg(long = "set-fulcio-target")]
    fulcio_target: Option<PathBuf>,

    /// Status for the Fulcio target
    #[arg(long, default_value = "Active")]
    fulcio_status: String,

    /// URI for the Fulcio target
    #[arg(long, default_value = "https://fulcio.sigstore.dev")]
    fulcio_uri: String,

    /// Path to the new Ctlog target file
    #[arg(long = "set-ctlog-target")]
    ctlog_target: Option<PathBuf>,

    /// Status for the Ctlog certificate
    #[arg(long, default_value = "Active")]
    ctlog_status: String,

    /// URI for the Ctlog certificate
    #[arg(long, default_value = "https://ctfe.sigstore.dev/test")]
    ctlog_uri: String,

    /// Path to the new rekor target file
    #[arg(long = "set-rekor-target")]
    rekor_target: Option<PathBuf>,

    /// Status for the rekor certificate
    #[arg(long, default_value = "Active")]
    rekor_status: String,

    /// URI for the rekor certificate
    #[arg(long, default_value = "https://rekor.sigstore.dev")]
    rekor_uri: String,

    /// Path to the new Timestamp Authority target file
    #[arg(long = "set-tsa-target")]
    tsa_target: Option<PathBuf>,

    /// Status for the tsa certificate
    #[arg(long, default_value = "Active")]
    tsa_status: String,

    /// URI for the tsa certificate
    #[arg(long, default_value = "")]
    tsa_uri: String,

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
    pub(crate) async fn run(&self) -> Result<()> {
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

        if self.force_version {
            self.update_metadata_version(&mut editor);
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
        // If the "remove-target" argument was passed, remove the target
        // from the repository.
        for target_name in &self.delete_targets {
            editor
                .remove_target(target_name)
                .context(error::RemoveTargetSnafu {
                    name: target_name.raw(),
                })?;
            self.remove_target_file(target_name.raw()).await?;
        }

        // If the "set-fulcio-target" argument was passed, build a target
        // and add it to the repository.
        // user can specify fulcio-status, fulcio-uri & fulcio-usage
        self.set_fulcio_target(&mut editor).await?;

        // If the "set-ctlog-target" argument was passed, build a target
        // and add it to the repository.
        // user can specify ctlog-status, ctlog-uri & ctlog-usage
        self.set_ctlog_target(&mut editor).await?;

        // If the "set-rekor-target" argument was passed, build a target
        // and add it to the repository.
        // user can specify rekor-status, rekor-uri & rekor-usage
        self.set_rekor_target(&mut editor).await?;

        // If the "set-tsa-target" argument was passed, build a target
        // and add it to the repository.
        // user can specify tsa-status, tsa-uri & tsa-usage
        self.set_tsa_target(&mut editor).await?;

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
            let targets_outdir = &self.outdir.join("targets");
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
        signed_repo
            .write(&self.outdir)
            .await
            .context(error::WriteRepoSnafu {
                directory: &self.outdir,
            })?;

        Ok(())
    }

    async fn set_fulcio_target(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if let Some(ref fulcio_target_path) = self.fulcio_target {
            let mut fulcio_target = build_targets(fulcio_target_path, self.follow).await?;

            if self.fulcio_status != "Active" && self.fulcio_status != "Expired" {
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
        }
        Ok(())
    }

    async fn set_ctlog_target(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if let Some(ref ctlog_target_path) = self.ctlog_target {
            let mut ctlog_target = build_targets(ctlog_target_path, self.follow).await?;

            if self.ctlog_status != "Active" && self.ctlog_status != "Expired" {
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
        }
        Ok(())
    }

    async fn set_rekor_target(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if let Some(ref rekor_target_path) = self.rekor_target {
            let mut rekor_target = build_targets(rekor_target_path, self.follow).await?;

            if self.rekor_status != "Active" && self.rekor_status != "Expired" {
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
        }
        Ok(())
    }

    async fn set_tsa_target(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if let Some(ref tsa_target_path) = self.tsa_target {
            let mut tsa_target = build_targets(tsa_target_path, self.follow).await?;

            if self.tsa_status != "Active" && self.tsa_status != "Expired" {
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
        }
        Ok(())
    }

    async fn remove_target_file(&self, target_name: &str) -> Result<()> {
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
                tokio::fs::remove_file(&file_path)
                    .await
                    .context(error::RemoveTargetPathSnafu {
                        path: file_path.clone(),
                    })?;
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
}

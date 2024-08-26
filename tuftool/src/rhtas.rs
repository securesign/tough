// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::common::UNUSED_URL;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use serde_json::json;
use snafu::{OptionExt, ResultExt};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
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
    snapshot_expires: DateTime<Utc>,

    /// Version of snapshot.json file
    #[arg(long)]
    snapshot_version: NonZeroU64,

    /// Path to the new Fulcio target file to add to the targets
    #[arg(long = "set-fulcio-target")]
    fulcio_target: Option<PathBuf>,

    /// Status for the Fulcio target
    #[arg(long, default_value = "Active")]
    fulcio_status: String,

    /// URI for the Fulcio target
    #[arg(long, default_value = "https://fulcio.sigstore.dev")]
    fulcio_uri: String,

    /// Usage for the Fulcio target
    #[arg(long, default_value = "Fulcio")]
    fulcio_usage: String,

    /// Path to the new Ctlog target file
    #[arg(long = "set-ctlog-target")]
    ctlog_target: Option<PathBuf>,

    /// Status for the Ctlog certificate
    #[arg(long, default_value = "Active")]
    ctlog_status: String,

    /// URI for the Ctlog certificate
    #[arg(long, default_value = "https://ctfe.sigstore.dev/test")]
    ctlog_uri: String,

    /// Usage for the Ctlog certificate
    #[arg(long, default_value = "CTFE")]
    ctlog_usage: String,

    /// Path to the new rekor target file
    #[arg(long = "set-rekor-target")]
    rekor_target: Option<PathBuf>,

    /// Status for the rekor certificate
    #[arg(long, default_value = "Active")]
    rekor_status: String,

    /// URI for the rekor certificate
    #[arg(long, default_value = "https://rekor.sigstore.dev")]
    rekor_uri: String,

    /// Usage for the rekor certificate
    #[arg(long, default_value = "Rekor")]
    rekor_usage: String,

    /// Path to the new Timestamp Authority target file
    #[arg(long = "set-tsa-target")]
    tsa_target: Option<PathBuf>,

    /// Status for the tsa certificate
    #[arg(long, default_value = "Active")]
    tsa_status: String,

    /// URI for the tsa certificate
    #[arg(long, default_value = "")]
    tsa_uri: String,

    /// Usage for the tsa certificate
    #[arg(long, default_value = "Timestamp Authority")]
    tsa_usage: String,

    /// Expiration of targets.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long, value_parser = parse_datetime)]
    targets_expires: DateTime<Utc>,

    /// Version of targets.json file
    #[arg(long)]
    targets_version: NonZeroU64,

    /// Expiration of timestamp.json file; can be in full RFC 3339 format, or something like 'in
    /// 7 days'
    #[arg(long, value_parser = parse_datetime)]
    timestamp_expires: DateTime<Utc>,

    /// Version of timestamp.json file
    #[arg(long)]
    timestamp_version: NonZeroU64,
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

    async fn update_metadata(&self, mut editor: RepositoryEditor) -> Result<()> {
        let mut keys = Vec::new();
        for source in &self.keys {
            let key_source = parse_key_source(source)?;
            keys.push(key_source);
        }

        editor
            .targets_version(self.targets_version)
            .context(error::DelegationStructureSnafu)?
            .targets_expires(self.targets_expires)
            .context(error::DelegationStructureSnafu)?
            .snapshot_version(self.snapshot_version)
            .snapshot_expires(self.snapshot_expires)
            .timestamp_version(self.timestamp_version)
            .timestamp_expires(self.timestamp_expires);

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

        // Sign the repo
        let signed_repo = editor.sign(&keys).await.context(error::SignRepoSnafu)?;

        // Write the metadata to the outdir
        let metadata_dir = &self.outdir.join("metadata");
        signed_repo
            .write(metadata_dir)
            .await
            .context(error::WriteRepoSnafu {
                directory: metadata_dir,
            })?;

        Ok(())
    }
    async fn set_fulcio_target(&self, editor: &mut RepositoryEditor) -> Result<()> {
        if let Some(ref fulcio_target_path) = self.fulcio_target {
            let mut fulcio_target = build_targets(fulcio_target_path, self.follow).await?;

            let custom_sigstore_metadata = json!({
                "status": self.fulcio_status,
                "uri": self.fulcio_uri,
                "usage": self.fulcio_usage
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

            let custom_sigstore_metadata = json!({
                "status": self.ctlog_status,
                "uri": self.ctlog_uri,
                "usage": self.ctlog_usage
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

            let custom_sigstore_metadata = json!({
                "status": self.rekor_status,
                "uri": self.rekor_uri,
                "usage": self.rekor_usage
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

            let custom_sigstore_metadata = json!({
                "status": self.tsa_status,
                "uri": self.tsa_uri,
                "usage": self.tsa_usage
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
}

// Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::build_targets;
use crate::common::UNUSED_URL;
use crate::datetime::parse_datetime;
use crate::error::{self, Result};
use crate::source::parse_key_source;
use chrono::{DateTime, Utc};
use clap::Parser;
use snafu::{OptionExt, ResultExt};
use std::fs;
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::{ExpirationEnforcement, RepositoryLoader};
use url::Url;

#[derive(Debug, Parser)]
pub(crate) struct UpdateArgs {
    /// Allow repo download for expired metadata
    #[arg(long)]
    allow_expired_repo: bool,

    /// Follow symbolic links in the given directory when adding targets
    #[arg(short, long)]
    follow: bool,

    /// Incoming metadata from delegatee
    #[arg(short, long = "incoming-metadata")]
    indir: Option<Url>,

    /// Number of target hashing threads to run when adding targets
    /// (default: number of cores)
    // No default is specified in structopt here. This is because rayon
    // automatically spawns the same number of threads as cores when any
    // of its parallel methods are called.
    #[arg(short, long)]
    jobs: Option<NonZeroUsize>,

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

    /// Directory of targets
    #[arg(short, long = "add-targets")]
    targets_indir: Option<PathBuf>,

    /// Behavior when a target exists with the same name and hash in the desired repository
    /// directory, for example from another repository when you're sharing target directories.
    /// Options are "replace", "fail", and "skip"
    #[arg(long, default_value = "skip")]
    target_path_exists: PathExists,

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

impl UpdateArgs {
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

        self.update_all_metadata(&mut editor)?;

        if self.force_version {
            self.update_metadata_version(&mut editor)?;
        } else if self.snapshot_version.is_some()
            || self.targets_version.is_some()
            || self.timestamp_version.is_some()
        {
            return error::ForceVersionMissingSnafu {}.fail();
        }

        // If the "add-targets" argument was passed, build a list of targets
        // and add them to the repository. If a user specifies job count we
        // override the default, which is the number of cores.
        if let Some(ref targets_indir) = self.targets_indir {
            if let Some(jobs) = self.jobs {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(usize::from(jobs))
                    .build_global()
                    .context(error::InitializeThreadPoolSnafu)?;
            }

            let new_targets = build_targets(targets_indir, self.follow).await?;

            for (target_name, target) in new_targets {
                editor
                    .add_target(target_name, target)
                    .context(error::DelegationStructureSnafu)?;
            }
        };

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
        let expiration_enforcement = if self.allow_expired_repo {
            expired_repo_warning(&self.outdir);
            ExpirationEnforcement::Unsafe
        } else {
            ExpirationEnforcement::Safe
        };
        let repo = RepositoryLoader::new(
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

        let signed_repo;

        if self.targets_indir.is_some()
            || self.targets_version.is_some()
            || self.targets_expires.is_some()
        {
            signed_repo = editor.sign(&keys).await.context(error::SignRepoSnafu)?;
        } else if self.snapshot_expires.is_some() || self.snapshot_version.is_some() {
            signed_repo = editor
                .sign_snapshot(&keys, repo)
                .await
                .context(error::SignRepoSnafu)?;
        } else if self.timestamp_expires.is_some() || self.timestamp_version.is_some() {
            signed_repo = editor
                .sign_timestamp(&keys, repo)
                .await
                .context(error::SignRepoSnafu)?;
        } else {
            signed_repo = editor
                .preserve_metadata(repo)
                .context(error::SignRepoSnafu)?;
        }

        // copies any targets that were added
        if let Some(ref targets_indir) = self.targets_indir {
            let targets_outdir = &self.outdir.join("targets");
            signed_repo
                .copy_targets(targets_indir, targets_outdir, self.target_path_exists)
                .await
                .context(error::LinkTargetsSnafu {
                    indir: &targets_indir,
                    outdir: targets_outdir,
                })?;
        };

        // Write the metadata to the outdir
        signed_repo
            .write(&self.outdir)
            .await
            .context(error::WriteRepoSnafu {
                directory: &self.outdir,
            })?;

        let root_path = &self.outdir.join("root.json");
        let _ = fs::copy(&self.root, root_path);
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
        if self.targets_indir.is_some()
            || self.targets_version.is_some()
            || self.targets_expires.is_some()
        {
            if self.targets_expires.is_some() {
                editor
                    .targets_expires(self.targets_expires.unwrap())
                    .context(error::DelegationStructureSnafu)?;
            }
            editor
                .bump_targets_version()
                .context(error::DelegationStructureSnafu)?;
        }
        if self.snapshot_expires.is_some() {
            editor.snapshot_expires(self.snapshot_expires.unwrap());
        }
        editor.bump_snapshot_version();

        if self.timestamp_expires.is_some() {
            editor.timestamp_expires(self.timestamp_expires.unwrap());
        }
        editor.bump_timestamp_version();

        Ok(())
    }
}

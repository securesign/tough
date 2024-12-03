//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The errors that can be raised by sigstore-rs

use thiserror::Error;

pub type Result<T> = std::result::Result<T, SigstoreError>;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum SigstoreError {
    #[error("failed to parse URL: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),

    #[cfg(feature = "sigstore-trust-root")]
    #[cfg_attr(docsrs, doc(cfg(feature = "sigstore-trust-root")))]
    #[error(transparent)]
    TufError(#[from] Box<tough::error::Error>),

    #[error("TUF target {0} not found inside of repository")]
    TufTargetNotFoundError(String),

    #[error("{0}")]
    TufMetadataError(String),

    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error("{0}")]
    UnexpectedError(String),

    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::error::Error),

    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error(transparent)]
    WebPKIError(#[from] webpki::Error),

    #[error("serialization error: {0}")]
    SerializationError(String),
}

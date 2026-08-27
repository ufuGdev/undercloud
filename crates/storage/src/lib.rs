// SPDX-License-Identifier: Apache-2.0
//! `StorageProvider` trait and the shared, retry-aware provider error model.

mod backoff;
mod error;
mod provider;

pub use backoff::backoff_delay;
pub use error::ProviderError;
pub use provider::{
    GetObjectRequest, ObjectLocator, ObjectMetadata, ObjectPage, ObjectReceipt, ObjectStream,
    PageCursor, ProviderCapabilities, ProviderHealth, PutObjectRequest, QuotaInfo, QuotaState,
    StorageProvider,
};

#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate delog;
generate_macros!();

mod client;
mod container;

pub use client::EncryptionUtil;
pub use container::EncryptedDataContainer;

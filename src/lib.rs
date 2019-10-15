#![allow(bare_trait_objects)]
#![cfg_attr(all(feature = "mesalock_sgx", not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#![cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

extern crate asnom;
extern crate byteorder;
extern crate webpki;
extern crate rustls;
extern crate mio;

mod ldap;
mod bind;
mod tls;
pub use ldap::Ldap;

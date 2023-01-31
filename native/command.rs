use argon2::{hash_encoded, verify_encoded, Config, ThreadMode, Variant, Version};
use deno_bindgen::deno_bindgen;

use crate::error::Error;

#[deno_bindgen]
pub struct HashOptions {
    salt: Vec<u8>,
    secret: Option<Vec<u8>>,
    data: Option<Vec<u8>>,
    version: Option<String>,
    variant: Option<String>,
    memory_cost: Option<u32>,
    time_cost: Option<u32>,
    lanes: Option<u32>,
    thread_mode: Option<u8>,
    hash_length: Option<u32>,
}

#[deno_bindgen]
pub struct HashResult {
    result: Vec<u8>,
    error: Option<String>,
}

#[deno_bindgen]
pub struct VerifyResult {
    result: bool,
    error: Option<String>,
}

#[deno_bindgen(non_blocking)]
pub fn hash(password: &str, options: HashOptions) -> HashResult {
    match hash_internal(password, options) {
        Ok(result) => {
            HashResult{
                result: result.into_bytes(),
                error: None,
            }
        }
        Err(err) => {
            HashResult{
                result: vec![],
                error: Some(format!("{err}")),
            }
        }
    }
}

#[deno_bindgen(non_blocking)]
pub fn verify(hash_: &str, password: &str) -> VerifyResult {
    match verify_internal(hash_, password) {
        Ok(result) => {
            VerifyResult{
                result,
                error: None,
            }
        }
        Err(err) => {
            VerifyResult{
                result: false,
                error: Some(format!("{err}")),
            }
        }
    }
}


fn hash_internal(password: &str, options: HashOptions) -> Result<String, Error> {
    let salt = &options.salt[..];

    let mut config: Config = Config::default();

    if let Some(ref secret) = options.secret {
        config.secret = &secret[..];
    }

    if let Some(ref data) = options.data {
        config.ad = &data[..];
    }

    if let Some(memory_cost) = options.memory_cost {
        config.mem_cost = memory_cost;
    }

    if let Some(time_cost) = options.time_cost {
        config.time_cost = time_cost;
    }

    if let Some(variant) = options.variant {
        if let Ok(v) = Variant::from_str(&variant) {
            config.variant = v;
        }
    }

    if let Some(version) = options.version {
        if let Ok(v) = Version::from_str(&version) {
            config.version = v;
        }
    }

    if let Some(lanes) = options.lanes {
        config.lanes = lanes;
    }

    if let Some(hash_length) = options.hash_length {
        config.hash_length = hash_length;
    }

    if let Some(thread_mode) = options.thread_mode {
        match thread_mode {
            0 => config.thread_mode = ThreadMode::Sequential,
            1 => config.thread_mode = ThreadMode::Parallel,
            _ => {}
        }
    }

    Ok(hash_encoded(password.as_bytes(), salt, &config)?)
}

fn verify_internal(hash_: &str, password: &str) -> Result<bool, Error> {
    Ok(verify_encoded(
        hash_,
        password.as_bytes(),
    )?)
}

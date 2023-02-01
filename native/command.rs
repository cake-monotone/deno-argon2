use argon2::{hash_encoded, verify_encoded, Config, ThreadMode, Variant, Version};
use bytes::Bytes;

use crate::error::Error;

#[derive(Deserialize)]
pub struct HashOptions {
    salt: Bytes,
    secret: Option<Bytes>,
    data: Option<Bytes>,
    version: Option<String>,
    variant: Option<String>,
    #[serde(rename(deserialize = "memoryCost"))]
    memory_cost: Option<u32>,
    #[serde(rename(deserialize = "timeCost"))]
    time_cost: Option<u32>,
    #[serde(rename(deserialize = "lanes"))]
    lanes: Option<u32>,
    #[serde(rename(deserialize = "threadMode"))]
    thread_mode: Option<u8>,
    #[serde(rename(deserialize = "hashLength"))]
    hash_length: Option<u32>,
}

#[derive(Deserialize)]
struct HashParams {
    password: String,
    options: HashOptions,
}

#[derive(Deserialize)]
struct VerifyParams {
    password: String,
    hash: String,
}

#[derive(Serialize)]
pub struct HashResult {
    result: Vec<u8>,
    error: Option<String>,
}

#[derive(Serialize)]
pub struct VerifyResult {
    result: bool,
    error: Option<String>,
}

fn pack_result(s: &str) -> Vec<u8> {
    let len = (s.len() as u32).to_be_bytes();
    let mut packed = len.to_vec();
    packed.extend_from_slice(s.as_bytes());

    packed
}

#[no_mangle]
pub extern "C" fn hash(ptr: *const u8, len: usize) -> *const u8 {
    let data_buf = unsafe{ std::slice::from_raw_parts(ptr, len) };
    
    let result = match hash_internal(data_buf) {
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
    };

    let result = serde_json::to_string(&result).expect("failed to json-strigify the result");
    let result = pack_result(&result);

    let return_ptr = result.as_ptr();
    std::mem::forget(result);
    return_ptr
}


#[no_mangle]
pub extern "C" fn verify(ptr: *const u8, len: usize) -> *const u8 {
    let data_buf = unsafe{ std::slice::from_raw_parts(ptr, len) };

    let result = match verify_internal(data_buf) {
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
    };

    let result = serde_json::to_string(&result).expect("failed to json-strigify the result");
    let result = pack_result(&result);

    let return_ptr = result.as_ptr();
    std::mem::forget(result);
    return_ptr
}


fn hash_internal(data_buf: &[u8]) -> Result<String, Error> {
    let params: HashParams = serde_json::from_slice(data_buf)?;
    let salt = &params.options.salt;

    let mut config: Config = Config::default();

    if let Some(ref secret) = params.options.secret {
        config.secret = &secret[..];
    }

    if let Some(ref data) = params.options.data {
        config.ad = &data[..];
    }

    if let Some(memory_cost) = params.options.memory_cost {
        config.mem_cost = memory_cost;
    }

    if let Some(time_cost) = params.options.time_cost {
        config.time_cost = time_cost;
    }

    if let Some(variant) = params.options.variant {
        if let Ok(v) = Variant::from_str(&variant) {
            config.variant = v;
        }
    }

    if let Some(version) = params.options.version {
        if let Ok(v) = Version::from_str(&version) {
            config.version = v;
        }
    }

    if let Some(lanes) = params.options.lanes {
        config.lanes = lanes;
    }

    if let Some(hash_length) = params.options.hash_length {
        config.hash_length = hash_length;
    }

    if let Some(thread_mode) = params.options.thread_mode {
        match thread_mode {
            0 => config.thread_mode = ThreadMode::Sequential,
            1 => config.thread_mode = ThreadMode::Parallel,
            _ => {}
        }
    }

    Ok(hash_encoded(&params.password.into_bytes(), salt, &config)?)
}

fn verify_internal(data_buf: &[u8]) -> Result<bool, Error> {
    let options: VerifyParams = serde_json::from_slice(data_buf)?;

    Ok(verify_encoded(
        &options.hash,
        options.password.as_bytes(),
    )?)
}

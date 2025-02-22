mod msg;
mod state;
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use sha1::{Digest, Sha1};  // Changed from sha512 to sha1
use secret_toolkit::crypto::{Prng, sha_256};
use secret_toolkit::viewing_key::{ViewingKey, ViewingKeyStore};

use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CONFIG, SECRETS, VIEWING_KEYS};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    CONFIG.save(deps.storage, &Config { prng_seed: msg.prng_seed })?;
    Ok(Response::default())
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::SetSecret { secret, viewing_key } => set_secret(deps, info, secret, viewing_key),
        ExecuteMsg::CreateViewingKey { entropy } => create_viewing_key(deps, env, info, entropy),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetTOTP { viewing_key } => to_binary(&get_totp(deps, viewing_key)?),
        QueryMsg::ExportSecret { viewing_key } => to_binary(&export_secret(deps, viewing_key)?),
    }
}

fn create_viewing_key(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    entropy: String,
) -> StdResult<Response> {
    let config = CONFIG.load(deps.storage)?;
    let key = ViewingKey::create(
        deps.storage,
        &info,
        &env,
        &config.prng_seed,
        entropy.as_bytes(),
    );
    VIEWING_KEYS.insert(deps.storage, &info.sender.to_string(), &key)?;
    Ok(Response::new().add_attribute("viewing_key", key))
}

fn set_secret(
    deps: DepsMut,
    info: MessageInfo,
    secret: String,
    viewing_key: String,
) -> StdResult<Response> {
    let stored_vk = VIEWING_KEYS.get(deps.storage, &info.sender.to_string())
        .ok_or_else(|| StdError::generic_err("Viewing key not found"))?;
    if viewing_key != stored_vk {
        return Err(StdError::generic_err("Invalid viewing key"));
    }
    SECRETS.insert(deps.storage, &info.sender.to_string(), &secret)?;
    Ok(Response::new().add_attribute("action", "set_secret"))
}

fn get_totp(deps: Deps, viewing_key: String) -> StdResult<String> {
    let user_addr = deps.api.addr_validate(&viewing_key)?;
    let stored_vk = VIEWING_KEYS.get(deps.storage, &user_addr.to_string())
        .ok_or_else(|| StdError::generic_err("Viewing key not found"))?;
    if viewing_key != stored_vk {
        return Err(StdError::generic_err("Invalid viewing key"));
    }

    let secret = SECRETS.get(deps.storage, &user_addr.to_string())
        .ok_or_else(|| StdError::generic_err("No secret found"))?;

    generate_totp(&secret)
}

fn generate_totp(secret: &str) -> StdResult<String> {
    let time_step = 30u64;
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let counter = current_time / time_step;

    let mut hmac = Sha1::new();
    hmac.update(secret.as_bytes());
    hmac.update(&counter.to_be_bytes());
    let result = hmac.finalize();

    let offset = (result[19] & 0xf) as usize;
    let code = ((result[offset] & 0x7f) as u32) << 24
        | (result[offset + 1] as u32) << 16
        | (result[offset + 2] as u32) << 8
        | (result[offset + 3] as u32);
    
    Ok(format!("{:06}", code % 1_000_000))
}

fn export_secret(deps: Deps, viewing_key: String) -> StdResult<String> {
    let user_addr = deps.api.addr_validate(&viewing_key)?;
    let stored_vk = VIEWING_KEYS.get(deps.storage, &user_addr.to_string())
        .ok_or_else(|| StdError::generic_err("Viewing key not found"))?;
    if viewing_key != stored_vk {
        return Err(StdError::generic_err("Invalid viewing key"));
    }

    SECRETS.get(deps.storage, &user_addr.to_string())
        .ok_or_else(|| StdError::generic_err("No secret found"))
}
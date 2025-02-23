use cosmwasm_std::Storage;
use cosmwasm_std::{Deps, DepsMut, MessageInfo, Response, StdError, StdResult};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use secret_toolkit::storage::{Keymap};

// Define storage keys
pub const SECRETS: Keymap<String, String> = Keymap::new(b"secrets");

// Store user's TOTP secret
pub fn set_secret(deps: DepsMut, info: MessageInfo, secret: String) -> StdResult<Response> {
    SECRETS.insert(&mut (deps.storage as &mut dyn Storage), &info.sender.to_string(), &secret)
        .map_err(|e| StdError::generic_err(e.to_string()))?;
    Ok(Response::new().add_attribute("action", "set_secret"))
}

// Generate a TOTP code (Only user can access their own OTP)
pub fn get_totp(deps: Deps, address: String) -> StdResult<String> {
    let secret = SECRETS.get(&(deps.storage as &dyn Storage), &address)
        .ok_or_else(|| StdError::generic_err("Unauthorized or no secret found"))?;

    let time_step = 30;
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .map_err(|e| StdError::generic_err(e.to_string()))?.as_secs();
    let counter = timestamp / time_step as u64;

    let mut mac = Hmac::<Sha1>::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[19] & 0x0F) as usize;
    let code = ((u32::from_be_bytes([result[offset], result[offset + 1], result[offset + 2], result[offset + 3]]) & 0x7FFFFFFF) % 1_000_000).to_string();

    Ok(format!("{:06}", code))
}

// Export for use with TOTP apps
pub fn export_secret(deps: Deps, address: String) -> StdResult<String> {
    let secret = SECRETS.get(&(deps.storage as &dyn Storage), &address)
        .ok_or_else(|| StdError::generic_err("Unauthorized or no secret found"))?;
    Ok(secret)
}
use schemars::JsonSchema;
use secret_toolkit::storage::{Item, Keymap};
use serde::{Deserialize, Serialize};

pub static CONFIG_KEY: &[u8] = b"config";
pub const VIEWING_KEY_SIZE: usize = 32;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub prng_seed: Vec<u8>,
}

pub const PREFIX_VIEWING_KEY: &[u8] = b"viewing_key";
pub const PREFIX_SECRETS: &[u8] = b"secrets";

pub const CONFIG: Item<Config> = Item::new(CONFIG_KEY);
pub const VIEWING_KEYS: Keymap<String> = Keymap::new(PREFIX_VIEWING_KEY);
pub const SECRETS: Keymap<String> = Keymap::new(PREFIX_SECRETS);
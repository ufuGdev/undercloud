use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn main() {
    let dotenv_values = load_dotenv_values();
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let workspace_dotenv = manifest.join("../../.env");
    println!("cargo:rerun-if-changed={}", workspace_dotenv.display());
    for key in [
        "UNDERCLOUD_OFFICIAL_BUILD",
        "UNDERCLOUD_GOOGLE_CLIENT_ID",
        "UNDERCLOUD_GOOGLE_CLIENT_SECRET",
        "UNDERCLOUD_ONEDRIVE_CLIENT_ID",
        "UNDERCLOUD_DROPBOX_APP_KEY",
        "UNDERCLOUD_DROPBOX_REDIRECT_PORTS",
    ] {
        println!("cargo:rerun-if-env-changed={key}");
    }

    let official = config_value("UNDERCLOUD_OFFICIAL_BUILD", &dotenv_values)
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if official {
        for key in [
            "UNDERCLOUD_GOOGLE_CLIENT_ID",
            "UNDERCLOUD_GOOGLE_CLIENT_SECRET",
            "UNDERCLOUD_ONEDRIVE_CLIENT_ID",
            "UNDERCLOUD_DROPBOX_APP_KEY",
        ] {
            let value = config_value(key, &dotenv_values).unwrap_or_default();
            if !valid_official_id(key, &value) {
                panic!("official build requires a valid {key}");
            }
        }
    }

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let generated = format!(
        "pub const GOOGLE_CLIENT_ID: Option<&str> = {};\n\
         pub const GOOGLE_CLIENT_SECRET: Option<&str> = {};\n\
         pub const ONEDRIVE_CLIENT_ID: Option<&str> = {};\n\
         pub const DROPBOX_APP_KEY: Option<&str> = {};\n\
         pub const DROPBOX_REDIRECT_PORTS: Option<&str> = {};\n",
        rust_option(config_value("UNDERCLOUD_GOOGLE_CLIENT_ID", &dotenv_values)),
        rust_option(config_value(
            "UNDERCLOUD_GOOGLE_CLIENT_SECRET",
            &dotenv_values
        )),
        rust_option(config_value(
            "UNDERCLOUD_ONEDRIVE_CLIENT_ID",
            &dotenv_values
        )),
        rust_option(config_value("UNDERCLOUD_DROPBOX_APP_KEY", &dotenv_values)),
        rust_option(config_value(
            "UNDERCLOUD_DROPBOX_REDIRECT_PORTS",
            &dotenv_values
        )),
    );
    fs::write(out_dir.join("oauth_build_config.rs"), generated)
        .expect("write generated OAuth build configuration");
}

fn rust_option(value: Option<String>) -> String {
    value
        .map(|value| format!("Some({:?})", value))
        .unwrap_or_else(|| "None".to_owned())
}

fn valid_official_id(key: &str, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty()
        || value != value.trim()
        || value.to_ascii_lowercase().contains("placeholder")
        || value.contains("YOUR_")
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }
    match key {
        "UNDERCLOUD_GOOGLE_CLIENT_ID" => value.ends_with(".apps.googleusercontent.com"),
        "UNDERCLOUD_GOOGLE_CLIENT_SECRET" => true,
        "UNDERCLOUD_ONEDRIVE_CLIENT_ID" => {
            value.len() == 36
                && value.chars().enumerate().all(|(index, character)| {
                    matches!(index, 8 | 13 | 18 | 23)
                        .then_some(character == '-')
                        .unwrap_or_else(|| character.is_ascii_hexdigit())
                })
        }
        "UNDERCLOUD_DROPBOX_APP_KEY" => value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '.')
        }),
        _ => false,
    }
}

fn load_dotenv_values() -> HashMap<String, String> {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let workspace_dotenv = manifest.join("../../.env");
    dotenvy::from_path_iter(workspace_dotenv)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .collect()
}

fn config_value(key: &str, dotenv_values: &HashMap<String, String>) -> Option<String> {
    std::env::var(key)
        .ok()
        .or_else(|| dotenv_values.get(key).cloned())
}

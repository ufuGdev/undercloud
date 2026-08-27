use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PREFERENCE_FILE: &str = "vault-library.json";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultEntry {
    pub id: String,
    pub name: String,
    pub catalog_path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LibraryInfo {
    pub root: String,
    pub vaults: Vec<VaultEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Preference {
    root: String,
}

pub fn default_root(app_data_dir: &Path) -> PathBuf {
    app_data_dir.join("vaults")
}

pub fn preference_path(app_config_dir: &Path) -> PathBuf {
    app_config_dir.join(PREFERENCE_FILE)
}

pub fn load_root(app_config_dir: &Path, app_data_dir: &Path) -> Result<PathBuf, std::io::Error> {
    let preference = preference_path(app_config_dir);
    let root = match fs::read(&preference) {
        Ok(bytes) => serde_json::from_slice::<Preference>(&bytes)
            .ok()
            .map(|value| PathBuf::from(value.root))
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| default_root(app_data_dir)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => default_root(app_data_dir),
        Err(error) => return Err(error),
    };
    Ok(root)
}

pub fn save_root(app_config_dir: &Path, root: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(app_config_dir)?;
    let temp = preference_path(app_config_dir).with_extension("tmp");
    let bytes = serde_json::to_vec(&Preference {
        root: root.to_string_lossy().into_owned(),
    })
    .map_err(std::io::Error::other)?;
    fs::write(&temp, bytes)?;
    fs::rename(temp, preference_path(app_config_dir))
}

pub fn validate_root(root: &Path) -> Result<PathBuf, &'static str> {
    let metadata = fs::symlink_metadata(root).map_err(|_| "vault_library_unavailable")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("invalid_vault_library");
    }
    fs::canonicalize(root).map_err(|_| "vault_library_unavailable")
}

pub fn discover(root: &Path) -> Vec<VaultEntry> {
    let Ok(root_metadata) = fs::symlink_metadata(root) else {
        return Vec::new();
    };
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut vaults = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).ok()?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return None;
            }
            let id = Uuid::parse_str(entry.file_name().to_str()?).ok()?;
            let catalog = path.join("vault.sqlite3");
            let catalog_metadata = fs::symlink_metadata(&catalog).ok()?;
            if !catalog_metadata.is_file() || catalog_metadata.file_type().is_symlink() {
                return None;
            }
            Some(VaultEntry {
                id: id.to_string(),
                name: fs::read_to_string(path.join("vault-name"))
                    .ok()
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
                    .unwrap_or_else(|| format!("Vault {}", &id.to_string()[..8])),
                catalog_path: catalog.to_string_lossy().into_owned(),
            })
        })
        .collect::<Vec<_>>();
    vaults.sort_by(|left, right| left.id.cmp(&right.id));
    vaults.dedup_by(|left, right| left.id == right.id);
    vaults
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_root_is_under_app_data() {
        assert_eq!(
            default_root(Path::new("/data")),
            PathBuf::from("/data/vaults")
        );
    }

    #[test]
    fn discovery_is_immediate_and_ignores_malformed_entries() {
        let dir = tempdir().unwrap();
        let valid = Uuid::new_v4();
        fs::create_dir(dir.path().join(valid.to_string())).unwrap();
        fs::write(
            dir.path().join(valid.to_string()).join("vault.sqlite3"),
            b"",
        )
        .unwrap();
        fs::create_dir_all(dir.path().join("not-a-vault").join("nested")).unwrap();
        fs::create_dir(dir.path().join(Uuid::new_v4().to_string())).unwrap();
        assert_eq!(discover(dir.path()).len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn discovery_rejects_symlinked_catalogs() {
        let dir = tempdir().unwrap();
        let id = Uuid::new_v4();
        let vault = dir.path().join(id.to_string());
        fs::create_dir(&vault).unwrap();
        let outside = dir.path().join("outside.sqlite3");
        fs::write(&outside, b"not a catalog").unwrap();
        std::os::unix::fs::symlink(&outside, vault.join("vault.sqlite3")).unwrap();
        assert!(discover(dir.path()).is_empty());
    }

    #[test]
    fn preference_round_trips() {
        let config = tempdir().unwrap();
        let data = tempdir().unwrap();
        let root = data.path().join("custom");
        fs::create_dir(&root).unwrap();
        save_root(config.path(), &root).unwrap();
        assert_eq!(load_root(config.path(), data.path()).unwrap(), root);
    }
}

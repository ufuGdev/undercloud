#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

mod commands;
mod observability;
mod vault_library;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            app.manage(observability::initialize(app.handle()));
            Ok(())
        })
        .manage(commands::AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::create_vault,
            commands::vault_library_info,
            commands::set_vault_library_location,
            commands::reset_vault_library_location,
            commands::open_vault_library_folder,
            commands::move_vault_to_library,
            commands::rename_vault,
            commands::open_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::vault_status,
            commands::authorize_cloud_provider,
            commands::cancel_authorization,
            commands::remove_cloud_provider,
            commands::storage_target_ids,
            commands::provider_summaries,
            commands::add_local_provider,
            commands::remove_provider,
            commands::rename_provider,
            commands::activity_events,
            commands::list_files,
            commands::protection_map,
            commands::list_trash,
            commands::prepare_file_deletion,
            commands::confirm_file_deletion,
            commands::restore_from_trash,
            commands::upload_file,
            commands::restore_file,
            commands::cancel_restore,
            commands::cancel_upload,
            commands::file_health,
            commands::verify_all,
            commands::repair_file,
            commands::change_password,
            commands::export_recovery_kit,
            commands::import_recovery_kit,
            commands::recovery_freshness,
            commands::pick_file,
            commands::pick_folder,
            commands::logging_status,
            commands::open_log_folder
        ])
        .run(tauri::generate_context!())
        .expect("desktop runtime failed");
}

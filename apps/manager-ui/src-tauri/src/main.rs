//! Desktop binary entry point for the Aegis manager UI.
//!
//! On Windows in release builds we suppress the extra console window; all real
//! logic lives in the library so it stays testable and (optionally) shareable
//! with a mobile target.
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
#![forbid(unsafe_code)]

fn main() {
    aegis_manager_ui_lib::run();
}

use std::{env, process::Command};

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();

    println!("cargo::rerun-if-changed=src/driver/trampoline.asm");

    let status = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg("-o")
        .arg(format!("{}/trampoline", out_dir))
        .arg("src/driver/trampoline.asm")
        .status()
        .expect("Failed to run nasm");

    if !status.success() {
        panic!("NASM failed with exit status {}", status);
    }
}

//! Generate bindings to the Linux c Bluetooth API.

use std::path::{Path, PathBuf};
use std::{fs, io, process};

fn main() -> io::Result<()> {
    let workspace_path = std::env::current_dir()?;

    let bo_tie_linux_path: PathBuf = [&*workspace_path, Path::new("base-crates"), Path::new("bo-tie-linux")]
        .into_iter()
        .collect();

    let gen_bindings_path: PathBuf = [&*bo_tie_linux_path, Path::new("ci"), Path::new("gen-bindings")]
        .into_iter()
        .collect();

    let target_dir: PathBuf = [
        &*workspace_path,
        Path::new("target"),
        Path::new("ci"),
        Path::new("bo-tie-linux"),
        Path::new("bindings"),
    ]
    .into_iter()
    .collect();

    if !target_dir.exists() {
        fs::create_dir_all(&target_dir)?;
    }

    let generated_bindings_file: PathBuf = [&*target_dir, Path::new("bindings.rs")].into_iter().collect();

    println!("generating bindings...");

    let output = process::Command::new("docker")
        .arg("build")
        .arg("-o")
        .arg(target_dir)
        .arg(gen_bindings_path)
        .env("DOCKER_BUILDKIT", "1")
        .output()?;

    if !output.status.success() {
        return Err(io::Error::other(std::str::from_utf8(&output.stderr).unwrap()));
    }

    if !generated_bindings_file.exists() {
        return Err(io::Error::other("bindings file not generated"));
    }

    let new_bindings_dir: PathBuf = [&*bo_tie_linux_path, Path::new("src"), Path::new("device")]
        .into_iter()
        .collect();

    if !new_bindings_dir.exists() {
        fs::create_dir_all(&new_bindings_dir)?;
    }

    let new_bindings_file: PathBuf = [&*new_bindings_dir, Path::new("bindings.rs")].into_iter().collect();

    println!("outputting bindings to file {:?}", new_bindings_file.display());

    if cfg!(windows) {
        process::Command::new("copy")
            .arg(generated_bindings_file)
            .arg(new_bindings_file)
            .output()?;
    } else if cfg!(unix) {
        process::Command::new("cp")
            .arg(generated_bindings_file)
            .arg(new_bindings_file)
            .output()?;
    } else {
        unimplemented!("copy for this os in not implemented")
    }

    Ok(())
}

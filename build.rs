use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let go_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("go");
    let archive_path = out_dir.join("libcoraza.a");

    // Detect cross-compilation target
    let target = env::var("TARGET").unwrap();
    let (goos, goarch, goarm, cc) = match target.as_str() {
        t if t.contains("aarch64") && t.contains("linux") => {
            ("linux", "arm64", "", "aarch64-linux-gnu-gcc")
        }
        t if t.contains("armv7") && t.contains("linux") => {
            ("linux", "arm", "7", "arm-linux-gnueabihf-gcc")
        }
        t if t.contains("x86_64") && t.contains("linux") => ("linux", "amd64", "", "gcc"),
        other => panic!("Unsupported target: {other}"),
    };

    // Build Go c-archive with performance build tags
    let mut cmd = Command::new("go");
    cmd.current_dir(&go_dir)
        .args([
            "build",
            "-buildmode=c-archive",
            "-tags",
            "coraza.rule.rx_prefilter,coraza.rule.multiphase_evaluation,coraza.rule.no_regex_multiline",
            "-o",
        ])
        .arg(&archive_path)
        .arg(".")
        .env("CGO_ENABLED", "1")
        .env("GOOS", goos)
        .env("GOARCH", goarch);

    if !goarm.is_empty() {
        cmd.env("GOARM", goarm);
    }

    // Set cross-compiler if not native
    if !target.contains("x86_64") || !cfg!(target_arch = "x86_64") {
        cmd.env("CC", cc);
    }

    let status = cmd.status().expect("Failed to run `go build`");
    assert!(status.success(), "Go c-archive build failed");

    // Link the Go archive and its runtime dependencies
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=coraza");
    println!("cargo:rustc-link-lib=dylib=pthread");
    println!("cargo:rustc-link-lib=dylib=m");
    println!("cargo:rustc-link-lib=dylib=dl");

    // Also link resolv on Linux (Go net package needs it)
    if goos == "linux" {
        println!("cargo:rustc-link-lib=dylib=resolv");
    }

    // Rerun if Go sources change
    println!("cargo:rerun-if-changed=go/");
    for entry in std::fs::read_dir(&go_dir).expect("Failed to read go/ directory") {
        let entry = entry.expect("Failed to read directory entry");
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|ext| ext == "go" || ext == "mod" || ext == "sum")
        {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

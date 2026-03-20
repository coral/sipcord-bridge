//! Build script for pjsua bindings
//!
//! This script builds pjproject from source if not found, then generates
//! Rust bindings using bindgen.
//!
//! Set PJPROJECT_DIR to a pre-built pjproject install prefix to skip the
//! cmake build (used in Docker to separate the slow C build into its own layer).

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PJPROJECT_DIR");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    // If PJPROJECT_DIR is set, use pre-built pjproject (e.g. from a separate Docker stage).
    // Otherwise build from source via cmake.
    let include_paths = if let Ok(prefix) = env::var("PJPROJECT_DIR") {
        let prefix = PathBuf::from(&prefix);
        println!(
            "cargo:warning=Using pre-built pjproject from: {}",
            prefix.display()
        );

        let lib_dir = prefix.join("lib");
        println!("cargo:rustc-link-search=native={}", lib_dir.display());

        // Link libraries in the correct dependency order (same as build-from-source path)
        let pj_libs = [
            "pjsua-lib",
            "pjsua2",
            "pjsip-ua",
            "pjsip-simple",
            "pjsip",
            "pjmedia-codec",
            "pjmedia",
            "pjmedia-audiodev",
            "pjnath",
            "pjlib-util",
            "pjlib",
            "srtp",
            "resample",
            "speex",
            "g7221",
            "gsm",
            "ilbc",
        ];
        for lib in &pj_libs {
            println!("cargo:rustc-link-lib=static={}", lib);
        }

        vec![prefix.join("include")]
    } else {
        build_from_source(&out_dir)
    };

    // ---- System libraries (common to both paths) ----

    #[cfg(target_os = "macos")]
    {
        println!("cargo:rustc-link-lib=framework=AudioToolbox");
        println!("cargo:rustc-link-lib=framework=AudioUnit");
        println!("cargo:rustc-link-lib=framework=CoreAudio");
        println!("cargo:rustc-link-lib=framework=CoreServices");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=AVFoundation");
        println!("cargo:rustc-link-lib=framework=CoreMedia");
        println!("cargo:rustc-link-lib=framework=CoreVideo");
        println!("cargo:rustc-link-lib=framework=VideoToolbox");
        println!("cargo:rustc-link-lib=framework=Security");
    }

    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-lib=asound");
        println!("cargo:rustc-link-lib=pthread");
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=rt");
        println!("cargo:rustc-link-lib=uuid");
        println!("cargo:rustc-link-lib=opencore-amrnb");
        println!("cargo:rustc-link-lib=opencore-amrwb");
        println!("cargo:rustc-link-lib=opus");
    }

    // OpenSSL
    #[cfg(target_os = "macos")]
    {
        let openssl_paths = [
            "/opt/homebrew/opt/openssl@3/lib",
            "/opt/homebrew/opt/openssl/lib",
            "/usr/local/opt/openssl@3/lib",
            "/usr/local/opt/openssl/lib",
        ];
        for path in &openssl_paths {
            if std::path::Path::new(path).exists() {
                println!("cargo:rustc-link-search=native={}", path);
                break;
            }
        }

        let amr_paths = [
            "/opt/homebrew/opt/opencore-amr/lib",
            "/usr/local/opt/opencore-amr/lib",
        ];
        for path in &amr_paths {
            if std::path::Path::new(path).exists() {
                println!("cargo:rustc-link-search=native={}", path);
                println!("cargo:rustc-link-lib=opencore-amrnb");
                println!("cargo:rustc-link-lib=opencore-amrwb");
                break;
            }
        }

        let opus_paths = ["/opt/homebrew/opt/opus/lib", "/usr/local/opt/opus/lib"];
        for path in &opus_paths {
            if std::path::Path::new(path).exists() {
                println!("cargo:rustc-link-search=native={}", path);
                println!("cargo:rustc-link-lib=opus");
                break;
            }
        }
    }

    println!("cargo:rustc-link-lib=ssl");
    println!("cargo:rustc-link-lib=crypto");

    #[cfg(target_os = "macos")]
    println!("cargo:rustc-link-lib=c++");
    #[cfg(target_os = "linux")]
    println!("cargo:rustc-link-lib=stdc++");

    // ---- Generate bindings ----

    let mut clang_args = Vec::new();

    for path in &include_paths {
        clang_args.push(format!("-I{}", path.display()));
    }

    #[cfg(target_endian = "little")]
    {
        clang_args.push("-DPJ_IS_LITTLE_ENDIAN=1".to_string());
        clang_args.push("-DPJ_IS_BIG_ENDIAN=0".to_string());
    }
    #[cfg(target_endian = "big")]
    {
        clang_args.push("-DPJ_IS_LITTLE_ENDIAN=0".to_string());
        clang_args.push("-DPJ_IS_BIG_ENDIAN=1".to_string());
    }

    #[cfg(target_os = "macos")]
    {
        clang_args.push("-DPJ_DARWINOS=1".to_string());
        clang_args.push("-DPJ_HAS_LIMITS_H=1".to_string());
    }
    #[cfg(target_os = "linux")]
    {
        clang_args.push("-DPJ_LINUX=1".to_string());
        clang_args.push("-DPJ_HAS_LIMITS_H=1".to_string());
    }

    #[cfg(target_pointer_width = "64")]
    clang_args.push("-DPJ_HAS_INT64=1".to_string());

    clang_args.push("-DPJ_AUTOCONF=1".to_string());

    let pjsua_header = include_paths
        .iter()
        .find_map(|p| {
            let header = p.join("pjsua-lib/pjsua.h");
            if header.exists() {
                return Some(header);
            }
            let header = p.join("pjsua.h");
            if header.exists() {
                Some(header)
            } else {
                None
            }
        })
        .expect("Could not find pjsua.h header in installed location");

    println!(
        "cargo:warning=Using pjsua.h from: {}",
        pjsua_header.display()
    );
    println!("cargo:warning=Include paths: {:?}", include_paths);

    let bindings = bindgen::Builder::default()
        .header(pjsua_header.to_str().unwrap())
        .clang_args(&clang_args)
        .generate_comments(false)
        .allowlist_type(r"pj.*")
        .allowlist_type(r"PJ.*")
        .allowlist_var(r"pj.*")
        .allowlist_var(r"PJ.*")
        .allowlist_function(r"pj.*")
        .allowlist_function(r"PJ.*")
        .generate()
        .expect("Unable to generate bindings");

    let bindings_path = out_dir.join("bindings.rs");
    bindings
        .write_to_file(&bindings_path)
        .expect("Couldn't write bindings!");

    println!(
        "cargo:warning=Bindings written to: {}",
        bindings_path.display()
    );
}

/// Build pjproject from source and return include paths.
fn build_from_source(out_dir: &Path) -> Vec<PathBuf> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let pjproject_src = manifest_dir.join("pjproject");

    let pjproject_build = out_dir.join("pjproject-build");
    let pjproject_install = out_dir.join("pjproject-install");

    std::fs::create_dir_all(&pjproject_build).expect("Failed to create build directory");
    std::fs::create_dir_all(&pjproject_install).expect("Failed to create install directory");

    let include_dir = pjproject_install.join("include");
    let lib_dir = pjproject_install.join("lib");

    build_pjproject(&pjproject_src, &pjproject_build, &pjproject_install);

    let include_paths = vec![include_dir.clone()];
    let lib_paths = vec![lib_dir.clone()];

    // Set up library paths
    for path in &lib_paths {
        println!("cargo:rustc-link-search=native={}", path.display());
    }

    // For built-from-source pjproject, libraries are in the build directory subdirs
    let pjproject_build_for_libs = out_dir.join("pjproject-build");
    if pjproject_build_for_libs.exists() {
        let lib_subdirs = [
            "pjlib",
            "pjlib-util",
            "pjmedia",
            "pjnath",
            "pjsip",
            "third_party/resample",
            "third_party/speex",
            "third_party/g7221",
            "third_party/yuv",
            "third_party/gsm",
            "third_party/srtp",
            "third_party/ilbc",
        ];

        for subdir in &lib_subdirs {
            let lib_path = pjproject_build_for_libs.join(subdir);
            if lib_path.exists() {
                println!("cargo:rustc-link-search=native={}", lib_path.display());
            }
        }

        // Link libraries in the correct order (dependencies matter!)
        let pj_libs = [
            "pjsua-lib",        // main pjsua library
            "pjsua2",           // C++ wrapper (may be needed)
            "pjsip-ua",         // SIP user agent
            "pjsip-simple",     // SIP SIMPLE presence
            "pjsip",            // Core SIP
            "pjmedia-codec",    // Media codecs
            "pjmedia",          // Media framework
            "pjmedia-audiodev", // Audio device
            "pjnath",           // NAT traversal
            "pjlib-util",       // Utility functions
            "pjlib",            // Core library
            // Third party
            "srtp",
            "resample",
            "speex",
            "g7221",
            "gsm",
            "ilbc",
        ];

        for lib in &pj_libs {
            println!("cargo:rustc-link-lib=static={}", lib);
        }
    } else {
        // Link against pjproject libraries from install directory (static)
        for lib_path in &lib_paths {
            if let Ok(entries) = std::fs::read_dir(lib_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension() {
                        if ext == "a" {
                            if let Some(name) = path.file_stem() {
                                let name = name.to_string_lossy();
                                if name.starts_with("lib") {
                                    let lib_name = name.strip_prefix("lib").unwrap();
                                    println!("cargo:rustc-link-lib=static={}", lib_name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    include_paths
}

fn build_pjproject(
    pjproject_src: &std::path::Path,
    pjproject_build: &std::path::Path,
    pjproject_install: &std::path::Path,
) {
    // Check for .pc file in build dir (CMake install doesn't always copy it to install dir)
    let pc_file = pjproject_build.join("libpjproject.pc");

    if !pc_file.exists() {
        println!("cargo:warning=Building pjproject from source (this may take several minutes)...");

        // Detect cross-compilation target
        let target = env::var("TARGET").unwrap_or_default();
        let host = env::var("HOST").unwrap_or_default();
        let is_cross = target != host;

        // Collect C/CXX flags — merged at the end into CMAKE_C_FLAGS/CMAKE_CXX_FLAGS.
        // pjsua.h guards PJSUA_MAX_CALLS with #ifndef, so -D on the command line wins.
        let mut c_flags: Vec<&str> = vec!["-DPJSUA_MAX_CALLS=128"];

        let mut cmake_args = vec![
            "-G".to_string(),
            "Unix Makefiles".to_string(),
            format!("-DCMAKE_INSTALL_PREFIX={}", pjproject_install.display()),
            "-DCMAKE_BUILD_TYPE=Release".to_string(),
            "-DBUILD_SHARED_LIBS=OFF".to_string(),
            "-DPJ_SKIP_EXPERIMENTAL_NOTICE=ON".to_string(),
            // Disable tests to avoid linking issues with cross-compilation
            "-DPJ_ENABLE_TESTS=OFF".to_string(),
            "-DBUILD_TESTING=OFF".to_string(),
            // Disable video support
            "-DPJMEDIA_WITH_VIDEO=OFF".to_string(),
            "-DPJMEDIA_WITH_FFMPEG=OFF".to_string(),
            "-DPJMEDIA_WITH_LIBYUV=OFF".to_string(),
            // Enable AMR codecs (IMS/MR-NB support)
            "-DPJMEDIA_WITH_OPENCORE_AMRNB_CODEC=ON".to_string(),
            "-DPJMEDIA_WITH_OPENCORE_AMRWB_CODEC=ON".to_string(),
            // Enable Opus codec
            "-DPJMEDIA_WITH_OPUS_CODEC=ON".to_string(),
            // Enable TLS/SSL support with OpenSSL
            "-DPJLIB_WITH_SSL=openssl".to_string(),
        ];

        // Configure cross-compilation toolchain
        if is_cross {
            println!("cargo:warning=Cross-compiling for {} from {}", target, host);

            // Map Rust target to cross-compiler prefix
            let cross_prefix = match target.as_str() {
                "aarch64-unknown-linux-gnu" => "aarch64-linux-gnu",
                "x86_64-unknown-linux-gnu" => "x86_64-linux-gnu",
                _ => "",
            };

            if !cross_prefix.is_empty() {
                let cc = format!("{}-gcc", cross_prefix);
                let cxx = format!("{}-g++", cross_prefix);

                // Check if cross-compiler exists
                if std::process::Command::new("which")
                    .arg(&cc)
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
                {
                    cmake_args.push(format!("-DCMAKE_C_COMPILER={}", cc));
                    cmake_args.push(format!("-DCMAKE_CXX_COMPILER={}", cxx));
                    println!("cargo:warning=Using cross-compiler: {}", cc);

                    // ARM64: Fix atomic alignment issues
                    // 1. -mno-outline-atomics: Use inline atomics instead of helper functions
                    // 2. -DPJ_POOL_ALIGNMENT=8: Force pjlib pool to use 8-byte alignment (C define)
                    if target.contains("aarch64") {
                        c_flags.push("-mno-outline-atomics");
                        c_flags.push("-DPJ_POOL_ALIGNMENT=8");
                        println!(
                            "cargo:warning=ARM64: Using inline atomics with 8-byte pool alignment"
                        );
                    }

                    // The cross-compiler (from crossbuild-essential-arm64) has --sysroot=/usr/aarch64-linux-gnu
                    // baked into its specs, but the actual libraries are in /usr/lib/aarch64-linux-gnu/
                    // via Debian's multiarch. We must override the sysroot to "/" so the linker
                    // finds libc at /lib/aarch64-linux-gnu/ instead of the non-existent
                    // /usr/aarch64-linux-gnu/lib/libc.so.6
                    cmake_args.push("-DCMAKE_SYSROOT=/".to_string());
                    println!("cargo:warning=Overriding sysroot to / for multiarch compatibility");

                    // Help CMake find cross-compiled libraries in multiarch paths
                    let multiarch_lib = format!("/usr/lib/{}", cross_prefix);
                    if std::path::Path::new(&multiarch_lib).exists() {
                        cmake_args.push(format!("-DCMAKE_FIND_ROOT_PATH=/usr;{}", multiarch_lib));
                        cmake_args.push("-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=BOTH".to_string());
                        cmake_args.push("-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=BOTH".to_string());
                        cmake_args.push("-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER".to_string());
                        println!(
                            "cargo:warning=Using multiarch library path: {}",
                            multiarch_lib
                        );

                        // Explicitly set OpenSSL paths for cross-compilation
                        let openssl_ssl = format!("{}/libssl.so", multiarch_lib);
                        let openssl_crypto = format!("{}/libcrypto.so", multiarch_lib);
                        if std::path::Path::new(&openssl_ssl).exists() {
                            cmake_args.push("-DOPENSSL_ROOT_DIR=/usr".to_string());
                            cmake_args.push("-DOPENSSL_INCLUDE_DIR=/usr/include".to_string());
                            cmake_args.push(format!("-DOPENSSL_SSL_LIBRARY={}", openssl_ssl));
                            cmake_args.push(format!("-DOPENSSL_CRYPTO_LIBRARY={}", openssl_crypto));
                            println!(
                                "cargo:warning=Using cross-compiled OpenSSL from {}",
                                multiarch_lib
                            );
                        }

                        // Explicitly set Opus paths for cross-compilation
                        let opus_lib = format!("{}/libopus.so", multiarch_lib);
                        if std::path::Path::new(&opus_lib).exists() {
                            cmake_args.push("-DOPUS_INCLUDE_DIR=/usr/include".to_string());
                            cmake_args.push(format!("-DOPUS_LIBRARY={}", opus_lib));
                            println!(
                                "cargo:warning=Using cross-compiled Opus from {}",
                                multiarch_lib
                            );
                        }
                    }
                }
            }
        } else {
            // Native build - find OpenSSL in standard locations
            let openssl_prefixes = if cfg!(target_os = "macos") {
                vec![
                    "/opt/homebrew/opt/openssl@3",
                    "/opt/homebrew/opt/openssl",
                    "/usr/local/opt/openssl@3",
                    "/usr/local/opt/openssl",
                ]
            } else {
                vec!["/usr", "/usr/local"]
            };

            for prefix in &openssl_prefixes {
                let include_path = format!("{}/include", prefix);
                if std::path::Path::new(&include_path)
                    .join("openssl/ssl.h")
                    .exists()
                {
                    println!("cargo:warning=Found OpenSSL at: {}", prefix);
                    cmake_args.push(format!("-DOPENSSL_ROOT_DIR={}", prefix));
                    if cfg!(target_os = "macos") {
                        cmake_args.push(format!("-DOPENSSL_INCLUDE_DIR={}", include_path));
                        let lib_path = format!("{}/lib", prefix);
                        let static_crypto = format!("{}/libcrypto.a", lib_path);
                        let static_ssl = format!("{}/libssl.a", lib_path);
                        if std::path::Path::new(&static_crypto).exists() {
                            cmake_args.push(format!("-DOPENSSL_CRYPTO_LIBRARY={}", static_crypto));
                            cmake_args.push(format!("-DOPENSSL_SSL_LIBRARY={}", static_ssl));
                        }
                    }
                    break;
                }
            }

            // Native build - find Opus codec library
            let opus_prefixes = if cfg!(target_os = "macos") {
                vec!["/opt/homebrew/opt/opus", "/usr/local/opt/opus"]
            } else {
                vec!["/usr", "/usr/local"]
            };

            for prefix in &opus_prefixes {
                let include_path = format!("{}/include", prefix);
                if std::path::Path::new(&include_path)
                    .join("opus/opus.h")
                    .exists()
                {
                    println!("cargo:warning=Found Opus at: {}", prefix);
                    cmake_args.push(format!("-DOPUS_INCLUDE_DIR={}", include_path));
                    let lib_path = format!("{}/lib", prefix);
                    let opus_lib = if cfg!(target_os = "macos") {
                        format!("{}/libopus.a", lib_path)
                    } else {
                        format!("{}/libopus.so", lib_path)
                    };
                    if std::path::Path::new(&opus_lib).exists() {
                        cmake_args.push(format!("-DOPUS_LIBRARY={}", opus_lib));
                    }
                    break;
                }
            }
        }

        // Merge all collected C/CXX flags into cmake args
        if !c_flags.is_empty() {
            let flags = c_flags.join(" ");
            println!("cargo:warning=C flags: {}", flags);
            cmake_args.push(format!("-DCMAKE_C_FLAGS={}", flags));
            cmake_args.push(format!("-DCMAKE_CXX_FLAGS={}", flags));
        }

        cmake_args.push(pjproject_src.to_str().unwrap().to_string());

        // Run CMake configure
        let cmake_result = Command::new("cmake")
            .current_dir(pjproject_build)
            .args(&cmake_args)
            .output()
            .expect("Failed to run cmake configure");

        if !cmake_result.status.success() {
            eprintln!(
                "CMake configure stdout: {}",
                String::from_utf8_lossy(&cmake_result.stdout)
            );
            eprintln!(
                "CMake configure stderr: {}",
                String::from_utf8_lossy(&cmake_result.stderr)
            );
            panic!("CMake configure failed");
        }

        // Get number of CPUs for parallel build
        let num_cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);

        // Run CMake build - only build the libraries we need, not sample apps
        println!(
            "cargo:warning=Compiling pjproject with {} threads...",
            num_cpus
        );
        let mut build_args = vec![
            "--build".to_string(),
            ".".to_string(),
            "--config".to_string(),
            "Release".to_string(),
        ];

        // Specify only the library targets we need
        let targets = [
            "pjlib",
            "pjlib-util",
            "pjnath",
            "pjmedia",
            "pjmedia-audiodev",
            "pjmedia-codec",
            "pjsip",
            "pjsip-simple",
            "pjsip-ua",
            "pjsua-lib",
            "pjsua2",
            "resample",
            "srtp",
            "speex",
            "g7221",
            "gsm",
            "ilbc",
        ];
        for target in &targets {
            build_args.push("--target".to_string());
            build_args.push(target.to_string());
        }
        build_args.push("-j".to_string());
        build_args.push(num_cpus.to_string());

        let build_result = Command::new("cmake")
            .current_dir(pjproject_build)
            .args(&build_args)
            .output()
            .expect("Failed to run cmake build");

        if !build_result.status.success() {
            eprintln!(
                "CMake build stdout: {}",
                String::from_utf8_lossy(&build_result.stdout)
            );
            eprintln!(
                "CMake build stderr: {}",
                String::from_utf8_lossy(&build_result.stderr)
            );
            panic!("CMake build failed");
        }
        println!("cargo:warning=Library builds complete");

        // Run CMake install - may fail for sample apps but that's OK
        let install_result = Command::new("cmake")
            .current_dir(pjproject_build)
            .args(["--install", "."])
            .output()
            .expect("Failed to run cmake install");

        if !install_result.status.success() {
            // Install might fail for sample apps we didn't build, but libraries are installed
            println!("cargo:warning=CMake install had errors (OK if only sample apps failed)");
        }

        println!("cargo:warning=pjproject build complete!");
    } else {
        println!("cargo:warning=Using cached pjproject build");
    }
}

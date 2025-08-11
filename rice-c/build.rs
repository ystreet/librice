// avoid linking/regenerating when running on docs.rs
#[cfg(docsrs)]
fn main() {}

#[cfg(not(docsrs))]
fn main() {
    use std::env;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let destdir = Path::new(&out_dir).join("rice-proto-cbuild");
    let pkgconfigdir = destdir.clone().join("lib").join("pkgconfig");
    let rice_proto_dir = manifest_dir.join("../rice-proto");

    let rice_proto_exists = std::fs::File::open(rice_proto_dir.as_path()).is_ok();
    if rice_proto_exists {
        println!(
            "cargo:rerun-if-changed={}",
            rice_proto_dir.to_str().unwrap()
        );
        println!(
            "cargo:rerun-if-changed={}",
            rice_proto_dir.join("src").to_str().unwrap()
        );
        println!(
            "cargo:rerun-if-changed={}",
            rice_proto_dir.join("src").join("capi").to_str().unwrap()
        );
    }

    // Default to building the internal module if not already configured and the rice-proto
    // project exists.
    if env::var_os("SYSTEM_DEPS_RICE_PROTO_BUILD_INTERNAL").is_none()
        && env::var_os("SYSTEM_DEPS_BUILD_INTERNAL").is_none()
        && rice_proto_exists
    {
        env::set_var("SYSTEM_DEPS_RICE_PROTO_BUILD_INTERNAL", "auto");
        // use static linking for `cargo tarpaulin` to be able to run doc tests correctly.
        env::set_var("SYSTEM_DEPS_RICE_PROTO_LINK", "static");
    }
    let config = system_deps::Config::new()
        .add_build_internal("rice-proto", move |lib, version| {
            if rice_proto_exists {
                let target = env::var("TARGET").unwrap();
                let mut cmd = Command::new("cargo");
                cmd.stderr(std::process::Stdio::piped())
                    .args(["cinstall", "-p", "rice-proto", "--prefix"])
                    .arg(&destdir)
                    .args(["--libdir", "lib"])
                    .args(["--target", &target])
                    .args([
                        "--target-dir",
                        destdir.join("target").as_path().to_str().unwrap(),
                    ]);
                let cmd_state = &mut cmd;
                if env::var("DEBUG").map(|v| v == "true").unwrap_or(false) {
                    cmd_state.arg("--debug");
                }
                let status = cmd
                    .stderr(std::process::Stdio::piped())
                    .spawn()
                    .expect("Failed to build internal copy of rice-proto");
                let output = status.wait_with_output().unwrap();
                let stderr = String::from_utf8(output.stderr).unwrap();
                if !output.status.success() {
                    eprintln!("stderr: {stderr}");
                    panic!("Could not build rice-proto");
                }
            }
            system_deps::Library::from_internal_pkg_config(pkgconfigdir, lib, version)
        })
        .probe()
        .unwrap();

    let rice_proto = config.get_by_name("rice-proto").unwrap();
    let mut rice_proto_h = None;
    for path in rice_proto.include_paths.iter() {
        let mut path = path.clone();
        path.push("rice-proto.h");
        if std::fs::metadata(&path).is_ok() {
            rice_proto_h = Some(path.clone());
            break;
        }
    }
    let rice_proto_h = rice_proto_h.expect("Could not find rice-proto.h header");

    let bindings = bindgen::Builder::default()
        .header(rice_proto_h.as_path().to_str().unwrap())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_file(".*/rice/rice-.*\\.h")
        .prepend_enum_name(false)
        .default_enum_style(bindgen::EnumVariation::Consts)
        .disable_nested_struct_naming()
        .disable_name_namespacing()
        .no_copy(
            "Rice(Candidate|Transmit|AgentSocket|StreamIncomingData|DataImpl|GatheredCandidate)",
        )
        .default_non_copy_union_style(bindgen::NonCopyUnionStyle::ManuallyDrop)
        .anon_fields_prefix("field")
        .use_core()
        .generate_cstr(true)
        .generate()
        .unwrap();

    if rice_proto_exists {
        // only update the bindings if we are building from a local checkout.
        bindings
            .write_to_file(manifest_dir.join("src").join("bindings.rs"))
            .unwrap();
    }
}

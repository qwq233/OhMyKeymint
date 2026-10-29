fn main() {
    // Let the NDK linker locate libc++abi instead of bundling it into the Rust archive.
    println!("cargo:rustc-link-lib=static:-bundle=c++abi");
}

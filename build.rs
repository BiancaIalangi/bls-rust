// TODO make compatible for all platforms
// depends on the system: arm or amd || linux or macos
fn main() {
    // current implementation is for linux amd64
    println!("cargo:rustc-link-search=native=.");
    println!("cargo:rustc-link-lib=static=bls384_256");
    println!("cargo:rustc-link-lib=stdc++");
}

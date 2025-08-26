fn main() {
    // Path to the directory containing libbls384_256.a
    let bls_lib_path = "/home/bibi/bls-eth-rust";

    println!("cargo:rustc-link-search=native={}", bls_lib_path);
    println!("cargo:rustc-link-lib=static=bls384_256"); // 'lib' prefix and '.a' suffix are omitted
}

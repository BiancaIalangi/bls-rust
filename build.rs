fn main() {
    // The rest of your build script for bls...
    let mut build = cc::Build::new();
    build
        .cpp(true)
        .flag("-std=c++11")
        .flag("-fPIC") // Position-Independent Code, necessary for static libraries
        .flag("-O2")
        .include("/home/bibi/vendor/mcl/include")
        .include("/home/bibi/vendor/bls/include")
        .file("/home/bibi/vendor/bls/src/bls_c384_256.cpp")
        .file("/home/bibi/vendor/mcl/src/bn_c384_256.cpp")
        .file("/home/bibi/vendor/mcl/src/fp.cpp")
        .file("/home/bibi/vendor/mcl/src/asm/bint-x64-amd64.s")
        .compile("libblscpp.a");

    println!("cargo:rustc-link-lib=static=blscpp");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rustc-link-lib=gmp")
}

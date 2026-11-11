//! rekit 自带 ELF fixture 源码（x86_64-unknown-linux-musl）。
//!
//! 目的：给 `rekit funcs` 提供一组**自有编译**、可复现的 ELF64 样本，
//! 带 `.eh_frame` / `.eh_frame_hdr`，函数数量小且可控，便于端到端断言。
//!
//! 构建（Windows + rustup 自带 rust-lld，无需 gcc/WSL）：
//!   rustup target add x86_64-unknown-linux-musl
//!   rustc --target x86_64-unknown-linux-musl -O -C panic=abort \
//!         -C force-unwind-tables=yes -C strip=symbols \
//!         -C linker=<rustup>/lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe \
//!         tests/fixtures/src/hello_elf.rs -o tests/fixtures/hello_elf
//!
//! `.eh_frame` 是异常展开表，`strip=symbols` 不会删它；`.eh_frame_hdr` 由
//! `--eh-frame-hdr`（rustc 默认传入）生成。

/// 六个互不内联的函数，故意保留不同的序言形状：
/// `push rbp`（framepush）与 `sub rsp`（stackalloc）都会出现，
/// 用来验证「按编译器形状库」在 GCC/Clang 风格样本上的表现。
#[inline(never)]
#[no_mangle]
pub extern "C" fn fx_add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fx_mul(a: u32, b: u32) -> u32 {
    a.wrapping_mul(b)
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fx_mix(a: u32, b: u32) -> u32 {
    let mut acc = a;
    let mut i = 0u32;
    while i < b {
        acc = acc.wrapping_mul(1664525).wrapping_add(1013904223);
        i += 1;
    }
    acc
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fx_leaf(a: u32) -> u32 {
    a ^ 0x5A5A_5A5A
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fx_chain(a: u32) -> u32 {
    fx_add(a, fx_mul(a, 3))
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn fx_main(a: u32) -> u32 {
    fx_chain(a)
        .wrapping_add(fx_mix(a, 5))
        .wrapping_add(fx_leaf(fx_add(a, 1)))
}

fn main() {
    std::process::exit((fx_main(7) & 0x7F) as i32);
}

// 结构体字段偏移恢复的 ground truth 样本。
//
// `#[repr(C)]` 固定布局：a@0x00(u8)、b@0x04(u32)、c@0x08(u64)、d@0x10(ptr)。
// `probe_read` / `probe_write` 都是 extern "C" + noinline，参数从寄存器进来，
// 便于验证 `rekit data` 的 `[参数寄存器 + 偏移]` 统计是否落在 0/4/8/16 上。
#[repr(C)]
pub struct Probe {
    pub a: u8,
    pub b: u32,
    pub c: u64,
    pub d: *const u8,
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn probe_read(p: &Probe) -> u64 {
    p.a as u64 + p.b as u64 + p.c + p.d as usize as u64
}

#[no_mangle]
#[inline(never)]
pub extern "C" fn probe_write(p: &mut Probe, v: u8) {
    p.a = v;
    p.b = v as u32 + 1;
    p.c = v as u64 + 2;
    p.d = std::ptr::null();
}

fn main() {
    let mut p = Probe {
        a: 1,
        b: 2,
        c: 3,
        d: std::ptr::null(),
    };
    println!("{}", probe_read(&p));
    probe_write(&mut p, 4);
    println!("{}", p.c);
}

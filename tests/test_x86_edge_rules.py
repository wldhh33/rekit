# -*- coding: utf-8 -*-
"""x86 边规则的两条硬约束（来自 2026-11-12 独立闭包对照的实测差异）。

1. `_direct_target` 只认直接 `call/jmp` 的立即数目标；`call [IAT]` 一律返回 `None`。
   这是 rekit 与 Ghidra 引用图的已知差异：Ghidra 会经 IAT 把 `call [__guard_check_icall_fptr]`
   解析成到桩函数的直接引用，rekit 不跟间接调用。该差异不改变结论，但必须钉住。
2. `_reachable_authority` 在权威函数体的**整段区间**上线性解码，`ret` 之后的尾部字节
   仍会被扫描，因此「`ret` 后的尾跳」构成边。这与块遍历（CFG）不一致，
   是 `召回结果.md` 已知问题里"让数字偏低"的那条不对称。此处钉住现状，
   避免以后有人无意中"修好"它却没更新报告。
"""

from __future__ import annotations

from rekit.core.funcs import AuthorityTable, CodeSpace, _direct_target, _reachable_authority


def test_direct_target_rejects_memory_operand() -> None:
    # x86 notepad 的 CFG 校验调用真实形态：call dword ptr [0x42A5A4]
    assert _direct_target("dword ptr [0x42a5a4]") is None
    assert _direct_target("qword ptr [rip + 0x1a2b]") is None


def test_direct_target_accepts_immediate() -> None:
    assert _direct_target("0x40b650") == 0x40B650


def test_reachable_authority_follows_jmp_after_ret() -> None:
    # 0x1000: ret
    # 0x1001: jmp 0x1010   （相对编码 E9 0A 00 00 00，下一条指令 0x1006 + 0xA = 0x1010）
    # 0x1006..0x100F: int3 填充
    # 0x1010: ret
    data = bytes.fromhex("c3 e9 0a 00 00 00".replace(" ", ""))
    data += b"\xcc" * 10 + b"\xc3"
    space = CodeSpace([(0x1000, data)], bits=32)
    auth = AuthorityTable(name="synthetic",
                          spans=[(0x1000, 0x1006), (0x1010, 0x1011)],
                          starts=[0x1000, 0x1010])

    reach = _reachable_authority(None, space, auth, {0x1000})

    # 块遍历到 `ret` 就停了，但线性解码会继续，于是尾部 jmp 把 0x1010 拖进分母。
    # 这正是冻结口径允许、且让 98.2% 偏低的那条不对称。
    assert reach == {0x1000, 0x1010}


def test_reachable_authority_drops_memory_edges() -> None:
    # 0x2000: call dword ptr [0x3000]（FF 15 00 30 00 00）; 0x2006: ret
    data = bytes.fromhex("ff1500300000") + b"\xc3"
    space = CodeSpace([(0x2000, data)], bits=32)
    auth = AuthorityTable(name="synthetic", spans=[(0x2000, 0x2007)],
                          starts=[0x2000])

    # 间接调用不构成边：闭包里只有自己。
    assert _reachable_authority(None, space, auth, {0x2000}) == {0x2000}

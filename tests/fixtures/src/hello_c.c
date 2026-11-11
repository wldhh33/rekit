/* 跨编译器 fixture 源码：同一份 C 代码给 GCC / Clang / MSVC 编译。
 *
 * 目的是让"函数边界发现"在四个工具链族上都有可复现样本，而不是只测 Rust。
 * 每个 fx_* 都禁止内联，便于对齐权威表（.pdata / .eh_frame）逐条核对。
 */
#include <stdio.h>

#if defined(_MSC_VER)
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

NOINLINE int fx_add(int a, int b) { return a + b; }

NOINLINE int fx_mul(int a, int b) { return a * b; }

NOINLINE int fx_mix(int a) {
    int r = 0;
    for (int i = 0; i < a; i++) {
        r += i ^ (r >> 1);
    }
    return r;
}

NOINLINE int fx_chain(int a) { return fx_mix(a) + fx_add(a, 3) + fx_mul(a, 5); }

NOINLINE int fx_leaf(int a) { return a * 7 + 1; }

typedef int (*binop)(int, int);

NOINLINE int fx_apply(binop f, int a, int b) { return f ? f(a, b) : -1; }

int main(void) {
    binop table[2] = {fx_add, fx_mul};
    int sum = 0;
    for (int i = 0; i < 2; i++) {
        sum += fx_apply(table[i], i + 1, i + 2);
    }
    printf("hello from C, sum=%d leaf=%d\n", sum + fx_chain(4), fx_leaf(3));
    return 0;
}

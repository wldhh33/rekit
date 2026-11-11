// 跨架构 fixture 源码：同一份 Go 代码编到 linux/amd64、linux/arm64、windows/amd64。
//
// `.gopclntab` 是 Go 自带的第三套权威函数表，因此这份样本同时验证
// "非 x86 架构" 与 "Go 权威表" 两条线。
package main

import "fmt"

//go:noinline
func fxAdd(a, b int) int { return a + b }

//go:noinline
func fxMul(a, b int) int { return a * b }

//go:noinline
func fxMix(a int) int {
	r := 0
	for i := 0; i < a; i++ {
		r += i ^ (r >> 1)
	}
	return r
}

//go:noinline
func fxChain(a int) int { return fxMix(a) + fxAdd(a, 3) + fxMul(a, 5) }

//go:noinline
func fxLeaf(a int) int { return a*7 + 1 }

func main() {
	fmt.Println("hello from Go", fxChain(10)+fxLeaf(3))
}

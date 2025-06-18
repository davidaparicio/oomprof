package main

import "fmt"

// zhttps://github.com/golang/go/issues/72063
// Y is the Y-combinator based on https://dreamsongs.com/Files/WhyOfY.pdf
func Y[Endo ~func(RecFct) RecFct, RecFct ~func(T) R, T, R any](f Endo) RecFct {

	type internal[RecFct ~func(T) R, T, R any] func(internal[RecFct, T, R]) RecFct

	g := func(h internal[RecFct, T, R]) RecFct {
		return func(t T) R {
			return f(h(h))(t)
		}
	}
	return g(g)
}

func main() {

	fct := Y(func(r func(int) int) func(int) int {
		return func(n int) int {
			if n <= 0 {
				return 1
			}
			return n * r(n-1)
		}
	})

	fmt.Println(fct(10))
}

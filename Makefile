default: release

check:
	dune build @check
	dune build @runtest

release:
	dune build --profile=release

fmt:
	dune build @fmt --auto-promote

clean:
	dune clean

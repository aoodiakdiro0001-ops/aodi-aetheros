# Aodı-AetherOS — Makefile (zero-dep convenience wrappers)
.PHONY: test build native probe demo clean lint

PY ?= python3

test:
	$(PY) tests/test_aether.py -v

build: native
	cd meshd && gofmt -l . && go vet ./... && go build -o ../bin/aether-meshd .

native:
	c++ -O2 -std=c++17 -Wall -o native/aether_vm native/aether_vm.cpp

lint:
	gofmt -l meshd
	$(PY) -m py_compile core/cli.py core/aether/*.py

probe:
	$(PY) core/cli.py probe

demo:
	$(PY) core/cli.py run "3*x + 7*y - 2" --inputs 11,-4 --redundancy 2
	$(PY) core/cli.py he-demo "a + b - c" --inputs 120,42,7 --remote

clean:
	rm -rf bin native/aether_vm core/aether/__pycache__ core/__pycache__ \
	       tests/__pycache__ he_key.json nodes.json

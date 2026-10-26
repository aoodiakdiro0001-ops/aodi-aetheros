# Aodı-AetherOS — zero-dependency driver (make)
PY ?= python3
GIT_TOP := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

.PHONY: help mesh core relay build test demo clean

help:
	@echo "targets: mesh core relay build test demo clean"

build: mesh
	cd mesh && go build -o ../bin/ae-mesh .

mesh:
	cd mesh && gofmt -w . && go vet ./... && go build -o ../bin/ae-mesh .

core:
	$(PY) core/server.py

relay:
	node relay/relay.js

test:
	$(PY) -m unittest discover tests

demo: build
	./bin/ae-mesh & sleep 1
	$(PY) core/server.py & sleep 1
	@echo "open http://127.0.0.1:9461/  ·  $(PY) core/cli.py status"

clean:
	rm -rf bin mesh/ae-mesh
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
	$(PY) -m unittest discover tests >/dev/null 2>&1 || true

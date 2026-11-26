# mateprobe — tareas de desarrollo y empaquetado.
# Requiere Go >= 1.27 solo para compilar; el binario resultante no necesita nada.

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
DIST    := dist
PLATFORMS := linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64

.PHONY: all check fmt vet test build build-linux dist examples clean

all: check build

check: fmt vet test

fmt:
	@test -z "$$(gofmt -l .)" || (echo "gofmt pendiente en:"; gofmt -l .; exit 1)

vet:
	go vet ./...

test:
	go test -race ./...

build:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/mateprobe ./cmd/mateprobe

# Solo Linux amd64: dist/mateprobe-<versión>-linux-amd64
build-linux:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/mateprobe-$(VERSION)-linux-amd64 ./cmd/mateprobe

# Binarios para todas las plataformas + SHA256SUMS.
dist: clean
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; ext=""; [ $$os = windows ] && ext=".exe"; \
	  out=$(DIST)/mateprobe-$(VERSION)-$$os-$$arch$$ext; \
	  echo "-> $$out"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags '$(LDFLAGS)' -o $$out ./cmd/mateprobe || exit 1; \
	done
	@cd $(DIST) && (sha256sum mateprobe-* > SHA256SUMS 2>/dev/null || shasum -a 256 mateprobe-* > SHA256SUMS)
	@echo "Listo: $(DIST)/"

# Regenera examples/ desde servidores locales (127.0.0.1:18081-18089).
examples:
	go run ./tools/genexamples examples
	go run ./tools/genauditexamples examples

# Borra solo los artefactos generados (archivos, no directorios).
clean:
	@rm -f $(DIST)/mateprobe $(DIST)/mateprobe-* $(DIST)/SHA256SUMS

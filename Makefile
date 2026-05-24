.PHONY: build run run-race test test-race test-coverage lint fmt vet tidy clean build-all install help

BINARY_NAME = silvia-castillo
BUILD_DIR   = bin
CMD_PATH    = ./cmd/silvia-castillo
VERSION     ?= dev
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_TIME  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS     = -ldflags "\
  -X github.com/vmvarela/iptablestutorial/internal/version.Version=$(VERSION) \
  -X github.com/vmvarela/iptablestutorial/internal/version.GitCommit=$(COMMIT) \
  -X github.com/vmvarela/iptablestutorial/internal/version.BuildTime=$(BUILD_TIME)"

build:
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)

run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

run-race:
	go run -race $(LDFLAGS) $(CMD_PATH)

test:
	go test -v ./...

test-race:
	go test -race -v ./...

test-coverage:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-fuzz:
	go test -fuzz=FuzzParseLine -fuzztime=30s ./internal/engine/
	go test -fuzz=FuzzTranslateCLI -fuzztime=30s ./internal/translate/

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w . 2>/dev/null || true

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf $(BUILD_DIR) coverage.out coverage.html

build-all:
	GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64  $(CMD_PATH)
	GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64  $(CMD_PATH)
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)

install:
	go install $(LDFLAGS) $(CMD_PATH)

help:
	@echo "Objetivos disponibles:"
	@echo "  build          Compilar el binario"
	@echo "  run            Compilar y ejecutar"
	@echo "  run-race       Ejecutar con detector de races"
	@echo "  test           Ejecutar tests"
	@echo "  test-race      Tests con detector de races"
	@echo "  test-coverage  Tests con informe de cobertura"
	@echo "  test-fuzz      Ejecutar fuzzing (30s)"
	@echo "  lint           Ejecutar golangci-lint"
	@echo "  fmt            Formatear código"
	@echo "  vet            go vet"
	@echo "  tidy           go mod tidy"
	@echo "  clean          Limpiar artefactos"
	@echo "  build-all      Compilar para todas las plataformas"
	@echo "  install        go install"

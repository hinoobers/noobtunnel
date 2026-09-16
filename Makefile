.PHONY: build test race vet dist clean demo

build:
	go build ./...

test:
	go test ./... -count=1

race:
	go test -race ./internal/... -count=1

vet:
	go vet ./...

dist:
	bash scripts/build.sh

demo:
	go run ./cmd/noobtunnel server --demo --backend fake --listen 127.0.0.1:8443 --admin-password demo-password-1

clean:
	rm -rf dist .gocache

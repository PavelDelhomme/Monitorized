.PHONY: build run test docker up down tidy

build:
	go build -ldflags="-s -w" -o bin/monitorized ./cmd/monitorized

run: build
	@test -f .env || (echo "Copiez .env.example vers .env" && exit 1)
	set -a && . ./.env && set +a && ./bin/monitorized

test:
	go test ./...

docker:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

tidy:
	go mod tidy

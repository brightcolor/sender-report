APP=sender-report

.PHONY: build run test compose-up compose-down

build:
	go build -o bin/$(APP) ./cmd/sender-report

run:
	go run ./cmd/sender-report

test:
	go test ./...

compose-up:
	docker compose up --build -d

compose-down:
	docker compose down

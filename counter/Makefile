.PHONY: all gen go build run

all:
	@echo "Usage:"
	@echo "  make gen   - Run go generate"
	@echo "  make go    - Install all required modules"
	@echo "  make build - Compile the project"
	@echo "  make run   - Run all above steps and execute the build binary"

gen:
	go generate ./...

go:
	go mod tidy

build: go gen 
	go build -o counter .

run: gen go build
	./counter
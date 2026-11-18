.PHONY: build test lint install clean

build:
	go build -o netboy .

test:
	go test -race ./...

lint:
	golangci-lint run ./...

install:
	go install .

clean:
	rm -f netboy coverage.out

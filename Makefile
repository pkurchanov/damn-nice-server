all:
	@make test

build:
	@go build -o ./bin/dns .

test: build
	@./bin/dns

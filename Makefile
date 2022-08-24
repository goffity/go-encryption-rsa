.PHONY: build run

gen-key:
	openssl genrsa -out private.pem 4096 && openssl rsa -in private.pem -pubout -out public.pem

run: gen-key
	go run .
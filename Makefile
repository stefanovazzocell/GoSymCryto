.PHONY: test
test:
	@go test -run=^Test -race -cover ./...

.PHONY: bench
bench:
	@go test -run=^$$ -cover -bench ./...

.PHONY: github_actions
github_actions:
	@echo "> Run 'go vet'..."
	@go vet ./...
	@echo "> Racing testing..."
	@go test -race -cover ./...
	@echo -e "\n> Racing benchmarks..."
	@go test -run=^$$ -race -cover -bench . -benchtime 1ms ./...
	@echo -e "\n> Running a very quick fuzz test..."
	@make fuzz-lite

.PHONY: security
security:
	@echo "> Run 'go vet'..."
	@go vet ./...
	@echo "> Racing testing..."
	@go test -race -cover ./...
	@echo -e "\n> Racing benchmarks..."
	@go test -run=^$$ -race -cover -bench . ./...
	@echo -e "\n> Running gosec..."
	@gosec ./...
	@echo -e "\n> Running a very quick fuzz test..."
	@make fuzz-lite

.PHONY: fuzz-lite
fuzz-lite:
	@echo "Fuzzing Encoding..."
	@go test -fuzz "FuzzEncoding" -run=^$$ -fuzztime 3s -race ./internal/helpers
	@echo "Fuzzing Encryption..."
	@go test -fuzz "FuzzEncryption" -run=^$$ -fuzztime 3s -race ./internal/helpers
	@echo "Fuzzing DeriveKey..."
	@go test -fuzz "FuzzDeriveKey" -run=^$$ -fuzztime 3s -race ./internal/helpers
	@echo "Fuzzing DeriveSecureKey..."
	@go test -fuzz "FuzzDeriveSecureKey" -run=^$$ -fuzztime 3s -race ./internal/helpers

.PHONY: fuzz
fuzz:
	@echo "Fuzzing Encoding..."
	@go test -fuzz "FuzzEncoding" -run=^$$ -fuzztime 30s -race ./internal/helpers
	@echo "Fuzzing Encryption..."
	@go test -fuzz "FuzzEncryption" -run=^$$ -fuzztime 1m -race ./internal/helpers
	@echo "Fuzzing DeriveKey..."
	@go test -fuzz "FuzzDeriveKey" -run=^$$ -fuzztime 30s -race ./internal/helpers
	@echo "Fuzzing DeriveSecureKey..."
	@go test -fuzz "FuzzDeriveSecureKey" -run=^$$ -fuzztime 1m -race ./internal/helpers

.PHONY: fuzz-long
fuzz-long:
	@echo "Fuzzing Encoding..."
	@go test -fuzz "FuzzEncoding" -run=^$$ -fuzztime 10m -race ./internal/helpers
	@echo "Fuzzing Encryption..."
	@go test -fuzz "FuzzEncryption" -run=^$$ -fuzztime 15m -race ./internal/helpers
	@echo "Fuzzing DeriveKey..."
	@go test -fuzz "FuzzDeriveKey" -run=^$$ -fuzztime 10m -race ./internal/helpers
	@echo "Fuzzing DeriveSecureKey..."
	@go test -fuzz "FuzzDeriveSecureKey" -run=^$$ -fuzztime 15m -race ./internal/helpers

.PHONY: clean
clean:
	rm -f *.out
	go clean
	go fmt ./...
	go vet ./...
.PHONY: build test clean lint run-ingest run-correlate run-query

BINDIR := bin
BINARIES := sentinel-ingest sentinel-correlate sentinel-query sentinel-cli
MODULE := github.com/SentinelSIEM/sentinel-siem

all: build

build:
	@mkdir -p $(BINDIR)
	@for bin in $(BINARIES); do \
		echo "Building $$bin..."; \
		go build -o $(BINDIR)/$$bin ./cmd/$$bin; \
	done
	@echo "All binaries built in $(BINDIR)/"

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -rf $(BINDIR)

run-ingest: build
	./$(BINDIR)/sentinel-ingest

run-correlate: build
	./$(BINDIR)/sentinel-correlate

run-query: build
	./$(BINDIR)/sentinel-query

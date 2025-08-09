all: mediacache mediacache-ipblocker

mediacache: cmd/mediacache/*.go
	go build -o bin/mediacache cmd/mediacache/*.go

mediacache-ipblocker: cmd/mediacache-ipblocker/*.go
	go build -o bin/mediacache-ipblocker cmd/mediacache-ipblocker/*.go

.PHONY: clean
clean:
	rm -rf bin

.PHONY: install
install:
	go install ./cmd/mediacache
	go install ./cmd/mediacache-ipblocker

.PHONY: fetch-blocklist
fetch-blocklist: mediacache-ipblocker
	./bin/mediacache-ipblocker -output blocklist.json -verbose

.PHONY: precommit
precommit:
	go fmt ./...
	go vet ./...

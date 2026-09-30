# The broker is built on the Mac and shipped as a static binary: bastion (Pi 5, linux/arm64) needs no Go toolchain.
.PHONY: test dist clean

test:
	cd broker && go vet ./... && go test -race -count=1 ./...

dist: test
	cd broker && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../deploy/broker ./cmd/broker
	@shasum -a 256 deploy/broker

clean:
	rm -f deploy/broker

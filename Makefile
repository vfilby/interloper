# The broker is built on the Mac and shipped as a static binary: bastion (Pi 5, linux/arm64) needs no Go toolchain.
.PHONY: test ios-test e2e e2e-ui dist clean

test:
	cd broker && go vet ./... && go test -race -count=1 ./...

ios-test:
	cd ios/ApproverKit && swift test

e2e:
	scripts/e2e-cli.sh

e2e-ui:
	scripts/e2e-ui.sh

dist: test
	cd broker && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../deploy/broker ./cmd/broker
	@shasum -a 256 deploy/broker

clean:
	rm -f deploy/broker

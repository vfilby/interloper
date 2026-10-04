# The broker is built on the Mac and shipped as a static binary: bastion (Pi 5, linux/arm64) needs no Go toolchain.
.PHONY: test ios-test e2e e2e-ui dist dist-adapter clean

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

# The Warpgate adapter for bastion (docs/runbooks/deploy-clearing-house.md). The hub is built on n from the
# pinned commit (DockerStacks/interloper-hub).
dist-adapter: test
	cd broker && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../deploy/adapter/wga-adapter ./cmd/wga-adapter
	@shasum -a 256 deploy/adapter/wga-adapter

clean:
	rm -f deploy/broker deploy/adapter/wga-adapter

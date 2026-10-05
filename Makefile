.PHONY: test ios-test e2e e2e-ui dist-adapter clean

test:
	cd broker && go vet ./... && go test -race -count=1 ./...

ios-test:
	cd ios/ApproverKit && swift test

e2e:
	scripts/e2e-cli.sh

e2e-ui:
	scripts/e2e-ui.sh

# The Warpgate adapter, for the Warpgate host (docs/runbooks/deploy-clearing-house.md).
dist-adapter: test
	cd broker && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o ../deploy/adapter/wga-adapter ./cmd/wga-adapter
	@shasum -a 256 deploy/adapter/wga-adapter

clean:
	rm -f deploy/adapter/wga-adapter

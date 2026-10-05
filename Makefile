.PHONY: check test ios-test e2e e2e-ui build dist-adapter docker-hub clean

# What CI runs on every push and pull request (.github/workflows/ci.yml), minus Docker.
check: test e2e
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

test:
	go vet ./... && go test -race -count=1 ./...

ios-test:
	cd ios/ApproverKit && swift test

e2e:
	scripts/e2e-cli.sh

e2e-ui:
	scripts/e2e-ui.sh

# Every command, for this machine, into bin/.
build:
	go build -o bin/ ./broker/cmd/... ./adapter/cmd/... ./adapters/warpgate/cmd/...

# The Warpgate adapter, for the Warpgate host (adapters/warpgate/README.md).
dist-adapter: test
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o adapters/warpgate/deploy/interpose-adapter ./adapters/warpgate/cmd/interpose-adapter
	@shasum -a 256 adapters/warpgate/deploy/interpose-adapter

# The hub's container image (docs/docker.md).
docker-hub:
	docker build -f broker/Dockerfile -t interpose-hub:local .

clean:
	rm -rf bin adapters/warpgate/deploy/interpose-adapter

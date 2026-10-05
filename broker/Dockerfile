# The hub (interpose-hub), built from source. Build from the repository root (one Go module):
#   docker build -f broker/Dockerfile -t interpose-hub:local .
# distroless/static: no shell, no package manager. Setup: docs/docker.md.
# The build stage runs on the build machine and cross-compiles for the target, so a multi-arch build needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY broker ./broker
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags='-s -w' -o /out/interpose-hub ./broker/cmd/interpose-hub

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/interpose-hub /interpose-hub
ENV GOMEMLIMIT=96MiB
EXPOSE 8740 8741
ENTRYPOINT ["/interpose-hub", "-state=/data"]

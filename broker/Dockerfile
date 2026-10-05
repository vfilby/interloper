# The hub (wga-hub), built from source. Build from the repository root (one Go module):
#   docker build -f broker/Dockerfile -t interpose-hub:local .
# distroless/static: no shell, no package manager. Setup: docs/docker.md.
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY internal ./internal
COPY broker ./broker
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/wga-hub ./broker/cmd/wga-hub

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wga-hub /wga-hub
ENV GOMEMLIMIT=96MiB
EXPOSE 8740 8741
ENTRYPOINT ["/wga-hub", "-state=/data"]

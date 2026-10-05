# The Warpgate adapter, built on the Warpgate host from the binary `make dist-adapter` produced (linux/arm64,
# static). distroless/static: no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY wga-adapter /wga-adapter
ENV GOMEMLIMIT=48MiB
ENTRYPOINT ["/wga-adapter"]

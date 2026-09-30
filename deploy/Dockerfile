# Built on bastion from the binary `make dist` produced on the Mac (linux/arm64, static).
# distroless/static: no shell, no package manager, runs as nonroot (65532).
FROM gcr.io/distroless/static-debian12:nonroot
COPY broker /broker
ENV GOMEMLIMIT=32MiB
USER 65532:65532
ENTRYPOINT ["/broker"]

# The mail adapter, built on the Mailpit host from the binary `make dist-adapter-mailpit` produced (linux/amd64 by
# default, static). distroless/static: no shell, no package manager.
FROM gcr.io/distroless/static-debian12:nonroot
COPY interpose-adapter-mailpit /interpose-adapter-mailpit
ENV GOMEMLIMIT=48MiB
ENTRYPOINT ["/interpose-adapter-mailpit"]

# syntax=docker/dockerfile:1
# OPA with the repository's policies baked in, so a deployment always runs
# the policies of the same commit as the API (no ConfigMap to keep in sync).
FROM openpolicyagent/opa:1.0.0-static
COPY policies /policies
USER 65532:65532
ENTRYPOINT ["/opa"]
CMD ["run", "--server", "--addr=0.0.0.0:8181", "--log-format=json", "--authentication=token", "--authorization=basic", "/policies"]

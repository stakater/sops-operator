# Serves the file-based catalog rendered by hack/generate-catalog-index.sh.
FROM quay.io/operator-framework/opm:v1.74.0
ENTRYPOINT ["/bin/opm"]
CMD ["serve", "/configs", "--cache-dir=/tmp/cache"]
# The rendered catalog to serve; the OLM e2e run builds from its own copy of catalog/.
ARG CATALOG_RELEASE=catalog/release
ADD ${CATALOG_RELEASE} /configs
RUN ["/bin/opm", "serve", "/configs", "--cache-dir=/tmp/cache", "--cache-only"]
LABEL operators.operatorframework.io.index.configs.v1=/configs

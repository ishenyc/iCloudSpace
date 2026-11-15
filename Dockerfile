FROM --platform=$BUILDPLATFORM node:26.13.1-bookworm-slim@sha256:5df79989ed685e09f0a98019db4cebfb22fb9df1a53c0161664a011f7ff6b0f1 AS web
WORKDIR /work
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/tsconfig.json frontend/vite.config.ts frontend/index.html frontend/viewer.html frontend/docs.html ./
COPY frontend/src/ ./src/
COPY frontend/public/ ./public/
RUN npm run build

FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb AS go-source
ENV GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0
WORKDIR /work
COPY backend/go.mod backend/go.sum ./
RUN --mount=type=cache,id=icloudspace-modules,target=/go/pkg/mod go mod download
COPY backend/cmd/ ./cmd/
COPY backend/internal/ ./internal/

FROM go-source AS application-build
ARG TARGETARCH
RUN --mount=type=cache,id=icloudspace-modules,target=/go/pkg/mod \
    --mount=type=cache,id=icloudspace-compile,target=/root/.cache/go-build \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/icloudspace ./cmd/icloudspace && \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/icloudspace-operator ./cmd/icloudspace-operator && \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/icloudspace-install ./cmd/icloudspace-install && \
    GOOS=linux GOARCH=$TARGETARCH go build -trimpath -buildvcs=false -ldflags='-s -w -buildid=' -o /out/icloudspace-health ./cmd/icloudspace-health

FROM scratch AS application
ARG SOURCE_REVISION=unspecified
ARG SOURCE_DIGEST=unspecified
LABEL org.opencontainers.image.title="iCloudSpace" \
      org.opencontainers.image.revision=$SOURCE_REVISION \
      io.icloudspace.source-digest=$SOURCE_DIGEST \
      org.opencontainers.image.authors="iShenyc" \
      org.opencontainers.image.licenses="MIT"
COPY --from=application-build /out/icloudspace /icloudspace
COPY --from=application-build /out/icloudspace-operator /icloudspace-operator
COPY --from=application-build /out/icloudspace-install /icloudspace-install
COPY --from=application-build /out/icloudspace-health /icloudspace-health
COPY --from=go-source /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=go-source /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=web /work/dist /web
COPY LICENSE THIRD_PARTY_NOTICES.md /licenses/
COPY --from=go-source /usr/share/doc/ca-certificates/copyright /usr/share/doc/ca-certificates/copyright
COPY --from=go-source /usr/share/doc/tzdata/copyright /usr/share/doc/tzdata/copyright
COPY --from=go-source /usr/share/common-licenses/GPL-2 /usr/share/common-licenses/GPL-2
USER 65532:65532
EXPOSE 8080 1993
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/icloudspace-health", "-address", "127.0.0.1:8080"]
ENTRYPOINT ["/icloudspace"]
CMD ["-process", "/run/space/process.json"]

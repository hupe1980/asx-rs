# asx-phase4-peer: phase4 4.8.1 as an AS4 counterparty for the asx-rs interop job.
# Base images are pinned by manifest-list digest (multi-arch). The build stage
# runs on the build platform: bytecode is architecture-neutral, no emulation.
FROM --platform=$BUILDPLATFORM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -B -q --strict-checksums dependency:go-offline -DexcludeReactor=true || true
COPY src ./src
RUN mvn -B -q --strict-checksums -DskipTests package \
 && mkdir -p /out \
 && cp target/peer.jar /out/peer.jar \
 && cp -r target/lib /out/lib

FROM eclipse-temurin:21.0.8_9-jre@sha256:66bb900643426ad01996d25bada7d56751913f9cec3b827fcb715d2ec9a0fbfc
ARG PEER_REVISION=4.8.1-r3
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="asx-phase4-peer" \
      org.opencontainers.image.version="${PEER_REVISION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.source="https://github.com/hupe1980/asx-rs" \
      org.opencontainers.image.licenses="Apache-2.0" \
      io.asx.phase4.version="4.8.1"
RUN groupadd --system --gid 10001 peer \
 && useradd --system --uid 10001 --gid peer --home-dir /app --shell /usr/sbin/nologin peer \
 && mkdir -p /data /config \
 && chown peer:peer /data
COPY --from=build /out/ /app/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["java", "-Xmx384m", "-jar", "/app/peer.jar"]
CMD ["--peer.config=/config/peer.json"]

# Backend image for the scan funnel. Build context MUST be the repo root, because
# the server imports ../bin/scan.mjs:  docker build -f server/Dockerfile .
FROM node:22-slim

# tar: the scanner downloads + extracts target repos as tarballs. ca-certificates:
# https to the GitHub API + OSV.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates tar \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Zero runtime deps — just the code the server needs (bin/ + server/).
COPY bin ./bin
COPY server ./server

ENV NODE_ENV=production \
    PORT=8080 \
    JOBS_FILE=/data/jobs.json

EXPOSE 8080
# /data is a mounted volume in prod so jobs survive restarts (see fly.toml).
CMD ["node", "server/index.mjs"]

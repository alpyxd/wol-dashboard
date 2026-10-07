FROM node:22-bookworm-slim

# Uygulamanın dışarıdan çağırdığı araçlar: ip (ARP/neigh), ping, ssh/ssh-keygen
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 iputils-ping openssh-client tzdata \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY server.js .

# data.json ve keys/ bu klasörde tutulur (docker-compose'da ./data'ya bağlanır)
ENV PORT=80 \
    WOL_DATA_DIR=/data \
    TZ=Europe/Istanbul
VOLUME /data

CMD ["node", "server.js"]

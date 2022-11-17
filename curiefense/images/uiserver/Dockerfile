FROM node:16.17.0 as builder

# grab latest commit
WORKDIR /
RUN git clone --depth=1 https://github.com/reblaze/ui.git

WORKDIR /ui
RUN npm install
RUN npm run build


FROM docker.io/curiefense/openresty:1.21.4.1-bionic

USER root

COPY /init/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
RUN /usr/bin/apt-get update && \
    /usr/bin/apt-get install -yq --no-install-recommends dumb-init && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /ui/dist /app
COPY init/start_nginx.sh /init/start_nginx.sh

EXPOSE 80

ENTRYPOINT ["/usr/bin/dumb-init", "/bin/bash", "/docker-entrypoint.sh", "/init/start_nginx.sh"]

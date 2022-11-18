FROM docker.io/curiefense/openresty:1.21.4.1-bionic

COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY start_nginx.sh /init/start_nginx.sh
RUN chmod +x /init/start_nginx.sh

FROM node:16.17.0 as builder

WORKDIR /
RUN git clone --depth=1 https://github.com/reblaze/ui.git

WORKDIR /ui
RUN npm install
RUN npm run build

COPY --from=builder /ui/dist /app

CMD /init/start_nginx.sh

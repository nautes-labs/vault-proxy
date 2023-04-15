FROM debian:11.4-slim

RUN echo 'deb http://mirrors.aliyun.com/debian/ bullseye main non-free contrib \
      deb-src http://mirrors.aliyun.com/debian/ bullseye main non-free contrib \
      deb http://mirrors.aliyun.com/debian-security/ bullseye-security main \
      deb-src http://mirrors.aliyun.com/debian-security/ bullseye-security main \
      deb http://mirrors.aliyun.com/debian/ bullseye-updates main non-free contrib \
      deb-src http://mirrors.aliyun.com/debian/ bullseye-updates main non-free contrib \
      deb http://mirrors.aliyun.com/debian/ bullseye-backports main non-free contrib \
      deb-src http://mirrors.aliyun.com/debian/ bullseye-backports main non-free contrib' > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates netbase curl \
    && rm -rf /var/lib/apt/lists/ \
    && apt-get autoremove -y && apt-get autoclean -y

COPY  ./bin /app
COPY  ./configs /data/conf

WORKDIR /app

EXPOSE 8000
VOLUME /data/conf

CMD ["./vproxy", "-conf", "/data/conf"]

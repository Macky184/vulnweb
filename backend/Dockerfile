FROM ubuntu:22.04

# build tools
RUN apt-get update && apt-get install -y build-essential util-linux gdb

WORKDIR /app

COPY src/main.c ./main.c
COPY pages ./pages

ARG CFLAGS="-O0 -g"
RUN gcc main.c -o vuln_server ${CFLAGS}

EXPOSE 8080

CMD ["./vuln_server"]
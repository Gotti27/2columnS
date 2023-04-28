FROM gotti27/2columns-builder:latest

WORKDIR /firewall

COPY . .

RUN gcc -o main main.c

CMD ./main

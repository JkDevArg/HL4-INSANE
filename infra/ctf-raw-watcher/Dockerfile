FROM alpine:3.20
RUN apk add --no-cache nftables docker-cli bash
COPY watch.sh /watch.sh
RUN chmod +x /watch.sh
CMD ["/watch.sh"]

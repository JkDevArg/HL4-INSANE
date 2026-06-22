# pwn-pgrce-01 — servidor PostgreSQL "MoneyPipe" (data warehouse de la fintech).
# Postgres 16. El rol de la app es SUPERUSER a proposito (vulnerable). La flag
# se escribe a /flag.txt en runtime desde el env FLAG (no en la imagen).
FROM postgres:16-alpine

# Seed del data warehouse (rol superuser app + tabla transactions).
COPY init.sql /docker-entrypoint-initdb.d/10-init.sql

# Wrapper de entrypoint: vuelca FLAG -> /flag.txt y luego arranca postgres.
COPY write-flag.sh /usr/local/bin/write-flag.sh
RUN chmod +x /usr/local/bin/write-flag.sh

ENTRYPOINT ["write-flag.sh"]
CMD ["postgres"]

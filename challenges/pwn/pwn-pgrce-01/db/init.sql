-- pwn-pgrce-01 — seed del data warehouse "MoneyPipe".
--
-- Crea el rol que usa la app ETL y lo hace SUPERUSER (mala configuracion
-- REAL en muchos pipelines de fintech). Esto es lo que permite escalar la
-- SQLi a RCE via COPY ... TO/FROM PROGRAM.
--
-- POSTGRES_USER del contenedor es 'postgres' (bootstrap). Aqui creamos el
-- usuario de aplicacion 'moneypipe_etl' SUPERUSER, y la base 'moneypipe'.

-- Usuario de la aplicacion: SUPERUSER (vulnerable a proposito).
CREATE ROLE moneypipe_etl WITH LOGIN SUPERUSER PASSWORD 'etl_pipe_2024';

-- Base de datos de reportes, propiedad del rol ETL.
CREATE DATABASE moneypipe OWNER moneypipe_etl;

-- Esquema de demo dentro de la base de la app.
\connect moneypipe

SET ROLE moneypipe_etl;

CREATE TABLE transactions (
    id       SERIAL PRIMARY KEY,
    account  TEXT NOT NULL,
    region   TEXT NOT NULL,
    currency TEXT NOT NULL,
    amount   NUMERIC(14, 2) NOT NULL,
    status   TEXT NOT NULL
);

INSERT INTO transactions (account, region, currency, amount, status) VALUES
    ('ACME-001',   'LATAM', 'PEN', 15230.50, 'settled'),
    ('ACME-002',   'LATAM', 'USD',  9800.00, 'pending'),
    ('GLOBEX-114', 'EMEA',  'EUR', 42100.75, 'settled'),
    ('GLOBEX-115', 'EMEA',  'GBP',  3120.10, 'reversed'),
    ('INITECH-7',  'APAC',  'JPY', 88000.00, 'settled'),
    ('INITECH-8',  'APAC',  'USD', 12345.67, 'pending'),
    ('SOYLENT-3',  'LATAM', 'BRL', 22500.00, 'settled'),
    ('SOYLENT-4',  'NA',    'USD',  7777.77, 'flagged'),
    ('UMBRELLA-9', 'NA',    'CAD', 19999.99, 'settled'),
    ('WAYNE-21',   'NA',    'USD', 65000.00, 'pending');

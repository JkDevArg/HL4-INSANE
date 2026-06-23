# Solución — web-supply-01 · Poisoned Pipeline

**Categoría:** web · **Dificultad:** insane · **Vuln central:** Supply chain / Dependency confusion + RCE en `pip install` vía `setup.py`.

## Resumen

El portal de ACME reconstruye el microservicio `acme-billing` instalando el
paquete interno `acme-utils` desde un **index PyPI privado** (`registry`) que
permite **subir paquetes sin autenticación ni firma**. Tras instalar, el runner
hace un *smoke test*: **importa** la dependencia y registra su banner de versión
en el log. La `FLAG` está en el entorno del runner (secreto de CI).

El atacante publica una versión **mayor** de `acme-utils` cuyo módulo, al ser
importado por el smoke test, lee `os.environ["FLAG"]` y lo incluye en el banner
→ la flag aparece en el log del build.

## Reconocimiento

1. `GET /` muestra el portal y la política de CI:
   ```
   pip install --index-url http://registry:8080/simple/ \
       --extra-index-url https://pypi.org/simple/ acme-utils
   ```
   El index interno (`--index-url`) tiene **prioridad** sobre PyPI público:
   clásico vector de *dependency confusion*. Además dice "cualquiera puede
   publicar (sin firma)".
2. El registry está expuesto al jugador (puerto `8081`). `GET /simple/acme-utils/`
   muestra la versión actual: `acme-utils-1.0.0`.

## Explotación (paso a paso)

1. **Construir el paquete malicioso.** `solution/exploit/setup.py` define
   `version=9.9.9` (mayor que 1.0.0). El módulo `acme_utils.py` expone
   `version_banner()` que lee `os.environ["FLAG"]` y lo devuelve. Ese código
   corre en el runner cuando el smoke test importa la dependencia.
   ```sh
   python setup.py sdist --dist-dir ./dist
   ```
2. **Publicar en el registry interno** (upload anónimo):
   ```sh
   twine upload --repository-url http://<host>:8081/ -u any -p any \
       ./dist/acme-utils-9.9.9.tar.gz
   ```
3. **Disparar el rebuild**:
   ```sh
   curl -X POST http://<host>:8080/build
   # -> {"id":"abc123...","rc":0,"log":"..."}
   ```
   El runner resuelve `acme-utils` → toma la **9.9.9** del index interno →
   en el smoke test importa el módulo y llama `version_banner()`, que filtra
   la flag al log.
4. **Leer la flag** del log:
   ```sh
   curl -s http://<host>:8080/build/abc123 | grep -o 'HL4{[^}]*}'
   # HL4{EJEMPLO}
   ```

Todo automatizado en `solution/exploit/pwn.sh <host>`.

## Por qué es INSANE

- Requiere reconocer el vector de cadena de suministro (no es un SQLi/XSS típico).
- Hay que entender que el código de una dependencia se ejecuta con los secretos
  del runner de CI, y que el secreto vive en el runner, no en el portal HTTP
  (no se puede leer directo).
- El canal de exfiltración natural es el **log del build** (no hay egress de red
  hacia el atacante por el aislamiento de equipos).

## Mitigaciones (didáctico)

- Firmar paquetes / usar índices con autenticación y *namespace pinning*.
- `pip install --require-hashes` con `hashes` fijados.
- `--no-build-isolation` controlado / wheels prebuildeadas verificadas.
- No prefijar el index interno sobre el público sin *scope* de nombres.
- No inyectar secretos al entorno de instalación de dependencias.

## Nota anti-cheat

La flag es **dinámica y única por equipo** (HMAC del flag-service,
`ARCHITECTURE §4`), inyectada por env `FLAG` solo en el runner de **esta**
instancia. Compartir la técnica no entrega puntos: cada equipo debe envenenar
**su** registry y leer **su** log para obtener **su** flag. Enviar la flag de
otro equipo a la plataforma dispara `cheat_flag_share` vía `POST /whose-flag`.
Además, un build que instala una versión no oficial de `acme-utils` emite un
evento SIEM `scan_detected`/`alert` al collector.

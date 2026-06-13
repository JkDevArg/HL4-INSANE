# Templates de retos — CTFHL4-INSANE

Plantillas base para crear retos nuevos respetando el **contrato** de
`docs/ARCHITECTURE.md` (secciones 4, 6.3, 7 y 8).

## Categorías disponibles

| Template | Tipo de servicio | Stack | `serve` |
|---|---|---|---|
| `web/`    | HTTP             | Flask   | `http` |
| `api/`    | HTTP (REST/JSON) | FastAPI | `http` |
| `crypto/` | TCP (`nc`-style) | Python `socketserver` | `tcp` |

---

## 1. Cómo se inyecta la flag (LEER PRIMERO)

La flag **NUNCA** se hardcodea en el código ni en la imagen. El orquestador
de la plataforma genera una instancia del reto **por equipo** y le inyecta la
flag única vía variable de entorno `FLAG`.

Flujo (decisión de diseño, ver `ARCHITECTURE.md §4`):

1. El orquestador pide la flag al flag-service:
   `GET http://flag-service:8001/flag?team_id=team_03&challenge_id=web-supply-01`
   → `{"flag": "flag{ab12...}"}`.
2. El orquestador lanza el contenedor del equipo pasando esa flag por env:
   ```bash
   TEAM_ID=team_03 FLAG="flag{ab12...}" docker compose -p web-supply-01__team_03 up -d
   ```
3. El reto lee `os.environ["FLAG"]` al arrancar.

> **Por qué env y no que el reto llame al flag-service:**
> es más simple y más seguro. El contenedor del reto está en la red Docker
> del equipo (`172.30.N.0/24`) y **no necesita** alcanzar al flag-service
> (`10.10.100.20`). Reducir la superficie de red = menos pivoting posible
> desde un reto comprometido hacia servicios internos. La generación
> HMAC sigue centralizada en el flag-service; el reto solo recibe el valor.

Todos los `docker-compose.yml` son parametrizables:

```yaml
environment:
  FLAG: "${FLAG:-flag{EJEMPLO_LOCAL}}"   # inyectada por equipo
  TEAM_ID: "${TEAM_ID:-team_local}"
```

Si lanzas en local sin pasar `FLAG`, cae al valor `flag{EJEMPLO_LOCAL}` para
que el reto siga siendo jugable en desarrollo.

---

## 2. Crear un reto nuevo desde un template

```bash
# Ejemplo: nuevo reto web "web-ssti-02"
cp -r challenges/_templates/web challenges/web/web-ssti-02
cd challenges/web/web-ssti-02
```

Luego:

1. Edita `challenge.yaml`: cambia `id`, `name`, `description`, `points`, `ports`.
   - `id` debe seguir la convención `<cat>-<slug>-<NN>` (`ARCHITECTURE §7`).
   - `type: per-team` siempre para retos con flag dinámica.
2. Implementa la vulnerabilidad real en la app (`app/`).
3. Asegúrate de que la app lea la flag SOLO de `os.environ["FLAG"]`.
4. Escribe el `solution/README.md` con el writeup paso a paso y la nota
   anti-cheat (por qué el reto resiste compartir).
5. Prueba en local:
   ```bash
   FLAG="flag{EJEMPLO}" TEAM_ID=team_01 docker compose up --build
   ```

---

## 3. Checklist de contrato (obligatorio antes de mergear)

- [ ] `challenge.yaml` válido (`ARCHITECTURE §8`): `id`, `category`,
      `difficulty: insane`, `type: per-team`, `serve`, `flag_via: flag-service`,
      `points`, `ports`, `siem`, `description`.
- [ ] Flag leída de `os.environ["FLAG"]`. **Cero** flags hardcodeadas.
- [ ] `docker-compose.yml` parametrizable por `TEAM_ID` y `FLAG`.
- [ ] Contenedor nombrable como `<challenge_id>__team_NN` (`§7`).
- [ ] Si `siem: true`: emite eventos al collector con el esquema `§5`.
- [ ] `solution/` con writeup reproducible + nota anti-cheat.
- [ ] La flag de ejemplo en `solution/` es `flag{EJEMPLO}`, nunca una real.

---

## 4. Emisión de eventos SIEM (si `siem: true`)

Esquema exacto de `ARCHITECTURE §5`. Fire-and-forget: si el collector está
caído, **no** debe romper la request del jugador. Ver `web/app/siem.py`
como referencia copiable. Endpoint: `POST http://collector:9000/event`.

`event_type` válidos para retos: normalmente `scan_detected` o `ids_alert`
(accesos sospechosos detectados por el propio reto), `severity` `warn`/`alert`.

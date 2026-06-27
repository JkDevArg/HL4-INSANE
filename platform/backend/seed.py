"""Siembra 5 equipos + 60 retos únicos + asignaciones exclusivas por equipo.

Anti-trampa: cada equipo recibe 3 retos DISTINTOS por categoría.
Ningún equipo comparte retos con otro equipo.

Categorías: web, crypto, pwn, rev
Equipos: 5 × 12 retos = 60 instancias totales

IPs por slot (172.30.{N}.XX):
  web:    slot1=.10  slot2=.11  slot3=.12
  crypto: slot1=.20  slot2=.21  slot3=.22
  pwn:    slot1=.30  slot2=.31  slot3=.32
  rev:    slot1=.40  slot2=.41  slot3=.42

Uso:
    python seed.py              # siembra incremental
    python seed.py --reset      # borra TODO y resiembra desde cero
"""
import argparse
import asyncio
import secrets
import string

from sqlalchemy import delete, select, update

from app.auth import hash_password
from app.db import SessionLocal, init_db
from app.models import Challenge, ChallengeInstance, Solve, Team, TeamChallengeAssignment

# ---------------------------------------------------------------------------
# 60 RETOS ÚNICOS — 15 web + 15 crypto + 15 pwn + 15 rev
# (challenge_id, category, name, points, description, connection_info_template)
# {N} = número de equipo (se sustituye al mostrar retos al jugador)
# ---------------------------------------------------------------------------
CHALLENGES = [

    # ── WEB — Team 1 (slots .10 .11 .12) ────────────────────────────────────
    (
        "web-oss-registry",
        "web",
        "OSS Registry",
        850,
        "Registro de paquetes open-source corporativo. El pipeline de CI descarga e instala "
        "paquetes automáticamente. Hay un endpoint de publicación mal protegido. "
        "Compromete el registry → inyecta un paquete malicioso → el runner lo ejecuta → "
        "pivota al build-server donde vive el secreto.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-gitops-pipeline",
        "web",
        "GitOps Pipeline",
        900,
        "Plataforma GitOps interna que sincroniza repos con un runner de CI/CD. "
        "El directorio .git está expuesto. Recupera credenciales de commits purgados, "
        "forja el HMAC del webhook, dispara el pipeline y pivota al cluster interno.",
        "http://172.30.{N}.11:8080",
    ),
    (
        "web-saml-sso",
        "web",
        "SAML Federation",
        875,
        "Portal SSO empresarial con federación SAML. El validador de firmas XML "
        "es vulnerable a Signature Wrapping. Forja una aserción de administrador, "
        "accede al panel de administración, explota el XXE en el módulo de importación "
        "de usuarios y usa el SSRF para acceder a los metadatos del cloud provider.",
        "http://172.30.{N}.12:8080",
    ),

    # ── WEB — Team 2 (slots .10 .11 .12) ────────────────────────────────────
    (
        "web-cache-deception",
        "web",
        "Cache Deception",
        825,
        "CDN corporativo con caché agresiva. El backend confunde extensiones de archivo "
        "con tipos de respuesta. Envía a un admin un enlace que cachea su token de sesión, "
        "roba la sesión, accede al panel de administración y exfilttra las claves de API.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-http-desync",
        "web",
        "HTTP Desync Attack",
        900,
        "Proxy reverso + backend con interpretación diferente de Content-Length vs "
        "Transfer-Encoding. Construye una petición que envenena la cola del backend, "
        "intercepta la solicitud del siguiente usuario (admin) y roba su sesión.",
        "http://172.30.{N}.11:8080",
    ),
    (
        "web-xxe-ssrf",
        "web",
        "XXE → SSRF Chain",
        850,
        "Sistema de importación de facturas en XML. El parser es vulnerable a XXE. "
        "Extrae archivos internos → descubre la URL de un servicio interno → "
        "usa el SSRF para acceder al metadata del cloud → obtén IAM credentials → flag.",
        "http://172.30.{N}.12:8080",
    ),

    # ── WEB — Team 3 (slots .10 .11 .12) ────────────────────────────────────
    (
        "web-sqli-chain",
        "web",
        "SQLi → RCE Chain",
        875,
        "ERP web con múltiples capas de sanitización. La vulnerabilidad de inyección SQL "
        "está en el parámetro de ordenamiento. Extrae credenciales → accede al panel admin → "
        "explota el módulo de backup para escribir un webshell → ejecuta comandos en el servidor.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-graphql-chain",
        "web",
        "GraphQL Federation Takeover",
        900,
        "API GraphQL federada con múltiples subgrafos. La introspección está habilitada. "
        "Abusa del batching para bypassear el rate-limit → explota mass assignment en una "
        "mutación → escala a rol interno → accede al subgrafo de secretos.",
        "http://172.30.{N}.11:8080",
    ),
    (
        "web-ssti-chain",
        "web",
        "SSTI → Sandbox Escape",
        850,
        "Generador de reportes con motor de plantillas configurable por el usuario. "
        "El sistema usa Jinja2 con un sandbox personalizado. Encuentra el vector de "
        "inyección, escapa el sandbox mediante la cadena de MRO y ejecuta comandos.",
        "http://172.30.{N}.12:8080",
    ),

    # ── WEB — Team 4 (slots .10 .11 .12) ────────────────────────────────────
    (
        "web-oauth-misconfig",
        "web",
        "OAuth2 Misconfiguration",
        825,
        "Plataforma OAuth2 con múltiples clientes registrados. El servidor no valida "
        "correctamente redirect_uri contra el cliente. Redirige el authorization code "
        "a tu servidor → intercambia el code por tokens → escala privilegios via "
        "un segundo cliente con scope más amplio.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-prototype-pollution",
        "web",
        "Prototype Pollution → RCE",
        875,
        "API Node.js que hace deep merge de objetos de configuración enviados por el usuario. "
        "Contamina el prototipo de Object para inyectar propiedades en el motor de templates, "
        "logra ejecución de código arbitrario y exfiltra el flag del sistema de archivos.",
        "http://172.30.{N}.11:8080",
    ),
    (
        "web-websocket-chain",
        "web",
        "WebSocket Hijack Chain",
        900,
        "Aplicación de colaboración en tiempo real con WebSockets. El handshake no valida "
        "el origen correctamente. Secuestra una sesión de WebSocket de un admin, inyecta "
        "mensajes de control que ejecutan acciones privilegiadas en el servidor.",
        "http://172.30.{N}.12:8080",
    ),

    # ── WEB — Team 5 (slots .10 .11 .12) ────────────────────────────────────
    (
        "web-cors-chain",
        "web",
        "CORS Misconfiguration Chain",
        825,
        "API corporativa con CORS mal configurado: refleja el origen de la petición. "
        "Crea una página que hace fetch cross-origin con credenciales al endpoint de "
        "administración, exfiltra tokens de sesión y los usa para acceder a datos sensibles.",
        "http://172.30.{N}.10:8080",
    ),
    (
        "web-java-deserialization",
        "web",
        "Java Deserialization Gadget Chain",
        900,
        "Aplicación Java con endpoint que deserializa objetos via Java serialization nativa. "
        "Identifica las dependencias en el classpath, construye una gadget chain con "
        "ysoserial/manualmente y obtén RCE para leer el flag.",
        "http://172.30.{N}.11:8080",
    ),
    (
        "web-waf-bypass",
        "web",
        "WAF Bypass → SQLi → Flag",
        875,
        "Portal protegido por un WAF personalizado con múltiples capas de detección. "
        "La aplicación backend tiene una SQLi clásica. Analiza el WAF, encuentra el "
        "vector de bypass mediante encoding/fragmentación y exfiltra el flag de la BD.",
        "http://172.30.{N}.12:8080",
    ),

    # ── CRYPTO — Team 1 (slots .20 .21 .22) ──────────────────────────────────
    (
        "crypto-lattice-ecdsa",
        "crypto",
        "Lattice ECDSA Key Recovery",
        900,
        "Servicio de firma digital ECDSA que reutiliza parcialmente los nonces (los bits "
        "menos significativos son predecibles). Recolecta suficientes firmas, construye "
        "el sistema de ecuaciones y usa un ataque de red (LLL/BKZ) para recuperar la "
        "clave privada. Firma el mensaje requerido para obtener el flag.",
        "nc 172.30.{N}.20 9999",
    ),
    (
        "crypto-jwt-confusion",
        "crypto",
        "JWT Algorithm Confusion",
        850,
        "Servicio de autenticación con JWT RS256. El validador acepta el algoritmo "
        "declarado en el header. Descarga la clave pública del endpoint JWKS, "
        "convierte el formato y forja un token HS256 firmado con la clave pública "
        "como secreto para obtener acceso de administrador.",
        "http://172.30.{N}.21:9999",
    ),
    (
        "crypto-tls-downgrade",
        "crypto",
        "TLS Downgrade + Custom MAC Bypass",
        925,
        "Servidor con soporte para cifrados legacy DH con parámetros débiles (512 bits). "
        "Fuerza un downgrade Logjam, intercept la sesión TLS y bypasea el MAC de un "
        "protocolo de aplicación personalizado para descifrar el payload con el flag.",
        "nc 172.30.{N}.22 9999",
    ),

    # ── CRYPTO — Team 2 (slots .20 .21 .22) ──────────────────────────────────
    (
        "crypto-rsa-lsb",
        "crypto",
        "RSA LSB Oracle",
        875,
        "Servicio de descifrado RSA que revela si el plaintext descifrado es par o impar "
        "(bit menos significativo). Con O(log n) consultas al oráculo, recupera el "
        "plaintext completo mediante búsqueda binaria. El plaintext es el flag.",
        "nc 172.30.{N}.20 9999",
    ),
    (
        "crypto-padding-oracle",
        "crypto",
        "CBC Padding Oracle",
        850,
        "Sistema de sesiones cifradas con AES-CBC. El servidor devuelve errores distintos "
        "para padding inválido vs MAC inválido. Usa el oráculo de padding para descifrar "
        "un token de sesión de administrador y forja uno nuevo para acceder al flag.",
        "nc 172.30.{N}.21 9999",
    ),
    (
        "crypto-hash-length-ext",
        "crypto",
        "Hash Length Extension",
        825,
        "API con autenticación basada en HMAC-SHA256 sin prefijo de longitud seguro. "
        "El servidor usa hash(secret || message) y expone el hash de un mensaje conocido. "
        "Extiende el hash para añadir parámetros adicionales sin conocer el secreto "
        "y accede al endpoint privilegiado.",
        "http://172.30.{N}.22:9999",
    ),

    # ── CRYPTO — Team 3 (slots .20 .21 .22) ──────────────────────────────────
    (
        "crypto-hastad-broadcast",
        "crypto",
        "Hastad Broadcast Attack",
        875,
        "Servidor que cifra el mismo mensaje con RSA para múltiples destinatarios usando "
        "e=3 y módulos diferentes. Recolecta los 3 cifrados, aplica el Teorema Chino del "
        "Resto y extrae la raíz cúbica entera para recuperar el plaintext (el flag).",
        "http://172.30.{N}.20:9999",
    ),
    (
        "crypto-fermat-rsa",
        "crypto",
        "Fermat Factorization",
        825,
        "Servicio RSA con módulos generados con primos muy cercanos entre sí. "
        "El método de factorización de Fermat converge rápidamente cuando |p-q| es pequeño. "
        "Factoriza el módulo, calcula la clave privada y descifra el flag.",
        "nc 172.30.{N}.21 9999",
    ),
    (
        "crypto-dsa-nonce",
        "crypto",
        "DSA Nonce Reuse",
        900,
        "Servicio de firma DSA que reutiliza el nonce k en dos firmas distintas. "
        "Con dos firmas (r,s1) y (r,s2) sobre mensajes conocidos y el mismo k, "
        "recupera k y luego la clave privada x. Úsala para firmar el mensaje de autenticación.",
        "nc 172.30.{N}.22 9999",
    ),

    # ── CRYPTO — Team 4 (slots .20 .21 .22) ──────────────────────────────────
    (
        "crypto-ecdh-invalid",
        "crypto",
        "ECDH Invalid Curve Attack",
        925,
        "Servidor de intercambio de claves ECDH sobre P-256. No valida que el punto "
        "enviado por el cliente pertenezca a la curva. Envía puntos de orden pequeño "
        "de curvas contiguas (Invalid Curve Attack), recupera la clave privada por "
        "CRT y descifra el mensaje cifrado con la clave de sesión.",
        "nc 172.30.{N}.20 9999",
    ),
    (
        "crypto-cbc-bitflip",
        "crypto",
        "CBC Bit-Flip + Oracle Chain",
        850,
        "Sistema de autorización con tokens AES-CBC. El servidor revela si el token "
        "descifrado contiene el campo role=admin. Usa bit-flipping en el IV/bloque "
        "anterior para modificar el campo role sin conocer la clave, luego "
        "encadena con un oráculo de verificación para refinar el ataque.",
        "nc 172.30.{N}.21 9999",
    ),
    (
        "crypto-gcm-nonce",
        "crypto",
        "AES-GCM Nonce Reuse",
        875,
        "Servicio de cifrado AES-GCM que reutiliza el nonce en múltiples mensajes. "
        "Con dos cifrados bajo el mismo (key, nonce), xorea los keystreamblocks para "
        "recuperar diferencias de plaintext. Uno de los plaintexts es conocido: "
        "usa esto para recuperar el otro (el flag).",
        "nc 172.30.{N}.22 9999",
    ),

    # ── CRYPTO — Team 5 (slots .20 .21 .22) ──────────────────────────────────
    (
        "crypto-rsa-crt-fault",
        "crypto",
        "RSA-CRT Fault Attack",
        925,
        "Servicio de firma RSA con CRT. Bajo ciertas condiciones de carga, produce "
        "firmas faulty (un factor del CRT falla). Con una firma faulty y la firma correcta "
        "del mismo mensaje, MCD(firma_faulty - firma_correcta, n) = p. "
        "Factoriza n, calcula d y firma el mensaje de autenticación.",
        "nc 172.30.{N}.20 9999",
    ),
    (
        "crypto-bleichenbacher",
        "crypto",
        "Bleichenbacher PKCS#1 v1.5",
        950,
        "Servidor TLS-like que devuelve errores diferenciados para padding PKCS#1 v1.5 "
        "inválido. Implementa el ataque de Bleichenbacher (millones de oráculos) para "
        "descifrar un mensaje RSA capturado sin conocer la clave privada.",
        "nc 172.30.{N}.21 9999",
    ),
    (
        "crypto-wiener",
        "crypto",
        "Wiener's Attack + Extension",
        875,
        "Servicio RSA con exponente privado d demasiado pequeño (d < n^0.25). "
        "Aplica el ataque de Wiener con fracciones continuas para recuperar d "
        "directamente desde el exponente público e y el módulo n. "
        "Descifra el flag cifrado con la clave pública.",
        "nc 172.30.{N}.22 9999",
    ),

    # ── PWN — Team 1 (slots .30 .31 .32) ─────────────────────────────────────
    (
        "pwn-heap-chain",
        "pwn",
        "Heap Exploitation Chain",
        925,
        "Binario ELF x64 con allocator personalizado basado en ptmalloc. "
        "Hay un heap overflow de un byte en la gestión de chunks. "
        "Explota tcache poisoning → arbitrary write → GOT overwrite → shell. "
        "ASLR + PIE + canary activos. Requiere leak de heap y libc.",
        "nc 172.30.{N}.30 9998",
    ),
    (
        "pwn-rop-chain",
        "pwn",
        "ROP Chain + ret2libc",
        875,
        "Servidor x64 sin PIE, con stack canary. Buffer overflow clásico en la "
        "función de autenticación. No hay shell directa: construye una cadena ROP "
        "para hacer leak de libc via puts, calcular el offset de system() y "
        "ejecutar /bin/sh en el segundo stage.",
        "nc 172.30.{N}.31 9998",
    ),
    (
        "pwn-kernel-lpe",
        "pwn",
        "Kernel Module LPE",
        975,
        "Sistema con un módulo de kernel vulnerable (character device). "
        "El ioctl tiene un race condition que permite escritura arbitraria en memoria kernel. "
        "Explota el race para sobrescribir credenciales del proceso y escalar a root. "
        "Lee el flag en /root/flag.txt.",
        "nc 172.30.{N}.32 9998",
    ),

    # ── PWN — Team 2 (slots .30 .31 .32) ─────────────────────────────────────
    (
        "pwn-format-string",
        "pwn",
        "Format String → Arbitrary Write",
        875,
        "Binario x64 con ASLR + PIE que imprime input del usuario sin sanitizar "
        "(printf(buf)). Usa el format string para leer direcciones de la pila (leak PIE + libc), "
        "calcula los offsets y sobrescribe el GOT entry de exit() con system(). "
        "Luego trigger la llamada con '/bin/sh'.",
        "nc 172.30.{N}.30 9998",
    ),
    (
        "pwn-race-condition",
        "pwn",
        "TOCTOU Race → Privilege Escalation",
        900,
        "Servicio setuid con una ventana TOCTOU entre el check de permisos y el open() "
        "del archivo. Usa symlink swapping con alta frecuencia para que el proceso abra "
        "/etc/shadow en lugar del archivo autorizado. Extrae las credenciales de root.",
        "nc 172.30.{N}.31 9998",
    ),
    (
        "pwn-uaf-chain",
        "pwn",
        "Use-After-Free → Type Confusion",
        950,
        "Gestor de objetos en C++ con virtual dispatch. Un UAF libera un objeto "
        "sin invalidar el puntero. Controla la realocación del chunk liberado con "
        "un objeto de tipo diferente, corrompiendo el vtable pointer. "
        "Redirige el control flow a través del vtable falso para obtener shell.",
        "nc 172.30.{N}.32 9998",
    ),

    # ── PWN — Team 3 (slots .30 .31 .32) ─────────────────────────────────────
    (
        "pwn-seccomp-bypass",
        "pwn",
        "Seccomp Filter Bypass",
        925,
        "Sandbox con filtro seccomp estricto que bloquea execve/execveat. "
        "El binario tiene un overflow que te da control del RIP. "
        "No puedes hacer execve: usa open/read/write para exfiltrar el flag "
        "mediante una cadena ROP que hace llamadas al sistema directamente.",
        "nc 172.30.{N}.30 9998",
    ),
    (
        "pwn-pie-leak",
        "pwn",
        "PIE Leak → Full ASLR Bypass",
        875,
        "Binario PIE con una vulnerability de info leak en la función de logging. "
        "Un format string limitado (solo %p) te permite leer 3 valores del stack. "
        "Identifica qué apuntan esos valores, calcula la base de PIE y libc, "
        "y construye el exploit para control total del flujo.",
        "nc 172.30.{N}.31 9998",
    ),
    (
        "pwn-vm-escape",
        "pwn",
        "Custom VM Escape",
        975,
        "Intérprete de bytecode personalizado con instrucciones para "
        "leer/escribir memoria del VM. Un error de bounds checking en el opcode "
        "STORE permite escribir fuera del sandbox del VM. "
        "Escapa al heap del host, sobrescribe estructuras de control y ejecuta shellcode.",
        "nc 172.30.{N}.32 9998",
    ),

    # ── PWN — Team 4 (slots .30 .31 .32) ─────────────────────────────────────
    (
        "pwn-srop-chain",
        "pwn",
        "SROP (Sigreturn-Oriented Programming)",
        925,
        "Binario minimalista: solo tiene syscall + ret. No hay gadgets útiles para "
        "ROP clásico. Usa SROP: construye un sigreturn frame falso en el stack, "
        "llama a rt_sigreturn y controla todos los registros del proceso incluyendo "
        "RIP y RSP para ejecutar código arbitrario.",
        "nc 172.30.{N}.30 9998",
    ),
    (
        "pwn-off-by-one",
        "pwn",
        "Off-By-One Heap Feng Shui",
        900,
        "Implementación de lista enlazada con un off-by-one en la función de copia "
        "de strings (falta el null terminator). Usa heap feng shui para controlar "
        "el layout del heap, el off-by-one corrompe el size field de un chunk "
        "adyacente y encadena con una primitiva de lectura arbitraria.",
        "nc 172.30.{N}.31 9998",
    ),
    (
        "pwn-sandbox-escape",
        "pwn",
        "Python Sandbox Escape",
        875,
        "Intérprete Python con un eval() 'seguro' que filtra builtins y módulos. "
        "El sandbox usa __import__ = None y restringe globals. "
        "Escapa el sandbox mediante la cadena de MRO de subclases para "
        "recuperar __import__ y ejecutar comandos del sistema.",
        "nc 172.30.{N}.32 9998",
    ),

    # ── PWN — Team 5 (slots .30 .31 .32) ─────────────────────────────────────
    (
        "pwn-aarch64-rop",
        "pwn",
        "AArch64 ROP Chain",
        950,
        "Binario ARM64 con stack overflow. Los gadgets ROP son distintos a x86: "
        "usa pares load/store y la convención de llamada AArch64 (x0-x7, lr, sp). "
        "Construye la cadena ROP para hacer leak de libc via puts(), calcular "
        "la dirección de system() y ejecutar /bin/sh en AArch64.",
        "nc 172.30.{N}.30 9998",
    ),
    (
        "pwn-heap-master",
        "pwn",
        "Heap Master (Full Chain)",
        975,
        "Challenge multi-stage: primero un UAF para obtener un leak del heap, "
        "luego tcache dup para obtener arbitrary alloc, sobreescribe un objeto "
        "con un fake FILE struct para redirigir _IO_file_overflow a un one-gadget. "
        "Full ASLR + PIE + canary + RELRO.",
        "nc 172.30.{N}.31 9998",
    ),
    (
        "pwn-driver-exploit",
        "pwn",
        "Kernel Driver Privilege Escalation",
        975,
        "Driver de kernel con un buffer overflow en el handler de ioctl. "
        "El overflow alcanza la return address del kernel stack. "
        "Desactiva SMEP/SMAP mediante ROP en espacio de kernel y ejecuta "
        "un payload que eleva los privilegios del proceso a root.",
        "nc 172.30.{N}.32 9998",
    ),

    # ── REV — Team 1 (slots .40 .41 .42) ─────────────────────────────────────
    (
        "rev-firmware-chain",
        "rev",
        "IoT Firmware Supply Chain",
        925,
        "Imagen de firmware de un dispositivo IoT embebido. Extrae el filesystem "
        "(squashfs) con binwalk, encuentra el demonio de gestión con criptografía "
        "propietaria, parchea el binario para saltar la validación, descifra la "
        "partición de configuración cifrada y extrae credenciales hardcodeadas "
        "que dan acceso a la API de gestión donde está el flag.",
        "http://172.30.{N}.40:8080  (GET /firmware  POST /submit)",
    ),
    (
        "rev-malware-dropper",
        "rev",
        "Multi-Stage Malware Analysis",
        900,
        "Binario PE empaquetado con UPX + capa adicional de ofuscación. "
        "Desempaqueta la primera capa, deobfusca el segundo stage (strings XOR), "
        "emula el beacon C2, forja la respuesta del C2 con el comando correcto, "
        "extrae el payload final y reversa el bytecode del intérprete embebido.",
        "http://172.30.{N}.41:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-wasm-chain",
        "rev",
        "WebAssembly → Native Bridge",
        875,
        "Módulo WebAssembly con lógica de validación de licencia. Decompila el WASM, "
        "identifica la función de verificación, encuentra el algoritmo de hash "
        "personalizado, calcula una colisión y bypasea la verificación. "
        "Accede al bridge nativo que expone el flag.",
        "http://172.30.{N}.42:8080  (GET /binary  POST /submit)",
    ),

    # ── REV — Team 2 (slots .40 .41 .42) ─────────────────────────────────────
    (
        "rev-vm-bytecode",
        "rev",
        "Custom VM Bytecode Reversal",
        900,
        "Binario ELF que implementa una máquina virtual con set de instrucciones "
        "propio (20+ opcodes). El programa en bytecode valida una contraseña. "
        "Reversa el ISA, escribe un disassembler, analiza el bytecode del programa "
        "y deriva la contraseña correcta para desbloquear el flag.",
        "http://172.30.{N}.40:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-go-binary",
        "rev",
        "Go Binary Anti-Analysis",
        875,
        "Binario Go compilado estáticamente con anti-debug y string obfuscation. "
        "Las strings están cifradas en el binario y se descifran en runtime. "
        "Usa técnicas de análisis estático en Go (tipos de runtime, goroutines), "
        "parchea las checks anti-debug y extrae el algoritmo de validación.",
        "http://172.30.{N}.41:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-dotnet-obf",
        "rev",
        ".NET Obfuscated Validator",
        850,
        "Assembly .NET obfuscado con ConfuserEx. Los nombres de métodos y campos "
        "están renombrados, el flujo de control está virtualizado. "
        "Usa de4dot para desofuscar parcialmente, luego analiza manualmente "
        "el control flow graph para entender el algoritmo de validación.",
        "http://172.30.{N}.42:8080  (GET /binary  POST /submit)",
    ),

    # ── REV — Team 3 (slots .40 .41 .42) ─────────────────────────────────────
    (
        "rev-packed-delta",
        "rev",
        "Packed Binary + Delta Decryption",
        875,
        "Binario ELF con sección de datos cifrada mediante un cipher de delta "
        "personalizado y un packer que reconstruye el código en runtime. "
        "Dumpea el proceso después del unpack, identifica la rutina de descifrado, "
        "reimpleméntala y descifra la sección para encontrar el flag embebido.",
        "http://172.30.{N}.40:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-anti-debug-chain",
        "rev",
        "Anti-Debug Chain Bypass",
        900,
        "Binario con cadena de 6 técnicas anti-debug encadenadas: ptrace self-check, "
        "timing attacks, /proc/self/status parsing, RDTSC, TLS callbacks y "
        "signal handlers. Debes bypassear cada capa en orden para que el binario "
        "revele el flag. Algunos bypasses invalidan los anteriores.",
        "http://172.30.{N}.41:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-llvm-obf",
        "rev",
        "LLVM Obfuscation (Ollvm)",
        950,
        "Binario compilado con OLLVM: control flow flattening + bogus control flow + "
        "instruction substitution. El algoritmo de validación es prácticamente "
        "ilegible con análisis estático solo. Usa análisis dinámico + concolic "
        "execution (angr/triton) para resolver las restricciones y obtener el input válido.",
        "http://172.30.{N}.42:8080  (GET /binary  POST /submit)",
    ),

    # ── REV — Team 4 (slots .40 .41 .42) ─────────────────────────────────────
    (
        "rev-rust-binary",
        "rev",
        "Rust Binary Reverse",
        875,
        "Binario Rust compilado en release mode (sin debug symbols). Los panics "
        "y el mangling de nombres complican el análisis. Identifica las funciones "
        "clave mediante patrones de código Rust, analiza el algoritmo de "
        "transformación de input y calcula el input que produce el hash esperado.",
        "http://172.30.{N}.40:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-kernel-module",
        "rev",
        "Kernel Module Reverse",
        925,
        "Módulo de kernel (.ko) que implementa un character device con protocolo "
        "binario propietario. El módulo descifra el flag solo si se le envía la "
        "secuencia correcta de ioctls con los parámetros exactos. "
        "Reversa el módulo para entender el protocolo y obtener el flag.",
        "http://172.30.{N}.41:8080  (GET /ko  POST /submit)",
    ),
    (
        "rev-mobile-apk",
        "rev",
        "Android APK → Native Library",
        900,
        "APK Android con lógica de validación en una biblioteca nativa (.so) "
        "llamada via JNI. La biblioteca tiene anti-emulación y root detection. "
        "Usa jadx para el Java wrapper, ghidra/IDA para la nativa, "
        "parchea las checks de entorno y extrae el algoritmo de validación.",
        "http://172.30.{N}.42:8080  (GET /apk  POST /submit)",
    ),

    # ── REV — Team 5 (slots .40 .41 .42) ─────────────────────────────────────
    (
        "rev-symbolic-exec",
        "rev",
        "Symbolic Execution Challenge",
        950,
        "Binario diseñado para resistir análisis manual: miles de comparaciones "
        "y transformaciones. La única vía práctica es ejecución simbólica (angr). "
        "Hay trampas: loops infinitos si no se acota el estado, y hooks necesarios "
        "para bypassear las llamadas al sistema que angr no maneja.",
        "http://172.30.{N}.40:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-taint-analysis",
        "rev",
        "Taint Analysis Puzzle",
        925,
        "Binario que procesa el input a través de múltiples capas de transformaciones "
        "con dependencias de datos cruzadas. El análisis estático es insuficiente. "
        "Usa taint analysis dinámica (DynamoRIO/PIN) para trazar el flujo de datos "
        "desde el input hasta las comparaciones finales y reconstruye el input válido.",
        "http://172.30.{N}.41:8080  (GET /binary  POST /submit)",
    ),
    (
        "rev-decompiler-puzzle",
        "rev",
        "Decompiler Output Puzzle",
        875,
        "Binario específicamente construido para confundir decompiladores (Ghidra/IDA). "
        "Usa overlapping instructions, fake return addresses y aliasing de registros. "
        "El código real está entrelazado con código basura que los decompiladores "
        "mezclan. Requiere análisis manual del ensamblador puro.",
        "http://172.30.{N}.42:8080  (GET /binary  POST /submit)",
    ),

    # ── GOBL1N — Todos los equipos (slot .50) ────────────────────────────────
    # Único reto compartido: todos los equipos juegan la misma ROM (GBC).
    # La flag es team-specific (generada por flag-service).
    # El jugador DEBE jugar 3 min en el emulador antes de que el botón se active.
    (
        "gobl1n-poke-l4bs",
        "gobl1n",
        "POKE_L4BS",
        1200,
        "Consola retro emulada en la nube. El juego esconde un secreto. "
        "Juega y encuéntralo.",
        "http://172.30.{N}.50:8080",
    ),
]

# ---------------------------------------------------------------------------
# Asignaciones: 3 retos por categoría por equipo, sin solapamiento
# ---------------------------------------------------------------------------
TEAM_NAMES = {
    1: "Bytreach",
    2: "MoodySploiters",
    3: "DARKHIVE",
    4: "Threat Hunters",
    5: "Capa 8",
}

# [team_id → [challenge_id, ...]] — 12 retos únicos por equipo
ASSIGNMENTS: dict[str, list[str]] = {
    "team_01": [
        "web-oss-registry",    "web-gitops-pipeline",   "web-saml-sso",
        "crypto-lattice-ecdsa","crypto-jwt-confusion",  "crypto-tls-downgrade",
        "pwn-heap-chain",      "pwn-rop-chain",          "pwn-kernel-lpe",
        "rev-vm-bytecode",     "rev-go-binary",           "rev-dotnet-obf",
        "gobl1n-poke-l4bs",
    ],
    "team_02": [
        "web-cache-deception", "web-http-desync",        "web-xxe-ssrf",
        "crypto-rsa-lsb",      "crypto-padding-oracle",  "crypto-hash-length-ext",
        "pwn-format-string",   "pwn-race-condition",      "pwn-uaf-chain",
        "rev-vm-bytecode",     "rev-go-binary",           "rev-dotnet-obf",
        "gobl1n-poke-l4bs",
    ],
    "team_03": [
        "web-sqli-chain",      "web-graphql-chain",      "web-ssti-chain",
        "crypto-hastad-broadcast","crypto-fermat-rsa",   "crypto-dsa-nonce",
        "pwn-seccomp-bypass",  "pwn-pie-leak",            "pwn-vm-escape",
        "rev-vm-bytecode",     "rev-go-binary",           "rev-dotnet-obf",
        "gobl1n-poke-l4bs",
    ],
    "team_04": [
        "web-oauth-misconfig", "web-prototype-pollution", "web-websocket-chain",
        "crypto-ecdh-invalid", "crypto-cbc-bitflip",      "crypto-gcm-nonce",
        "pwn-srop-chain",      "pwn-off-by-one",           "pwn-sandbox-escape",
        "rev-vm-bytecode",     "rev-go-binary",           "rev-dotnet-obf",
        "gobl1n-poke-l4bs",
    ],
    "team_05": [
        "web-cors-chain",      "web-java-deserialization", "web-waf-bypass",
        "crypto-rsa-crt-fault","crypto-bleichenbacher",    "crypto-wiener",
        "pwn-aarch64-rop",     "pwn-heap-master",           "pwn-driver-exploit",
        "rev-vm-bytecode",     "rev-go-binary",           "rev-dotnet-obf",
        "gobl1n-poke-l4bs",
    ],
}


# ---------------------------------------------------------------------------
# Nombres y descripciones GENÉRICAS para los jugadores
# (sin pistas sobre el vector de ataque — los retos reales se mantienen
#  en CHALLENGES solo como referencia interna para el staff del CTF)
# ---------------------------------------------------------------------------
_CATEGORY_DESCS: dict[str, str] = {
    "web":    "Servicio web en producción. Analiza el objetivo y extrae la flag del sistema.",
    "crypto": "Servicio criptográfico activo. Estudia el protocolo y obtén la flag.",
    "pwn":    "Binario en ejecución en el servidor. Explótalo y lee la flag.",
    "rev":    "Artefacto binario para analizar. Entiende su lógica y extrae la flag.",
    "gobl1n": "Plataforma de juego retro. Explora el entorno y extrae la flag.",
}
_ROMAN = ("I", "II", "III")

# _PUBLIC_META[challenge_id] = (nombre_publico, descripcion_publica)
# Se genera automáticamente a partir de ASSIGNMENTS: sin pistas del vector.
_PUBLIC_META: dict[str, tuple[str, str]] = {}
for _tid, _cids in ASSIGNMENTS.items():
    _by_cat: dict[str, list[str]] = {}
    for _cid in _cids:
        _cat = next(c for _id, c, *_ in CHALLENGES if _id == _cid)
        _by_cat.setdefault(_cat, []).append(_cid)
    for _cat, _cat_cids in _by_cat.items():
        for _i, _cid in enumerate(_cat_cids):
            _PUBLIC_META[_cid] = (
                f"{_cat.upper()} {_ROMAN[_i]}",
                _CATEGORY_DESCS.get(_cat, "Sistema objetivo. Compromételo y obtén la flag."),
            )


def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    alphabet = alphabet.translate(str.maketrans("", "", "Il1O0"))
    return "".join(secrets.choice(alphabet) for _ in range(length))


async def seed(reset: bool) -> None:
    await init_db()

    async with SessionLocal() as db:
        if reset:
            await db.execute(delete(ChallengeInstance))
            await db.execute(delete(TeamChallengeAssignment))
            await db.execute(delete(Solve))
            await db.execute(delete(Challenge))
            await db.execute(delete(Team))
            await db.commit()
            print("[reset] Tablas limpiadas.")

        # --- Retos ---
        existing_cids = {c for (c,) in (await db.execute(
            select(Challenge.challenge_id)
        )).all()}

        new_count = 0
        updated_count = 0
        for order, (cid, cat, name, pts, desc, conn) in enumerate(CHALLENGES):
            pub_name, pub_desc = _PUBLIC_META.get(cid, (name, desc))
            if cid in existing_cids:
                # Actualiza nombre, descripción y puntos sin borrar solves.
                await db.execute(
                    update(Challenge).where(Challenge.challenge_id == cid)
                    .values(name=pub_name, description=pub_desc, points=pts)
                )
                updated_count += 1
                continue
            db.add(Challenge(
                challenge_id=cid, category=cat, name=pub_name, difficulty="insane",
                points=pts, description=pub_desc, connection_info=conn,
                visible=True, sort_order=order,
            ))
            new_count += 1
        await db.commit()
        print(f"[seed] {new_count} retos nuevos + {updated_count} actualizados ({len(CHALLENGES)} total).")

        # --- Equipos ---
        existing_teams = {t for (t,) in (await db.execute(
            select(Team.team_id)
        )).all()}

        credentials: list[tuple[str, str]] = []
        for n in range(1, 6):
            tid = f"team_{n:02d}"
            if tid in existing_teams:
                continue
            pw = _random_password()
            credentials.append((tid, pw))
            db.add(Team(
                team_id=tid,
                display_name=TEAM_NAMES[n],
                password_hash=hash_password(pw),
            ))
        await db.commit()

        # --- Asignaciones (idempotente) ---
        existing_asgn = {
            (row[0], row[1])
            for row in (await db.execute(
                select(TeamChallengeAssignment.team_id, TeamChallengeAssignment.challenge_id)
            )).all()
        }

        for tid, cids in ASSIGNMENTS.items():
            for cid in cids:
                if (tid, cid) not in existing_asgn:
                    db.add(TeamChallengeAssignment(team_id=tid, challenge_id=cid))
        await db.commit()
        print("[seed] Asignaciones guardadas (3 retos × 4 categorías × 5 equipos = 60 instancias).")

    # --- Credenciales ---
    if credentials:
        print("\n=== CREDENCIALES (guardar en lugar seguro) ===")
        print(f"{'EQUIPO':<14} {'NOMBRE':<20} CONTRASEÑA")
        print("-" * 52)
        lines = []
        for tid, pw in credentials:
            n = int(tid.split("_")[1])
            name = TEAM_NAMES[n]
            print(f"{tid:<14} {name:<20} {pw}")
            lines.append(f"{tid}\t{name}\t{pw}")
            for cid in ASSIGNMENTS.get(tid, []):
                cat = next(c for _id, c, *_ in CHALLENGES if _id == cid)
                print(f"  [{cat:6}] {cid}")
        with open("credentials.txt", "w", encoding="utf-8") as fh:
            fh.write("team_id\tdisplay_name\tpassword\n")
            fh.write("\n".join(lines) + "\n")
        print("\nGuardado en credentials.txt")
    else:
        print("Equipos ya existían.")

    print("\n[seed] Completado.")
    print("Asignaciones por equipo:")
    for tid, cids in sorted(ASSIGNMENTS.items()):
        n = int(tid.split("_")[1])
        print(f"  {tid} ({TEAM_NAMES[n]}):")
        for cid in cids:
            cat = next(c for _id, c, *_ in CHALLENGES if _id == cid)
            print(f"    [{cat:6}] {cid}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    asyncio.run(seed(args.reset))

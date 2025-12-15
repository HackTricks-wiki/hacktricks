# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patrones comunes en CTF

- "Signature" es en realidad `hash(secret || message)` → length extension.
- Hashes de contraseñas unsalted → trivial cracking / lookup.
- Confundir hash con MAC (hash != autenticación).

## Hash length extension attack

### Técnica

A menudo puedes explotar esto si un servidor calcula una "signature" como:

`sig = HASH(secret || message)`

y usa un hash Merkle–Damgård (ejemplos clásicos: MD5, SHA-1, SHA-256).

Si conoces:

- `message`
- `sig`
- función hash
- (o puedes brute-forcear) `len(secret)`

Entonces puedes calcular una signature válida para:

`message || padding || appended_data`

sin conocer el secret.

### Limitación importante: HMAC is not affected

Los ataques de length extension se aplican a construcciones como `HASH(secret || message)` para hashes Merkle–Damgård. No se aplican a **HMAC** (p. ej., HMAC-SHA256), que está diseñado específicamente para evitar esta clase de problema.

### Herramientas

- hash_extender:
{{#ref}}
https://github.com/iagox86/hash_extender
{{#endref}}
- hashpump:
{{#ref}}
https://github.com/bwall/HashPump
{{#endref}}

### Buena explicación

{{#ref}}
https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
{{#endref}}

## Password hashing and cracking

### Primeras preguntas

- ¿Está **salted**? (busca formatos `salt$hash`)
- ¿Es un **fast hash** (MD5/SHA1/SHA256) o un **slow KDF** (bcrypt/scrypt/argon2/PBKDF2)?
- ¿Tienes una **format hint** (hashcat mode / John format)?

### Flujo de trabajo práctico

1. Identifica el hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Si es unsalted y común: prueba DBs online y herramientas de identificación de la sección crypto workflow.
3. De lo contrario, crackea:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errores comunes que puedes explotar

- Misma contraseña reutilizada entre usuarios → crackea una, pivot.
- Hashes truncados / transformaciones personalizadas → normaliza y reintenta.
- Parámetros débiles de KDF (p. ej., pocas iteraciones PBKDF2) → aún crackeable.

{{#include ../../banners/hacktricks-training.md}}

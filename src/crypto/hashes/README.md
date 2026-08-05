# Hashes, MACs y KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patrones comunes de CTF

- "Signature" es en realidad `hash(secret || message)` → length extension.
- Password hashes sin salt → cracking trivial / lookup.
- Confundir hash con MAC (hash != autenticación).

## Ataque de hash length extension

### Técnica

A menudo puedes explotar esto si un servidor calcula una "signature" como:

`sig = HASH(secret || message)`

y utiliza un hash Merkle–Damgård (ejemplos clásicos: MD5, SHA-1, SHA-256).

Si conoces:

- `message`
- `sig`
- función hash
- (o puedes hacer brute-force de) `len(secret)`

Entonces puedes calcular una signature válida para:

`message || padding || appended_data`

sin conocer el secret.<sup>[[1]](#references)</sup>

### Limitación importante: HMAC no se ve afectado

Los ataques de length extension se aplican a construcciones como `HASH(secret || message)` para hashes Merkle–Damgård. No se aplican a **HMAC** (por ejemplo, HMAC-SHA256), que está diseñado específicamente para evitar esta clase de problema.<sup>[[1]](#references)</sup>

### Tools

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

## Password hashing y cracking

### Primeras preguntas

- ¿Tiene **salt**? (busca formatos `salt$hash`)
- ¿Es un **hash rápido** (MD5/SHA1/SHA256) o un **KDF lento** (bcrypt/scrypt/argon2/PBKDF2)?
- ¿Tienes una **pista sobre el formato** (modo de hashcat / formato de John)?

### Flujo de trabajo práctico

1. Identifica el hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Si no tiene salt y es común: prueba DBs online y las herramientas de identificación de la sección de crypto workflow.
3. De lo contrario, haz cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errores comunes que puedes explotar

- Misma password reutilizada entre usuarios → crackea una y haz pivot.
- Hashes truncados / transforms personalizadas → normaliza y vuelve a intentarlo.
- Parámetros débiles del KDF (por ejemplo, pocas iteraciones de PBKDF2) → todavía se pueden crackear.

## Referencias

- [1] [Everything you need to know about hash length extension attacks](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)

{{#include ../../banners/hacktricks-training.md}}

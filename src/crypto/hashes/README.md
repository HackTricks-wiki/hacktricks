# Hashes, MACs y KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patrones comunes de CTF

- "Signature" en realidad es `hash(secret || message)` → extensión de longitud.
- Hashes de contraseñas sin salt → cracking repetido más rápido y ataques de búsqueda precomputada.
- Confundir hash con MAC (hash != autenticación).

## Ataque de extensión de longitud de hash

### Técnica

Un ataque de extensión de longitud puede ser posible cuando un servidor calcula una "signature" como:

`sig = HASH(secret || message)`

y utiliza un hash Merkle-Damgård como MD5, SHA-1 o SHA-256.

Si conoces:

- `message`
- `sig`
- función hash
- (o puedes hacer brute-force de) `len(secret)`

Entonces puedes calcular una signature válida para:

`message || padding || appended_data`

sin conocer el secreto.<sup>[[1]](#references)</sup>

### Limitación importante: HMAC no se ve afectado

Los ataques de extensión de longitud se aplican a construcciones de prefijo vulnerables como `HASH(secret || message)`. No exponen la construcción HMAC (por ejemplo, HMAC-SHA256), que combina una clave con aplicaciones hash internas y externas separadas.<sup>[[1]](#references)[[2]](#references)</sup>

### Herramientas

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings de Python para la herramienta de extensión de longitud HashPump<sup>[[7]](#references)</sup>

### Buena explicación

[Todo lo que necesitas saber sobre los ataques de extensión de longitud de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing y cracking de contraseñas

### Primeras preguntas<sup>[[4]](#references)</sup>

- ¿Está **salted**? (busca formatos `salt$hash`)
- ¿Es un **hash rápido** (MD5/SHA1/SHA256) o un **KDF lento** (bcrypt/scrypt/argon2/PBKDF2)?
- ¿Tienes una **pista sobre el formato** (modo de hashcat / formato de John)?

### Flujo de trabajo práctico<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifica el hash:
- `hashid <hash>`
- `hashcat --example-hashes | rg -n "<pattern>"`
2. Si no tiene salt y es común: prueba DBs online y herramientas de identificación de la sección de crypto workflow.
3. De lo contrario, haz cracking:
- `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
- `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errores comunes que puedes explotar

- Misma contraseña reutilizada entre usuarios → crackea una y haz pivot.
- Hashes truncados / transforms personalizados → normaliza y vuelve a intentarlo.
- Parámetros débiles del KDF (por ejemplo, pocas iteraciones de PBKDF2) → todavía se pueden crackear.

## References

- [1] [SkullSecurity - Todo lo que necesitas saber sobre los ataques de extensión de longitud de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - El código de autenticación de mensajes basado en hash con clave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Hoja de trucos para el almacenamiento de contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes de ejemplo de Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opciones de línea de comandos de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings de Python de `hashpumpy` para HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}

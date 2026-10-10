# Hashes, MACs y KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patrones comunes en CTF

- Una «firma» es en realidad `hash(secret || message)` → extensión de longitud.
- Hashes de contraseñas sin salt → cracking repetido más rápido y ataques de búsqueda precomputada.
- Confundir hash con MAC (hash != autenticación).

## Hash length extension attack

### Técnica

Un ataque de extensión de longitud puede ser posible cuando un servidor calcula una «firma» como:

`sig = HASH(secret || message)`

y usa un hash Merkle-Damgård, como MD5, SHA-1 o SHA-256.

Si conoces:

- `message`
- `sig`
- la función hash
- (o puedes aplicar fuerza bruta a) `len(secret)`

Entonces puedes calcular una firma válida para:

`message || padding || appended_data`

sin conocer el secreto.<sup>[[1]](#references)</sup>

### Limitación importante: HMAC no se ve afectado

Los ataques de extensión de longitud se aplican a construcciones vulnerables con prefijo, como `HASH(secret || message)`. No exponen la construcción HMAC (por ejemplo, HMAC-SHA256), que combina una clave con aplicaciones separadas del hash interno y externo.<sup>[[1]](#references)[[2]](#references)</sup>

### Herramientas

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings de Python para la herramienta de extensión de longitud HashPump<sup>[[7]](#references)</sup>

### Una buena explicación

[Todo lo que necesitas saber sobre los ataques de extensión de longitud de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing y cracking de contraseñas

### Primeras preguntas<sup>[[4]](#references)</sup>

- ¿Tiene **salt**? (busca formatos `salt$hash`)
- ¿Es un **hash rápido** (MD5/SHA1/SHA256) o una **KDF lenta** (bcrypt/scrypt/argon2/PBKDF2)?
- ¿Tienes una **pista del formato** (modo de hashcat / formato de John)?

### Flujo de trabajo práctico<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifica el hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Si no tiene salt y es común: prueba bases de datos en línea y herramientas de identificación de la sección de flujo de trabajo de crypto.
3. Si no, haz cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errores comunes que puedes aprovechar

- La misma contraseña se reutiliza entre usuarios → crackea una y pivota.
- Hashes truncados o transformaciones personalizadas → normaliza y vuelve a intentarlo.
- Parámetros débiles de KDF (por ejemplo, pocas iteraciones de PBKDF2) → aún se pueden crackear.

### Oracle bcrypt de entrada elegida con un secreto añadido

Un helper invocable que devuelve `bcrypt(user_input || secret)` puede exponer información sobre un secreto añadido si su implementación de bcrypt trunca silenciosamente la entrada después de 72 **bytes**. Un límite de caracteres aplicado antes de la codificación UTF-8 no impone ese límite de bytes: los caracteres multibyte pueden ocupar la entrada de bcrypt y dejar espacio solo para un pequeño prefijo del secreto. Las entradas elegidas y sus hashes devueltos pueden permitir entonces comprobar sin conexión bytes candidatos del sufijo. Esto requiere controlar la entrada del helper, conocer su transformación y codificación exactas, y que la implementación realmente trunque; que exista un helper invocable o un hash bcrypt por sí solo no demuestra toda la cadena. [La documentación de pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) indica que el `hashpw` actual genera un error con entradas de más de 72 bytes, mientras que el comportamiento anterior las truncaba silenciosamente. Otros wrappers pueden aplicar un prehash o rechazar entradas largas, así que verifica la implementación instalada en lugar de asumir que trunca.

Usar un secreto recuperado contra otra cuenta también requiere pruebas de que su hash expuesto se generó con el **mismo** secreto y transformación, además de una credencial o vía de inicio de sesión independiente. Un helper de hashing ejecutado como root solo debe considerarse un oracle si el usuario con menos privilegios puede invocarlo según la política efectiva; la enumeración pasiva del host no necesita llamarlo ni enviar contraseñas elegidas.

## References

- [1] [SkullSecurity - Todo lo que necesitas saber sobre los ataques de extensión de longitud de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Código de autenticación de mensajes con hash y clave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Guía práctica de almacenamiento de contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes de ejemplo de hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opciones de línea de comandos de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings de Python de `hashpumpy` para HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}

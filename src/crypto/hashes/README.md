# Hashes, MACs y KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patrones comunes de CTF

- La «firma» en realidad es `hash(secret || message)` → length extension.
- Hashes de contraseñas sin salt → cracking repetido más rápido y ataques de búsqueda precalculada.
- Confundir hash con MAC (hash != autenticación).

## Ataque de hash length extension

### Técnica

Un ataque de length extension puede ser posible cuando un servidor calcula una «firma» como:

`sig = HASH(secret || message)`

y usa un hash Merkle-Damgård, como MD5, SHA-1 o SHA-256.

Si conoces:

- `message`
- `sig`
- la función hash
- (o puedes averiguar por fuerza bruta) `len(secret)`

Entonces puedes calcular una firma válida para:

`message || padding || appended_data`

sin conocer el secreto.<sup>[[1]](#references)</sup>

### Limitación importante: HMAC no se ve afectado

Los ataques de length extension se aplican a construcciones de prefijo vulnerables, como `HASH(secret || message)`. No exponen la construcción HMAC (por ejemplo, HMAC-SHA256), que combina una clave con aplicaciones separadas de hash interno y externo.<sup>[[1]](#references)[[2]](#references)</sup>

### Herramientas

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings de Python para la herramienta de length extension HashPump<sup>[[7]](#references)</sup>

### Buena explicación

[Todo lo que necesitas saber sobre los ataques de hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing y cracking de contraseñas

### Primeras preguntas<sup>[[4]](#references)</sup>

- ¿Tiene **salt**? (busca formatos `salt$hash`)
- ¿Es un **hash rápido** (MD5/SHA1/SHA256) o un **KDF lento** (bcrypt/scrypt/argon2/PBKDF2)?
- ¿Tienes una **pista sobre el formato** (modo de hashcat / formato de John)?

### Flujo de trabajo práctico<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifica el hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Si no tiene salt y es común: prueba bases de datos en línea y herramientas de identificación de la sección de flujo de trabajo de criptografía.
3. De lo contrario, haz cracking:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errores comunes que puedes aprovechar

- Se reutiliza la misma contraseña entre usuarios → haz cracking de una y pivota.
- Hashes truncados / transformaciones personalizadas → normaliza y vuelve a intentarlo.
- Parámetros débiles del KDF (p. ej., pocas iteraciones de PBKDF2) → sigue siendo posible hacer cracking.

### Oracle bcrypt con entrada elegida y un secreto añadido

Un helper invocable que devuelve `bcrypt(user_input || secret)` puede revelar información sobre un secreto añadido si su implementación de bcrypt trunca silenciosamente la entrada después de 72 **bytes**. Un límite de caracteres aplicado antes de la codificación UTF-8 no impone ese límite en bytes: los caracteres multibyte pueden llenar la entrada de bcrypt y dejar espacio solo para un pequeño prefijo del secreto. Las entradas elegidas y los hashes devueltos pueden entonces permitir comprobaciones fuera de línea de bytes candidatos del sufijo. Esto requiere controlar la entrada del helper, conocer su transformación y codificación exactas, y que la implementación realmente trunque; la existencia de un helper invocable o de un hash bcrypt por sí sola no demuestra esta cadena. La [documentación de pyca/bcrypt](https://github.com/pyca/bcrypt#maximum-password-length) indica que la versión actual de `hashpw` genera un error para entradas de más de 72 bytes, mientras que el comportamiento anterior las truncaba silenciosamente. Otros wrappers pueden aplicar un prehash o rechazar entradas largas, así que verifica la implementación instalada en lugar de asumir que trunca.

Usar un secreto recuperado contra otra cuenta también requiere pruebas de que su hash expuesto se generó con el **mismo** secreto y la misma transformación, además de una credencial o ruta de inicio de sesión independiente. Un helper de hashing que se ejecuta como root solo debe considerarse un oracle si el usuario con menos privilegios puede invocarlo según la política efectiva; la enumeración pasiva del host no tiene por qué llamarlo ni enviar contraseñas elegidas.

## References

- [1] [SkullSecurity - Todo lo que necesitas saber sobre los ataques de hash length extension](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Código de autenticación de mensajes basado en hash con clave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Hoja de referencia sobre almacenamiento de contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes de ejemplo de Hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opciones de línea de comandos de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings de Python de `hashpumpy` para HashPump](https://pypi.org/project/hashpumpy/)
{{#include ../../banners/hacktricks-training.md}}

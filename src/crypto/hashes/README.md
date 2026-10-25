# Hashes, MACs & KDFs

{{#include ../../banners/hacktricks-training.md}}

## Patrones comunes de CTF

- La «firma» en realidad es `hash(secret || message)` → length extension.
- Hashes de contraseñas sin salt → cracking repetido más rápido y ataques de búsqueda precomputada.
- Confundir un hash con un MAC (hash != autenticación).

## Búsquedas de hashes MD5 con entrada elegida

Estos ejemplos de Python buscan dos patrones de salida diferentes: un sufijo MD5 elegido y un valor MD5 que comienza con `0e` seguido únicamente de dígitos. El último patrón es relevante cuando una aplicación compara cadenas numéricas de forma flexible; consulta el comportamiento específico de PHP y las salvedades según la versión en [comparaciones flexibles en PHP](../../network-services-pentesting/pentesting-web/php-tricks-esp/README.md#loose-comparisons-and-type-juggling).

### Fuerza bruta de sufijos de hash MD5

```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
    plaintext = str(candidate)
    hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
    if hash[-1*(len(target)):] == target: #End in target
        print('plaintext:"' + plaintext + '", md5:' + hash)
        break
    candidate = candidate + 1
```

### Generación de hashes 0e de MD5 para comparaciones laxas

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
	target = '0e'
	plaintext = f"a_prefix{str(num)}a_suffix"
	hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

	if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
		print('plaintext: ' + plaintext + ', md5: ' + hash)
		queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
	for num in range(thread_i, 100**50, threads):
		loose_comparison(queue, num)

def main():
	procs = []
	queue = Queue()
	threads = cpu_count() # 2

	for thread_i in range(threads):
		proc = Process(target=worker, args=(queue, thread_i, threads ))
		proc.daemon = True # kill all subprocess when main process exits.
		procs.append(proc)
		proc.start()

	while queue.empty(): # exits when a subprocess is done
		pass
	return 0

main()
```

## Ataque de extensión de longitud de hash

### Técnica

Un ataque de extensión de longitud puede ser posible cuando un servidor calcula una «firma» como:

`sig = HASH(secret || message)`

y usa una función hash Merkle-Damgård, como MD5, SHA-1 o SHA-256.

Si conoces:

- `message`
- `sig`
- la función hash
- (o puedes hacer brute-force para averiguar) `len(secret)`

Entonces puedes calcular una firma válida para:

`message || padding || appended_data`

sin conocer el secreto.<sup>[[1]](#references)</sup>

### Limitación importante: HMAC no se ve afectado

Los ataques de extensión de longitud se aplican a construcciones de prefijo vulnerables, como `HASH(secret || message)`. No afectan a la construcción HMAC (por ejemplo, HMAC-SHA256), que combina una clave con aplicaciones separadas de hash interno y externo.<sup>[[1]](#references)[[2]](#references)</sup>

Para saber cómo encontrar y probar estas firmas en APIs web, consulta [Firmas de solicitudes y parámetros](../../pentesting-web/web-api-pentesting.md#request-and-parameter-signatures).

### Herramientas

- [`hash_extender`](https://github.com/iagox86/hash_extender)<sup>[[3]](#references)</sup>
- [`hashpumpy`](https://pypi.org/project/hashpumpy/), bindings de Python para la herramienta de extensión de longitud HashPump<sup>[[7]](#references)</sup>

### Buena explicación

[Todo lo que necesitas saber sobre los ataques de extensión de longitud de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)<sup>[[1]](#references)</sup>

## Hashing ambiguo de tuplas y MACs

### Ataque de confusión de límites

Las APIs de hash incremental no autentican los límites entre llamadas. `update(A); update(B)` calcula el hash de la misma cadena de bytes que `update(A + B)`. Por lo tanto, aplicar hash o MAC a una concatenación sin procesar no autentica una tupla. Si los campos adyacentes tienen longitudes variables, un atacante puede redistribuir los bytes en una tupla diferente sin encontrar una colisión en la función hash subyacente:<sup>[[8]](#references)[[9]](#references)</sup>

```python
import hashlib

def raw_hash(parts):
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()

assert raw_hash([b"alice", b"admin"]) == raw_hash([b"aliceadmin", b""])
```

Esto se vuelve explotable cuando el verificador cree que el digest vincula los significados de los campos, pero una entrada controlada por el atacante puede llegar a otro parser o paso del protocolo que asigne límites diferentes. Los compromisos pueden admitir aperturas alternativas y los transcripts de Fiat-Shamir pueden interpretarse como afirmaciones diferentes. HMAC evita [la extensión de longitud de hash](#hash-length-extension-attack), pero `HMAC(K, A || B)` sigue teniendo esta ambigüedad de codificación de tuplas, porque ambas tuplas producen los mismos bytes de mensaje.<sup>[[8]](#references)[[9]](#references)</sup>

Usa este flujo de auditoría para comprobar si una codificación de tuplas ambigua cruza un límite de seguridad.<sup>[[8]](#references)[[9]](#references)</sup>

1. Busca `HASH(A || B)`, `HMAC(K, A || B)` y llamadas consecutivas a `update()`/`Write()` sobre dos o más campos.
2. Marca todos los campos controlados por el atacante o de longitud variable. Intenta mover bytes de un lado a otro de cada límite manteniendo intacta la concatenación completa. Incluye campos vacíos.
3. Comprueba si los esquemas de delimitación permiten que las entradas contengan los bytes delimitadores, si hay discrepancias en el escape y si algunos diseños codifican la longitud solo de ciertos campos.
4. Rastrea cómo analiza cada consumidor los bytes autenticados. Un caso candidato solo es significativo si una partición alternativa cambia una decisión de seguridad, una afirmación de prueba, un registro, una transacción o la apertura de un compromiso. Los campos de ancho fijo o una serialización canónica e inyectiva evitan este ataque concreto.
5. Comprueba si el mismo digest codificado se acepta en otra versión del protocolo, tipo de mensaje, ronda o aplicación. Vincula estos contextos explícitamente en lugar de confiar en que los llamadores los mantengan separados.

### SequenceHash y SequenceMAC

SequenceHash es una construcción independiente de la función hash para secuencias de cadenas de bytes. Cada operación `add()` es atómica: añade el valor y un sufijo de longitud fijo de 16 bytes en little-endian al hash interno. Los valores vacíos siguen siendo objetos distintos. Un hash externo evita exponer un estado interno susceptible a la extensión de longitud, mientras que una cadena de personalización opcional proporciona separación de dominio. No sustituyas `add()` por las llamadas de escritura normales de la API de la función hash subyacente.<sup>[[8]](#references)[[9]](#references)</sup>

```python
import sequencehash

h = sequencehash.SequenceHash.new("sha256")
h.add(b"alice")
h.add(b"admin")
digest = h.result_with_customizer(b"example:v1:user-record")
```

Elige el personalizador como parte de la definición del protocolo e incluye información suficiente para distinguir la aplicación, la versión del protocolo, el tipo de mensaje y la ronda. SequenceHash sigue requiriendo que todas las partes acuerden el orden de los campos, la codificación de bytes y la serialización canónica, y no puede proteger un campo omitido. Las implementaciones deben comprobarse con los vectores de prueba intermedios y finales de C2SP.<sup>[[8]](#references)[[11]](#references)</sup>

Para la autenticación, SequenceMAC ofrece la misma codificación atómica y la misma interfaz de personalización. Requiere una clave de al menos 32 bytes. A diferencia del preprocesamiento de claves de HMAC, sus encabezados se comprometen a la longitud exacta de la clave: una clave sin procesar larga no equivale a su prehash, y añadir bytes cero cambia la clave. Esta distinción importa cuando los componentes aceptan distintas representaciones de claves o metadatos de longitud.<sup>[[8]](#references)[[9]](#references)</sup>

```python
key = b"\x00" * 32
mac = sequencehash.SequenceMAC.new(key, digestmod="sha256")
mac.add(header_bytes)
mac.add(body_bytes)
tag = mac.result_with_customizer(b"example:v1:request-mac")
```

La API de Python y las implementaciones equivalentes en Go y Rust están disponibles como referencia, pero las implementaciones del protocolo deben seguir la especificación vigente de C2SP en lugar de recrear la codificación a partir de este resumen.<sup>[[8]](#references)[[10]](#references)</sup>

## Hashing y cracking de contraseñas

### Preguntas iniciales<sup>[[4]](#references)</sup>

- ¿Tiene **salt**? (busca formatos `salt$hash`)
- ¿Es un **hash rápido** (MD5/SHA1/SHA256) o una **KDF lenta** (bcrypt/scrypt/argon2/PBKDF2)?
- ¿Tienes una **indicación del formato** (modo de hashcat / formato de John)?

### Flujo de trabajo práctico<sup>[[5]](#references)[[6]](#references)</sup>

1. Identifica el hash:
   - `hashid <hash>`
   - `hashcat --example-hashes | rg -n "<pattern>"`
2. Si no tiene salt y es común: prueba bases de datos en línea y herramientas de identificación de la sección sobre flujo de trabajo de criptografía.
3. De lo contrario, intenta crackearlo:
   - `hashcat -m <mode> -a 0 hashes.txt wordlist.txt`
   - `john --wordlist=wordlist.txt --format=<fmt> hashes.txt`

### Errores comunes que puedes aprovechar

- Se reutiliza la misma contraseña entre usuarios → crackea una y pivota.
- Hashes truncados / transformaciones personalizadas → normaliza y vuelve a intentarlo.
- Parámetros débiles de KDF (por ejemplo, pocas iteraciones de PBKDF2) → aún se pueden crackear.

### Oracle de bcrypt con entrada elegida y un secreto añadido

Un helper invocable que devuelve `bcrypt(user_input || secret)` puede revelar información sobre un secreto añadido si su implementación de bcrypt trunca silenciosamente la entrada después de 72 **bytes**. Un límite de caracteres aplicado antes de la codificación UTF-8 no impone ese límite de bytes: los caracteres multibyte pueden llenar la entrada de bcrypt y dejar espacio solo para un pequeño prefijo del secreto. Las entradas elegidas y los hashes devueltos pueden entonces permitir verificaciones sin conexión de bytes candidatos del sufijo. Esto requiere controlar la entrada del helper, conocer su transformación y codificación exactas, y que la implementación realmente trunque; que exista un helper invocable o un hash de bcrypt no demuestra por sí solo esta cadena. [pyca/bcrypt documenta](https://github.com/pyca/bcrypt#maximum-password-length) que la función `hashpw` actual genera un error con entradas de más de 72 bytes, mientras que el comportamiento anterior las truncaba silenciosamente. Otros wrappers pueden aplicar un prehash o rechazar entradas largas, así que verifica la implementación instalada en lugar de asumir que trunca.

Usar un secreto recuperado contra otra cuenta también requiere pruebas de que su hash expuesto se generó con el **mismo** secreto y transformación, además de una ruta de credenciales o inicio de sesión independiente. Un helper de hashing ejecutado como root solo debe considerarse un oracle si el usuario con menos privilegios puede invocarlo según la política efectiva; la enumeración pasiva del host no necesita llamarlo ni enviar contraseñas elegidas.

## References

- [1] [SkullSecurity - Todo lo que necesitas saber sobre los ataques de extensión de longitud de hash](https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks)
- [2] [NIST FIPS 198-1 - Código de autenticación de mensajes basado en hash con clave](https://csrc.nist.gov/pubs/fips/198-1/final)
- [3] [hash_extender](https://github.com/iagox86/hash_extender)
- [4] [OWASP - Guía de almacenamiento de contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [5] [Hashes de ejemplo de hashcat](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [6] [Opciones de línea de comandos de John the Ripper](https://www.openwall.com/john/doc/OPTIONS.shtml)
- [7] [PyPI: bindings de Python de `hashpumpy` para HashPump](https://pypi.org/project/hashpumpy/)
- [8] [C2SP - Especificación de SequenceHash y SequenceMAC](https://c2sp.org/sequencehash)
- [9] [Trail of Bits - SequenceHash: multihashing para todos](https://blog.trailofbits.com/2026/10/02/sequencehash-multihashing-for-the-rest-of-us/)
- [10] [Trail of Bits - Implementación de SequenceHash en Python](https://github.com/trailofbits/sequencehash-py)
- [11] [C2SP CCTV - Vectores de prueba de SequenceHash](https://github.com/C2SP/CCTV/tree/main/sequencehash)

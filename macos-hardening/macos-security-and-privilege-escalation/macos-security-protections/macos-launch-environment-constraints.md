# Restricciones de Lanzamiento/Entorno en macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Información Básica

Las restricciones de lanzamiento en macOS se introdujeron para mejorar la seguridad al **regular cómo, quién y desde dónde se puede iniciar un proceso**. Introducidas en macOS Ventura, proporcionan un marco que categoriza **cada binario del sistema en categorías de restricciones** distintas, que se definen dentro de la **caché de confianza**, una lista que contiene los binarios del sistema y sus respectivos hashes. Estas restricciones se extienden a cada binario ejecutable dentro del sistema, lo que implica un conjunto de **reglas** que delinean los requisitos para **lanzar un binario en particular**. Las reglas abarcan restricciones propias que un binario debe cumplir, restricciones parentales que deben cumplir el proceso padre y restricciones responsables que deben cumplir otras entidades relevantes.

El mecanismo se extiende a las aplicaciones de terceros a través de las **restricciones de entorno**, a partir de macOS Sonoma, lo que permite a los desarrolladores proteger sus aplicaciones especificando un **conjunto de claves y valores para las restricciones de entorno**.

Define las **restricciones de lanzamiento y biblioteca de entorno** en diccionarios de restricciones que guardas en archivos de lista de propiedades de **`launchd`**, o en archivos de lista de propiedades separados que utilizas en la firma de código.

Existen 4 tipos de restricciones:

* **Restricciones Propias**: Restricciones aplicadas al binario **en ejecución**.
* **Proceso Padre**: Restricciones aplicadas al **proceso padre** (por ejemplo, **`launchd`** ejecutando un servicio XP).
* **Restricciones Responsables**: Restricciones aplicadas al **proceso que llama al servicio** en una comunicación XPC.
* **Restricciones de Carga de Biblioteca**: Utiliza restricciones de carga de biblioteca para describir selectivamente el código que se puede cargar.

Entonces, cuando un proceso intenta lanzar otro proceso, llamando a `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)`, el sistema operativo verifica que el **archivo ejecutable** cumpla con su **propia restricción propia**. También verifica que el **archivo ejecutable del proceso padre** cumpla con la **restricción del proceso padre** del ejecutable, y que el **archivo ejecutable del proceso responsable** cumpla con la **restricción del proceso responsable** del ejecutable. Si alguna de estas restricciones de lanzamiento no se cumple, el sistema operativo no ejecuta el programa.

Si al cargar una biblioteca alguna parte de la **restricción de la biblioteca no es verdadera**, tu proceso **no carga** la biblioteca.

## Categorías de LC

Un LC está compuesto por **hechos** y **operaciones lógicas** (and, or...) que combinan hechos.

Los [**hechos que un LC puede utilizar están documentados**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Por ejemplo:

* is-init-proc: Un valor booleano que indica si el ejecutable debe ser el proceso de inicialización del sistema operativo (`launchd`).
* is-sip-protected: Un valor booleano que indica si el ejecutable debe ser un archivo protegido por System Integrity Protection (SIP).
* `on-authorized-authapfs-volume:` Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
* `on-authorized-authapfs-volume`: Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
* Volumen Cryptexes
* `on-system-volume:` Un valor booleano que indica si el sistema operativo cargó el ejecutable desde el volumen del sistema actualmente arrancado.
* Dentro de /System...
* ...

Cuando un binario de Apple está firmado, se **asigna a una categoría de LC** dentro de la **caché de confianza**.

* Las **categorías de LC de iOS 16** se [**han invertido y documentado aquí**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Las **categorías de LC actuales (macOS 14** - Somona) se han invertido y sus [**descripciones se pueden encontrar aquí**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Por ejemplo, la Categoría 1 es:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(en volumen autorizado authapfs || en volumen del sistema)`: Debe estar en el volumen del sistema o Cryptexes.
* `tipo de lanzamiento == 1`: Debe ser un servicio del sistema (plist en LaunchDaemons).
* &#x20; `categoría de validación == 1`: Un ejecutable del sistema operativo.
* `es-proceso-inicio`: Launchd

### Reversión de Categorías LC

Tienes más información [**aquí**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), pero básicamente, están definidas en **AMFI (AppleMobileFileIntegrity)**, por lo que necesitas descargar el Kit de Desarrollo del Kernel para obtener el **KEXT**. Los símbolos que comienzan con **`kConstraintCategory`** son los más **interesantes**. Extrayéndolos obtendrás un flujo codificado DER (ASN.1) que deberás decodificar con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) o la biblioteca python-asn1 y su script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), lo cual te dará una cadena más comprensible.

## Restricciones del entorno

Estas son las Restricciones de Lanzamiento configuradas en **aplicaciones de terceros**. El desarrollador puede seleccionar los **hechos** y los **operandos lógicos a utilizar** en su aplicación para restringir el acceso a sí misma.

Es posible enumerar las Restricciones del Entorno de una aplicación con:
```bash
codesign -d -vvvv app.app
```
## Cachés de confianza

En **macOS** hay algunos cachés de confianza:

* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
* **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
* **`/System/Library/Security/OSLaunchPolicyData`**

Y en iOS parece que está en **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

### Enumeración de los cachés de confianza

Los archivos de caché de confianza anteriores están en formato **IMG4** e **IM4P**, siendo IM4P la sección de carga útil de un formato IMG4.

Puedes usar [**pyimg4**](https://github.com/m1stadev/PyIMG4) para extraer la carga útil de las bases de datos:

{% code overflow="wrap" %}
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
{% endcode %}

(Otra opción podría ser utilizar la herramienta [**img4tool**](https://github.com/tihmstar/img4tool), que funcionará incluso en M1 aunque la versión sea antigua y para x86\_64 si la instalas en las ubicaciones adecuadas).

Ahora puedes utilizar la herramienta [**trustcache**](https://github.com/CRKatri/trustcache) para obtener la información en un formato legible:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
La caché de confianza sigue la siguiente estructura, por lo que la **categoría LC es la cuarta columna**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Entonces, podrías usar un script como [**este**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) para extraer datos.

A partir de esos datos, puedes verificar las aplicaciones con un **valor de restricciones de lanzamiento de `0`**, que son aquellas que no tienen restricciones ([**ver aquí**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) para saber qué significa cada valor).

## Mitigaciones de ataque

Las restricciones de lanzamiento habrían mitigado varios ataques antiguos al **asegurarse de que el proceso no se ejecute en condiciones inesperadas**: por ejemplo, desde ubicaciones inesperadas o invocado por un proceso padre inesperado (si solo launchd debería lanzarlo).

Además, las restricciones de lanzamiento también **mitigan los ataques de degradación**.

Sin embargo, no mitigan los abusos comunes de **XPC**, las inyecciones de código de **Electron** o las inyecciones de **dylib** sin validación de biblioteca (a menos que se conozcan las ID de equipo que pueden cargar bibliotecas).

### Protección de XPC Daemon

En el momento de escribir esto (lanzamiento de Sonoma), el **proceso responsable** del servicio XPC del demonio **es el propio servicio XPC** en lugar del cliente conectado. (FB enviado: FB13206884). Suponiendo por un momento que sea un error, aún **no podremos lanzar el servicio XPC en nuestro código atacante**, pero si ya está **activo** (quizás porque fue invocado por la aplicación original), no hay nada que nos impida **conectarnos a él**. Entonces, aunque establecer la restricción podría ser una buena idea y **limitaría el tiempo de ataque**, no resuelve el problema principal, y nuestro servicio XPC aún debe validar correctamente el cliente conectado. Esa sigue siendo la única forma de asegurarlo. Además, como se mencionó al principio, ni siquiera funciona de esta manera ahora.

### Protección de Electron

Incluso si es necesario que la aplicación se **abra mediante LaunchService** (en las restricciones del padre). Esto se puede lograr utilizando **`open`** (que puede establecer variables de entorno) o utilizando la **API de Launch Services** (donde se pueden indicar variables de entorno).

## Referencias

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**merchandising oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

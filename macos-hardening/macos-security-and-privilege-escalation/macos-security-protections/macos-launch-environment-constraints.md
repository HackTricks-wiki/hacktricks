# Restricciones de Inicio/Ambiente de macOS y Caché de Confianza

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres que tu **empresa sea anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Información Básica

Las restricciones de inicio en macOS se introdujeron para mejorar la seguridad al **regular cómo, quién y desde dónde puede iniciarse un proceso**. Introducidas en macOS Ventura, proporcionan un marco que categoriza **cada binario del sistema en categorías de restricciones distintas**, definidas dentro de la **caché de confianza**, una lista que contiene binarios del sistema y sus respectivos hashes. Estas restricciones se extienden a cada binario ejecutable dentro del sistema, implicando un conjunto de **reglas** que delinean los requisitos para **iniciar un binario en particular**. Las reglas abarcan restricciones propias que un binario debe cumplir, restricciones parentales que deben cumplir su proceso padre y restricciones responsables que deben cumplir otras entidades relevantes.

El mecanismo se extiende a aplicaciones de terceros a través de **Restricciones de Ambiente**, comenzando desde macOS Sonoma, lo que permite a los desarrolladores proteger sus aplicaciones especificando un **conjunto de claves y valores para las restricciones de ambiente**.

Defines **restricciones de inicio y biblioteca de ambiente** en diccionarios de restricciones que guardas en **archivos de lista de propiedades de `launchd`**, o en **archivos de lista de propiedades separados** que utilizas en la firma de código.

Existen 4 tipos de restricciones:

* **Restricciones Propias**: Restricciones aplicadas al binario **en ejecución**.
* **Proceso Padre**: Restricciones aplicadas al **proceso padre del proceso** (por ejemplo, **`launchd`** ejecutando un servicio XP).
* **Restricciones Responsables**: Restricciones aplicadas al **proceso que llama al servicio** en una comunicación XPC.
* **Restricciones de Carga de Biblioteca**: Utiliza restricciones de carga de biblioteca para describir selectivamente el código que se puede cargar.

Por lo tanto, cuando un proceso intenta iniciar otro proceso —llamando a `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)`—, el sistema operativo verifica que el **archivo ejecutable** cumpla su **propia restricción**, que el **proceso padre** del proceso cumpla la **restricción del padre del ejecutable**, y que el **proceso responsable** del proceso cumpla la **restricción del proceso responsable del ejecutable**. Si alguna de estas restricciones de inicio no se cumple, el sistema operativo no ejecuta el programa.

Si al cargar una biblioteca alguna parte de la **restricción de la biblioteca no es verdadera**, tu proceso **no carga** la biblioteca.

## Categorías de LC

Un LC está compuesto por **hechos** y **operaciones lógicas** (y, o...) que combinan hechos.

Los [**hechos que un LC puede usar están documentados**](https://developer.apple.com/documentation/security/defining\_launch\_environment\_and\_library\_constraints). Por ejemplo:

* is-init-proc: Un valor booleano que indica si el ejecutable debe ser el proceso de inicialización del sistema operativo (`launchd`).
* is-sip-protected: Un valor booleano que indica si el ejecutable debe ser un archivo protegido por la Protección de Integridad del Sistema (SIP).
* `on-authorized-authapfs-volume:` Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
* `on-authorized-authapfs-volume`: Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
* Volumen Cryptexes
* `on-system-volume:` Un valor booleano que indica si el sistema operativo cargó el ejecutable desde el volumen del sistema actualmente arrancado.
* Dentro de /System...
* ...

Cuando un binario de Apple está firmado, se **asigna a una categoría de LC** dentro de la **caché de confianza**.

* Las **16 categorías de LC de iOS** fueron [**invertidas y documentadas aquí**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).
* Las actuales **categorías de LC (macOS 14** - Somona) han sido invertidas y sus [**descripciones se pueden encontrar aquí**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).

Por ejemplo, la Categoría 1 es:
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
* `(en-volumen-authapfs-autorizado || en-volumen-del-sistema)`: Debe estar en el volumen del Sistema o Cryptexes.
* `tipo-de-lanzamiento == 1`: Debe ser un servicio del sistema (plist en LaunchDaemons).
* `categoría-de-validación == 1`: Un ejecutable del sistema operativo.
* `es-proceso-de-inicio`: Launchd

### Reversión de Categorías LC

Tienes más información [**sobre esto aquí**](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/#reversing-constraints), pero básicamente, están definidos en **AMFI (AppleMobileFileIntegrity)**, por lo que necesitas descargar el Kit de Desarrollo del Kernel para obtener el **KEXT**. Los símbolos que comienzan con **`kConstraintCategory`** son los **interesantes**. Al extraerlos, obtendrás un flujo codificado DER (ASN.1) que necesitarás decodificar con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) o la biblioteca python-asn1 y su script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master) que te dará una cadena más comprensible.

## Restricciones del Entorno

Estas son las Restricciones de Lanzamiento configuradas en **aplicaciones de terceros**. El desarrollador puede seleccionar los **hechos** y **operandos lógicos a utilizar** en su aplicación para restringir el acceso a la misma.

Es posible enumerar las Restricciones del Entorno de una aplicación con:
```bash
codesign -d -vvvv app.app
```
## Cachés de confianza

En **macOS** existen algunos cachés de confianza:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Y en iOS parece estar en **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

{% hint style="warning" %}
En macOS que se ejecuta en dispositivos con Apple Silicon, si un binario firmado por Apple no está en el caché de confianza, AMFI se negará a cargarlo.
{% endhint %}

### Enumeración de cachés de confianza

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

(Otra opción podría ser usar la herramienta [**img4tool**](https://github.com/tihmstar/img4tool), la cual funcionará incluso en M1 aunque la versión sea antigua y para x86\_64 si la instalas en las ubicaciones adecuadas).

Ahora puedes usar la herramienta [**trustcache**](https://github.com/CRKatri/trustcache) para obtener la información en un formato legible:
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
Luego, podrías usar un script como [**este**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) para extraer datos.

A partir de esos datos, puedes verificar las aplicaciones con un valor de **restricciones de inicio de `0`**, que son las que no están restringidas ([**ver aquí**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) para ver qué representa cada valor).

## Mitigaciones de Ataque

Las Restricciones de Inicio habrían mitigado varios ataques antiguos al **asegurarse de que el proceso no se ejecute en condiciones inesperadas:** Por ejemplo, desde ubicaciones inesperadas o ser invocado por un proceso padre inesperado (si solo launchd debería iniciarlo).

Además, las Restricciones de Inicio también **mitigan ataques degradados**.

Sin embargo, **no mitigan abusos comunes de XPC**, inyecciones de código de **Electron** o inyecciones de **dylib** sin validación de biblioteca (a menos que se conozcan los IDs de equipo que pueden cargar bibliotecas).

### Protección de Demonio XPC

En la versión Sonoma, un punto notable es la **configuración de responsabilidad** del servicio XPC del demonio. El servicio XPC es responsable de sí mismo, a diferencia de que el cliente conectado sea responsable. Esto está documentado en el informe de retroalimentación FB13206884. Esta configuración puede parecer defectuosa, ya que permite ciertas interacciones con el servicio XPC:

- **Iniciar el Servicio XPC**: Si se asume que es un error, esta configuración no permite iniciar el servicio XPC a través de código malicioso.
- **Conectar a un Servicio Activo**: Si el servicio XPC ya está en ejecución (posiblemente activado por su aplicación original), no hay barreras para conectarse a él.

Si bien implementar restricciones en el servicio XPC podría ser beneficioso al **reducir la ventana para posibles ataques**, no aborda la preocupación principal. Asegurar la seguridad del servicio XPC requiere fundamentalmente **validar efectivamente al cliente conectado**. Este sigue siendo el único método para fortalecer la seguridad del servicio. Además, cabe destacar que la configuración de responsabilidad mencionada está actualmente operativa, lo que puede no estar alineado con el diseño previsto.


### Protección de Electron

Incluso si es necesario que la aplicación se **abra mediante LaunchService** (en las restricciones de los padres). Esto se puede lograr utilizando **`open`** (que puede establecer variables de entorno) o utilizando la **API de Launch Services** (donde se pueden indicar variables de entorno).

## Referencias

* [https://youtu.be/f1HA5QhLQ7Y?t=24146](https://youtu.be/f1HA5QhLQ7Y?t=24146)
* [https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/](https://theevilbit.github.io/posts/launch\_constraints\_deep\_dive/)
* [https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
* [https://developer.apple.com/videos/play/wwdc2023/10266/](https://developer.apple.com/videos/play/wwdc2023/10266/)

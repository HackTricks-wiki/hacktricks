# macOS Launch/Environment Constraints & Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Información básica

Las launch constraints en macOS se introdujeron para mejorar la seguridad mediante la **regulación de cómo, quién y desde dónde se puede iniciar un proceso**. Introducidas en macOS Ventura, proporcionan un framework que clasifica **cada binario del sistema en distintas categorías de constraints**, definidas dentro del **trust cache**, una lista que contiene los binarios del sistema y sus respectivos hashes​. Estas constraints se extienden a todos los binarios ejecutables del sistema e implican un conjunto de **reglas** que delimitan los requisitos para **iniciar un binario concreto**. Las reglas incluyen self constraints que debe satisfacer un binario, parent constraints que debe cumplir su proceso padre y responsible constraints que deben cumplir otras entidades relevantes​.<sup>[[1]](#references)[[4]](#references)</sup>

El mecanismo se extiende a las aplicaciones de terceros mediante **Environment Constraints**, начиная con macOS Sonoma, lo que permite a los desarrolladores proteger sus aplicaciones especificando un **conjunto de claves y valores para las environment constraints.**<sup>[[5]](#references)</sup>

Las **launch environment and library constraints** se definen en diccionarios de constraints que se guardan en **archivos de listas de propiedades de `launchd`**, o en **archivos de listas de propiedades independientes** que se utilizan en code signing.<sup>[[5]](#references)</sup>

Hay 4 tipos de constraints:

- **Self Constraints**: Constraints aplicadas al binario **en ejecución**.
- **Parent Process**: Constraints aplicadas al **proceso padre** del proceso (por ejemplo, **`launchd`** ejecutando un servicio XP)
- **Responsible Constraints**: Constraints aplicadas al **proceso que llama al servicio** en una comunicación XPC
- **Library load constraints**: Utiliza library load constraints para describir selectivamente el código que se puede cargar

Por tanto, cuando un proceso intenta iniciar otro proceso —llamando a `execve(_:_:_:)` o `posix_spawn(_:_:_:_:_:_:)`—, el sistema operativo comprueba que el archivo **ejecutable** **satisface su propia self constraint**. También comprueba que el ejecutable del proceso **padre** **satisface la parent constraint** del ejecutable y que el ejecutable del proceso **responsable** **satisface la responsible process constraint** del ejecutable. Si alguna de estas launch constraints no se satisface, el sistema operativo no ejecuta el programa.

Si, al cargar una library, cualquier parte de la **library constraint no es verdadera**, el proceso **no carga** la library.

## Categorías de LC

Una LC está compuesta por **facts** y **operaciones lógicas** (and, or...) que combinan facts.

Los[ **facts que puede utilizar una LC están documentados**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Por ejemplo:

- is-init-proc: Un valor booleano que indica si el ejecutable debe ser el proceso de inicialización del sistema operativo (`launchd`).
- is-sip-protected: Un valor booleano que indica si el ejecutable debe ser un archivo protegido por System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
- `on-authorized-authapfs-volume`: Un valor booleano que indica si el sistema operativo cargó el ejecutable desde un volumen APFS autorizado y autenticado.
- Volumen de Cryptexes
- `on-system-volume:`Un valor booleano que indica si el sistema operativo cargó el ejecutable desde el volumen del sistema actualmente iniciado.
- Dentro de /System...
- ...

Cuando se firma un binario de Apple, se **asigna a una categoría de LC** dentro del **trust cache**.

- Las **categorías de LC de iOS 16** fueron [**revertidas y documentadas aquí**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Las **categorías de LC actuales (macOS 14** - Somona) han sido revertidas y sus [**descripciones se pueden encontrar aquí**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Por ejemplo, la categoría 1 es:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Debe estar en el volumen System o Cryptexes.
- `launch-type == 1`: Debe ser un servicio del sistema (plist en LaunchDaemons).
- `validation-category == 1`: Un ejecutable del sistema operativo.
- `is-init-proc`: Launchd

### Inversión de categorías LC

Tienes más información [**aquí**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), pero básicamente, están definidas en **AMFI (AppleMobileFileIntegrity)**, por lo que necesitas descargar el Kernel Development Kit para obtener el **KEXT**. Los símbolos que comienzan por **`kConstraintCategory`** son los **interesantes**. Al extraerlos, obtendrás un flujo codificado en DER (ASN.1) que tendrás que decodificar con [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) o con la biblioteca python-asn1 y su script `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), que te proporcionará una cadena más comprensible.<sup>[[3]](#references)[[8]](#references)</sup>

## Restricciones del entorno

Estas son las Launch Constraints configuradas en **aplicaciones de terceros**. El desarrollador puede seleccionar los **hechos** y **operandos lógicos** que se usarán en su aplicación para restringir el acceso a esta.

Es posible enumerar las Environment Constraints de una aplicación con:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

En **macOS** hay algunos trust caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

Y en iOS parece estar en **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> En macOS ejecutándose en dispositivos Apple Silicon, si un binario firmado por Apple no está en el trust cache, AMFI se negará a cargarlo.

### Enumeración de Trust Caches

Los archivos de trust cache anteriores están en formato **IMG4** e **IM4P**, siendo IM4P la sección payload de un formato IMG4.

Puedes usar [**pyimg4**](https://github.com/m1stadev/PyIMG4) para extraer el payload de las bases de datos:
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
(Otra opción podría ser utilizar la herramienta [**img4tool**](https://github.com/tihmstar/img4tool), que se ejecutará incluso en M1 aunque la versión sea antigua y en x86_64 si la instalas en las ubicaciones adecuadas).

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
La trust cache sigue la siguiente estructura, por lo que la **categoría LC es la 4.ª columna**
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

Con esos datos puedes comprobar las Apps con un **valor de launch constraints de `0`**, que son las que no tienen restricciones ([**consulta aquí**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056) para saber qué significa cada valor).<sup>[[6]](#references)</sup>

## Mitigaciones contra ataques

Launch Constraints habrían mitigado varios ataques antiguos al **asegurarse de que el proceso no se ejecute en condiciones inesperadas:** por ejemplo, desde ubicaciones inesperadas o invocado por un proceso padre inesperado (si únicamente launchd debería iniciarlo).

Además, Launch Constraints también **mitigan los ataques de downgrade**.

Sin embargo, **no mitigan los abusos comunes de XPC**, las inyecciones de código de **Electron** ni las **inyecciones de dylib** sin library validation (a menos que se conozcan los team IDs que pueden cargar libraries).<sup>[[3]](#references)</sup>

### Protección de los daemons XPC

En la versión Sonoma, un aspecto destacable es la **configuración de responsabilidad** del servicio XPC del daemon. El servicio XPC es responsable de sí mismo, en lugar de que el cliente que se conecta sea el responsable. Esto está documentado en el informe de feedback FB13206884. Esta configuración puede parecer defectuosa, ya que permite ciertas interacciones con el servicio XPC:

- **Iniciar el servicio XPC**: Si se considera un bug, esta configuración no permite iniciar el servicio XPC mediante código del atacante.
- **Conectarse a un servicio activo**: Si el servicio XPC ya está ejecutándose (posiblemente activado por su aplicación original), no existen barreras para conectarse a él.

Aunque implementar restricciones en el servicio XPC podría ser beneficioso para **reducir la ventana de posibles ataques**, no aborda la preocupación principal. Garantizar la seguridad del servicio XPC requiere fundamentalmente **validar eficazmente el cliente que se conecta**. Este sigue siendo el único método para reforzar la seguridad del servicio. También cabe señalar que la configuración de responsabilidad mencionada está actualmente operativa, lo que podría no coincidir con el diseño previsto.<sup>[[3]](#references)</sup>

### Protección de Electron

Incluso si se requiere que la aplicación tenga que ser **abierta por LaunchService** (en las restricciones de los procesos padre). Esto puede lograrse usando **`open`** (que puede establecer variables de entorno) o mediante la **API de Launch Services** (donde se pueden indicar variables de entorno).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Anulación de las restricciones integradas en el momento del spawn

Launch constraints (oficialmente **lightweight code requirements**, *LWCR*) son aplicadas por la **política MAC de AMFI**. `posix_spawn` permite que un caller entregue un blob arbitrario a una política MAC mediante **`posix_spawnattr_setmacpolicyinfo_np()`**, y AMFI aceptaba un diccionario LWCR proporcionado por el caller a través de esa ruta. El bug consistía en que las **restricciones proporcionadas por el atacante reemplazaban las integradas en el binario**, en lugar de comprobarse además de estas:

- Crear un diccionario de launch-constraints mínimo (incluso vacío).
- Establecer la **categoría de restricciones en `127`**, un valor que AMFI permite en los atributos de spawn, pero que **no aplica**: solo registra `Launch Constraint Violation (not enforcing)` en lugar de bloquear la ejecución.
- Pasarlo mediante los atributos de spawn; el proceso se inicia en un contexto que sus restricciones reales de self/parent habrían prohibido.

Después de la corrección, se validan **tanto las restricciones integradas como las proporcionadas**, por lo que el diccionario proporcionado ya no puede debilitar las restricciones integradas.<sup>[[2]](#references)</sup>

> [!TIP]
> Esta es la forma general que debes buscar al auditar la aplicación de restricciones: una API que permita que una entrada no confiable *proporcione* una policy suele ser interesante cuando el motor de policy trata el valor proporcionado como un reemplazo en lugar de como un requisito adicional.

## Referencias

- [1] [Objective by the Sea #OBTS v6.0, día 2 (emisión en directo)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Análisis profundo de Launch and Environment Constraints - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [¿Por qué no se ejecuta una app del sistema o una herramienta de comandos? Launch constraints y trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protege tu app de Mac con environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Descripción de las Launch Constraints introducidas en iOS 16 (gist de LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [Launch Constraints de macOS Sonoma (14) (gist de theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Más allá de los buenos y antiguos `LaunchAgents` - información al respecto](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}

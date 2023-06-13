## Gatekeeper

**Gatekeeper** es una función de seguridad desarrollada para los sistemas operativos Mac, diseñada para garantizar que los usuarios **ejecuten solo software confiable** en sus sistemas. Funciona mediante la **validación del software** que un usuario descarga e intenta abrir desde **fuentes fuera de la App Store**, como una aplicación, un complemento o un paquete de instalación.

El mecanismo clave de Gatekeeper radica en su proceso de **verificación**. Verifica si el software descargado está **firmado por un desarrollador reconocido**, asegurando la autenticidad del software. Además, verifica si el software está **notarizado por Apple**, confirmando que está libre de contenido malicioso conocido y que no ha sido manipulado después de la notarización.

Además, Gatekeeper refuerza el control y la seguridad del usuario al **solicitar a los usuarios que aprueben la apertura** del software descargado por primera vez. Esta protección ayuda a evitar que los usuarios ejecuten involuntariamente código ejecutable potencialmente dañino que puedan haber confundido con un archivo de datos inofensivo.
```bash
# Check the status
spctl --status
# Enable Gatekeeper
sudo spctl --master-enable
# Disable Gatekeeper
sudo spctl --master-disable
```
### Firmas de Aplicaciones

Las firmas de aplicaciones, también conocidas como firmas de código, son un componente crítico de la infraestructura de seguridad de Apple. Se utilizan para **verificar la identidad del autor del software** (el desarrollador) y para asegurarse de que el código no ha sido manipulado desde la última vez que se firmó.

Así es como funciona:

1. **Firmar la Aplicación:** Cuando un desarrollador está listo para distribuir su aplicación, **firma la aplicación utilizando una clave privada**. Esta clave privada está asociada con un **certificado que Apple emite al desarrollador** cuando se inscribe en el Programa de Desarrolladores de Apple. El proceso de firma implica la creación de un hash criptográfico de todas las partes de la aplicación y la encriptación de este hash con la clave privada del desarrollador.
2. **Distribuir la Aplicación:** La aplicación firmada se distribuye a los usuarios junto con el certificado del desarrollador, que contiene la clave pública correspondiente.
3. **Verificar la Aplicación:** Cuando un usuario descarga e intenta ejecutar la aplicación, el sistema operativo Mac utiliza la clave pública del certificado del desarrollador para descifrar el hash. Luego recalcula el hash en función del estado actual de la aplicación y lo compara con el hash descifrado. Si coinciden, significa que **la aplicación no ha sido modificada** desde que el desarrollador la firmó, y el sistema permite que se ejecute la aplicación.

Las firmas de aplicaciones son una parte esencial de la tecnología Gatekeeper de Apple. Cuando un usuario intenta **abrir una aplicación descargada de Internet**, Gatekeeper verifica la firma de la aplicación. Si está firmada con un certificado emitido por Apple a un desarrollador conocido y el código no ha sido manipulado, Gatekeeper permite que se ejecute la aplicación. De lo contrario, bloquea la aplicación y alerta al usuario.

A partir de macOS Catalina, **Gatekeeper también verifica si la aplicación ha sido notarizada** por Apple, agregando una capa adicional de seguridad. El proceso de notarización verifica la aplicación en busca de problemas de seguridad conocidos y código malicioso, y si estos controles pasan, Apple agrega un ticket a la aplicación que Gatekeeper puede verificar.

#### Verificar Firmas

Cuando se verifica una **muestra de malware**, siempre se debe **verificar la firma** del binario, ya que el **desarrollador** que lo firmó puede estar **relacionado** con **malware**.
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarización

El proceso de notarización de Apple sirve como una salvaguarda adicional para proteger a los usuarios de software potencialmente dañino. Implica que el desarrollador envíe su aplicación para su examen por el **Servicio de Notarización de Apple**, que no debe confundirse con la Revisión de la Aplicación. Este servicio es un **sistema automatizado** que examina el software enviado en busca de la presencia de **contenido malicioso** y cualquier problema potencial con la firma de código.

Si el software **supera** esta inspección sin plantear ninguna preocupación, el Servicio de Notarización genera un ticket de notarización. Luego, se requiere que el desarrollador **adjunte este ticket a su software**, un proceso conocido como "grapado". Además, el ticket de notarización también se publica en línea donde Gatekeeper, la tecnología de seguridad de Apple, puede acceder a él.

En la primera instalación o ejecución del software por parte del usuario, la existencia del ticket de notarización, ya sea grapado al ejecutable o encontrado en línea, **informa a Gatekeeper que el software ha sido notarizado por Apple**. Como resultado, Gatekeeper muestra un mensaje descriptivo en el cuadro de diálogo de inicio inicial, indicando que el software ha sido sometido a controles de contenido malicioso por parte de Apple. Este proceso mejora la confianza del usuario en la seguridad del software que instala o ejecuta en sus sistemas.

### Archivos en cuarentena

Al **descargar** una aplicación o archivo, ciertas **aplicaciones** de macOS como navegadores web o clientes de correo electrónico **adjuntan un atributo de archivo extendido**, comúnmente conocido como la "**bandera de cuarentena**", al archivo descargado. Este atributo actúa como medida de seguridad para **marcar el archivo** como proveniente de una fuente no confiable (Internet) y potencialmente con riesgos. Sin embargo, no todas las aplicaciones adjuntan este atributo, por ejemplo, el software común de cliente BitTorrent generalmente omite este proceso.

**La presencia de una bandera de cuarentena señala la función de seguridad de Gatekeeper de macOS cuando un usuario intenta ejecutar el archivo**.

En el caso de que **no esté presente la bandera de cuarentena** (como con los archivos descargados a través de algunos clientes BitTorrent), **es posible que no se realicen las comprobaciones de Gatekeeper**. Por lo tanto, los usuarios deben tener precaución al abrir archivos descargados de fuentes menos seguras o desconocidas.

{% hint style="info" %}
La **comprobación** de la **validez** de las firmas de código es un proceso **intensivo en recursos** que incluye la generación de **hashes criptográficos** del código y todos sus recursos empaquetados. Además, la comprobación de la validez del certificado implica hacer una **comprobación en línea** a los servidores de Apple para ver si ha sido revocado después de emitido. Por estas razones, una comprobación completa de firma de código y notarización es **impráctica para ejecutar cada vez que se inicia una aplicación**.

Por lo tanto, estas comprobaciones se **ejecutan solo al ejecutar aplicaciones con el atributo en cuarentena**.
{% endhint %}

{% hint style="warning" %}
**Tenga en cuenta que Safari y otros navegadores web y aplicaciones son los que necesitan marcar los archivos descargados**

Además, **los archivos creados por procesos en sandbox** también se les agrega este atributo para evitar que se escapen del sandbox.
{% endhint %}

Es posible **verificar su estado y habilitar/deshabilitar** (se requiere root) con:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
También puedes **encontrar si un archivo tiene el atributo extendido de cuarentena** con:
```bash
xattr portada.png
com.apple.macl
com.apple.quarantine
```
Verifique el **valor** de los **atributos extendidos** con:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 0081;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
```
Y **elimina** ese atributo con:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
Y encuentra todos los archivos en cuarentena con:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

## XProtect

XProtect es una función integrada de **anti-malware** en macOS. Es parte del sistema de seguridad de Apple que trabaja silenciosamente en segundo plano para mantener su Mac seguro de malware conocido y complementos maliciosos.

XProtect funciona **verificando cualquier archivo descargado contra su base de datos** de malware conocido y tipos de archivo inseguros. Cuando descarga un archivo a través de ciertas aplicaciones, como Safari, Mail o Mensajes, XProtect escanea automáticamente el archivo. Si coincide con algún malware conocido en su base de datos, XProtect **impedirá que el archivo se ejecute** y le alertará sobre la amenaza.

La base de datos de XProtect se **actualiza regularmente** por Apple con nuevas definiciones de malware, y estas actualizaciones se descargan e instalan automáticamente en su Mac. Esto asegura que XProtect siempre esté actualizado con las últimas amenazas conocidas.

Sin embargo, vale la pena señalar que **XProtect no es una solución antivirus completa**. Solo verifica una lista específica de amenazas conocidas y no realiza un escaneo de acceso como la mayoría del software antivirus. Por lo tanto, aunque XProtect proporciona una capa de protección contra el malware conocido, todavía se recomienda tener precaución al descargar archivos de Internet o abrir archivos adjuntos de correo electrónico.

Puede obtener información sobre la última actualización de XProtect en ejecución:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
## MRT - Herramienta de eliminación de malware

La Herramienta de eliminación de malware (MRT) es otra parte de la infraestructura de seguridad de macOS. Como su nombre indica, la función principal de MRT es **eliminar el malware conocido de los sistemas infectados**.

Una vez que se detecta malware en un Mac (ya sea por XProtect o por algún otro medio), MRT se puede utilizar para **eliminar automáticamente el malware**. MRT opera en segundo plano y se ejecuta típicamente cuando el sistema se actualiza o cuando se descarga una nueva definición de malware (parece que las reglas que MRT tiene para detectar malware están dentro del binario).

Si bien tanto XProtect como MRT son parte de las medidas de seguridad de macOS, realizan funciones diferentes:

* **XProtect** es una herramienta preventiva. **Verifica los archivos a medida que se descargan** (a través de ciertas aplicaciones), y si detecta algún tipo de malware conocido, **evita que el archivo se abra**, evitando así que el malware infecte su sistema en primer lugar.
* **MRT**, por otro lado, es una **herramienta reactiva**. Opera después de que se ha detectado malware en un sistema, con el objetivo de eliminar el software ofensivo para limpiar el sistema.

## Limitantes de procesos

### SIP - Protección de integridad del sistema

{% content-ref url="macos-sip.md" %}
[macos-sip.md](macos-sip.md)
{% endcontent-ref %}

### Sandbox

El Sandbox de macOS **limita las aplicaciones** que se ejecutan dentro del sandbox a las **acciones permitidas especificadas en el perfil de Sandbox** con el que se está ejecutando la aplicación. Esto ayuda a garantizar que **la aplicación solo acceda a los recursos esperados**.

{% content-ref url="macos-sandbox/" %}
[macos-sandbox](macos-sandbox/)
{% endcontent-ref %}

### TCC - Transparencia, Consentimiento y Control

**TCC (Transparencia, Consentimiento y Control)** es un mecanismo en macOS para **limitar y controlar el acceso de la aplicación a ciertas funciones**, generalmente desde una perspectiva de privacidad. Esto puede incluir cosas como servicios de ubicación, contactos, fotos, micrófono, cámara, accesibilidad, acceso completo al disco y mucho más.

{% content-ref url="macos-tcc/" %}
[macos-tcc](macos-tcc/)
{% endcontent-ref %}

## Caché de confianza

La caché de confianza de Apple macOS, a veces también denominada caché AMFI (Integridad de archivos móviles de Apple), es un mecanismo de seguridad en macOS diseñado para **evitar que se ejecute software no autorizado o malintencionado**. Esencialmente, es una lista de hashes criptográficos que el sistema operativo utiliza para **verificar la integridad y autenticidad del software**.

Cuando una aplicación o archivo ejecutable intenta ejecutarse en macOS, el sistema operativo verifica la caché de confianza AMFI. Si se encuentra el **hash del archivo en la caché de confianza**, el sistema **permite** que el programa se ejecute porque lo reconoce como confiable.

## Restricciones de lanzamiento

Controla desde dónde y qué puede lanzar un binario firmado por Apple:

* No se puede lanzar una aplicación directamente si debe ser ejecutada por launchd
* No se puede ejecutar una aplicación fuera de la ubicación de confianza (como /System/)

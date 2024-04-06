# macOS Gatekeeper / Quarantine / XProtect

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión del PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud)
*
* .

</details>

## Gatekeeper

**Gatekeeper** es una función de seguridad desarrollada para sistemas operativos Mac, diseñada para garantizar que los usuarios **ejecuten solo software confiable** en sus sistemas. Funciona mediante la **validación del software** que un usuario descarga e intenta abrir desde **fuentes fuera de la App Store**, como una aplicación, un complemento o un paquete de instalación.

El mecanismo clave de Gatekeeper radica en su proceso de **verificación**. Verifica si el software descargado está **firmado por un desarrollador reconocido**, asegurando la autenticidad del software. Además, verifica si el software está **notarizado por Apple**, confirmando que está libre de contenido malicioso conocido y que no ha sido manipulado después de la notarización.

Además, Gatekeeper refuerza el control y la seguridad del usuario al **solicitar aprobación a los usuarios para abrir** el software descargado por primera vez. Esta protección ayuda a evitar que los usuarios ejecuten involuntariamente código ejecutable potencialmente dañino que podrían haber confundido con un archivo de datos inofensivo.

### Firmas de Aplicaciones

Las firmas de aplicaciones, también conocidas como firmas de código, son un componente crítico de la infraestructura de seguridad de Apple. Se utilizan para **verificar la identidad del autor del software** (el desarrollador) y para garantizar que el código no haya sido manipulado desde la última vez que se firmó.

Así es como funciona:

1. **Firmar la Aplicación:** Cuando un desarrollador está listo para distribuir su aplicación, **firma la aplicación utilizando una clave privada**. Esta clave privada está asociada con un **certificado que Apple emite al desarrollador** cuando se inscribe en el Programa para Desarrolladores de Apple. El proceso de firma implica crear un hash criptográfico de todas las partes de la aplicación y cifrar este hash con la clave privada del desarrollador.
2. **Distribuir la Aplicación:** La aplicación firmada se distribuye a los usuarios junto con el certificado del desarrollador, que contiene la clave pública correspondiente.
3. **Verificar la Aplicación:** Cuando un usuario descarga e intenta ejecutar la aplicación, su sistema operativo Mac utiliza la clave pública del certificado del desarrollador para descifrar el hash. Luego recalcula el hash basado en el estado actual de la aplicación y lo compara con el hash descifrado. Si coinciden, significa que **la aplicación no ha sido modificada** desde que el desarrollador la firmó, y el sistema permite que la aplicación se ejecute.

Las firmas de aplicaciones son una parte esencial de la tecnología Gatekeeper de Apple. Cuando un usuario intenta **abrir una aplicación descargada de Internet**, Gatekeeper verifica la firma de la aplicación. Si está firmada con un certificado emitido por Apple a un desarrollador conocido y el código no ha sido manipulado, Gatekeeper permite que la aplicación se ejecute. De lo contrario, bloquea la aplicación y alerta al usuario.

A partir de macOS Catalina, **Gatekeeper también verifica si la aplicación ha sido notarizada** por Apple, añadiendo una capa adicional de seguridad. El proceso de notarización verifica la aplicación en busca de problemas de seguridad conocidos y código malicioso, y si estas verificaciones son exitosas, Apple agrega un ticket a la aplicación que Gatekeeper puede verificar.

#### Verificar Firmas

Al verificar alguna **muestra de malware**, siempre debes **verificar la firma** del binario, ya que el **desarrollador** que lo firmó podría estar **relacionado** con **malware**.

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

El proceso de notarización de Apple sirve como una salvaguarda adicional para proteger a los usuarios de software potencialmente dañino. Implica que el **desarrollador envíe su aplicación para ser examinada** por el **Servicio de Notarización de Apple**, que no debe confundirse con la Revisión de la App. Este servicio es un **sistema automatizado** que examina el software enviado en busca de **contenido malicioso** y posibles problemas con la firma de código.

Si el software **supera** esta inspección sin plantear preocupaciones, el Servicio de Notarización genera un ticket de notarización. Luego, se requiere que el desarrollador **adjunte este ticket a su software**, un proceso conocido como 'engrapado'. Además, el ticket de notarización también se publica en línea donde Gatekeeper, la tecnología de seguridad de Apple, puede acceder a él.

En la primera instalación o ejecución del software por parte del usuario, la existencia del ticket de notarización, ya sea adjunto al ejecutable o encontrado en línea, **informa a Gatekeeper que el software ha sido notarizado por Apple**. Como resultado, Gatekeeper muestra un mensaje descriptivo en el diálogo de inicio inicial, indicando que el software ha sido sometido a controles de contenido malicioso por parte de Apple. Este proceso mejora la confianza del usuario en la seguridad del software que instalan o ejecutan en sus sistemas.

### Enumeración de GateKeeper

GateKeeper es tanto **varios componentes de seguridad** que evitan que se ejecuten aplicaciones no confiables como también **uno de los componentes**.

Es posible ver el **estado** de GateKeeper con:

```bash
# Check the status
spctl --status
```

{% hint style="danger" %}
Ten en cuenta que las comprobaciones de firma de GateKeeper se realizan solo en **archivos con el atributo de Cuarentena**, no en todos los archivos.
{% endhint %}

GateKeeper verificará si, según las **preferencias y la firma**, un binario puede ejecutarse:

<figure><img src="../../../.gitbook/assets/image (678).png" alt=""><figcaption></figcaption></figure>

La base de datos que mantiene esta configuración se encuentra en **`/var/db/SystemPolicy`**. Puedes verificar esta base de datos como root con:

```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```

Observa cómo la primera regla terminó en "**App Store**" y la segunda en "**Developer ID**" y que en la imagen anterior estaba **habilitado para ejecutar aplicaciones de la App Store e identificados por desarrolladores**.\
Si **modificas** esa configuración a App Store, las reglas de "**Notarized Developer ID" desaparecerán**.

También hay miles de reglas de **tipo GKE**:

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

Estos son los hashes que provienen de **`/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`, `/var/db/gke.bundle/Contents/Resources/gk.db`** y **`/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`**

O también puedes listar la información anterior con:

```bash
sudo spctl --list
```

Las opciones **`--master-disable`** y **`--global-disable`** de **`spctl`** deshabilitarán completamente estas verificaciones de firma:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Cuando esté completamente habilitado, aparecerá una nueva opción:

<figure><img src="../../../.gitbook/assets/image (679).png" alt=""><figcaption></figcaption></figure>

Es posible **verificar si una aplicación será permitida por GateKeeper** con:

```bash
spctl --assess -v /Applications/App.app
```

Es posible agregar nuevas reglas en GateKeeper para permitir la ejecución de ciertas aplicaciones con:

```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```

### Archivos en Cuarentena

Al **descargar** una aplicación o archivo, ciertas aplicaciones de macOS como navegadores web o clientes de correo electrónico **adjuntan un atributo de archivo extendido**, comúnmente conocido como la "**bandera de cuarentena**," al archivo descargado. Este atributo actúa como una medida de seguridad para **marcar el archivo** como proveniente de una fuente no confiable (internet) y potencialmente portador de riesgos. Sin embargo, no todas las aplicaciones adjuntan este atributo, por ejemplo, el software común de cliente BitTorrent generalmente omite este proceso.

**La presencia de una bandera de cuarentena señala la función de seguridad Gatekeeper de macOS cuando un usuario intenta ejecutar el archivo**.

En el caso de que la **bandera de cuarentena no esté presente** (como en archivos descargados a través de algunos clientes BitTorrent), es posible que **no se realicen las verificaciones de Gatekeeper**. Por lo tanto, los usuarios deben tener precaución al abrir archivos descargados de fuentes menos seguras o desconocidas.

{% hint style="info" %}
**Verificar** la **validez** de las firmas de código es un proceso **intensivo en recursos** que incluye generar **hashes** criptográficos del código y todos sus recursos empaquetados. Además, verificar la validez del certificado implica realizar una **verificación en línea** a los servidores de Apple para ver si ha sido revocado después de ser emitido. Por estas razones, realizar una verificación completa de firma de código y notarización es **impracticable de ejecutar cada vez que se inicia una aplicación**.

Por lo tanto, estas verificaciones **solo se ejecutan al ejecutar aplicaciones con el atributo de cuarentena**.
{% endhint %}

{% hint style="warning" %}
Este atributo debe ser **establecido por la aplicación que crea/descarga** el archivo.

Sin embargo, los archivos que están en sandbox tendrán este atributo establecido para cada archivo que crean. Y las aplicaciones que no están en sandbox pueden establecerlo por sí mismas, o especificar la clave [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information\_property\_list/lsfilequarantineenabled?language=objc) en el **Info.plist** lo que hará que el sistema establezca el atributo extendido `com.apple.quarantine` en los archivos creados.
{% endhint %}

Es posible **verificar su estado y habilitar/deshabilitar** (se requieren permisos de root) con:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

También puedes **verificar si un archivo tiene el atributo de cuarentena extendida** con:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Verifique el **valor** de los **atributos** **extendidos** y descubra la aplicación que escribió el atributo de cuarentena con:

```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```

De hecho, un proceso "podría establecer banderas de cuarentena a los archivos que crea" (intenté aplicar la bandera USER\_APPROVED en un archivo creado pero no se aplica):

<details>

<summary>Código fuente para aplicar banderas de cuarentena</summary>

\`\`\`c #include #include

enum qtn\_flags { QTN\_FLAG\_DOWNLOAD = 0x0001, QTN\_FLAG\_SANDBOX = 0x0002, QTN\_FLAG\_HARD = 0x0004, QTN\_FLAG\_USER\_APPROVED = 0x0040, };

\#define qtn\_proc\_alloc \_qtn\_proc\_alloc #define qtn\_proc\_apply\_to\_self \_qtn\_proc\_apply\_to\_self #define qtn\_proc\_free \_qtn\_proc\_free #define qtn\_proc\_init \_qtn\_proc\_init #define qtn\_proc\_init\_with\_self \_qtn\_proc\_init\_with\_self #define qtn\_proc\_set\_flags \_qtn\_proc\_set\_flags #define qtn\_file\_alloc \_qtn\_file\_alloc #define qtn\_file\_init\_with\_path \_qtn\_file\_init\_with\_path #define qtn\_file\_free \_qtn\_file\_free #define qtn\_file\_apply\_to\_path \_qtn\_file\_apply\_to\_path #define qtn\_file\_set\_flags \_qtn\_file\_set\_flags #define qtn\_file\_get\_flags \_qtn\_file\_get\_flags #define qtn\_proc\_set\_identifier \_qtn\_proc\_set\_identifier

typedef struct \_qtn\_proc \*qtn\_proc\_t; typedef struct \_qtn\_file \*qtn\_file\_t;

int qtn\_proc\_apply\_to\_self(qtn\_proc\_t); void qtn\_proc\_init(qtn\_proc\_t); int qtn\_proc\_init\_with\_self(qtn\_proc\_t); int qtn\_proc\_set\_flags(qtn\_proc\_t, uint32\_t flags); qtn\_proc\_t qtn\_proc\_alloc(); void qtn\_proc\_free(qtn\_proc\_t); qtn\_file\_t qtn\_file\_alloc(void); void qtn\_file\_free(qtn\_file\_t qf); int qtn\_file\_set\_flags(qtn\_file\_t qf, uint32\_t flags); uint32\_t qtn\_file\_get\_flags(qtn\_file\_t qf); int qtn\_file\_apply\_to\_path(qtn\_file\_t qf, const char \*path); int qtn\_file\_init\_with\_path(qtn\_file\_t qf, const char _path); int qtn\_proc\_set\_identifier(qtn\_proc\_t qp, const char_ bundleid);

int main() {

qtn\_proc\_t qp = qtn\_proc\_alloc(); qtn\_proc\_set\_identifier(qp, "xyz.hacktricks.qa"); qtn\_proc\_set\_flags(qp, QTN\_FLAG\_DOWNLOAD | QTN\_FLAG\_USER\_APPROVED); qtn\_proc\_apply\_to\_self(qp); qtn\_proc\_free(qp);

FILE \*fp; fp = fopen("thisisquarantined.txt", "w+"); fprintf(fp, "Hello Quarantine\n"); fclose(fp);

return 0;

}

````
</details>

Y **elimina** ese atributo con:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
````

Y encuentra todos los archivos en cuarentena con:

{% code overflow="wrap" %}
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
{% endcode %}

La información de cuarentena también se almacena en una base de datos central gestionada por LaunchServices en **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**.

**Quarantine.kext**

La extensión del kernel solo está disponible a través de la **caché del kernel en el sistema**; sin embargo, _puedes_ descargar el **Kit de Depuración del Kernel desde https://developer.apple.com/**, que contendrá una versión simbolizada de la extensión.

#### XProtect

XProtect es una función integrada de **anti-malware** en macOS. XProtect **verifica cualquier aplicación cuando se ejecuta por primera vez o se modifica contra su base de datos** de malware conocido y tipos de archivo inseguros. Cuando descargas un archivo a través de ciertas aplicaciones, como Safari, Mail o Mensajes, XProtect escanea automáticamente el archivo. Si coincide con algún malware conocido en su base de datos, XProtect **impedirá que el archivo se ejecute** y te alertará sobre la amenaza.

La base de datos de XProtect se **actualiza regularmente** por Apple con nuevas definiciones de malware, y estas actualizaciones se descargan e instalan automáticamente en tu Mac. Esto asegura que XProtect esté siempre actualizado con las últimas amenazas conocidas.

Sin embargo, vale la pena señalar que **XProtect no es una solución antivirus completa**. Solo verifica una lista específica de amenazas conocidas y no realiza escaneos de acceso como la mayoría de los software antivirus.

Puedes obtener información sobre la última actualización de XProtect ejecutando:

{% code overflow="wrap" %}
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
{% endcode %}

XProtect se encuentra en una ubicación protegida por SIP en **/Library/Apple/System/Library/CoreServices/XProtect.bundle** y dentro del paquete puedes encontrar la información que XProtect utiliza:

* **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Permite que el código con esos cdhashes use privilegios heredados.
* **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista de complementos y extensiones que están prohibidos de cargar a través de BundleID y TeamID o indicando una versión mínima.
* **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reglas Yara para detectar malware.
* **`XProtect.bundle/Contents/Resources/gk.db`**: Base de datos SQLite3 con hashes de aplicaciones bloqueadas y TeamIDs.

Ten en cuenta que hay otra aplicación en **`/Library/Apple/System/Library/CoreServices/XProtect.app`** relacionada con XProtect que no está involucrada en el proceso de Gatekeeper.

#### No es Gatekeeper

Ten en cuenta que Gatekeeper **no se ejecuta cada vez** que ejecutas una aplicación, solo _**AppleMobileFileIntegrity**_ (AMFI) solo **verificará las firmas de código ejecutable** cuando ejecutes una aplicación que ya ha sido ejecutada y verificada por Gatekeeper.

Por lo tanto, anteriormente era posible ejecutar una aplicación para almacenarla en caché con Gatekeeper, luego **modificar archivos no ejecutables de la aplicación** (como archivos Electron asar o NIB) y si no había otras protecciones en su lugar, la aplicación se **ejecutaba** con las **adiciones maliciosas**.

Sin embargo, ahora esto no es posible porque macOS **evita modificar archivos** dentro de los paquetes de aplicaciones. Por lo tanto, si intentas el ataque [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), descubrirás que ya no es posible abusar de él porque después de ejecutar la aplicación para almacenarla en caché con Gatekeeper, no podrás modificar el paquete. Y si cambias, por ejemplo, el nombre del directorio Contents a NotCon (como se indica en el exploit), y luego ejecutas el binario principal de la aplicación para almacenarlo en caché con Gatekeeper, se producirá un error y no se ejecutará.

### Saltos de Gatekeeper

Cualquier forma de evadir Gatekeeper (lograr que el usuario descargue algo y lo ejecute cuando Gatekeeper debería prohibirlo) se considera una vulnerabilidad en macOS. Estos son algunos CVE asignados a técnicas que permitieron evadir Gatekeeper en el pasado:

#### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Se observó que si se utiliza **Archive Utility** para la extracción, los archivos con **rutas que exceden los 886 caracteres** no reciben el atributo extendido com.apple.quarantine. Esta situación permite inadvertidamente que esos archivos **circunvalen las** verificaciones de seguridad de Gatekeeper.

Consulta el [**informe original**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) para obtener más información.

#### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Cuando se crea una aplicación con **Automator**, la información sobre lo que necesita para ejecutarse está dentro de `application.app/Contents/document.wflow` y no en el ejecutable. El ejecutable es simplemente un binario genérico de Automator llamado **Automator Application Stub**.

Por lo tanto, podrías hacer que `application.app/Contents/MacOS/Automator\ Application\ Stub` **apunte con un enlace simbólico a otro Automator Application Stub dentro del sistema** y ejecutará lo que está dentro de `document.wflow` (tu script) **sin activar Gatekeeper** porque el ejecutable real no tiene el atributo de cuarentena.

Ejemplo de la ubicación esperada: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Consulta el [**informe original**](https://ronmasas.com/posts/bypass-macos-gatekeeper) para obtener más información.

#### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

En este bypass se creó un archivo zip con una aplicación comenzando a comprimir desde `application.app/Contents` en lugar de `application.app`. Por lo tanto, el **atributo de cuarentena** se aplicó a todos los **archivos de `application.app/Contents`** pero **no a `application.app`**, que es lo que Gatekeeper estaba verificando, por lo que Gatekeeper fue evadido porque cuando se activaba `application.app` **no tenía el atributo de cuarentena.**

```bash
zip -r test.app/Contents test.zip
```

Verifica el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) para obtener más información.

#### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Aunque los componentes son diferentes, la explotación de esta vulnerabilidad es muy similar a la anterior. En este caso, generaremos un Archivo de Apple desde **`application.app/Contents`** para que **`application.app` no reciba el atributo de cuarentena** al ser descomprimido por **Archive Utility**.

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Verifique el [**informe original**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) para obtener más información.

#### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

El ACL **`writeextattr`** se puede utilizar para evitar que alguien escriba un atributo en un archivo:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Además, el formato de archivo **AppleDouble** copia un archivo incluyendo sus ACEs.

En el [**código fuente**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) es posible ver que la representación de texto de ACL almacenada dentro del xattr llamado **`com.apple.acl.text`** se establecerá como ACL en el archivo descomprimido. Por lo tanto, si comprimiste una aplicación en un archivo zip con el formato de archivo **AppleDouble** con un ACL que evita que se escriban otros xattrs en él... el xattr de cuarentena no se estableció en la aplicación:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Consulta el [**informe original**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) para obtener más información.

Ten en cuenta que esto también podría ser explotado con AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

#### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Se descubrió que **Google Chrome no estaba estableciendo el atributo de cuarentena** a los archivos descargados debido a algunos problemas internos de macOS.

#### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Los formatos de archivo AppleDouble almacenan los atributos de un archivo en un archivo separado que comienza por `._`, esto ayuda a copiar los atributos de los archivos **entre máquinas macOS**. Sin embargo, se observó que después de descomprimir un archivo AppleDouble, el archivo que comienza con `._` **no recibía el atributo de cuarentena**.

{% code overflow="wrap" %}
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
{% endcode %}

Al poder crear un archivo que no tenga el atributo de cuarentena establecido, era **posible evadir Gatekeeper.** El truco consistía en **crear una aplicación de archivo DMG** utilizando la convención de nombres AppleDouble (comenzar con `._`) y crear un **archivo visible como un enlace simbólico a este archivo oculto** sin el atributo de cuarentena.\
Cuando se ejecuta el **archivo dmg**, al no tener un atributo de cuarentena, **evadirá Gatekeeper**.

```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```

#### Prevenir la xattr de cuarentena

En un paquete ".app", si la xattr de cuarentena no se agrega a él, al ejecutarlo **Gatekeeper no se activará**.

</details>

# Robo de Certificados de AD CS

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de GitHub de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## ¿Qué puedo hacer con un certificado?

Antes de revisar cómo robar los certificados, aquí tienes información sobre cómo encontrar para qué sirve el certificado:
```powershell
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exportación de Certificados Usando las Crypto APIs – THEFT1

La forma más fácil de extraer un certificado de usuario o máquina y su clave privada es a través de una **sesión de escritorio interactiva**. Si la **clave privada** es **exportable**, simplemente se puede hacer clic derecho en el certificado en `certmgr.msc`, y seguir `All Tasks → Export`... para exportar un archivo .pfx protegido con contraseña. \
También se puede lograr esto **programáticamente**. Ejemplos incluyen el cmdlet `ExportPfxCertificate` de PowerShell o [el proyecto C# CertStealer de TheWover](https://github.com/TheWover/CertStealer).

Estos métodos utilizan por debajo la **Microsoft CryptoAPI** (CAPI) o la más moderna Cryptography API: Next Generation (CNG) para interactuar con el almacén de certificados. Estas APIs realizan varios servicios criptográficos necesarios para el almacenamiento de certificados y autenticación (entre otros usos).

Si la clave privada no es exportable, CAPI y CNG no permitirán la extracción de certificados no exportables. Los comandos `crypto::capi` y `crypto::cng` de **Mimikatz** pueden parchear CAPI y CNG para **permitir la exportación** de claves privadas. `crypto::capi` **parchea** **CAPI** en el proceso actual mientras que `crypto::cng` requiere **parchear** la memoria de **lsass.exe**.

## Robo de Certificado de Usuario a través de DPAPI – THEFT2

Más información sobre DPAPI en:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows **almacena las claves privadas de los certificados usando DPAPI**. Microsoft distingue las ubicaciones de almacenamiento para las claves privadas de usuario y máquina. Al descifrar manualmente los blobs encriptados de DPAPI, un desarrollador necesita entender qué API de criptografía utilizó el SO ya que la estructura de archivos de la clave privada varía entre las dos APIs. Cuando se usa SharpDPAPI, este automáticamente tiene en cuenta las diferencias de formato de archivo.&#x20;

Windows **almacena más comúnmente los certificados de usuario** en el registro en la clave `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, aunque algunos certificados personales para usuarios **también** se almacenan en `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Las ubicaciones de **claves privadas de usuario** asociadas están principalmente en `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para claves **CAPI** y `%APPDATA%\Microsoft\Crypto\Keys\` para claves **CNG**.

Para obtener un certificado y su clave privada asociada, se necesita:

1. Identificar **qué certificado se quiere robar** del almacén de certificados del usuario y extraer el nombre del almacén de claves.
2. Encontrar la **masterkey DPAPI** necesaria para descifrar la clave privada asociada.
3. Obtener la masterkey DPAPI en texto plano y usarla para **descifrar la clave privada**.

Para **obtener la masterkey DPAPI en texto plano**:
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para simplificar la desencriptación de archivos masterkey y archivos de clave privada, se puede utilizar el comando `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) con los argumentos `/pvk`, `/mkfile`, `/password`, o `{GUID}:KEY` para desencriptar las claves privadas y los certificados asociados, generando un archivo de texto `.pem`.
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Robo de Certificados de Máquina vía DPAPI – THEFT3

Windows almacena los certificados de máquina en la clave de registro `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` y guarda las claves privadas en varios lugares diferentes dependiendo de la cuenta.\
Aunque SharpDPAPI buscará en todas estas ubicaciones, los resultados más interesantes suelen venir de `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI) y `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG). Estas **claves privadas** están asociadas con el **almacén de certificados de máquina** y Windows las cifra con las **claves maestras DPAPI de la máquina**.\
No se pueden descifrar estas claves usando la clave de respaldo DPAPI del dominio, sino que se **debe** usar el **secreto DPAPI\_SYSTEM LSA** en el sistema que es **accesible solo por el usuario SYSTEM**.&#x20;

Puedes hacer esto manualmente con el comando **`lsadump::secrets`** de **Mimikatz** y luego usar la clave extraída para **descifrar las masterkeys de máquina**. \
También puedes parchear CAPI/CNG como antes y usar el comando de **Mimikatz** `crypto::certificates /export /systemstore:LOCAL_MACHINE`. \
El comando certificates de **SharpDPAPI** con la bandera **`/machine`** (con privilegios elevados) automáticamente se **elevará** a **SYSTEM**, **volcará** el secreto **DPAPI\_SYSTEM** LSA, usará esto para **descifrar** y encontrar las masterkeys DPAPI de máquina, y usará los textos de las claves en plano como una tabla de búsqueda para descifrar cualquier clave privada de certificado de máquina.

## Búsqueda de Archivos de Certificados – THEFT4

A veces, **los certificados están simplemente en el sistema de archivos**, como en comparticiones de archivos o en la carpeta de Descargas.\
Los tipos más comunes de archivos de certificados enfocados en Windows que hemos visto son **`.pfx`** y **`.p12`**, con **`.pkcs12`** y **`.pem`** apareciendo a veces pero menos frecuentemente.\
Otras extensiones de archivos relacionados con certificados de interés son: **`.key`** (_clave privada_), **`.crt/.cer`** (_solo certificado_), **`.csr`** (_Solicitud de Firma de Certificado, no contiene certificados ni claves privadas_), **`.jks/.keystore/.keys`** (_Java Keystore. Puede contener certificados + claves privadas usadas por aplicaciones Java_).

Para encontrar estos archivos, simplemente busca esas extensiones usando powershell o el cmd.

Si encuentras un archivo de certificado **PKCS#12** y está **protegido con contraseña**, puedes extraer un hash usando [pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) y **romper** la contraseña usando JohnTheRipper.

## Robo de Credenciales NTLM vía PKINIT – THEFT5

> Para **soportar la autenticación NTLM** \[MS-NLMP] para aplicaciones que se conectan a servicios de red que **no soportan la autenticación Kerberos**, cuando se usa PKCA, el KDC devuelve la función unidireccional (OWF) de **NTLM del usuario** en el certificado de atributo de privilegio (PAC) **`PAC_CREDENTIAL_INFO`** buffer

Entonces, si una cuenta se autentica y obtiene un **TGT a través de PKINIT**, hay una "salvaguarda" incorporada que permite al host actual **obtener nuestro hash NTLM del TGT** para soportar la autenticación heredada. Esto implica **descifrar** una **estructura `PAC_CREDENTIAL_DATA`** que es una representación serializada en Representación de Datos de Red (NDR) del texto plano NTLM.

[**Kekeo**](https://github.com/gentilkiwi/kekeo) se puede usar para solicitar un TGT con esta información y recuperar el NTML del usuario.
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
La implementación de Kekeo también funcionará con certificados protegidos por tarjeta inteligente que estén actualmente conectados si puedes [**recuperar el pin**](https://github.com/CCob/PinSwipe)**.** También será compatible con [**Rubeus**](https://github.com/GhostPack/Rubeus).

## Referencias

* Toda la información fue tomada de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si quieres ver a tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Consigue el [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sigue** a **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de github de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

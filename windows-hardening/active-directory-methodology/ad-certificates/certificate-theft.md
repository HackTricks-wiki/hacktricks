# Robo de Certificados AD CS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén la [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## ¿Qué puedo hacer con un certificado?

Antes de ver cómo robar los certificados, aquí tienes información sobre cómo encontrar para qué sirve el certificado:
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
## Exportando Certificados Usando las APIs de Criptografía – THEFT1

La forma más fácil de extraer un certificado de usuario o de máquina y su clave privada es a través de una **sesión de escritorio interactiva**. Si la **clave privada** es **exportable**, simplemente se puede hacer clic derecho en el certificado en `certmgr.msc` y seleccionar `Todas las tareas → Exportar`… para exportar un archivo .pfx protegido por contraseña. \
También se puede hacer esto de forma **programática**. Ejemplos incluyen el cmdlet `ExportPfxCertificate` de PowerShell o el proyecto CertStealer de TheWover en C# (https://github.com/TheWover/CertStealer).

Estos métodos utilizan la **API de criptografía de Microsoft** (CAPI) o la API de criptografía de próxima generación (CNG) para interactuar con el almacén de certificados. Estas APIs realizan varios servicios criptográficos necesarios para el almacenamiento y la autenticación de certificados (entre otros usos).

Si la clave privada no es exportable, CAPI y CNG no permitirán la extracción de certificados no exportables. Los comandos `crypto::capi` y `crypto::cng` de Mimikatz pueden parchear CAPI y CNG para **permitir la exportación** de claves privadas. `crypto::capi` **parchea** **CAPI** en el proceso actual mientras que `crypto::cng` requiere **parchear** la memoria de **lsass.exe**.

## Robo de Certificado de Usuario a través de DPAPI – THEFT2

Más información sobre DPAPI en:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

Windows **almacena las claves privadas de los certificados usando DPAPI**. Microsoft separa las ubicaciones de almacenamiento de las claves privadas de usuario y de máquina. Al descifrar manualmente los bloques DPAPI cifrados, un desarrollador necesita entender qué API de criptografía usó el sistema operativo ya que la estructura del archivo de clave privada difiere entre las dos APIs. Al usar SharpDPAPI, se tiene en cuenta automáticamente estas diferencias de formato de archivo.&#x20;

Windows **almacena comúnmente los certificados de usuario** en el registro en la clave `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, aunque algunos certificados personales para usuarios también se almacenan en `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Las ubicaciones de las **claves privadas asociadas** de los usuarios están principalmente en `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para las claves de **CAPI** y en `%APPDATA%\Microsoft\Crypto\Keys\` para las claves de **CNG**.

Para obtener un certificado y su clave privada asociada, se necesita:

1. Identificar **qué certificado se quiere robar** del almacén de certificados del usuario y extraer el nombre del almacén de claves.
2. Encontrar la **clave maestra DPAPI** necesaria para descifrar la clave privada asociada.
3. Obtener la clave maestra DPAPI en texto plano y usarla para **descifrar la clave privada**.

Para **obtener la clave maestra DPAPI en texto plano**:
```bash
# With mimikatz
## Running in a process in the users context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# with mimikatz
## knowing the users password
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para simplificar la descifrado de archivos de clave maestra y clave privada, se puede utilizar el comando `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) con los argumentos `/pvk`, `/mkfile`, `/password` o `{GUID}:KEY` para descifrar las claves privadas y los certificados asociados, generando un archivo de texto `.pem`.
```bash
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Transfor .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Robo de certificado de máquina a través de DPAPI - THEFT3

Windows almacena los certificados de máquina en la clave del registro `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` y almacena las claves privadas en varios lugares diferentes dependiendo de la cuenta.\
Aunque SharpDPAPI buscará en todas estas ubicaciones, los resultados más interesantes suelen provenir de `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (CAPI) y `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (CNG). Estas **claves privadas** están asociadas con la **tienda de certificados de máquina** y Windows las cifra con las **claves maestras DPAPI de la máquina**.\
No se pueden descifrar estas claves utilizando la clave de respaldo DPAPI del dominio, sino que **debe** utilizar el **secreto LSA DPAPI\_SYSTEM** en el sistema al que solo tiene acceso el usuario **SYSTEM**.&#x20;

Puede hacer esto manualmente con el comando **`lsadump::secrets`** de **Mimikatz** y luego utilizar la clave extraída para **descifrar las claves maestras de la máquina**.\
También puede parchear CAPI/CNG como antes y utilizar el comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` de **Mimikatz**.\
El comando de certificados de **SharpDPAPI** con la bandera **`/machine`** (mientras se eleva) automáticamente **se eleva** a **SYSTEM**, **volca** el **secreto LSA DPAPI\_SYSTEM**, lo utiliza para **descifrar** y encontrar las claves maestras DPAPI de la máquina, y utiliza los textos sin formato de la clave como una tabla de búsqueda para descifrar cualquier clave privada de certificado de máquina.

## Encontrar archivos de certificado - THEFT4

A veces, los **certificados están simplemente en el sistema de archivos**, como en carpetas compartidas o en la carpeta de Descargas.\
El tipo más común de archivos de certificado enfocados en Windows que hemos visto son archivos **`.pfx`** y **`.p12`**, con **`.pkcs12`** y **`.pem`** apareciendo a veces pero con menos frecuencia.\
Otras extensiones de archivo relacionadas con certificados interesantes son: **`.key`** (_clave privada_), **`.crt/.cer`** (_solo certificado_), **`.csr`** (_solicitud de firma de certificado, no contiene certificados ni claves privadas_), **`.jks/.keystore/.keys`** (_Java Keystore. Puede contener certificados + claves privadas utilizados por aplicaciones Java_).

Para encontrar estos archivos, simplemente busque esas extensiones utilizando PowerShell o el cmd.

Si encuentra un archivo de certificado **PKCS#12** y está **protegido con contraseña**, puede extraer un hash utilizando [pfx2john.py](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john\_8py\_source.html) y **crackearlo** utilizando JohnTheRipper.

## Robo de credenciales NTLM a través de PKINIT - THEFT5

> Para **soportar la autenticación NTLM** \[MS-NLMP\] para aplicaciones que se conectan a servicios de red que **no admiten la autenticación Kerberos**, cuando se utiliza PKCA, el KDC devuelve la función unidireccional (OWF) NTLM del usuario en el búfer de **`PAC_CREDENTIAL_INFO`** del certificado de atributos de privilegio (PAC).

Por lo tanto, si la cuenta se autentica y obtiene un **TGT a través de PKINIT**, hay un "sistema de seguridad" incorporado que permite al host actual **obtener nuestro hash NTLM del TGT** para admitir la autenticación heredada. Esto implica **descifrar** una **estructura de datos PAC_CREDENTIAL_DATA** que es una representación serializada de Network Data Representation (NDR) del texto sin formato NTLM.

[**Kekeo**](https://github.com/gentilkiwi/kekeo) se puede utilizar para solicitar un TGT con esta información y recuperar los NTLM del usuario.
```bash
tgt::pac /caname:thename-DC-CA /subject:harmj0y /castore:current_user /domain:domain.local
```
La implementación de Kekeo también funcionará con certificados protegidos por tarjeta inteligente que estén actualmente conectados si puedes recuperar el pin. También será compatible con Rubeus.

## Referencias

* Toda la información fue tomada de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!

- Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)

- **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

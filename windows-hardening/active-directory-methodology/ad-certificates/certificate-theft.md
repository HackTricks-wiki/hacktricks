# Robo de Certificados de AD CS

<details>

<summary><strong>Aprende hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

**Este es un pequeño resumen de los capítulos de Robo del increíble estudio de [https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified\_Pre-Owned.pdf)**


## ¿Qué puedo hacer con un certificado?

Antes de verificar cómo robar los certificados, aquí tienes información sobre para qué se puede utilizar el certificado:
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
## Exportando Certificados Utilizando las APIs de Criptografía – ROBO1

En una **sesión de escritorio interactiva**, extraer un certificado de usuario o de máquina, junto con la clave privada, puede hacerse fácilmente, especialmente si la **clave privada es exportable**. Esto se puede lograr navegando hasta el certificado en `certmgr.msc`, haciendo clic derecho sobre él y seleccionando `Todas las tareas → Exportar` para generar un archivo .pfx protegido por contraseña.

Para un enfoque **programático**, herramientas como el cmdlet PowerShell `ExportPfxCertificate` o proyectos como [el proyecto CertStealer de C# de TheWover](https://github.com/TheWover/CertStealer) están disponibles. Estos utilizan la **API de Criptografía de Microsoft** (CAPI) o la API de Criptografía: Generación Siguiente (CNG) para interactuar con el almacén de certificados. Estas APIs proporcionan una variedad de servicios criptográficos, incluidos los necesarios para el almacenamiento y autenticación de certificados.

Sin embargo, si una clave privada está configurada como no exportable, tanto CAPI como CNG normalmente bloquearán la extracción de dichos certificados. Para evitar esta restricción, se pueden emplear herramientas como **Mimikatz**. Mimikatz ofrece los comandos `crypto::capi` y `crypto::cng` para parchear las respectivas APIs, permitiendo la exportación de claves privadas. Específicamente, `crypto::capi` parchea el CAPI dentro del proceso actual, mientras que `crypto::cng` apunta a la memoria de **lsass.exe** para parchear.

## Robo de Certificado de Usuario a través de DPAPI – ROBO2

Más información sobre DPAPI en:

{% content-ref url="../../windows-local-privilege-escalation/dpapi-extracting-passwords.md" %}
[dpapi-extracting-passwords.md](../../windows-local-privilege-escalation/dpapi-extracting-passwords.md)
{% endcontent-ref %}

En Windows, **las claves privadas de los certificados están protegidas por DPAPI**. Es crucial reconocer que las **ubicaciones de almacenamiento de las claves privadas de usuario y máquina** son distintas, y las estructuras de archivos varían dependiendo de la API criptográfica utilizada por el sistema operativo. **SharpDPAPI** es una herramienta que puede navegar automáticamente estas diferencias al descifrar los bloques de DPAPI.

Los **certificados de usuario** se encuentran principalmente en el registro bajo `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, pero algunos también se pueden encontrar en el directorio `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Las **claves privadas** correspondientes a estos certificados generalmente se almacenan en `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para claves de **CAPI** y `%APPDATA%\Microsoft\Crypto\Keys\` para claves de **CNG**.

Para **extraer un certificado y su clave privada asociada**, el proceso implica:

1. **Seleccionar el certificado objetivo** del almacén del usuario y recuperar el nombre del almacén de claves.
2. **Localizar la clave maestra DPAPI requerida** para descifrar la clave privada correspondiente.
3. **Descifrar la clave privada** utilizando la clave maestra DPAPI en texto plano.

Para **adquirir la clave maestra DPAPI en texto plano**, se pueden utilizar los siguientes enfoques:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para agilizar la descifrado de archivos de clave maestra y archivos de clave privada, el comando `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) resulta beneficioso. Acepta `/pvk`, `/mkfile`, `/password` o `{GUID}:KEY` como argumentos para descifrar las claves privadas y certificados vinculados, generando posteriormente un archivo `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Robo de Certificado de Máquina a través de DPAPI – THEFT3

Los certificados de máquina almacenados por Windows en el registro en `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates` y las claves privadas asociadas ubicadas en `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (para CAPI) y `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (para CNG) están encriptados utilizando las claves maestras DPAPI de la máquina. Estas claves no pueden ser descifradas con la clave de respaldo DPAPI del dominio; en su lugar, se requiere el **secreto LSA DPAPI_SYSTEM**, al que solo el usuario SYSTEM puede acceder.

La descifrado manual se puede lograr ejecutando el comando `lsadump::secrets` en **Mimikatz** para extraer el secreto LSA DPAPI_SYSTEM, y posteriormente utilizando esta clave para descifrar las claves maestras de la máquina. Alternativamente, el comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` de Mimikatz se puede utilizar después de parchear CAPI/CNG como se describió anteriormente.

**SharpDPAPI** ofrece un enfoque más automatizado con su comando de certificados. Cuando se utiliza la bandera `/machine` con permisos elevados, se escala a SYSTEM, extrae el secreto LSA DPAPI_SYSTEM, lo utiliza para descifrar las claves maestras DPAPI de la máquina, y luego emplea estas claves en texto plano como una tabla de búsqueda para descifrar cualquier clave privada de certificado de máquina.


## Encontrar Archivos de Certificado – THEFT4

A veces los certificados se encuentran directamente dentro del sistema de archivos, como en carpetas compartidas o en la carpeta de Descargas. Los tipos de archivos de certificado más comúnmente encontrados dirigidos a entornos de Windows son archivos `.pfx` y `.p12`. Aunque con menos frecuencia, también aparecen archivos con extensiones `.pkcs12` y `.pem`. Otras extensiones de archivo relacionadas con certificados que son notables incluyen:
- `.key` para claves privadas,
- `.crt`/`.cer` para solo certificados,
- `.csr` para Solicitudes de Firma de Certificado, que no contienen certificados o claves privadas,
- `.jks`/`.keystore`/`.keys` para Almacenes de Claves de Java, que pueden contener certificados junto con claves privadas utilizadas por aplicaciones Java.

Estos archivos se pueden buscar utilizando PowerShell o el símbolo del sistema buscando las extensiones mencionadas.

En casos donde se encuentra un archivo de certificado PKCS#12 y está protegido por una contraseña, la extracción de un hash es posible mediante el uso de `pfx2john.py`, disponible en [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Posteriormente, se puede emplear JohnTheRipper para intentar descifrar la contraseña.
```powershell
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Robo de Credenciales NTLM a través de PKINIT - THEFT5

El contenido proporcionado explica un método para el robo de credenciales NTLM a través de PKINIT, específicamente a través del método de robo etiquetado como THEFT5. Aquí se presenta una reexplicación en voz pasiva, con el contenido anonimizado y resumido cuando sea aplicable:

Para admitir la autenticación NTLM [MS-NLMP] para aplicaciones que no facilitan la autenticación Kerberos, el KDC está diseñado para devolver la función unidireccional NTLM del usuario (OWF) dentro del certificado de atributos de privilegio (PAC), específicamente en el búfer `PAC_CREDENTIAL_INFO`, cuando se utiliza PKCA. En consecuencia, si una cuenta autentica y asegura un Ticket-Granting Ticket (TGT) a través de PKINIT, se proporciona inherentemente un mecanismo que permite al host actual extraer el hash NTLM del TGT para mantener los protocolos de autenticación heredados. Este proceso implica la descifrado de la estructura `PAC_CREDENTIAL_DATA`, que es esencialmente una representación serializada NDR del texto sin formato NTLM.

La utilidad **Kekeo**, accesible en [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), se menciona como capaz de solicitar un TGT que contenga estos datos específicos, facilitando así la recuperación del NTLM del usuario. El comando utilizado para este propósito es el siguiente:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
Además, se señala que Kekeo puede procesar certificados protegidos por tarjeta inteligente, siempre que se pueda recuperar el PIN, con referencia a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). La misma capacidad se indica que es compatible con **Rubeus**, disponible en [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Esta explicación encapsula el proceso y las herramientas involucradas en el robo de credenciales NTLM a través de PKINIT, centrándose en la recuperación de hashes NTLM a través de TGT obtenidos mediante PKINIT, y las utilidades que facilitan este proceso.

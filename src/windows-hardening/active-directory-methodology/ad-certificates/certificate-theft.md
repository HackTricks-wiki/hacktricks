# Robo de certificados de AD CS

{{#include ../../../banners/hacktricks-training.md}}

**Este es un pequeño resumen de los capítulos sobre Theft de la excelente investigación de [https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)**<sup>[[1]](#references)</sup>

## ¿Qué puedo hacer con un certificado?

Antes de comprobar cómo robar los certificados, aquí tienes información sobre cómo determinar para qué puede ser útil el certificado:
```bash
# Powershell
$CertPath = "C:\path\to\cert.pfx"
$CertPass = "P@ssw0rd"
$Cert = New-Object
System.Security.Cryptography.X509Certificates.X509Certificate2 @($CertPath, $CertPass)
$Cert.EnhancedKeyUsageList

# cmd
certutil.exe -dump -v cert.pfx
```
## Exporting Certificates Using the Crypto APIs – THEFT1

En una **interactive desktop session**, extraer un certificado de usuario o de máquina, junto con la private key, puede hacerse fácilmente, especialmente si la **private key es exportable**. Esto se puede lograr navegando hasta el certificado en `certmgr.msc`, haciendo clic derecho sobre él y seleccionando `All Tasks → Export` para generar un archivo .pfx protegido con contraseña.<sup>[[1]](#references)</sup>

Para un **enfoque programático**, existen herramientas como el cmdlet de PowerShell `ExportPfxCertificate` o proyectos como [TheWover’s CertStealer C# project](https://github.com/TheWover/CertStealer). Estos utilizan la **Microsoft CryptoAPI** (CAPI) o la Cryptography API: Next Generation (CNG) para interactuar con el almacén de certificados. Estas APIs proporcionan diversos servicios criptográficos, incluidos los necesarios para el almacenamiento y la autenticación de certificados.

Sin embargo, si una private key está configurada como no exportable, tanto CAPI como CNG normalmente bloquearán la extracción de dichos certificados. Para eludir esta restricción, se pueden utilizar herramientas como **Mimikatz**. Mimikatz ofrece los comandos `crypto::capi` y `crypto::cng` para parchear las APIs correspondientes, permitiendo exportar private keys. En concreto, `crypto::capi` parchea CAPI dentro del proceso actual, mientras que `crypto::cng` apunta a la memoria de **lsass.exe** para aplicar el parche.

## User Certificate Theft via DPAPI – THEFT2

Más información sobre DPAPI en:


{{#ref}}
../../windows-local-privilege-escalation/dpapi-extracting-passwords.md
{{#endref}}

En Windows, las **certificate private keys están protegidas por DPAPI**. Es fundamental reconocer que las **ubicaciones de almacenamiento de las private keys de usuario y de máquina** son distintas, y que las estructuras de archivos varían según la cryptographic API utilizada por el sistema operativo. **SharpDPAPI** es una herramienta que puede gestionar automáticamente estas diferencias al descifrar los blobs de DPAPI.<sup>[[1]](#references)</sup>

Los **certificados de usuario** se almacenan principalmente en el registro, en `HKEY_CURRENT_USER\SOFTWARE\Microsoft\SystemCertificates`, aunque algunos también pueden encontrarse en el directorio `%APPDATA%\Microsoft\SystemCertificates\My\Certificates`. Las **private keys** correspondientes a estos certificados suelen almacenarse en `%APPDATA%\Microsoft\Crypto\RSA\User SID\` para las claves **CAPI** y en `%APPDATA%\Microsoft\Crypto\Keys\` para las claves **CNG**.

Para **extraer un certificado y su private key asociada**, el proceso implica:

1. **Seleccionar el certificado objetivo** del almacén del usuario y obtener su nombre de almacén de claves.
2. **Localizar la DPAPI masterkey necesaria** para descifrar la private key correspondiente.
3. **Descifrar la private key** utilizando la DPAPI masterkey en texto plano.

Para **obtener la DPAPI masterkey en texto plano**, se pueden utilizar los siguientes enfoques:
```bash
# With mimikatz, when running in the user's context
dpapi::masterkey /in:"C:\PATH\TO\KEY" /rpc

# With mimikatz, if the user's password is known
dpapi::masterkey /in:"C:\PATH\TO\KEY" /sid:accountSid /password:PASS
```
Para agilizar el descifrado de archivos masterkey y archivos de claves privadas, el comando `certificates` de [**SharpDPAPI**](https://github.com/GhostPack/SharpDPAPI) resulta útil. Acepta `/pvk`, `/mkfile`, `/password` o `{GUID}:KEY` como argumentos para descifrar las claves privadas y los certificados vinculados, generando posteriormente un archivo `.pem`.
```bash
# Decrypting using SharpDPAPI
SharpDPAPI.exe certificates /mkfile:C:\temp\mkeys.txt

# Converting .pem to .pfx
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
## Theft of Machine Certificates via DPAPI – THEFT3

Los certificados de máquina almacenados por Windows en el registro, en `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates`, y las claves privadas asociadas ubicadas en `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\RSA\MachineKeys` (para CAPI) y `%ALLUSERSPROFILE%\Application Data\Microsoft\Crypto\Keys` (para CNG), están cifrados mediante las claves maestras DPAPI de la máquina. Estas claves no se pueden descifrar con la clave de respaldo DPAPI del dominio; en su lugar, se requiere el **secreto LSA DPAPI_SYSTEM**, al que solo puede acceder el usuario SYSTEM.<sup>[[1]](#references)</sup>

El descifrado manual se puede realizar ejecutando el comando `lsadump::secrets` en **Mimikatz** para extraer el secreto LSA DPAPI_SYSTEM y, posteriormente, utilizando esta clave para descifrar las claves maestras de la máquina. Como alternativa, se puede utilizar el comando `crypto::certificates /export /systemstore:LOCAL_MACHINE` de Mimikatz después de aplicar parches a CAPI/CNG, tal como se describió anteriormente.

**SharpDPAPI** ofrece un enfoque más automatizado mediante su comando certificates. Cuando se utiliza el indicador `/machine` con permisos elevados, escala a SYSTEM, extrae el secreto LSA DPAPI_SYSTEM, lo utiliza para descifrar las claves maestras DPAPI de la máquina y, posteriormente, emplea estas claves en texto plano como una tabla de búsqueda para descifrar cualquier clave privada de certificado de máquina.

## Búsqueda de archivos de certificados – THEFT4

A veces, los certificados se encuentran directamente en el sistema de archivos, por ejemplo, en recursos compartidos o en la carpeta Downloads. Los tipos de archivos de certificados más comunes dirigidos a entornos Windows son los archivos `.pfx` y `.p12`. Aunque con menor frecuencia, también aparecen archivos con las extensiones `.pkcs12` y `.pem`. Otras extensiones de archivos relacionadas con certificados que conviene destacar incluyen:<sup>[[1]](#references)</sup>

- `.key` para claves privadas,
- `.crt`/`.cer` únicamente para certificados,
- `.csr` para Certificate Signing Requests, que no contienen certificados ni claves privadas,
- `.jks`/`.keystore`/`.keys` para Java Keystores, que pueden contener certificados junto con claves privadas utilizadas por aplicaciones Java.

Estos archivos se pueden buscar mediante PowerShell o el símbolo del sistema, buscando las extensiones mencionadas.

Cuando se encuentra un archivo de certificado PKCS#12 protegido mediante una contraseña, es posible extraer un hash utilizando `pfx2john.py`, disponible en [fossies.org](https://fossies.org/dox/john-1.9.0-jumbo-1/pfx2john_8py_source.html). Posteriormente, se puede utilizar JohnTheRipper para intentar crackear la contraseña.
```bash
# Example command to search for certificate files in PowerShell
Get-ChildItem -Recurse -Path C:\Users\ -Include *.pfx, *.p12, *.pkcs12, *.pem, *.key, *.crt, *.cer, *.csr, *.jks, *.keystore, *.keys

# Example command to use pfx2john.py for extracting a hash from a PKCS#12 file
pfx2john.py certificate.pfx > hash.txt

# Command to crack the hash with JohnTheRipper
john --wordlist=passwords.txt hash.txt
```
## Robo de credenciales NTLM mediante PKINIT – THEFT5 (UnPAC the hash)

El contenido explica un método para el robo de credenciales NTLM mediante PKINIT, concretamente a través del método de robo denominado THEFT5. A continuación, se presenta una nueva explicación en voz pasiva, con el contenido anonimizado y resumido cuando corresponde:<sup>[[1]](#references)</sup>

Para admitir la autenticación NTLM `MS-NLMP` en aplicaciones que no admiten la autenticación Kerberos, el KDC está diseñado para devolver la función unidireccional (OWF) NTLM del usuario dentro del certificado de atributos de privilegios (PAC), concretamente en el búfer `PAC_CREDENTIAL_INFO`, cuando se utiliza PKCA. Por lo tanto, si una cuenta se autentica y obtiene un Ticket-Granting Ticket (TGT) mediante PKINIT, se proporciona de forma inherente un mecanismo que permite al host actual extraer el hash NTLM del TGT para mantener la compatibilidad con protocolos de autenticación heredados. Este proceso implica el descifrado de la estructura `PAC_CREDENTIAL_DATA`, que es esencialmente una representación serializada mediante NDR del texto plano de NTLM.

Se menciona que la herramienta **Kekeo**, disponible en [https://github.com/gentilkiwi/kekeo](https://github.com/gentilkiwi/kekeo), puede solicitar un TGT que contenga estos datos, facilitando así la recuperación del NTLM del usuario. El comando utilizado para este propósito es el siguiente:
```bash
tgt::pac /caname:generic-DC-CA /subject:genericUser /castore:current_user /domain:domain.local
```
**`Rubeus`** también puede obtener esta información con la opción **`asktgt [...] /getcredentials`**.

Además, se señala que Kekeo puede procesar certificados protegidos por smartcard, siempre que se pueda recuperar el PIN, con una referencia a [https://github.com/CCob/PinSwipe](https://github.com/CCob/PinSwipe). También se indica que **Rubeus** admite la misma capacidad, disponible en [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus).

Esta explicación resume el proceso y las herramientas involucradas en el robo de credenciales NTLM mediante PKINIT, centrándose en la obtención de hashes NTLM a través de un TGT obtenido mediante PKINIT y en las utilidades que facilitan este proceso.

## Referencias

- [1] [Certified Pre-Owned: Abusing Active Directory Certificate Services](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf)

{{#include ../../../banners/hacktricks-training.md}}

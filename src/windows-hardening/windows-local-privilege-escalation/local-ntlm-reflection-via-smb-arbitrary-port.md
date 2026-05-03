# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Skoro novije Windows build verzije uvele su **SMB client support for alternative TCP ports**. Ta funkcija može da se zloupotrebi da se **local NTLM authentication** pretvori u **SYSTEM local privilege escalation** kada napadač može da:

1. Otvori SMB connection ka listener-u pod kontrolom napadača na **non-445 port**
2. Zadrži tu TCP connection aktivnom
3. Navede **privileged local client** da pristupi **istoj SMB share path**
4. Relay-uje dobijenu **local NTLM authentication** nazad ka pravom SMB servisu mašine

Ovo je primitive iza **CVE-2026-24294**, patch-ovanog u **March 2026**.

## Why it works

Stariji CMTI / serialized-SPN reflection trik je opisan ovde:

{{#ref}}
../ntlm/README.md
{{#endref}}

Ova novija varijanta ne treba marshalled hostname. Umesto toga zloupotrebljava dva SMB client ponašanja:

- **Alternative port support** na **Windows 11 24H2** i **Windows Server 2025**, dostupno korisnicima sa `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, gde više authenticated sessions može da koristi istu TCP connection

To znači da korisnik sa niskim privilegijama prvo može da napravi TCP connection od SMB client-a ka attacker SMB server-u na visokom portu, a zatim da navede privileged servis da pristupi **istoj UNC path**. Ako Windows odluči da ponovo iskoristi postojeću TCP connection, privileged NTLM exchange se šalje preko transporta pod kontrolom napadača i može da se relay-uje do lokalnog SMB servera.

## Preconditions

- Target podržava SMB alternative ports:
- **Windows 11 24H2** ili noviji
- **Windows Server 2025** ili noviji
- Napadač može da pokrene lokalni ili udaljeni SMB server na izabranom visokom portu
- Napadač može da navede privileged servis da pristupi UNC path
- Privileged authentication mora biti **NTLM local authentication**
- Target mora biti relayable:
- Synacktiv je prijavio da je to radilo podrazumevano na **Windows Server 2025**
- Njihov chain nije radio na **Windows 11 24H2** zato što je outbound SMB signing tamo podrazumevano enforced

## Userland and internals

Iz command line-a funkcija izgleda jednostavno:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programski, klijent koristi `WNetAddConnection4W` sa nedokumentovanim `lpUseOptions` podacima. Relevantna opcija je `TraP` (transport parameters), koja na kraju stiže do kernel SMB klijenta kroz FSCTL i parsira je `mrxsmb`.

Važne praktične napomene:

- **UNC sintaksa i dalje nema polje za port**
- **`net use` je po logon sesiji**
- Bypass i dalje radi zato što su **TCP konekcija i SMB sesija odvojeni objekti**
- Ponovno korišćenje **iste putanje deljenja** je obavezno ako exploit zavisi od toga da SMB klijent ponovo koristi prethodno kreiranu TCP konekciju

## Tok eksploatacije

### 1. Kreiraj SMB transport pod kontrolom napadača

Pokreni SMB server na visokom portu i nateraj Windows da se poveže na njega:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Server može da prihvati bilo koji credential pair koji kontrolišeš, na primer `user:user`. Cilj ovog koraka još nije privilege escalation, već samo da nateraš Windows SMB client da otvori i zadrži reusable TCP connection ka tvom listeneru.

### 2. Coerce privilegovani servis na isti UNC path

Koristi coercion primitive kao što je **PetitPotam** protiv **istog** `\\192.168.56.3\share` path-a. Ako je coerced client privilegovan i target name je lokalni (`localhost` ili lokalni IP/host), Windows vrši **NTLM local authentication**.

Pošto se TCP connection ponovo koristi, taj privilegovani NTLM exchange ide ka attacker SMB servisu umesto direktno ka pravom lokalnom SMB serveru.

### 3. Relay privilegovanu autentikaciju nazad ka lokalnom SMB

Attacker-controlled SMB service prosleđuje privilegovani NTLM exchange ka `ntlmrelayx.py`, koji ga relays ka pravom SMB listeneru na mašini i dobija session kao `NT AUTHORITY\SYSTEM`.

Tipični alati iz javnog writeup-a:

- `smbserver.py` na custom portu da primi privilegovani auth preko ponovo korišćenog TCP connection-a
- `ntlmrelayx.py` da relays uhvaćeni NTLM ka lokalnom SMB
- `PetitPotam.exe` ili druga coercion primitive da prisili privilegovanu autentikaciju

## Operator notes

- Ovo je **local privilege escalation** tehnika, ne generički remote relay trik
- Attacker-controlled SMB service mora da obradi privilegovanu autentikaciju na **istoj TCP connection** koja je prvobitno korišćena za mountovanje share-a
- Ako coerced access pogodi **drugi share path**, Windows može uspostaviti drugu connection i chain puca
- SMB signing zahtevi mogu da unište relay čak i kada arbitrary-port korak radi
- Ako imaš samo Kerberos material ili ne možeš da forsiraš lokalni NTLM, ova tačna varijanta nije dovoljna

## Detection and hardening

- Patch **CVE-2026-24294** iz **March 2026 Patch Tuesday**
- Prati `net use` ili `New-SmbMapping` koji koriste **non-default SMB ports**
- Alarmiraj na neuobičajen outbound SMB sa workstations ili servers ka **high TCP ports**
- Pregledaj coercion mogućnosti kao što su **EFSRPC / PetitPotam-style** triggers
- Enforce SMB signing gde je moguće; Synacktiv je posebno naveo da je ovo blokiralo njihov relay na Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}

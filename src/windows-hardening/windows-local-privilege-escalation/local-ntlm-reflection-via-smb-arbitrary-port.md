# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Novije Windows verzije uvele su **SMB client support for alternative TCP ports**. Ta funkcija može da se zloupotrebi za pretvaranje **local NTLM authentication** u **SYSTEM local privilege escalation** kada napadač može da:<sup>[[1]](#references)</sup>

1. Otvori SMB vezu ka listeneru pod kontrolom napadača na **non-445 portu**
2. Održi tu TCP vezu aktivnom
3. Prinudi **privileged local client** da pristupi **istoj SMB share putanji**
4. Relay-uje rezultat **local NTLM authentication** nazad ka pravom SMB servisu na računaru

Ovo je primitiv iza **CVE-2026-24294**, zakrpljenog u **martu 2026.**<sup>[[1]](#references)[[4]](#references)</sup>

## Zašto funkcioniše

Stariji CMTI / serialized-SPN reflection trick obrađen je ovde:

{{#ref}}
../ntlm/README.md
{{#endref}}

Ova novija varijanta ne zahteva marshalled hostname. Umesto toga, zloupotrebljava dva ponašanja SMB clienta:<sup>[[1]](#references)</sup>

- **Alternative port support** na **Windows 11 24H2** i **Windows Server 2025**, dostupnu korisnicima putem `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, pri čemu više authenticated sessions može da koristi istu TCP vezu

To znači da low-privileged user prvo može da kreira TCP vezu od SMB clienta ka attacker SMB serveru na high portu, a zatim da prinudi privileged service da pristupi **potpuno istoj UNC putanji**. Ako Windows odluči da ponovo upotrebi postojeću TCP vezu, privileged NTLM exchange se šalje kroz transport pod kontrolom napadača i može da se relay-uje ka lokalnom SMB serveru.<sup>[[1]](#references)</sup>

## Preduslovi

- Target podržava SMB alternative ports:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** ili noviji
- **Windows Server 2025** ili noviji
- Napadač može da pokrene lokalni ili udaljeni SMB server na izabranom high portu
- Napadač može da prinudi privileged service da pristupi UNC putanji
- Privileged authentication mora biti **NTLM local authentication**
- Target mora biti pogodan za relay:<sup>[[1]](#references)</sup>
- Synacktiv je prijavio da je ovo podrazumevano funkcionisalo na **Windows Server 2025**
- Njihov chain nije funkcionisao na **Windows 11 24H2** zato što je outbound SMB signing tamo podrazumevano obavezan

## Userland i interni detalji

Iz komandne linije ova funkcija deluje jednostavno:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programski, klijent koristi `WNetAddConnection4W` sa nedokumentovanim podacima `lpUseOptions`. Relevantna opcija je `TraP` (transport parameters), koja na kraju kroz FSCTL stiže do kernel SMB klijenta i koju parsira `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Važne praktične napomene:<sup>[[1]](#references)</sup>

- **UNC sintaksa i dalje nema polje za port**
- **`net use` važi po logon sesiji**
- Zaobilaženje i dalje funkcioniše zato što su **TCP konekcija i SMB sesija zasebni objekti**
- Ponovna upotreba **iste putanje deljenog resursa** je obavezna ako exploit zavisi od toga da SMB klijent ponovo iskoristi prethodno kreiranu TCP konekciju

## Tok eksploatacije

### 1. Kreirajte SMB transport pod kontrolom napadača

Pokrenite SMB server na visokom portu i naterajte Windows da se poveže sa njim:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Server može prihvatiti bilo koji par kredencijala koji kontrolišete, na primer `user:user`. Cilj ovog koraka još nije eskalacija privilegija, već samo da Windows SMB klijent otvori i zadrži ponovo upotrebljivu TCP vezu ka vašem listeneru.<sup>[[1]](#references)</sup>

### 2. Naterajte privilegovanu uslugu da koristi istu UNC putanju

Koristite coercion primitive kao što je **PetitPotam** protiv **iste** `\\192.168.56.3\share` putanje. Ako je coerced klijent privilegovan, a ciljno ime je lokalno (`localhost` ili lokalna IP adresa/ime hosta), Windows obavlja **NTLM local authentication**.

Pošto se TCP veza ponovo koristi, ta privilegovana NTLM razmena odlazi ka SMB servisu napadača umesto direktno ka stvarnom lokalnom SMB serveru.<sup>[[1]](#references)</sup>

### 3. Relaying privilegovane autentikacije nazad ka lokalnom SMB-u

SMB servis pod kontrolom napadača prosleđuje privilegovanu NTLM razmenu ka `ntlmrelayx.py`, koji je relays ka stvarnom SMB listeneru računara i dobija sesiju kao `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Tipični alati iz javno dostupnog writeup-a:<sup>[[1]](#references)</sup>

- `smbserver.py` na prilagođenom portu za prijem privilegovane autentikacije preko ponovo upotrebljene TCP veze
- `ntlmrelayx.py` za relay zarobljenog NTLM-a ka lokalnom SMB-u
- `PetitPotam.exe` ili drugi coercion primitive za prisiljavanje privilegovane autentikacije

## Napomene za operatera

- Ovo je tehnika za **local privilege escalation**, a ne generički remote relay trik<sup>[[1]](#references)</sup>
- SMB servis pod kontrolom napadača mora obraditi privilegovanu autentikaciju na **istoj TCP vezi** koja je prvobitno korišćena za mount share-a<sup>[[1]](#references)</sup>
- Ako coerced pristup pogodi **drugačiju share putanju**, Windows može uspostaviti drugu vezu i lanac se prekida<sup>[[1]](#references)</sup>
- Zahtevi za SMB signing mogu onemogućiti relay čak i kada arbitrary-port korak funkcioniše<sup>[[1]](#references)</sup>
- Ako imate samo Kerberos materijal ili ne možete prisiliti lokalni NTLM, ova konkretna varijanta nije dovoljna<sup>[[1]](#references)</sup>

## Detekcija i hardening

- Instalirajte zakrpu za **CVE-2026-24294** iz **March 2026 Patch Tuesday**<sup>[[4]](#references)</sup>
- Pratite korišćenje `net use` ili `New-SmbMapping` sa **SMB portovima koji nisu podrazumevani**<sup>[[1]](#references)</sup>
- Generišite upozorenje za neuobičajen odlazni SMB sa radnih stanica ili servera ka **visokim TCP portovima**<sup>[[1]](#references)</sup>
- Proverite mogućnosti za coercion, kao što su okidači u stilu **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- Gde je moguće, primenite SMB signing; Synacktiv posebno navodi da je to blokiralo njihov relay na Windows 11 24H2<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}

# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Najnowsze buildy Windows wprowadziły **SMB client support for alternative TCP ports**. Tę funkcję można nadużyć, aby zamienić **local NTLM authentication** w **SYSTEM local privilege escalation**, gdy atakujący może:

1. Otworzyć połączenie SMB do listenera kontrolowanego przez atakującego na **non-445 port**
2. Utrzymać to połączenie TCP aktywne
3. Zmusić **privileged local client** do dostępu do **samej ścieżki SMB share**
4. Przekażyć wynikające z tego **local NTLM authentication** z powrotem do prawdziwej usługi SMB maszyny

To jest primitive stojący za **CVE-2026-24294**, załatanym w **March 2026**.

## Why it works

Starszy trik CMTI / serialized-SPN reflection jest opisany tutaj:

{{#ref}}
../ntlm/README.md
{{#endref}}

Ta nowsza odmiana **nie** wymaga marshalled hostname. Zamiast tego nadużywa dwóch zachowań SMB client:

- **Alternative port support** na **Windows 11 24H2** i **Windows Server 2025**, dostępny dla użytkowników przez `net use \\host\share /tcpport:<port>`
- **SMB connection reuse / multiplexing**, gdzie wiele authenticated sessions może korzystać z tego samego połączenia TCP

To oznacza, że użytkownik o niskich uprawnieniach może najpierw utworzyć połączenie TCP z SMB client do attacker SMB server na wysokim porcie, a potem zmusić privileged service do dostępu do **dokładnie tej samej ścieżki UNC**. Jeśli Windows zdecyduje się ponownie użyć istniejącego połączenia TCP, privileged NTLM exchange zostanie wysłany przez transport kontrolowany przez atakującego i może zostać przekażony do lokalnego SMB server.

## Preconditions

- Target wspiera SMB alternative ports:
- **Windows 11 24H2** lub nowszy
- **Windows Server 2025** lub nowszy
- Atakujący może uruchomić local lub remote SMB server na wybranym wysokim porcie
- Atakujący może zmusić privileged service do dostępu do UNC path
- Privileged authentication musi być **NTLM local authentication**
- Target musi być relayable:
- Synacktiv zgłosił, że działało domyślnie na **Windows Server 2025**
- Ich chain **nie** działał na **Windows 11 24H2**, ponieważ outbound SMB signing jest tam domyślnie wymuszany

## Userland and internals

Z poziomu command line ta funkcja wygląda prosto:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programatycznie klient używa `WNetAddConnection4W` z nieudokumentowanymi danymi `lpUseOptions`. Istotną opcją jest `TraP` (transport parameters), która ostatecznie trafia do kernel SMB client przez FSCTL i jest parsowana przez `mrxsmb`.

Ważne praktyczne uwagi:

- **Składnia UNC nadal nie ma pola portu**
- **`net use` jest per-logon-session**
- Obejście nadal działa, ponieważ **połączenie TCP i SMB session są oddzielnymi obiektami**
- Ponowne użycie **tej samej ścieżki share** jest obowiązkowe, jeśli exploit zależy od tego, że SMB client ponownie użyje wcześniej utworzonego połączenia TCP

## Exploitation flow

### 1. Create the attacker-controlled SMB transport

Uruchom SMB server na wysokim porcie i spraw, aby Windows połączył się z nim:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Serwer może zaakceptować dowolną parę poświadczeń, którą kontrolujesz, na przykład `user:user`. Celem tego kroku nie jest jeszcze privilege escalation, tylko sprawienie, aby klient Windows SMB otworzył i utrzymał ponowne używalne połączenie TCP do twojego listenera.

### 2. Wymuś na uprzywilejowanej usłudze użycie tej samej ścieżki UNC

Użyj prymitywu coercion, takiego jak **PetitPotam**, przeciwko **tej samej** ścieżce `\\192.168.56.3\share`. Jeśli wymuszony klient ma uprawnienia i nazwa celu jest lokalna (`localhost` albo lokalny IP/host), Windows wykonuje **NTLM local authentication**.

Ponieważ połączenie TCP jest ponownie używane, ten uprzywilejowany NTLM exchange trafia do SMB service atakującego zamiast bezpośrednio do prawdziwego lokalnego serwera SMB.

### 3. Przekaź uwierzytelnienie uprzywilejowanego konta z powrotem do lokalnego SMB

Kontrolowany przez atakującego SMB service przekazuje uprzywilejowany NTLM exchange do `ntlmrelayx.py`, który relayuje go do prawdziwego listenera SMB maszyny i uzyskuje session jako `NT AUTHORITY\SYSTEM`.

Typowe tooling z publicznego opisu:

- `smbserver.py` na niestandardowym porcie, aby odebrać uprzywilejowane auth przez ponownie użyte połączenie TCP
- `ntlmrelayx.py`, aby relayować przechwycony NTLM do lokalnego SMB
- `PetitPotam.exe` lub inny prymityw coercion, aby wymusić uprzywilejowane uwierzytelnienie

## Notatki dla operatora

- To jest technika **local privilege escalation**, a nie ogólny zdalny relay trick
- Kontrolowany przez atakującego SMB service musi obsłużyć uprzywilejowane uwierzytelnienie na **tym samym połączeniu TCP**, które zostało pierwotnie użyte do zamontowania share
- Jeśli wymuszony dostęp trafi w **inną ścieżkę share**, Windows może ustanowić inne połączenie i chain się rozpada
- Wymagania SMB signing mogą zabić relay nawet wtedy, gdy krok z arbitralnym portem działa
- Jeśli masz tylko materiał Kerberos albo nie możesz wymusić local NTLM, ta dokładna wariacja nie wystarczy

## Detection and hardening

- Zastosuj patch **CVE-2026-24294** z **March 2026 Patch Tuesday**
- Monitoruj `net use` lub `New-SmbMapping` używające **niestandardowych portów SMB**
- Alarmuj na nietypowy outbound SMB z workstation lub serwerów do **wysokich portów TCP**
- Przeglądaj możliwości coercion, takie jak wyzwalacze **EFSRPC / PetitPotam-style**
- Wymuszaj SMB signing, gdzie to możliwe; Synacktiv zauważył, że to zablokowało ich relay na Windows 11 24H2

## References

- [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [Project Zero - Windows Exploitation Tricks: Trapping Virtual Memory Access (2025 Update)](https://projectzero.google/2025/01/windows-exploitation-tricks-trapping.html)
- [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}

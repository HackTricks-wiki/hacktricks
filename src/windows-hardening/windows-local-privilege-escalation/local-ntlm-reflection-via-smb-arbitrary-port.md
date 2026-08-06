# Local NTLM Reflection via SMB Arbitrary Port

{{#include ../../banners/hacktricks-training.md}}

Nowsze kompilacje Windows wprowadziły **obsługę alternatywnych portów TCP przez klienta SMB**. Funkcja ta może zostać wykorzystana do przekształcenia **lokalnego uwierzytelniania NTLM** w **eskalację uprawnień lokalnych do SYSTEM**, gdy attacker może:<sup>[[1]](#references)</sup>

1. Otworzyć połączenie SMB do kontrolowanego przez attackera listenera na **porcie innym niż 445**
2. Utrzymać to połączenie TCP
3. Nakłonić **uprzywilejowanego lokalnego klienta** do uzyskania dostępu do **tej samej ścieżki udziału SMB**
4. Przekazać wynikowe **lokalne uwierzytelnianie NTLM** z powrotem do rzeczywistej usługi SMB na maszynie

Jest to primitive leżący u podstaw **CVE-2026-24294**, załatanego w **marcu 2026 r.**<sup>[[1]](#references)[[4]](#references)</sup>

## Dlaczego to działa

Starszy trik reflection z CMTI / serialized-SPN został opisany tutaj:

{{#ref}}
../ntlm/README.md
{{#endref}}

Ten nowszy wariant **nie wymaga marshalled hostname**. Zamiast tego wykorzystuje dwa zachowania klienta SMB:<sup>[[1]](#references)</sup>

- **Obsługę alternatywnych portów** w **Windows 11 24H2** i **Windows Server 2025**, udostępnioną użytkownikom za pomocą `net use \\host\share /tcpport:<port>`
- **Ponowne używanie / multiplexing połączenia SMB**, gdzie wiele uwierzytelnionych sesji może korzystać z tego samego połączenia TCP

Oznacza to, że użytkownik o niskich uprawnieniach może najpierw utworzyć połączenie TCP z klienta SMB do serwera SMB attackera na wysokim porcie, a następnie nakłonić uprzywilejowaną usługę do uzyskania dostępu do **dokładnie tej samej ścieżki UNC**. Jeśli Windows zdecyduje się ponownie użyć istniejącego połączenia TCP, uprzywilejowana wymiana NTLM zostanie wysłana przez transport kontrolowany przez attackera i może zostać przekazana do lokalnego serwera SMB.<sup>[[1]](#references)</sup>

## Wymagania wstępne

- Target obsługuje alternatywne porty SMB:<sup>[[2]](#references)</sup>
- **Windows 11 24H2** lub nowszy
- **Windows Server 2025** lub nowszy
- Attacker może uruchomić lokalny lub zdalny serwer SMB na wybranym wysokim porcie
- Attacker może nakłonić uprzywilejowaną usługę do uzyskania dostępu do ścieżki UNC
- Uwierzytelnianie uprzywilejowane musi być **lokalnym uwierzytelnianiem NTLM**
- Target musi nadawać się do relay:<sup>[[1]](#references)</sup>
- Synacktiv poinformował, że technika działała domyślnie w **Windows Server 2025**
- Ich chain nie działał w **Windows 11 24H2**, ponieważ wychodzące podpisywanie SMB jest tam domyślnie wymuszane

## Userland i internals

Z poziomu wiersza poleceń funkcja wygląda prosto:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Programowo klient używa `WNetAddConnection4W` z nieudokumentowanymi danymi `lpUseOptions`. Istotną opcją jest `TraP` (parametry transportu), która ostatecznie dociera do klienta SMB w jądrze za pośrednictwem FSCTL i jest analizowana przez `mrxsmb`.<sup>[[1]](#references)[[3]](#references)</sup>

Ważne uwagi praktyczne:<sup>[[1]](#references)</sup>

- **Składnia UNC nadal nie ma pola portu**
- **`net use` działa w ramach sesji logowania**
- Obejście nadal działa, ponieważ **połączenie TCP i sesja SMB są oddzielnymi obiektami**
- Ponowne użycie **tej samej ścieżki udziału** jest wymagane, jeśli exploit zależy od ponownego użycia wcześniej utworzonego połączenia TCP przez klienta SMB

## Przebieg exploitation

### 1. Utwórz kontrolowany przez atakującego transport SMB

Uruchom serwer SMB na wysokim porcie i nakaż systemowi Windows połączyć się z nim:
```cmd
net use \\192.168.56.3\share /tcpport:12345
```
Serwer może zaakceptować dowolną kontrolowaną przez Ciebie parę poświadczeń, na przykład `user:user`. Celem tego kroku nie jest jeszcze privilege escalation, lecz jedynie spowodowanie, aby klient Windows SMB otworzył i utrzymywał możliwe do ponownego wykorzystania połączenie TCP z Twoim listenerem.<sup>[[1]](#references)</sup>

### 2. Wymuszenie użycia tej samej ścieżki UNC przez uprzywilejowaną usługę

Użyj primitive coercion, takiego jak **PetitPotam**, wobec **tej samej** ścieżki `\\192.168.56.3\share`. Jeśli wymuszony klient ma uprawnienia i nazwa celu jest lokalna (`localhost` lub lokalny adres IP/host), Windows wykonuje **lokalne uwierzytelnianie NTLM**.

Ponieważ połączenie TCP jest ponownie wykorzystywane, ta uprzywilejowana wymiana NTLM trafia do usługi SMB atakującego zamiast bezpośrednio do rzeczywistego lokalnego serwera SMB.<sup>[[1]](#references)</sup>

### 3. Przekazanie uprzywilejowanego uwierzytelniania z powrotem do lokalnego SMB

Kontrolowana przez atakującego usługa SMB przekazuje uprzywilejowaną wymianę NTLM do `ntlmrelayx.py`, który przekazuje ją do rzeczywistego listenera SMB maszyny i uzyskuje sesję jako `NT AUTHORITY\SYSTEM`.<sup>[[1]](#references)</sup>

Typowe narzędzia z publicznego opisu:<sup>[[1]](#references)</sup>

- `smbserver.py` na niestandardowym porcie, aby odebrać uprzywilejowane uwierzytelnianie przez ponownie wykorzystane połączenie TCP
- `ntlmrelayx.py` do przekazania przechwyconego NTLM do lokalnego SMB
- `PetitPotam.exe` lub inny coercion primitive do wymuszenia uprzywilejowanego uwierzytelniania

## Uwagi operatora

- Jest to technika **local privilege escalation**, a nie ogólna metoda remote relay<sup>[[1]](#references)</sup>
- Kontrolowana przez atakującego usługa SMB musi obsłużyć uprzywilejowane uwierzytelnianie na **tym samym połączeniu TCP**, które pierwotnie zostało użyte do zamontowania udziału<sup>[[1]](#references)</sup>
- Jeśli wymuszony dostęp trafi do **innej ścieżki udziału**, Windows może ustanowić inne połączenie i łańcuch zostanie przerwany<sup>[[1]](#references)</sup>
- Wymagania dotyczące SMB signing mogą uniemożliwić relay, nawet jeśli krok z arbitrary-port działa<sup>[[1]](#references)</sup>
- Jeśli masz tylko materiał Kerberos lub nie możesz wymusić lokalnego NTLM, ten konkretny wariant nie wystarczy<sup>[[1]](#references)</sup>

## Wykrywanie i hardening

- Zainstaluj poprawkę **CVE-2026-24294** z **March 2026 Patch Tuesday**<sup>[[4]](#references)</sup>
- Monitoruj użycie `net use` lub `New-SmbMapping` z **niestandardowymi portami SMB**<sup>[[1]](#references)</sup>
- Generuj alerty dotyczące nietypowego wychodzącego ruchu SMB ze stacji roboczych lub serwerów do **wysokich portów TCP**<sup>[[1]](#references)</sup>
- Przeglądaj możliwości coercion, takie jak wyzwalacze w stylu **EFSRPC / PetitPotam**<sup>[[1]](#references)</sup>
- W miarę możliwości wymuszaj SMB signing; Synacktiv zwraca uwagę, że zablokowało to ich relay w Windows 11 24H2<sup>[[1]](#references)</sup>

## References

- [1] [Synacktiv - Bypassing Windows authentication reflection mitigations for SYSTEM shells - Part 1](https://www.synacktiv.com/en/publications/bypassing-windows-authentication-reflection-mitigations-for-system-shells-part-1.html)
- [2] [Microsoft Learn - Configure alternative SMB ports for Windows Server 2025](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ports)
- [3] [Microsoft Learn - WNetAddConnection4W](https://learn.microsoft.com/en-us/windows/win32/api/winnetwk/nf-winnetwk-wnetaddconnection4w)
- [4] [MSRC - CVE-2026-24294](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-24294)

{{#include ../../banners/hacktricks-training.md}}

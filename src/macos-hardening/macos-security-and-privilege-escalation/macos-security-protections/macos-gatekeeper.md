# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** to funkcja bezpieczeństwa opracowana dla systemów operacyjnych Mac, zaprojektowana w celu zapewnienia, że użytkownicy **uruchamiają wyłącznie zaufane oprogramowanie** na swoich systemach. Działa poprzez **weryfikowanie oprogramowania**, które użytkownik pobiera i próbuje otworzyć ze **źródeł spoza App Store**, takich jak aplikacja, plug-in lub pakiet instalacyjny.

Kluczowym mechanizmem Gatekeepera jest proces **weryfikacji**. Sprawdza on, czy pobrane oprogramowanie jest **podpisane przez rozpoznanego developera**, potwierdzając jego autentyczność. Ponadto ustala, czy oprogramowanie zostało **notaryzowane przez Apple**, co potwierdza, że nie zawiera znanej złośliwej zawartości i nie zostało zmodyfikowane po notaryzacji.

Dodatkowo Gatekeeper wzmacnia kontrolę użytkownika i bezpieczeństwo, **prosząc użytkowników o zatwierdzenie otwarcia** pobranego oprogramowania po raz pierwszy. To zabezpieczenie pomaga zapobiegać przypadkowemu uruchomieniu potencjalnie szkodliwego kodu wykonywalnego, który użytkownik mógł pomylić z nieszkodliwym plikiem danych.

### Podpisy aplikacji

Podpisy aplikacji, znane również jako podpisy kodu, są kluczowym elementem infrastruktury bezpieczeństwa Apple. Służą do **weryfikowania tożsamości autora oprogramowania** (developera) oraz zapewnienia, że kod nie został zmodyfikowany od momentu jego ostatniego podpisania.

Działa to następująco:

1. **Podpisywanie aplikacji:** Gdy developer jest gotowy do dystrybucji swojej aplikacji, **podpisuje aplikację za pomocą klucza prywatnego**. Ten klucz prywatny jest powiązany z **certyfikatem wystawionym developerowi przez Apple** w momencie przystąpienia do Apple Developer Program. Proces podpisywania obejmuje utworzenie kryptograficznego hasha wszystkich części aplikacji i zaszyfrowanie tego hasha kluczem prywatnym developera.
2. **Dystrybucja aplikacji:** Podpisana aplikacja jest następnie dystrybuowana użytkownikom wraz z certyfikatem developera, który zawiera odpowiadający mu klucz publiczny.
3. **Weryfikowanie aplikacji:** Gdy użytkownik pobiera aplikację i próbuje ją uruchomić, system operacyjny Mac używa klucza publicznego z certyfikatu developera do odszyfrowania hasha. Następnie ponownie oblicza hash na podstawie bieżącego stanu aplikacji i porównuje go z odszyfrowanym hashem. Jeśli wartości się zgadzają, oznacza to, że **aplikacja nie została zmodyfikowana** od czasu podpisania jej przez developera, a system zezwala na jej uruchomienie.

Podpisy aplikacji są istotną częścią technologii Gatekeeper firmy Apple. Gdy użytkownik próbuje **otworzyć aplikację pobraną z internetu**, Gatekeeper weryfikuje podpis aplikacji. Jeśli została ona podpisana certyfikatem wystawionym przez Apple znanemu developerowi, a kod nie został zmodyfikowany, Gatekeeper zezwala na jej uruchomienie. W przeciwnym razie blokuje aplikację i ostrzega użytkownika.

Od macOS Catalina **Gatekeeper sprawdza również, czy aplikacja została notaryzowana** przez Apple, dodając dodatkową warstwę bezpieczeństwa. Proces notaryzacji sprawdza aplikację pod kątem znanych problemów bezpieczeństwa i złośliwego kodu, a jeśli kontrole zakończą się pomyślnie, Apple dodaje do aplikacji ticket, który Gatekeeper może zweryfikować.

#### Sprawdzanie podpisów

Podczas sprawdzania **próbki malware** należy zawsze **sprawdzić podpis**, ponieważ **developer**, który ją podpisał, może być już **powiązany** z **malware.**
```bash
# Get signer
codesign -vv -d /bin/ls 2>&1 | grep -E "Authority|TeamIdentifier"

# Check if the app’s contents have been modified
codesign --verify --verbose /Applications/Safari.app

# Get entitlements from the binary
codesign -d --entitlements :- /System/Applications/Automator.app # Check the TCC perms

# Check if the signature is valid
spctl --assess --verbose /Applications/Safari.app

# Sign a binary
codesign -s <cert-name-keychain> toolsdemo
```
### Notarizacja

Proces notaryzacji Apple stanowi dodatkowe zabezpieczenie chroniące użytkowników przed potencjalnie szkodliwym oprogramowaniem. Polega on na **przesłaniu aplikacji przez dewelopera do zbadania** przez **Apple's Notary Service**, którego nie należy mylić z App Review. Usługa ta jest **automatycznym systemem**, który analizuje przesłane oprogramowanie pod kątem **złośliwej zawartości** oraz potencjalnych problemów z code-signing.

Jeśli oprogramowanie **przejdzie** tę kontrolę bez wzbudzania zastrzeżeń, Notary Service generuje ticket notaryzacji. Następnie deweloper musi **dołączyć ten ticket do swojego oprogramowania**, co jest procesem znanym jako „stapling”. Ponadto ticket notaryzacji jest publikowany online, gdzie Gatekeeper, technologia bezpieczeństwa Apple, może uzyskać do niego dostęp.

Podczas pierwszej instalacji lub uruchomienia oprogramowania przez użytkownika obecność ticketu notaryzacji — niezależnie od tego, czy jest on dołączony do pliku wykonywalnego, czy znaleziony online — **informuje Gatekeeper, że oprogramowanie zostało poddane notaryzacji przez Apple**. W rezultacie Gatekeeper wyświetla opisowy komunikat w oknie dialogowym przy pierwszym uruchomieniu, wskazujący, że Apple sprawdziło oprogramowanie pod kątem złośliwej zawartości. Proces ten zwiększa zatem zaufanie użytkowników do bezpieczeństwa oprogramowania instalowanego lub uruchamianego w ich systemach.

### spctl i syspolicyd

> [!CAUTION]
> Należy pamiętać, że od wersji Sequoia **`spctl`** nie pozwala już modyfikować konfiguracji Gatekeeper.

**`spctl`** to narzędzie CLI służące do wyliczania informacji o Gatekeeper oraz interakcji z nim (z daemonem `syspolicyd` za pośrednictwem komunikatów XPC). Na przykład można sprawdzić **status** GateKeeper za pomocą:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Należy pamiętać, że sprawdzanie podpisu przez GateKeeper jest wykonywane wyłącznie dla **plików z atrybutem Quarantine**, a nie dla każdego pliku.

GateKeeper sprawdzi, czy zgodnie z **preferencjami i podpisem** można wykonać plik binarny:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** to główny daemon odpowiedzialny za egzekwowanie zasad Gatekeeper. Utrzymuje bazę danych znajdującą się w `/var/db/SystemPolicy`. Kod obsługujący tę [bazę danych można znaleźć tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), a [szablon SQL tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Należy pamiętać, że baza danych nie jest ograniczana przez SIP i może być zapisywana przez root, a baza danych `/var/db/.SystemPolicy-default` jest używana jako oryginalna kopia zapasowa na wypadek uszkodzenia drugiej bazy.

Ponadto bund­le **`/var/db/gke.bundle`** i **`/var/db/gkopaque.bundle`** zawierają pliki z regułami, które są wstawiane do bazy danych. Możesz sprawdzić tę bazę danych jako root za pomocą:
```bash
# Open database
sqlite3 /var/db/SystemPolicy

# Get allowed rules
SELECT requirement,allow,disabled,label from authority where label != 'GKE' and disabled=0;
requirement|allow|disabled|label
anchor apple generic and certificate 1[subject.CN] = "Apple Software Update Certification Authority"|1|0|Apple Installer
anchor apple|1|0|Apple System
anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists|1|0|Mac App Store
anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13]) and notarized|1|0|Notarized Developer ID
[...]
```
**`syspolicyd`** udostępnia również serwer XPC z różnymi operacjami, takimi jak `assess`, `update`, `record` i `cancel`, które są również dostępne za pośrednictwem API **`Security.framework` `SecAssessment*`**, a **`spctl`** komunikuje się z **`syspolicyd`** za pomocą XPC.

Zauważ, że pierwsza reguła kończyła się na "**App Store**", a druga na "**Developer ID**" oraz że na poprzednim obrazie **zezwolono na wykonywanie aplikacji z App Store i od zidentyfikowanych deweloperów**.\
Jeśli **zmienisz** to ustawienie na App Store, reguły "**Notarized Developer ID" znikną**.

Istnieją również tysiące reguł **typu GKE**:
```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```
Są to hashe pochodzące z:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Możesz też wyświetlić wcześniejsze informacje za pomocą:
```bash
sudo spctl --list
```
Opcje **`--master-disable`** i **`--global-disable`** programu **`spctl`** całkowicie **wyłączą** te kontrole podpisów:
```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```
Po całkowitym włączeniu pojawi się nowa opcja:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Możliwe jest **sprawdzenie, czy aplikacja będzie dozwolona przez GateKeeper**, za pomocą:
```bash
spctl --assess -v /Applications/App.app
```
Możliwe jest dodanie nowych reguł w GateKeeper, aby zezwolić na uruchamianie określonych aplikacji za pomocą:
```bash
# Check if allowed - nop
spctl --assess -v /Applications/App.app
/Applications/App.app: rejected
source=no usable signature

# Add a label and allow this label in GateKeeper
sudo spctl --add --label "whitelist" /Applications/App.app
sudo spctl --enable --label "whitelist"

# Check again - yep
spctl --assess -v /Applications/App.app
/Applications/App.app: accepted
```
W odniesieniu do **kernel extensions** folder `/var/db/SystemPolicyConfiguration` zawiera pliki z listami kextów dozwolonych do załadowania. Ponadto `spctl` ma entitlement `com.apple.private.iokit.nvram-csr`, ponieważ może dodawać nowe, wstępnie zatwierdzone kernel extensions, które muszą być również zapisane w NVRAM w kluczu `kext-allowed-teams`.

#### Zarządzanie Gatekeeperem w macOS 15 (Sequoia) i nowszych

- Wieloletni bypass w Finderze **Ctrl+Open / kliknięcie prawym przyciskiem myszy → Open** został usunięty; po pierwszym oknie dialogowym z blokadą użytkownicy muszą jawnie zezwolić na uruchomienie zablokowanej aplikacji, wybierając **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` nie są już akceptowane; `spctl` działa zasadniczo tylko w trybie odczytu na potrzeby assessment i zarządzania etykietami, natomiast egzekwowanie zasad konfiguruje się za pomocą interfejsu użytkownika lub MDM.

Od macOS 15 Sequoia użytkownicy końcowi nie mogą już przełączać zasad Gatekeepera za pomocą `spctl`. Zarządzanie odbywa się za pośrednictwem System Settings lub przez wdrożenie profilu konfiguracyjnego MDM z payloadem `com.apple.systempolicy.control`. Przykładowy fragment profilu zezwalający na App Store i zidentyfikowanych developerów (ale nie opcję „Anywhere”):

<details>
<summary>Profil MDM zezwalający na App Store i zidentyfikowanych developerów</summary>
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>PayloadContent</key>
<array>
<dict>
<key>PayloadType</key>
<string>com.apple.systempolicy.control</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadIdentifier</key>
<string>com.example.gatekeeper</string>
<key>EnableAssessment</key>
<true/>
<key>AllowIdentifiedDevelopers</key>
<true/>
</dict>
</array>
<key>PayloadType</key>
<string>Configuration</string>
<key>PayloadIdentifier</key>
<string>com.example.profile.gatekeeper</string>
<key>PayloadUUID</key>
<string>00000000-0000-0000-0000-000000000000</string>
<key>PayloadVersion</key>
<integer>1</integer>
<key>PayloadDisplayName</key>
<string>Gatekeeper</string>
</dict>
</plist>
```
</details>

### Pliki objęte kwarantanną

Podczas **pobierania** aplikacji lub pliku określone **aplikacje** macOS, takie jak przeglądarki internetowe lub klienci poczty e-mail, **dołączają rozszerzony atrybut pliku**, powszechnie znany jako "**flaga kwarantanny**", do pobranego pliku. Atrybut ten pełni funkcję zabezpieczenia, **oznaczając plik** jako pochodzący z niezaufanego źródła (internetu) i potencjalnie stwarzający zagrożenie. Jednak nie wszystkie aplikacje dołączają ten atrybut; przykładowo popularne oprogramowanie klienckie BitTorrent zwykle omija ten proces.

**Obecność flagi kwarantanny sygnalizuje funkcji bezpieczeństwa Gatekeeper systemu macOS, że użytkownik próbuje uruchomić plik**.

Jeśli **flaga kwarantanny nie jest obecna** (jak w przypadku plików pobranych za pomocą niektórych klientów BitTorrent), **sprawdzanie Gatekeeper może nie zostać wykonane**. Dlatego użytkownicy powinni zachować ostrożność podczas otwierania plików pobranych z mniej bezpiecznych lub nieznanych źródeł.

> [!NOTE] > **Sprawdzanie** **ważności** podpisów kodu jest procesem wymagającym dużej ilości zasobów, który obejmuje generowanie kryptograficznych **hashy** kodu i wszystkich jego dołączonych zasobów. Ponadto sprawdzanie ważności certyfikatu wymaga wykonania **sprawdzenia online** na serwerach Apple, aby ustalić, czy certyfikat został unieważniony po jego wydaniu. Z tych powodów pełne sprawdzanie podpisu kodu i notaryzacji jest **niepraktyczne do wykonywania przy każdym uruchomieniu aplikacji**.
>
> Dlatego te kontrole są **wykonywane tylko podczas uruchamiania aplikacji z atrybutem kwarantanny.**

> [!WARNING]
> Ten atrybut musi zostać **ustawiony przez aplikację tworzącą/pobierającą** plik.
>
> Jednak pliki działające w sandboxie będą miały ten atrybut ustawiony dla każdego tworzonego przez siebie pliku. Aplikacje niedziałające w sandboxie mogą ustawić go samodzielnie lub określić klucz [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) w pliku **Info.plist**, co spowoduje, że system ustawi rozszerzony atrybut `com.apple.quarantine` dla tworzonych plików,

Ponadto wszystkie pliki utworzone przez proces wywołujący **`qtn_proc_apply_to_self`** zostają objęte kwarantanną. API **`qtn_file_apply_to_path`** dodaje natomiast atrybut kwarantanny do określonej ścieżki pliku.

Możliwe jest **sprawdzenie jego statusu oraz włączenie/wyłączenie** (wymagane uprawnienia root) za pomocą:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Możesz również **sprawdzić, czy plik ma rozszerzony atrybut kwarantanny**, za pomocą:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Sprawdź **wartość** **rozszerzonych** **atrybutów** i ustal aplikację, która zapisała atrybut kwarantanny, za pomocą:
```bash
xattr -l portada.png
com.apple.macl:
00000000  03 00 53 DA 55 1B AE 4C 4E 88 9D CA B7 5C 50 F3  |..S.U..LN.....P.|
00000010  16 94 03 00 27 63 64 97 98 FB 4F 02 84 F3 D0 DB  |....'cd...O.....|
00000020  89 53 C3 FC 03 00 27 63 64 97 98 FB 4F 02 84 F3  |.S....'cd...O...|
00000030  D0 DB 89 53 C3 FC 00 00 00 00 00 00 00 00 00 00  |...S............|
00000040  00 00 00 00 00 00 00 00                          |........|
00000048
com.apple.quarantine: 00C1;607842eb;Brave;F643CD5F-6071-46AB-83AB-390BA944DEC5
# 00c1 -- It has been allowed to eexcute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
W rzeczywistości proces „może ustawiać flagi kwarantanny dla tworzonych przez siebie plików” (próbowałem już zastosować flagę USER_APPROVED do utworzonego pliku, ale nie zostaje ona zastosowana):

<details>

<summary>Kod źródłowy zastosowania flag kwarantanny</summary>
```c
#include <stdio.h>
#include <stdlib.h>

enum qtn_flags {
QTN_FLAG_DOWNLOAD = 0x0001,
QTN_FLAG_SANDBOX = 0x0002,
QTN_FLAG_HARD = 0x0004,
QTN_FLAG_USER_APPROVED = 0x0040,
};

#define qtn_proc_alloc _qtn_proc_alloc
#define qtn_proc_apply_to_self _qtn_proc_apply_to_self
#define qtn_proc_free _qtn_proc_free
#define qtn_proc_init _qtn_proc_init
#define qtn_proc_init_with_self _qtn_proc_init_with_self
#define qtn_proc_set_flags _qtn_proc_set_flags
#define qtn_file_alloc _qtn_file_alloc
#define qtn_file_init_with_path _qtn_file_init_with_path
#define qtn_file_free _qtn_file_free
#define qtn_file_apply_to_path _qtn_file_apply_to_path
#define qtn_file_set_flags _qtn_file_set_flags
#define qtn_file_get_flags _qtn_file_get_flags
#define qtn_proc_set_identifier _qtn_proc_set_identifier

typedef struct _qtn_proc *qtn_proc_t;
typedef struct _qtn_file *qtn_file_t;

int qtn_proc_apply_to_self(qtn_proc_t);
void qtn_proc_init(qtn_proc_t);
int qtn_proc_init_with_self(qtn_proc_t);
int qtn_proc_set_flags(qtn_proc_t, uint32_t flags);
qtn_proc_t qtn_proc_alloc();
void qtn_proc_free(qtn_proc_t);
qtn_file_t qtn_file_alloc(void);
void qtn_file_free(qtn_file_t qf);
int qtn_file_set_flags(qtn_file_t qf, uint32_t flags);
uint32_t qtn_file_get_flags(qtn_file_t qf);
int qtn_file_apply_to_path(qtn_file_t qf, const char *path);
int qtn_file_init_with_path(qtn_file_t qf, const char *path);
int qtn_proc_set_identifier(qtn_proc_t qp, const char* bundleid);

int main() {

qtn_proc_t qp = qtn_proc_alloc();
qtn_proc_set_identifier(qp, "xyz.hacktricks.qa");
qtn_proc_set_flags(qp, QTN_FLAG_DOWNLOAD | QTN_FLAG_USER_APPROVED);
qtn_proc_apply_to_self(qp);
qtn_proc_free(qp);

FILE *fp;
fp = fopen("thisisquarantined.txt", "w+");
fprintf(fp, "Hello Quarantine\n");
fclose(fp);

return 0;

}
```
</details>

I **usuń** ten atrybut za pomocą:
```bash
xattr -d com.apple.quarantine portada.png
#You can also remove this attribute from every file with
find . -iname '*' -print0 | xargs -0 xattr -d com.apple.quarantine
```
I znajdź wszystkie pliki poddane kwarantannie za pomocą:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Informacje o kwarantannie są również przechowywane w centralnej bazie danych zarządzanej przez LaunchServices w **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, co pozwala interfejsowi GUI uzyskiwać dane o pochodzeniu pliku. Ponadto mogą one zostać nadpisane przez aplikacje, które mogą być zainteresowane ukryciem swojego pochodzenia. Można to również zrobić za pośrednictwem API LaunchServices.

#### **libquarantine.dylib**

Ta biblioteka eksportuje kilka funkcji pozwalających na modyfikowanie pól atrybutów rozszerzonych.

API `qtn_file_*` obsługują zasady kwarantanny plików, natomiast API `qtn_proc_*` są stosowane do procesów (plików utworzonych przez proces). Niewyeksportowane funkcje `__qtn_syscall_quarantine*` stosują te zasady, wywołując `mac_syscall` z argumentem `"Quarantine"` jako pierwszym argumentem, co wysyła żądania do `Quarantine.kext`.

#### **Quarantine.kext**

Rozszerzenie jądra jest dostępne wyłącznie w **kernel cache systemu**; można jednak _pobrać **Kernel Debug Kit ze strony**_ [**https://developer.apple.com/**](https://developer.apple.com/), który będzie zawierał wersję rozszerzenia z symbolami.

Ten Kext za pomocą MACF przechwytuje kilka wywołań, aby monitorować wszystkie zdarzenia cyklu życia plików: tworzenie, otwieranie, zmianę nazwy, tworzenie hard linków... a nawet `setxattr`, aby uniemożliwić ustawienie atrybutu rozszerzonego `com.apple.quarantine`.

Wykorzystuje również kilka MIB-ów:

- `security.mac.qtn.sandbox_enforce`: Wymuszanie kwarantanny wraz z Sandbox
- `security.mac.qtn.user_approved_exec`: Procesy objęte kwarantanną mogą wykonywać wyłącznie zatwierdzone pliki

#### Provenance xattr (Ventura i nowsze wersje)

macOS 13 Ventura wprowadził oddzielny mechanizm provenance, który jest inicjalizowany przy pierwszej próbie uruchomienia aplikacji objętej kwarantanną.<sup>[[2]](#references)</sup> Tworzone są dwa artefakty:

- Atrybut xattr `com.apple.provenance` w katalogu pakietu `.app` (wartość binarna o stałym rozmiarze, zawierająca klucz główny i flagi).
- Wiersz w tabeli `provenance_tracking` wewnątrz bazy danych ExecPolicy w `/var/db/SystemPolicyConfiguration/ExecPolicy/`, przechowujący cdhash aplikacji i metadane.

Praktyczne zastosowanie:
```bash
# Inspect provenance xattr (if present)
xattr -p com.apple.provenance /Applications/Some.app | hexdump -C

# Observe Gatekeeper/provenance events in real time
log stream --style syslog --predicate 'process == "syspolicyd"'

# Retrieve historical Gatekeeper decisions for a specific bundle
log show --last 2d --style syslog --predicate 'process == "syspolicyd" && eventMessage CONTAINS[cd] "GK scan"'
```
### XProtect

XProtect to wbudowana funkcja **anti-malware** w systemie macOS. XProtect **sprawdza każdą aplikację przy jej pierwszym uruchomieniu lub modyfikacji, porównując ją ze swoją bazą danych** znanego malware i niebezpiecznych typów plików. Gdy pobierasz plik za pośrednictwem niektórych aplikacji, takich jak Safari, Mail lub Messages, XProtect automatycznie skanuje ten plik. Jeśli pasuje on do znanego malware znajdującego się w bazie danych, XProtect **uniemożliwi uruchomienie pliku** i powiadomi Cię o zagrożeniu.

Baza danych XProtect jest **regularnie aktualizowana** przez Apple o nowe definicje malware, a aktualizacje są automatycznie pobierane i instalowane na Macu. Dzięki temu XProtect jest zawsze aktualny i zawiera informacje o najnowszych znanych zagrożeniach.

Warto jednak zauważyć, że **XProtect nie jest w pełni funkcjonalnym rozwiązaniem antywirusowym**. Sprawdza tylko określoną listę znanych zagrożeń i nie wykonuje skanowania on-access, jak większość oprogramowania antywirusowego.

Informacje o najnowszej aktualizacji XProtect możesz uzyskać, uruchamiając:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect znajduje się w lokalizacji chronionej przez SIP: **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a wewnątrz bundle można znaleźć informacje używane przez XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Umożliwia kodowi z tymi cdhashami korzystanie z legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista pluginów i extensions, których ładowanie jest zabronione na podstawie BundleID i TeamID, lub dla których wskazana jest minimalna wersja.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reguły Yara służące do wykrywania malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Baza danych SQLite3 zawierająca hashe zablokowanych aplikacji i TeamIDs.

Należy pamiętać, że istnieje również inna aplikacja w **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, powiązana z XProtect, ale niezaangażowana w proces Gatekeeper.

> XProtect Remediator: We współczesnym macOS Apple dostarcza skanery on-demand (XProtect Remediator), które są okresowo uruchamiane przez launchd w celu wykrywania i usuwania rodzin malware. Możesz obserwować te skany w unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### To nie Gatekeeper

> [!CAUTION]
> Należy pamiętać, że Gatekeeper **nie jest uruchamiany za każdym razem**, gdy wykonujesz aplikację. Tylko _**AppleMobileFileIntegrity**_ będzie **weryfikować sygnatury kodu wykonywalnego**, gdy wykonujesz aplikację, która została już wcześniej wykonana i zweryfikowana przez Gatekeeper.

Dlatego wcześniej możliwe było wykonanie aplikacji w celu zapisania jej w cache Gatekeeper, a następnie **zmodyfikowanie plików aplikacji, które nie są plikami wykonywalnymi** (takich jak pliki Electron asar lub NIB), i jeśli nie były aktywne żadne inne zabezpieczenia, aplikacja była **wykonywana** wraz z **złośliwymi** dodatkami.

Jednak obecnie nie jest to możliwe, ponieważ macOS **uniemożliwia modyfikowanie plików** wewnątrz application bundles. Jeśli więc spróbujesz ataku [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), przekonasz się, że nie można już go wykorzystać, ponieważ po wykonaniu aplikacji w celu zapisania jej w cache Gatekeeper nie będzie można zmodyfikować bundle. Jeśli natomiast zmienisz na przykład nazwę katalogu Contents na NotCon (jak wskazano w exploicie), a następnie wykonasz główny binary aplikacji, aby zapisać ją w cache Gatekeeper, wywoła to błąd i aplikacja nie zostanie wykonana.

## Gatekeeper Bypasses

Każdy sposób obejścia Gatekeeper (doprowadzenie do tego, aby użytkownik pobrał i wykonał coś, na co Gatekeeper powinien nie zezwolić) jest uznawany za vulnerability w macOS. Oto niektóre CVE przypisane do techniques, które w przeszłości umożliwiały bypass Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Zaobserwowano, że jeśli do ekstrakcji używane jest **Archive Utility**, pliki z **paths exceeding 886 characters** nie otrzymują extended attribute com.apple.quarantine. Ta sytuacja nieumyślnie umożliwia tym plikom **ominięcie** kontroli bezpieczeństwa Gatekeeper.<sup>[[5]](#references)</sup>

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Gdy aplikacja jest tworzona za pomocą **Automator**, informacje o tym, co musi ona wykonać, znajdują się w `application.app/Contents/document.wflow`, a nie w pliku wykonywalnym. Plik wykonywalny jest tylko ogólnym binary Automatora o nazwie **Automator Application Stub**.

Dlatego można było sprawić, aby `application.app/Contents/MacOS/Automator\ Application\ Stub` **wskazywał za pomocą symbolic link na inny Automator Application Stub znajdujący się w systemie**, a następnie wykonywał zawartość `document.wflow` (twój script) **bez uruchamiania Gatekeeper**, ponieważ właściwy plik wykonywalny nie miał quarantine xattr.<sup>[[6]](#references)</sup>

Przykładowa oczekiwana lokalizacja: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://ronmasas.com/posts/bypass-macos-gatekeeper).

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

W tym bypass utworzono plik zip z aplikacją, rozpoczynając kompresowanie od `application.app/Contents` zamiast od `application.app`. W rezultacie **quarantine attr** został zastosowany do wszystkich **files from `application.app/Contents`**, ale **nie do `application.app`**, które było sprawdzane przez Gatekeeper. Gatekeeper został więc ominięty, ponieważ w momencie uruchomienia `application.app` **nie posiadała ona atrybutu quarantine.**<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/), aby uzyskać więcej informacji.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Nawet jeśli komponenty są inne, wykorzystanie tej podatności jest bardzo podobne do poprzedniego. W tym przypadku wygenerujemy Apple Archive z **`application.app/Contents`**, dzięki czemu **`application.app` nie otrzyma atrybutu quarantine** podczas dekompresji przez **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/), aby uzyskać więcej informacji.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** można wykorzystać, aby uniemożliwić komukolwiek zapisanie atrybutu w pliku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Co więcej, format plików **AppleDouble** kopiuje plik wraz z jego ACE.<sup>[[9]](#references)</sup>

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana wewnątrz xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w zdekompresowanym pliku. Jeśli więc skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwia zapis innych xattr... xattr quarantine nie zostanie ustawiony w aplikacji:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/).

Pamiętaj, że można to również wykorzystać za pomocą AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Odkryto, że **Google Chrome nie ustawiał atrybutu kwarantanny** pobieranych plików z powodu pewnych wewnętrznych problemów macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Formaty plików AppleDouble przechowują atrybuty pliku w osobnym pliku zaczynającym się od `._`, co pomaga kopiować atrybuty plików **między komputerami Mac**. Zauważono jednak, że po zdekompresowaniu pliku AppleDouble plik zaczynający się od `._` **nie otrzymywał atrybutu kwarantanny**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Możliwość utworzenia pliku, który nie miał ustawionego atrybutu quarantine, **umożliwiała ominięcie Gatekeepera.** Sztuczka polegała na **utworzeniu aplikacji w pliku DMG** przy użyciu konwencji nazewnictwa AppleDouble (rozpoczęcie nazwy od `._`) oraz utworzeniu **widocznego pliku będącego dowiązaniem symbolicznym do tego ukrytego** pliku bez atrybutu quarantine.\
Gdy **plik dmg zostanie uruchomiony**, ponieważ nie ma atrybutu quarantine, **ominie Gatekeepera**.
```bash
# Create an app bundle with the backdoor an call it app.app

echo "[+] creating disk image with app"
hdiutil create -srcfolder app.app app.dmg

echo "[+] creating directory and files"
mkdir
mkdir -p s/app
cp app.dmg s/app/._app.dmg
ln -s ._app.dmg s/app/app.dmg

echo "[+] compressing files"
aa archive -d s/ -o app.aar
```
### [CVE-2023-41067]

Obejście Gatekeeper naprawione w macOS Sonoma 14.0 umożliwiało uruchamianie spreparowanych aplikacji bez wyświetlania monitu. Szczegóły ujawniono publicznie po wydaniu poprawki, a problem był aktywnie wykorzystywany w środowisku naturalnym przed jego naprawieniem. Upewnij się, że zainstalowano Sonoma 14.0 lub nowszą wersję.

### [CVE-2024-27853]

Obejście Gatekeeper w macOS 14.4 (wydanym w marcu 2024 r.), wynikające ze sposobu obsługi złośliwych archiwów ZIP przez `libarchive`, umożliwiało aplikacjom uniknięcie oceny. Zaktualizuj system do wersji 14.4 lub nowszej, w której Apple naprawiło ten problem.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** osadzony w pobranej aplikacji mógł zostać uruchomiony bez oceny Gatekeeper, ponieważ workflow były traktowane jako dane i wykonywane przez helper Automator poza standardową ścieżką monitu dotyczącego notarization. Spreparowany plik `.app`, zawierający Quick Action uruchamiający shell script (np. wewnątrz `Contents/PlugIns/*.workflow/Contents/document.wflow`), mógł więc zostać wykonany natychmiast po uruchomieniu. Apple dodało dodatkowe okno zgody i naprawiło ścieżkę oceny w Ventura **13.7**, Sonoma **14.7** oraz Sequoia **15**.<sup>[[3]](#references)</sup>

### Nieprawidłowe przekazywanie quarantine przez third-party unarchivers (2023–2024)

Kilka podatności w popularnych narzędziach do ekstrakcji (np. The Unarchiver) powodowało, że pliki wypakowane z archiwów nie otrzymywały xattr `com.apple.quarantine`, co stwarzało możliwości obejścia Gatekeeper. Podczas testów zawsze korzystaj z macOS Archive Utility lub poprawionych narzędzi i sprawdzaj xattr po wypakowaniu.

### uchg (z tego [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Utwórz katalog zawierający aplikację.
- Dodaj uchg do aplikacji.
- Skompresuj aplikację do pliku tar.gz.
- Wyślij plik tar.gz ofierze.
- Ofiara otwiera plik tar.gz i uruchamia aplikację.
- Gatekeeper nie sprawdza aplikacji.<sup>[[12]](#references)</sup>

### Zapobieganie atrybutowi xattr quarantine

Jeśli w pakiecie ".app" nie zostanie dodany atrybut xattr quarantine, podczas jego wykonywania **Gatekeeper nie zostanie uruchomiony**.


## Odniesienia

- [1] [Apple Platform Security: Informacje o zawartości zabezpieczeń macOS Sonoma 14.4 (w tym CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jak macOS śledzi obecnie pochodzenie aplikacji](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Informacje o zawartości zabezpieczeń macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia usuwa obejście Gatekeeper za pomocą „Open” po kliknięciu z wciśniętym klawiszem Control](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)
- [5] [WithSecure Labs: Odkrycie CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, obchodzenie macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identyfikuje podatność Safari umożliwiającą obejście Gatekeeper](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identyfikuje podatność macOS Archive Utility umożliwiającą obejście Gatekeeper (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Pięta achillesowa Gatekeeper: odkrycie podatności macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Odkrycie obejścia Gatekeeper (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Znalezienie i zgłoszenie exploita obchodzącego Gatekeeper z pomocą Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Obchodzenie mechanizmów bezpieczeństwa i prywatności macOS — od Gatekeeper do System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)

{{#include ../../../banners/hacktricks-training.md}}

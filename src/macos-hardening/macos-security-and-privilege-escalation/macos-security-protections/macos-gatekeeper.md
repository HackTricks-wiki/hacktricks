# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** to funkcja bezpieczeństwa opracowana dla systemów operacyjnych Mac, zaprojektowana w celu zapewnienia, że użytkownicy **uruchamiają w swoich systemach wyłącznie zaufane oprogramowanie**. Działa poprzez **weryfikowanie oprogramowania**, które użytkownik pobiera i próbuje otworzyć ze **źródeł spoza App Store**, takich jak aplikacja, plug-in lub pakiet instalacyjny.

Kluczowym mechanizmem Gatekeepera jest proces **weryfikacji**. Sprawdza on, czy pobrane oprogramowanie jest **podpisane przez rozpoznanego developera**, potwierdzając jego autentyczność. Ponadto ustala, czy oprogramowanie zostało **notaryzowane przez Apple**, co potwierdza, że nie zawiera znanych złośliwych treści i nie zostało zmodyfikowane po notaryzacji.

Dodatkowo Gatekeeper wzmacnia kontrolę użytkownika i bezpieczeństwo, **prosząc użytkowników o zatwierdzenie otwarcia** pobranego oprogramowania przy pierwszym uruchomieniu. Zabezpieczenie to pomaga zapobiegać przypadkowemu uruchomieniu potencjalnie szkodliwego kodu wykonywalnego, który użytkownik mógł pomylić z nieszkodliwym plikiem danych.

### Sygnatury aplikacji

Sygnatury aplikacji, znane również jako sygnatury kodu, są kluczowym elementem infrastruktury bezpieczeństwa Apple. Służą do **weryfikowania tożsamości autora oprogramowania** (developera) oraz zapewnienia, że kod nie został zmodyfikowany od czasu jego ostatniego podpisania.

Działa to w następujący sposób:

1. **Podpisywanie aplikacji:** Gdy developer jest gotowy do dystrybucji swojej aplikacji, **podpisuje ją za pomocą klucza prywatnego**. Klucz prywatny jest powiązany z **certyfikatem wydanym developerowi przez Apple** podczas rejestracji w Apple Developer Program. Proces podpisywania obejmuje utworzenie kryptograficznego hasha wszystkich elementów aplikacji i zaszyfrowanie tego hasha kluczem prywatnym developera.
2. **Dystrybucja aplikacji:** Podpisana aplikacja jest następnie dystrybuowana użytkownikom wraz z certyfikatem developera, który zawiera odpowiadający mu klucz publiczny.
3. **Weryfikowanie aplikacji:** Gdy użytkownik pobiera aplikację i próbuje ją uruchomić, system operacyjny Mac używa klucza publicznego z certyfikatu developera do odszyfrowania hasha. Następnie ponownie oblicza hash na podstawie bieżącego stanu aplikacji i porównuje go z odszyfrowanym hashem. Jeśli wartości się zgadzają, oznacza to, że **aplikacja nie została zmodyfikowana** od czasu podpisania jej przez developera, a system zezwala na jej uruchomienie.

Sygnatury aplikacji są istotną częścią technologii Gatekeeper firmy Apple. Gdy użytkownik próbuje **otworzyć aplikację pobraną z Internetu**, Gatekeeper weryfikuje sygnaturę aplikacji. Jeśli została podpisana certyfikatem wydanym przez Apple znanemu developerowi, a kod nie został zmodyfikowany, Gatekeeper zezwala na uruchomienie aplikacji. W przeciwnym razie blokuje aplikację i ostrzega użytkownika.

Od macOS Catalina **Gatekeeper sprawdza również, czy aplikacja została notaryzowana** przez Apple, dodając dodatkową warstwę bezpieczeństwa. Proces notaryzacji sprawdza aplikację pod kątem znanych problemów bezpieczeństwa i złośliwego kodu, a jeśli kontrole zakończą się pomyślnie, Apple dodaje do aplikacji ticket, który Gatekeeper może zweryfikować.

#### Sprawdzanie sygnatur

Podczas sprawdzania **próbki malware** należy zawsze **sprawdzić sygnaturę** pliku **binary**, ponieważ **developer**, który ją podpisał, może być już **powiązany** z **malware.**
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
### Notaryzacja

Proces notaryzacji Apple służy jako dodatkowe zabezpieczenie chroniące użytkowników przed potencjalnie szkodliwym oprogramowaniem. Polega on na **przesłaniu aplikacji przez developera do sprawdzenia** przez **Apple's Notary Service**, którego nie należy mylić z App Review. Usługa ta jest **automatycznym systemem**, który analizuje przesłane oprogramowanie pod kątem obecności **złośliwej zawartości** oraz potencjalnych problemów z code-signingiem.

Jeśli oprogramowanie **przejdzie** tę kontrolę bez wykrycia problemów, Notary Service generuje ticket notaryzacji. Następnie developer musi **dołączyć ten ticket do swojego oprogramowania** — proces ten nazywa się „stapling”. Ticket notaryzacji jest również publikowany online, gdzie Gatekeeper, technologia bezpieczeństwa Apple, może uzyskać do niego dostęp.

Podczas pierwszej instalacji lub uruchomienia oprogramowania przez użytkownika obecność ticketu notaryzacji — niezależnie od tego, czy jest on dołączony do pliku wykonywalnego, czy znaleziony online — **informuje Gatekeeper, że oprogramowanie zostało poddane notaryzacji przez Apple**. W rezultacie Gatekeeper wyświetla w początkowym oknie dialogowym uruchamiania opisowy komunikat informujący, że oprogramowanie zostało sprawdzone przez Apple pod kątem złośliwej zawartości. Proces ten zwiększa zaufanie użytkowników do bezpieczeństwa oprogramowania instalowanego lub uruchamianego w ich systemach.

### spctl & syspolicyd

> [!CAUTION]
> Należy pamiętać, że od wersji Sequoia **`spctl`** nie pozwala już modyfikować konfiguracji Gatekeeper.

**`spctl`** to narzędzie CLI służące do wyliczania elementów i interakcji z Gatekeeper (za pośrednictwem demona `syspolicyd` i komunikatów XPC). Przykładowo, status **GateKeeper** można sprawdzić za pomocą:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Pamiętaj, że sprawdzanie sygnatur przez GateKeeper jest wykonywane tylko dla **plików z atrybutem Quarantine**, a nie dla każdego pliku.

GateKeeper sprawdzi, czy zgodnie z **ustawieniami i sygnaturą** można wykonać plik binarny:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** to główny demon odpowiedzialny za egzekwowanie działania Gatekeeper. Utrzymuje bazę danych znajdującą się w `/var/db/SystemPolicy`; [tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) można znaleźć kod obsługujący tę [bazę danych](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), a [tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql) szablon SQL. Należy pamiętać, że baza danych nie jest ograniczana przez SIP i można w niej zapisywać jako root, a baza danych `/var/db/.SystemPolicy-default` jest używana jako oryginalna kopia zapasowa na wypadek uszkodzenia drugiej bazy.

Ponadto bundlowane pliki **`/var/db/gke.bundle`** i **`/var/db/gkopaque.bundle`** zawierają pliki z regułami, które są wstawiane do bazy danych. Jako root możesz sprawdzić tę bazę danych za pomocą:
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
**`syspolicyd`** udostępnia również serwer XPC z różnymi operacjami, takimi jak `assess`, `update`, `record` i `cancel`, które są również dostępne za pomocą API **`SecAssessment*`** z **`Security.framework`**, a **`spctl`** faktycznie komunikuje się z **`syspolicyd`** przez XPC.

Zwróć uwagę, że pierwsza reguła kończyła się na "**App Store**", a druga na "**Developer ID**" oraz że na poprzednim obrazie było **włączone wykonywanie aplikacji z App Store i od zidentyfikowanych developerów**.\
Jeśli **zmodyfikujesz** to ustawienie na App Store, reguły "**Notarized Developer ID" znikną**.

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
Opcje **`--master-disable`** i **`--global-disable`** narzędzia **`spctl`** całkowicie **wyłączą** te kontrole podpisów:
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

Możliwe jest **sprawdzenie, czy aplikacja zostanie dopuszczona przez GateKeeper** za pomocą:
```bash
spctl --assess -v /Applications/App.app
```
W systemie macOS 14 i nowszych **`syspolicy_check`** to przydatne narzędzie do kontroli pakietu aplikacji wyższego poziomu przed dystrybucją. Dostarcza bardziej praktycznych diagnostyk dotyczących trusted execution niż podstawowy wynik `spctl`, chociaż Apple nadal zaleca testowanie rzeczywistej ścieżki pobierania, rozpakowywania i pierwszego uruchomienia, ponieważ obejmuje ona również propagację kwarantanny.<sup>[[14]](#references)</sup>
```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
```
Możliwe jest dodanie nowych reguł w GateKeeperze, aby zezwolić na uruchamianie określonych aplikacji za pomocą:
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
W przypadku **kernel extensions** folder `/var/db/SystemPolicyConfiguration` zawiera pliki z listami kextów dozwolonych do załadowania. Ponadto `spctl` ma entitlement `com.apple.private.iokit.nvram-csr`, ponieważ może dodawać nowe, wstępnie zatwierdzone kernel extensions, które muszą być również zapisane w NVRAM w kluczu `kext-allowed-teams`.

#### Zarządzanie Gatekeeper w macOS 15 (Sequoia) i nowszych wersjach

- Długo istniejący bypass w Finderze **Ctrl+Open / kliknięcie prawym przyciskiem myszy → Open** został usunięty; po pierwszym oknie dialogowym o zablokowaniu aplikacji użytkownicy muszą jawnie zezwolić na jej uruchomienie w **System Settings → Privacy & Security → Open Anyway**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` nie są już akceptowane jako nieinteraktywne zmiany zasad. Operacje modyfikujące bazę reguł lub globalny stan oceny są deprecated, dlatego używaj `spctl` do oceny, a wymuszanie konfiguruj przez UI lub MDM.

Począwszy od macOS 15 Sequoia, użytkownicy końcowi nie mogą już przełączać zasad Gatekeeper za pomocą `spctl`. Zarządzanie odbywa się za pośrednictwem System Settings lub przez wdrożenie profilu konfiguracyjnego MDM z payloadem `com.apple.systempolicy.control`. Przykładowy fragment profilu zezwalający na App Store i zidentyfikowanych developerów (ale nie na „Anywhere”):

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

Podczas **pobierania** aplikacji lub pliku określone **aplikacje** macOS, takie jak przeglądarki internetowe lub klienci poczty e-mail, **dołączają rozszerzony atrybut pliku**, powszechnie znany jako "**quarantine flag**", do pobranego pliku. Atrybut ten działa jako środek bezpieczeństwa, **oznaczając plik** jako pochodzący z niezaufanego źródła (internetu) i potencjalnie niosący zagrożenia. Jednak nie wszystkie aplikacje dołączają ten atrybut — przykładowo popularne oprogramowanie klientów BitTorrent zwykle omija ten proces.

**Obecność quarantine flag sygnalizuje funkcji bezpieczeństwa Gatekeeper systemu macOS, że użytkownik próbuje uruchomić plik**.

Jeśli **quarantine flag nie jest obecny** (jak w przypadku plików pobranych za pomocą niektórych klientów BitTorrent), **checks Gatekeepera mogą nie zostać wykonane**. Dlatego użytkownicy powinni zachować ostrożność podczas otwierania plików pobranych z mniej bezpiecznych lub nieznanych źródeł.

> [!NOTE] > **Sprawdzanie** **poprawności** podpisów code signatures to proces wymagający dużych zasobów, obejmujący generowanie kryptograficznych **hashy** kodu i wszystkich dołączonych do niego zasobów. Ponadto sprawdzanie poprawności certyfikatu wymaga wykonania **online check** serwerów Apple w celu ustalenia, czy został on unieważniony po wydaniu. Z tych powodów pełne sprawdzanie code signature i notarization jest **niepraktyczne przy każdym uruchomieniu aplikacji**.
>
> Dlatego te checks są **wykonywane tylko podczas uruchamiania aplikacji z atrybutem quarantine**.

> [!WARNING]
> Ten atrybut musi zostać **ustawiony przez aplikację tworzącą/pobierającą** plik.
>
> Jednak pliki uruchamiane w sandboxie będą miały ten atrybut ustawiony dla każdego utworzonego przez siebie pliku. Aplikacje działające poza sandboxem mogą ustawić go samodzielnie lub określić klucz [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) w pliku **Info.plist**, co spowoduje, że system ustawi rozszerzony atrybut `com.apple.quarantine` na tworzonych plikach,

Ponadto wszystkie pliki utworzone przez proces wywołujący **`qtn_proc_apply_to_self`** są objęte kwarantanną. Alternatywnie API **`qtn_file_apply_to_path`** dodaje atrybut quarantine do określonej ścieżki pliku.

Możliwe jest **sprawdzenie jego statusu oraz włączenie/wyłączenie** (wymagany root) za pomocą:
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
Sprawdź **wartość** **rozszerzonych** **atrybutów** i ustal aplikację, która zapisała atrybut quarantine za pomocą:
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
# 00c1 -- The user has been allowed to execute this file (QTN_FLAG_USER_APPROVED = 0x0040)
# 607842eb -- Timestamp
# Brave -- App
# F643CD5F-6071-46AB-83AB-390BA944DEC5 -- UID assigned to the file downloaded
```
W rzeczywistości proces „mógłby ustawiać flagi kwarantanny dla tworzonych przez siebie plików” (próbowałem już zastosować flagę USER_APPROVED do utworzonego pliku, ale nie można jej zastosować):

<details>

<summary>Kod źródłowy — zastosowanie flag kwarantanny</summary>
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
Informacje o kwarantannie są również przechowywane w centralnej bazie danych zarządzanej przez LaunchServices w **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, co pozwala GUI uzyskiwać dane o pochodzeniu pliku. Ponadto dane te mogą zostać nadpisane przez aplikacje, które mogą być zainteresowane ukryciem swojego pochodzenia. Można to również zrobić za pomocą LaunchServices APIS.

#### **libquarantine.dylib**

Ta biblioteka eksportuje kilka funkcji umożliwiających modyfikowanie pól atrybutów rozszerzonych.

APIs `qtn_file_*` dotyczą zasad kwarantanny plików, natomiast APIs `qtn_proc_*` są stosowane do procesów (plików utworzonych przez proces). Niewyeksportowane funkcje `__qtn_syscall_quarantine*` stosują te zasady, wywołując `mac_syscall` z argumentem "Quarantine" jako pierwszym, co wysyła żądania do `Quarantine.kext`.

#### **Quarantine.kext**

Rozszerzenie jądra jest dostępne wyłącznie w **kernel cache systemu**; można jednak _pobrać **Kernel Debug Kit ze strony** [**https://developer.apple.com/**](https://developer.apple.com/), który będzie zawierał wersję rozszerzenia z symbolami.

Ten Kext używa MACF do przechwytywania kilku wywołań w celu przechwycenia wszystkich zdarzeń cyklu życia plików: tworzenia, otwierania, zmiany nazwy, tworzenia hard linków... a nawet `setxattr`, aby uniemożliwić ustawienie atrybutu rozszerzonego `com.apple.quarantine`.

Używa również kilku MIB-ów:

- `security.mac.qtn.sandbox_enforce`: Wymuszanie kwarantanny wraz z Sandbox
- `security.mac.qtn.user_approved_exec`: Procesy objęte kwarantanną mogą wykonywać wyłącznie zatwierdzone pliki

#### Provenance xattr (Ventura i nowsze)

macOS 13 Ventura wprowadził osobny mechanizm provenance, który jest uzupełniany przy pierwszej próbie uruchomienia aplikacji objętej kwarantanną.<sup>[[2]](#references)</sup> Tworzone są dwa artefakty:

- Atrybut rozszerzony `com.apple.provenance` w katalogu pakietu `.app` (binarna wartość o stałym rozmiarze zawierająca klucz główny i flagi).
- Wiersz w tabeli `provenance_tracking` w bazie danych ExecPolicy znajdującej się w `/var/db/SystemPolicyConfiguration/ExecPolicy/`, przechowujący cdhash aplikacji i metadane.

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

XProtect to wbudowana funkcja **anti-malware** w systemie macOS. XProtect **sprawdza każdą aplikację podczas jej pierwszego uruchomienia lub modyfikacji, porównując ją z bazą danych** znanego malware i niebezpiecznych typów plików. Gdy pobierasz plik za pomocą niektórych aplikacji, takich jak Safari, Mail lub Messages, XProtect automatycznie skanuje ten plik. Jeśli pasuje on do dowolnego znanego malware znajdującego się w bazie danych, XProtect **uniemożliwi uruchomienie pliku** i poinformuje Cię o zagrożeniu.

Baza danych XProtect jest **regularnie aktualizowana** przez Apple o nowe definicje malware, a aktualizacje te są automatycznie pobierane i instalowane na Macu. Dzięki temu XProtect jest zawsze aktualny i chroni przed najnowszymi znanymi zagrożeniami.

Warto jednak zauważyć, że **XProtect nie jest w pełni funkcjonalnym rozwiązaniem antywirusowym**. Sprawdza tylko określoną listę znanych zagrożeń i nie wykonuje skanowania on-access, jak większość oprogramowania antywirusowego.

Informacje o najnowszej aktualizacji XProtect można uzyskać, uruchamiając:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect znajduje się w lokalizacji chronionej przez SIP: **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a wewnątrz bundle można znaleźć informacje używane przez XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Zezwala kodowi z tymi cdhashami na używanie legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista pluginów i extensions, których ładowanie jest niedozwolone na podstawie BundleID i TeamID, lub wskazująca minimalną wersję.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reguły Yara do wykrywania malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Baza danych SQLite3 zawierająca hashe zablokowanych aplikacji i TeamIDs.

Należy pamiętać, że istnieje również inna aplikacja w **`/Library/Apple/System/Library/CoreServices/XProtect.app`**, powiązana z XProtect, ale niezaangażowana w proces Gatekeeper.

> XProtect Remediator: We współczesnym macOS Apple dostarcza skanery on-demand (XProtect Remediator), które są okresowo uruchamiane przez launchd w celu wykrywania i usuwania rodzin malware. Możesz obserwować te skany w unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nie Gatekeeper

> [!CAUTION]
> Należy pamiętać, że Gatekeeper **nie jest uruchamiany za każdym razem**, gdy wykonujesz aplikację. Tylko _**AppleMobileFileIntegrity**_ będzie **weryfikować podpisy kodu wykonywalnego**, gdy wykonujesz aplikację, która była już wcześniej wykonana i zweryfikowana przez Gatekeeper.

Dlatego wcześniej możliwe było wykonanie aplikacji w celu zapisania jej w cache Gatekeeper, a następnie **zmodyfikowanie plików aplikacji, które nie są wykonywalne** (takich jak pliki asar lub NIB używane przez Electron). Jeśli nie działały żadne inne zabezpieczenia, aplikacja była **wykonywana** wraz z **złośliwymi** dodatkami.

Obecnie nie jest to jednak możliwe, ponieważ macOS **uniemożliwia modyfikowanie plików** wewnątrz application bundles. Jeśli więc spróbujesz przeprowadzić atak [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), stwierdzisz, że nie można już go wykorzystać, ponieważ po wykonaniu aplikacji w celu zapisania jej w cache Gatekeeper nie będzie można zmodyfikować bundle. Jeśli na przykład zmienisz nazwę katalogu Contents na NotCon (jak wskazano w exploicie), a następnie wykonasz główny plik binarny aplikacji w celu zapisania jej w cache Gatekeeper, spowoduje to błąd i aplikacja nie zostanie wykonana.

## Obejścia Gatekeeper

Każdy sposób obejścia Gatekeeper (doprowadzenie do tego, aby użytkownik pobrał coś i wykonał to, mimo że Gatekeeper powinien na to nie zezwolić) jest uznawany za podatność w macOS. Poniżej przedstawiono niektóre CVE przypisane do technik, które w przeszłości umożliwiały obejście Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Zaobserwowano, że jeśli do rozpakowywania użyto **Archive Utility**, pliki ze **ścieżkami przekraczającymi 886 znaków** nie otrzymywały rozszerzonego atrybutu com.apple.quarantine. Sytuacja ta przypadkowo pozwalała tym plikom **ominąć kontrole bezpieczeństwa Gatekeeper**.<sup>[[5]](#references)</sup>

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Gdy aplikacja jest tworzona za pomocą **Automator**, informacje o tym, co ma zostać wykonane, znajdują się w `application.app/Contents/document.wflow`, a nie w pliku wykonywalnym. Plik wykonywalny jest jedynie ogólnym plikiem binarnym Automatora o nazwie **Automator Application Stub**.

Można więc sprawić, aby `application.app/Contents/MacOS/Automator\ Application\ Stub` **wskazywał za pomocą symbolic link do innego Automator Application Stub znajdującego się w systemie**. Spowoduje to wykonanie zawartości `document.wflow` (skryptu) **bez uruchamiania Gatekeeper**, ponieważ właściwy plik wykonywalny nie ma atrybutu quarantine xattr.<sup>[[6]](#references)</sup>

Przykładowa oczekiwana lokalizacja: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Więcej informacji można znaleźć w [**oryginalnym raporcie**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

W tym obejściu utworzono plik zip, rozpoczynając kompresowanie aplikacji od `application.app/Contents` zamiast od `application.app`. W rezultacie atrybut **quarantine attr** został zastosowany do wszystkich **plików z `application.app/Contents`**, ale **nie do `application.app`**, które było sprawdzane przez Gatekeeper. Gatekeeper został więc ominięty, ponieważ po uruchomieniu `application.app` **nie miała ona atrybutu quarantine**.<sup>[[7]](#references)</sup>
```bash
zip -r test.app/Contents test.zip
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) po więcej informacji.<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Nawet jeśli komponenty są różne, wykorzystanie tej luki jest bardzo podobne do poprzedniego. W tym przypadku wygenerujemy Apple Archive z **`application.app/Contents`**, dzięki czemu **`application.app` nie otrzyma atrybutu kwarantanny** podczas dekompresji przez **Archive Utility**.<sup>[[8]](#references)</sup>
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/), aby uzyskać więcej informacji.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** można użyć, aby uniemożliwić komukolwiek zapis atrybutu w pliku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Co więcej, format pliku **AppleDouble** kopiuje plik razem z jego ACE.<sup>[[9]](#references)</sup>

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana wewnątrz xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w zdekompresowanym pliku. Jeśli więc skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwia zapisanie innych xattr... xattr quarantine nie zostanie ustawiony w aplikacji:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Sprawdź [**oryginalny raport**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) aby uzyskać więcej informacji.<sup>[[9]](#references)</sup>

Należy zauważyć, że można to również wykorzystać za pomocą AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Odkryto, że **Google Chrome nie ustawiał atrybutu kwarantanny** pobieranym plikom z powodu pewnych wewnętrznych problemów macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble przechowuje atrybuty pliku w osobnym pliku, którego nazwa zaczyna się od `._`; ułatwia to kopiowanie atrybutów plików **między komputerami Mac**. Jednak po dekompresji pliku AppleDouble plik zaczynający się od `._` **nie otrzymywał atrybutu kwarantanny**.<sup>[[11]](#references)</sup>
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```
Możliwość utworzenia pliku, który nie będzie miał ustawionego atrybutu kwarantanny, pozwalała **ominąć Gatekeepera.** Sztuczka polegała na **utworzeniu pliku aplikacji DMG** z użyciem konwencji nazewnictwa AppleDouble (rozpoczęcie nazwy od `._`) oraz utworzeniu **widocznego pliku będącego dowiązaniem symbolicznym do tego ukrytego** pliku, bez atrybutu kwarantanny.\
Gdy **plik dmg zostanie wykonany**, ponieważ nie ma atrybutu kwarantanny, **ominie Gatekeepera**.
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

Apple naprawiło błąd logiki LaunchServices w macOS Sonoma 14.0 poprzez ulepszenie mechanizmów sprawdzania. Publiczny advisory stwierdza jedynie, że aplikacja mogła ominąć Gatekeeper, dlatego na podstawie samego wpisu CVE nie należy wnioskować o konkretnym formacie nośnika ani łańcuchu eksploatacji.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Obejście Gatekeeper w macOS 14.4 (wydanym w marcu 2024 r.), wynikające ze sposobu, w jaki `libarchive` obsługiwał złośliwe archiwa ZIP, pozwalało aplikacjom uniknąć oceny. Zaktualizuj system do wersji 14.4 lub nowszej, w której Apple naprawiło ten problem.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

**Automator Quick Action workflow** osadzony w pobranej aplikacji mógł zostać uruchomiony bez oceny Gatekeeper, ponieważ workflowy były traktowane jako dane i wykonywane przez pomocnika Automator poza zwykłą ścieżką wyświetlania monitu dotyczącego notarization. Spreparowany plik `.app`, zawierający Quick Action uruchamiający skrypt powłoki (np. wewnątrz `Contents/PlugIns/*.workflow/Contents/document.wflow`), mógł więc zostać wykonany natychmiast po uruchomieniu. Apple dodało dodatkowe okno dialogowe zgody i naprawiło ścieżkę oceny w Ventura **13.7**, Sonoma **14.7** oraz Sequoia **15**.<sup>[[3]](#references)</sup>

### Błędy propagacji kwarantanny na granicach rozpakowywania i kopiowania

Badanie z 2024 r. wykazało luki w propagacji w testowanych wersjach iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) oraz 7z Utility (DMG/ZIP/7Z); zaobserwowano również utratę atrybutu podczas kopiowania z hosta do gościa za pomocą VMware Tools. Kilku dostawców ogłosiło później poprawki, dlatego należy traktować te nazwy jako punkty wyjścia do **ponownych testów zależnych od wersji**, a nie jako stałą listę podatnego oprogramowania. Ten sam problem granicy zaufania dotyczy natywnych workflowów Unix: `curl`/`scp` nie dodają kwarantanny, a narzędzia wiersza poleceń `tar`/`unzip` nie dziedziczą jej automatycznie z archiwum będącego nośnikiem.<sup>[[15]](#references)</sup>

W ramach testów ofensywnych porównuj nośnik i finalną aplikację po **każdym** przejściu przez przeglądarkę, klienta pocztowego, archiwizator, obraz dysku, synchronizację z cloud, folder współdzielony oraz kopiowanie przez VM. Jawna odmowa `spctl` nie naprawia brakującego xattr: bez kwarantanny zwykła ścieżka Gatekeeper przy pierwszym otwarciu może nigdy nie zażądać tej oceny.<sup>[[15]](#references)</sup>
```bash
# 1. Confirm the browser-downloaded carrier is quarantined
xattr -p com.apple.quarantine ./payload.zip

# 2. Extract/copy it through the application under test, then inspect the result
xattr -p com.apple.quarantine ./out/Payload.app || echo "QUARANTINE LOST"
spctl --assess --type execute -vv ./out/Payload.app

# 3. Enumerate every app bundle whose top-level directory lost the marker
find ./out -type d -name '*.app' -prune -exec sh -c \
'for app do xattr -p com.apple.quarantine "$app" >/dev/null 2>&1 || echo "$app"; done' sh {} +
```
### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Utwórz katalog zawierający aplikację.
- Dodaj uchg do aplikacji.
- Skompresuj aplikację do pliku tar.gz.
- Wyślij plik tar.gz ofierze.
- Ofiara otwiera plik tar.gz i uruchamia aplikację.
- Gatekeeper nie sprawdza aplikacji.<sup>[[12]](#references)</sup>

### Zapobieganie atrybutowi xattr quarantine

Jeśli w pakiecie ".app" nie zostanie dodany atrybut xattr quarantine, podczas jego wykonywania **Gatekeeper nie zostanie uruchomiony**.

Zobacz [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks), aby poznać prymitywy oparte na systemie plików, flagach, ACL i AppleDouble, które mogą zapobiegać dodawaniu lub usuwać atrybuty rozszerzone.



## References

- [1] [Apple Platform Security: Informacje o zawartości zabezpieczeń systemu macOS Sonoma 14.4 (w tym CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jak macOS śledzi obecnie pochodzenie aplikacji](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Informacje o zawartości zabezpieczeń systemu macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia usuwa omijanie Gatekeepera za pomocą „Otwórz” po kliknięciu z wciśniętym klawiszem Control](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Odkrycie CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, Omijanie macOS Gatekeeper](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs identyfikuje lukę w Safari umożliwiającą obejście Gatekeepera](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs identyfikuje lukę w macOS Archive Utility umożliwiającą obejście Gatekeepera (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Pięta achillesowa Gatekeepera: odkrycie luki w systemie macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Odkrycie obejścia Gatekeepera (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Znalezienie i zgłoszenie exploita omijającego Gatekeepera z pomocą Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Omijanie mechanizmów bezpieczeństwa i prywatności systemu macOS — od Gatekeepera do System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Informacje o zawartości zabezpieczeń systemu macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Testowanie produktu poddanego notaryzacji](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Obejście Gatekeepera — odkrywanie słabości mechanizmu bezpieczeństwa macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}

# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** to funkcja bezpieczeństwa opracowana dla systemów Mac, zaprojektowana, aby zapewnić, że użytkownicy **uruchamiają tylko zaufane oprogramowanie** na swoich systemach. Działa poprzez **weryfikację oprogramowania** pobranego i próbującego się otworzyć z **źródeł poza App Store**, takich jak aplikacja, wtyczka czy pakiet instalacyjny.

Kluczowy mechanizm Gatekeeper polega na procesie **weryfikacji**. Sprawdza, czy pobrane oprogramowanie jest **podpisane przez rozpoznanego developera**, co potwierdza autentyczność oprogramowania. Dodatkowo ustala, czy oprogramowanie jest **notarised by Apple**, potwierdzając, że nie zawiera znanych złośliwych treści i nie zostało zmodyfikowane po notarizacji.

Ponadto Gatekeeper wzmacnia kontrolę i bezpieczeństwo użytkownika, **wyświetlając monity z prośbą o zatwierdzenie otwarcia** pobranego oprogramowania przy pierwszym uruchomieniu. To zabezpieczenie pomaga zapobiegać przypadkowemu uruchomieniu potencjalnie szkodliwego kodu wykonywalnego, który użytkownik mógł pomylić z nieszkodliwym plikiem danych.

### Application Signatures

Application signatures, znane również jako code signatures, są krytycznym elementem infrastruktury bezpieczeństwa Apple. Służą do **weryfikacji tożsamości autora oprogramowania** (developera) oraz do upewnienia się, że kod nie został zmodyfikowany od czasu ostatniego podpisania.

Jak to działa:

1. **Signing the Application:** Gdy developer jest gotowy do dystrybucji aplikacji, **podpisuje aplikację przy użyciu klucza prywatnego**. Ten klucz prywatny jest powiązany z **certyfikatem wydanym przez Apple developerowi** po zapisaniu się do Apple Developer Program. Proces podpisywania obejmuje utworzenie kryptograficznego skrótu wszystkich części aplikacji i zaszyfrowanie tego skrótu przy użyciu klucza prywatnego developera.
2. **Distributing the Application:** Podpisana aplikacja jest następnie dystrybuowana do użytkowników wraz z certyfikatem developera, który zawiera odpowiadający klucz publiczny.
3. **Verifying the Application:** Gdy użytkownik pobiera i próbuje uruchomić aplikację, system używa klucza publicznego z certyfikatu developera do odszyfrowania skrótu. System ponownie oblicza skrót na podstawie bieżącego stanu aplikacji i porównuje go z odszyfrowanym skrótem. Jeśli się zgadzają, oznacza to, że **aplikacja nie została zmodyfikowana** od momentu podpisania i system pozwala na jej uruchomienie.

Application signatures są istotną częścią technologii Gatekeeper. Gdy użytkownik próbuje **otworzyć aplikację pobraną z internetu**, Gatekeeper weryfikuje podpis aplikacji. Jeśli jest podpisana certyfikatem wydanym przez Apple znanemu developerowi i kod nie został naruszony, Gatekeeper pozwala na uruchomienie. W przeciwnym razie blokuje aplikację i ostrzega użytkownika.

Począwszy od macOS Catalina, **Gatekeeper również sprawdza, czy aplikacja została notarised by Apple**, dodając dodatkową warstwę zabezpieczeń. Proces notarizacji analizuje aplikację pod kątem znanych problemów bezpieczeństwa i złośliwego kodu, a jeśli te kontrole przejdą pomyślnie, Apple dodaje do aplikacji ticket, który Gatekeeper może zweryfikować.

#### Check Signatures

Podczas analizowania próbki złośliwego oprogramowania zawsze powinieneś **sprawdzić podpis** binarki, ponieważ developer, który ją podpisał, może być już powiązany z malware.
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

Proces notaryzacji Apple'a służy jako dodatkowe zabezpieczenie chroniące użytkowników przed potencjalnie szkodliwym oprogramowaniem. Polega na tym, że **deweloper zgłasza swoją aplikację do sprawdzenia** przez **Apple's Notary Service**, które nie powinno być mylone z App Review. Ta usługa jest **systemem automatycznym**, który analizuje przesłane oprogramowanie pod kątem **złośliwych treści** oraz potencjalnych problemów z podpisywaniem kodu.

Jeżeli oprogramowanie **przejdzie** tę kontrolę bez zastrzeżeń, Notary Service generuje notarization ticket. Deweloper musi następnie **dołączyć ten ticket do swojego oprogramowania**, proces znany jako 'stapling'. Ponadto notarization ticket jest również publikowany online, gdzie Gatekeeper, technologia bezpieczeństwa Apple'a, może go odczytać.

Przy pierwszej instalacji lub uruchomieniu oprogramowania na komputerze użytkownika, obecność notarization ticket — czy to przyczepionego do pliku wykonywalnego, czy dostępnego online — **informuje Gatekeeper, że oprogramowanie zostało notaryzowane przez Apple**. W rezultacie Gatekeeper wyświetla opisowy komunikat w początkowym oknie uruchamiania, wskazując, że oprogramowanie przeszło kontrole pod kątem złośliwych treści przeprowadzone przez Apple. Proces ten zwiększa zaufanie użytkownika do bezpieczeństwa oprogramowania, które instaluje lub uruchamia na swoim systemie.

### spctl & syspolicyd

> [!CAUTION]
> Należy zauważyć, że od wersji Sequoia **`spctl`** nie pozwala już na modyfikację konfiguracji Gatekeepera.

**`spctl`** jest narzędziem CLI do wypisywania i interakcji z GateKeeper (z demonem `syspolicyd` za pomocą komunikatów XPC). Na przykład można zobaczyć **status** GateKeepera za pomocą:
```bash
# Check the status
spctl --status
```
> [!CAUTION]
> Zwróć uwagę, że kontrole podpisu GateKeeper są wykonywane tylko dla **plików z atrybutem Quarantine**, a nie dla każdego pliku.

GateKeeper sprawdzi, czy zgodnie z **preferencjami & podpisem** plik binarny może zostać uruchomiony:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** jest głównym daemonem odpowiedzialnym za egzekwowanie GateKeepera. Utrzymuje on bazę danych znajdującą się w `/var/db/SystemPolicy` i można znaleźć kod wspierający tę bazę [kod bazy danych tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp) oraz [szablon SQL tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Zwróć uwagę, że baza danych nie jest ograniczona przez SIP i jest zapisywalna przez root, a baza `/var/db/.SystemPolicy-default` jest używana jako oryginalna kopia zapasowa na wypadek, gdyby druga uległa uszkodzeniu.

Dodatkowo bundle **`/var/db/gke.bundle`** i **`/var/db/gkopaque.bundle`** zawierają pliki z regułami, które są wstawiane do bazy danych. Możesz sprawdzić tę bazę jako root za pomocą:
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
**`syspolicyd`** również udostępnia serwer XPC z różnymi operacjami, takimi jak `assess`, `update`, `record` i `cancel`, które są także dostępne przy użyciu **`Security.framework`'s `SecAssessment*`** APIs, a **`spctl`** faktycznie komunikuje się z **`syspolicyd`** przez XPC.

Zauważ, jak pierwsza reguła kończyła się na "**App Store**" i druga na "**Developer ID**" oraz że na poprzednim obrazku było **włączone uruchamianie aplikacji z App Store i od zidentyfikowanych deweloperów**.\
Jeśli **zmodyfikujesz** to ustawienie na App Store, reguły "**Notarized Developer ID**" znikną.

Są też tysiące reguł **typu GKE** :
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

Możesz też wypisać powyższe informacje za pomocą:
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

Można **sprawdzić, czy aplikacja będzie dozwolona przez GateKeeper** za pomocą:
```bash
spctl --assess -v /Applications/App.app
```
Można dodać nowe reguły w GateKeeper, aby zezwolić na uruchamianie niektórych aplikacji za pomocą:
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
Jeśli chodzi o **kernel extensions**, folder `/var/db/SystemPolicyConfiguration` zawiera pliki z listami kextów dozwolonych do załadowania. Ponadto `spctl` ma entitlement `com.apple.private.iokit.nvram-csr`, ponieważ potrafi dodawać nowe wstępnie zatwierdzone kernel extensions, które muszą być również zapisane w NVRAM w kluczu `kext-allowed-teams`.

#### Zarządzanie Gatekeeperem w macOS 15 (Sequoia) i nowszych

- Długotrwałe obejście w Finderze **Ctrl+Open / Right‑click → Open** zostało usunięte; użytkownicy muszą jawnie zezwolić zablokowanej aplikacji w **System Settings → Privacy & Security → Open Anyway** po pierwszym dialogu blokady.
- `spctl --master-disable/--global-disable` nie są już akceptowane; `spctl` jest de facto tylko do odczytu dla oceny i zarządzania etykietami, natomiast egzekwowanie polityki konfigurowane jest przez UI lub MDM.

Począwszy od macOS 15 Sequoia, użytkownicy końcowi nie mogą już przełączać polityki Gatekeepera za pomocą `spctl`. Zarządzanie odbywa się przez System Settings lub poprzez wdrożenie profilu konfiguracyjnego MDM z payloadem `com.apple.systempolicy.control`. Przykładowy fragment profilu pozwalający na App Store i identified developers (ale nie "Anywhere"):

<details>
<summary>Profil MDM pozwalający na App Store i zidentyfikowanych deweloperów</summary>
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

### Pliki w kwarantannie

Po **pobraniu** aplikacji lub pliku, niektóre macOS-owe **aplikacje** takie jak przeglądarki internetowe czy klienci poczty **dołączają rozszerzony atrybut pliku**, powszechnie znany jako **„flaga kwarantanny”**, do pobranego pliku. Ten atrybut działa jako środek bezpieczeństwa, aby **oznaczyć plik** jako pochodzący z nieznanego źródła (Internet) i potencjalnie niosący ryzyko. Jednak nie wszystkie aplikacje dołączają ten atrybut — na przykład popularne oprogramowanie klienckie BitTorrent zwykle omija ten proces.

**Obecność flagi kwarantanny sygnalizuje funkcji bezpieczeństwa Gatekeeper w macOS, gdy użytkownik próbuje wykonać plik.**

W przypadku gdy **flaga kwarantanny nie jest obecna** (jak w przypadku plików pobranych za pomocą niektórych klientów BitTorrent), **sprawdzenia Gatekeepera mogą nie zostać wykonane**. Dlatego użytkownicy powinni zachować ostrożność przy otwieraniu plików pobranych z mniej bezpiecznych lub nieznanych źródeł.

> [!NOTE] > **Sprawdzanie** **ważności** podpisów kodu jest procesem **zasobożernym**, który obejmuje generowanie skrótów kryptograficznych (**hashy**) kodu oraz wszystkich dołączonych zasobów. Ponadto sprawdzenie ważności certyfikatu wymaga wykonania **sprawdzenia online** do serwerów Apple, aby ustalić, czy certyfikat nie został unieważniony po jego wydaniu. Z tych powodów pełna weryfikacja podpisu kodu i notarization jest **niepraktyczna do uruchamiania przy każdym uruchomieniu aplikacji**.
>
> Dlatego te sprawdzenia są **wykonywane tylko podczas uruchamiania aplikacji posiadających atrybut kwarantanny.**

> [!WARNING]
> Ten atrybut musi być **ustawiony przez aplikację tworzącą/pobierającą** plik.
>
> Jednak pliki tworzone przez aplikacje sandboxowane będą miały ten atrybut ustawiony dla każdego tworzonego pliku. Aplikacje niez sandboxowane mogą ustawić go samodzielnie lub określić klucz [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) w **Info.plist**, co spowoduje, że system ustawi rozszerzony atrybut `com.apple.quarantine` na tworzonych plikach,

Co więcej, wszystkie pliki tworzone przez proces wywołujący **`qtn_proc_apply_to_self`** są poddawane kwarantannie. API **`qtn_file_apply_to_path`** dodaje atrybut kwarantanny do określonej ścieżki pliku.

Można **sprawdzić jego stan oraz włączyć/wyłączyć** (wymagane uprawnienia root) za pomocą:
```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```
Możesz też **sprawdzić, czy plik ma rozszerzony atrybut kwarantanny** za pomocą:
```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```
Sprawdź **wartość** **rozszerzonych** **atrybutów** i dowiedz się, która aplikacja zapisała atrybut kwarantanny za pomocą:
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
Właściwie proces "mógłby ustawić flagi kwarantanny dla plików, które tworzy" (Próbowałem już zastosować flagę USER_APPROVED w utworzonym pliku, ale nie zostaje ona zastosowana):

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
I znajdź wszystkie pliki w kwarantannie za pomocą:
```bash
find / -exec ls -ld {} \; 2>/dev/null | grep -E "[x\-]@ " | awk '{printf $9; printf "\n"}' | xargs -I {} xattr -lv {} | grep "com.apple.quarantine"
```
Informacje o kwarantannie są również przechowywane w centralnej bazie danych zarządzanej przez LaunchServices w **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, co pozwala GUI uzyskać dane o pochodzeniu pliku. Ponadto może to zostać nadpisane przez aplikacje, które mogą chcieć ukryć jego pochodzenie. Można to także zrobić z poziomu LaunchServices APIS.

#### **libquarantine.dylib**

Ta biblioteka eksportuje kilka funkcji, które pozwalają manipulować polami rozszerzonych atrybutów.

Interfejsy `qtn_file_*` dotyczą polityk kwarantanny plików, interfejsy `qtn_proc_*` stosowane są do procesów (plików utworzonych przez proces). Niewyeksportowane funkcje `__qtn_syscall_quarantine*` to te, które stosują polityki — wywołują `mac_syscall` z "Quarantine" jako pierwszym argumentem, co wysyła żądania do `Quarantine.kext`.

#### **Quarantine.kext**

Rozszerzenie jądra jest dostępne tylko przez **kernel cache on the system**; jednak możesz pobrać **Kernel Debug Kit z** [**https://developer.apple.com/**](https://developer.apple.com/), który będzie zawierał symbolikowaną wersję rozszerzenia.

Ten Kext hookuje przez MACF kilka wywołań, aby przechwycić wszystkie zdarzenia cyklu życia pliku: tworzenie, otwieranie, zmienianie nazwy, tworzenie twardych łączy... nawet `setxattr`, aby zapobiec ustawieniu rozszerzonego atrybutu `com.apple.quarantine`.

It also uses a couple of MIBs:

- `security.mac.qtn.sandbox_enforce`: Wymuszanie kwarantanny w ramach Sandbox
- `security.mac.qtn.user_approved_exec`: Procesy objęte kwarantanną mogą wykonywać tylko zatwierdzone pliki

#### Provenance xattr (Ventura i nowsze)

macOS 13 Ventura wprowadził osobny mechanizm provenance, który jest wypełniany przy pierwszym uruchomieniu aplikacji objętej kwarantanną. Tworzone są dwa artefakty:

- Atrybut xattr `com.apple.provenance` na katalogu pakietu `.app` (wartość binarna o stałym rozmiarze zawierająca klucz główny i flagi).
- Wiersz w tabeli `provenance_tracking` w bazie ExecPolicy w `/var/db/SystemPolicyConfiguration/ExecPolicy/` przechowujący cdhash aplikacji i metadane.

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

XProtect to wbudowana funkcja **anti-malware** w macOS. XProtect **sprawdza każdą aplikację przy jej pierwszym uruchomieniu lub po modyfikacji względem swojej bazy** znanych malware i niebezpiecznych typów plików. Gdy pobierasz plik za pomocą niektórych aplikacji, takich jak Safari, Mail czy Messages, XProtect automatycznie skanuje plik. Jeśli pasuje do któregoś wpisu znanych malware w bazie, XProtect **zablokuje uruchomienie pliku** i poinformuje Cię o zagrożeniu.

Baza XProtect jest **regularnie aktualizowana** przez Apple o nowe definicje malware, a te aktualizacje są automatycznie pobierane i instalowane na Twoim Macu. Dzięki temu XProtect jest zawsze aktualny względem najnowszych znanych zagrożeń.

Warto jednak zauważyć, że **XProtect nie jest pełnoprawnym rozwiązaniem antywirusowym**. Sprawdza tylko określoną listę znanych zagrożeń i nie wykonuje on-access scanning tak jak większość oprogramowania antywirusowego.

Możesz uzyskać informacje o najnowszej aktualizacji XProtect, uruchamiając:
```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```
XProtect znajduje się w chronionej przez SIP lokalizacji **/Library/Apple/System/Library/CoreServices/XProtect.bundle** i wewnątrz bundle możesz znaleźć informacje, których używa XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Pozwala kodowi o tych cdhashach używać legacy entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista pluginów i rozszerzeń, których ładowanie jest zabronione poprzez BundleID i TeamID lub wskazująca minimalną wersję.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reguły Yara do wykrywania złośliwego oprogramowania.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Baza SQLite3 z hashami zablokowanych aplikacji i TeamID.

Zwróć uwagę, że istnieje inna aplikacja w **`/Library/Apple/System/Library/CoreServices/XProtect.app`** powiązana z XProtect, która nie bierze udziału w procesie Gatekeeper.

> XProtect Remediator: Na nowoczesnym macOS Apple dostarcza skanery na żądanie (XProtect Remediator), które uruchamiają się okresowo przez launchd, aby wykrywać i naprawiać rodziny złośliwego oprogramowania. Możesz obserwować te skany w unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### To nie Gatekeeper

> [!CAUTION]
> Zauważ, że Gatekeeper **nie jest uruchamiany za każdym razem** gdy wykonujesz aplikację; tylko _**AppleMobileFileIntegrity**_ (AMFI) będzie **weryfikować podpisy kodu wykonywalnego** gdy uruchamiasz aplikację, która została już wcześniej uruchomiona i zweryfikowana przez Gatekeeper.

W przeszłości było więc możliwe uruchomić aplikację, aby została zbuforowana przez Gatekeeper, a następnie **modyfikować nie-wykonywalne pliki aplikacji** (np. Electron asar lub pliki NIB) i jeśli nie było innych zabezpieczeń, aplikacja została by **uruchomiona** z **złośliwymi** dodatkami.

Jednak teraz nie jest to możliwe, ponieważ macOS **uniemożliwia modyfikowanie plików** wewnątrz bundle aplikacji. Zatem, jeśli spróbujesz ataku [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), stwierdzisz, że nie da się go już nadużyć, ponieważ po uruchomieniu aplikacji w celu zbuforowania przez Gatekeeper, nie będziesz w stanie zmodyfikować bundle. A jeśli zmienisz np. nazwę katalogu Contents na NotCon (jak wskazano w exploicie), a następnie uruchomisz główny binarny plik aplikacji, aby zbuforować ją w Gatekeeperze, to wywoła błąd i nie uruchomi się.

## Omijanie Gatekeepera

Każdy sposób na ominięcie Gatekeepera (sprawienie, by użytkownik pobrał coś i uruchomił to, gdy Gatekeeper powinien tego zabronić) jest traktowany jako luka w macOS. Oto kilka CVE przypisanych technikom, które w przeszłości pozwalały ominąć Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Zaobserwowano, że jeśli do rozpakowania używany jest **Archive Utility**, pliki z **ścieżkami przekraczającymi 886 znaków** nie otrzymują rozszerzonego atrybutu com.apple.quarantine. Ta sytuacja przypadkowo pozwala tym plikom **ominąć kontrole bezpieczeństwa Gatekeepera**.

Check the [**original report**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810) for more information.

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Gdy aplikacja jest tworzona za pomocą **Automator**, informacje o tym, co jest potrzebne do jej wykonania, znajdują się w `application.app/Contents/document.wflow`, a nie w wykonywalnym pliku. Wykonywalny plik to tylko ogólny binarny plik Automatora zwany **Automator Application Stub**.

W związku z tym można było sprawić, aby `application.app/Contents/MacOS/Automator\ Application\ Stub` **wskazywał symbolicznym linkiem na inny Automator Application Stub w systemie**, i wtedy wykonałoby to, co jest w `document.wflow` (twój skrypt) **bez wywołania Gatekeepera**, ponieważ rzeczywisty wykonywalny plik nie miał quarantine xattr.

Przykłowa oczekiwana lokalizacja: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Check the [**original report**](https://ronmasas.com/posts/bypass-macos-gatekeeper) for more information.

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

W tym obejściu utworzono plik zip z aplikacją, zaczynając kompresję od `application.app/Contents` zamiast od `application.app`. W rezultacie **atrybut quarantine** został zastosowany do wszystkich **plików z `application.app/Contents`**, ale **nie do `application.app`**, którego sprawdzał Gatekeeper, więc Gatekeeper został ominięty, ponieważ gdy `application.app` był uruchamiany, **nie miał atrybutu quarantine.**
```bash
zip -r test.app/Contents test.zip
```
Sprawdź [**original report**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/) aby uzyskać więcej informacji.

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Nawet jeśli komponenty są inne, eksploatacja tej podatności jest bardzo podobna do poprzedniej. W tym przypadku wygenerujemy Apple Archive z **`application.app/Contents`**, dzięki czemu **`application.app` won't get the quarantine attr** kiedy zostanie zdekompresowany przez **Archive Utility**.
```bash
aa archive -d test.app/Contents -o test.app.aar
```
Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/) aby uzyskać więcej informacji.

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** może zostać użyte do uniemożliwienia komukolwiek zapisania atrybutu w pliku:
```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```
Co więcej, format plików **AppleDouble** kopiuje plik wraz z jego ACEs.

W [**source code**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana w xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w rozpakowanym pliku. Więc jeśli skompresowałeś aplikację do pliku zip w formacie **AppleDouble** z ACL, które uniemożliwiają zapis innych xattr do niej... quarantine xattr nie został ustawiony w aplikacji:
```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```
Zapoznaj się z [**oryginalnym raportem**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/) aby uzyskać więcej informacji.

Należy zauważyć, że można to również wykorzystać za pomocą AppleArchives:
```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```
### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Odkryto, że **Google Chrome wasn't setting the quarantine attribute** dla pobranych plików z powodu pewnych wewnętrznych problemów macOS.

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

Formaty plików AppleDouble przechowują atrybuty pliku w oddzielnym pliku zaczynającym się od `._`, co ułatwia kopiowanie atrybutów plików **pomiędzy komputerami macOS**. Jednak zauważono, że po rozpakowaniu pliku AppleDouble plik zaczynający się od `._` **wasn't given the quarantine attribute**.
```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you downloaded the resulting test.aar and decompress it, the file test/._a won't have a quarantitne attribute
```
Możliwość utworzenia pliku, który nie miałby ustawionego atrybutu kwarantanny, sprawiała, że było **możliwe bypass Gatekeeper.** Trik polegał na **utworzeniu aplikacji w pliku DMG** przy użyciu konwencji nazewnictwa AppleDouble (rozpocząć ją od `._`) i utworzeniu **widocznego pliku jako sym link do tego ukrytego** pliku bez atrybutu kwarantanny.\
Gdy **dmg file is executed**, ponieważ nie ma atrybutu kwarantanny, to **bypass Gatekeeper**.
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

Omijanie Gatekeepera naprawione w macOS Sonoma 14.0 pozwalało spreparowanym aplikacjom uruchamiać się bez wyświetlania monitu. Szczegóły zostały publicznie ujawnione po wydaniu poprawki, a luka była aktywnie wykorzystywana w środowisku przed naprawą. Upewnij się, że zainstalowany jest Sonoma 14.0 lub nowszy.

### [CVE-2024-27853]

Omijanie Gatekeepera w macOS 14.4 (wydanym w marcu 2024) wynikające z obsługi przez `libarchive` złośliwych ZIP-ów pozwalało aplikacjom uniknąć oceny. Zaktualizuj do 14.4 lub nowszego, gdzie Apple zaadresowało problem.

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

An **Automator Quick Action workflow** osadzony w pobranej aplikacji mógł zostać uruchomiony bez oceny przez Gatekeeper, ponieważ workflowy były traktowane jako dane i wykonywane przez pomocnika Automator poza normalną ścieżką monitu o notarization. Spreparowane `.app` zawierające Quick Action uruchamiający skrypt powłoki (np. wewnątrz `Contents/PlugIns/*.workflow/Contents/document.wflow`) mogły zatem wykonać się natychmiast przy uruchomieniu. Apple dodało dodatkowy dialog zgody i naprawiło ścieżkę oceny w Ventura **13.7**, Sonoma **14.7**, i Sequoia **15**.

### Third‑party unarchivers mis‑propagating quarantine (2023–2024)

Kilka podatności w popularnych narzędziach do rozpakowywania (np. The Unarchiver) powodowało, że pliki wyodrębnione z archiwów traciły xattr `com.apple.quarantine`, co umożliwiało obejście Gatekeepera. Zawsze polegaj na macOS Archive Utility lub załatanych narzędziach podczas testów i weryfikuj xattry po rozpakowaniu.

### uchg (from this [talk](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Utwórz katalog zawierający aplikację.
- Dodaj uchg do aplikacji.
- Skompresuj aplikację do pliku tar.gz.
- Wyślij plik tar.gz do ofiary.
- Ofiara otwiera plik tar.gz i uruchamia aplikację.
- Gatekeeper nie sprawdza aplikacji.

### Prevent Quarantine xattr

W bundlu ".app", jeśli atrybut quarantine (xattr) nie zostanie do niego dodany, przy uruchomieniu **Gatekeeper nie zostanie wywołany**.


## References

- Apple Platform Security: About the security content of macOS Sonoma 14.4 (includes CVE-2024-27853) – [https://support.apple.com/en-us/HT214084](https://support.apple.com/en-us/HT214084)
- Eclectic Light: How macOS now tracks the provenance of apps – [https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- Apple: About the security content of macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128) – [https://support.apple.com/en-us/121234](https://support.apple.com/en-us/121234)
- MacRumors: macOS 15 Sequoia removes the Control‑click “Open” Gatekeeper bypass – [https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/](https://www.macrumors.com/2024/06/11/macos-sequoia-removes-open-anyway/)

{{#include ../../../banners/hacktricks-training.md}}

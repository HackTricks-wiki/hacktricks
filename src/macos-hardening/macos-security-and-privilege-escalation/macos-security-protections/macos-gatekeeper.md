# macOS Gatekeeper / Quarantine / XProtect

{{#include ../../../banners/hacktricks-training.md}}


## Gatekeeper

**Gatekeeper** to funkcja bezpieczeństwa opracowana dla systemów operacyjnych Mac, której celem jest zapewnienie, że użytkownicy **uruchamiają w swoich systemach wyłącznie zaufane oprogramowanie**. Działa poprzez **weryfikowanie oprogramowania**, które użytkownik pobiera i próbuje otworzyć ze **źródeł spoza App Store**, takiego jak aplikacja, wtyczka lub pakiet instalacyjny.

Kluczowym mechanizmem Gatekeepera jest proces **weryfikacji**. Sprawdza on, czy pobrane oprogramowanie jest **podpisane przez uznanego dewelopera**, co potwierdza jego autentyczność. Ponadto ustala, czy oprogramowanie zostało **notaryzowane przez Apple**, potwierdzając, że nie zawiera znanych szkodliwych treści i nie zostało zmodyfikowane po notaryzacji.

Dodatkowo Gatekeeper wzmacnia kontrolę użytkownika i bezpieczeństwo, **wyświetlając prośbę o zgodę na pierwsze otwarcie** pobranego oprogramowania. To zabezpieczenie pomaga zapobiegać przypadkowemu uruchomieniu przez użytkowników potencjalnie szkodliwego kodu wykonywalnego, który mogli pomylić z nieszkodliwym plikiem danych.

### Podpisy aplikacji

Podpisy aplikacji, znane również jako podpisy kodu, są kluczowym elementem infrastruktury bezpieczeństwa Apple. Służą do **weryfikowania tożsamości autora oprogramowania** (dewelopera) oraz do zapewnienia, że kod nie został zmodyfikowany od czasu jego ostatniego podpisania.

Oto jak to działa:

1. **Podpisywanie aplikacji:** Gdy deweloper jest gotowy do dystrybucji aplikacji, **podpisuje ją przy użyciu klucza prywatnego**. Ten klucz prywatny jest powiązany z **certyfikatem wydawanym deweloperowi przez Apple** po zapisaniu się do Apple Developer Program. Proces podpisywania polega na utworzeniu kryptograficznego skrótu wszystkich części aplikacji i zaszyfrowaniu go kluczem prywatnym dewelopera.
2. **Dystrybucja aplikacji:** Podpisana aplikacja jest następnie dystrybuowana użytkownikom wraz z certyfikatem dewelopera, który zawiera odpowiadający mu klucz publiczny.
3. **Weryfikacja aplikacji:** Gdy użytkownik pobiera aplikację i próbuje ją uruchomić, system operacyjny Mac używa klucza publicznego z certyfikatu dewelopera do odszyfrowania skrótu. Następnie ponownie oblicza skrót na podstawie aktualnego stanu aplikacji i porównuje go z odszyfrowanym skrótem. Jeśli są zgodne, oznacza to, że **aplikacja nie została zmodyfikowana** od czasu jej podpisania przez dewelopera, a system zezwala na jej uruchomienie.

Podpisy aplikacji są niezbędnym elementem technologii Gatekeeper firmy Apple. Gdy użytkownik próbuje **otworzyć aplikację pobraną z internetu**, Gatekeeper weryfikuje jej podpis. Jeśli aplikacja jest podpisana certyfikatem wydanym przez Apple znanemu deweloperowi, a kod nie został zmodyfikowany, Gatekeeper zezwala na jej uruchomienie. W przeciwnym razie blokuje aplikację i ostrzega użytkownika.

Od macOS Catalina **Gatekeeper sprawdza również, czy aplikacja została notaryzowana** przez Apple, dodając kolejną warstwę bezpieczeństwa. Proces notaryzacji sprawdza aplikację pod kątem znanych problemów z bezpieczeństwem i złośliwego kodu. Jeśli kontrole zakończą się pomyślnie, Apple dodaje do aplikacji bilet, który Gatekeeper może zweryfikować.

#### Sprawdzanie podpisów

Podczas analizy próbki **malware** należy zawsze **sprawdzić podpis** pliku binarnego, ponieważ **deweloper**, który go podpisał, może być już **powiązany** z **malware**.

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

Proces notaryzacji Apple stanowi dodatkowe zabezpieczenie chroniące użytkowników przed potencjalnie szkodliwym oprogramowaniem. Polega na **przesłaniu przez dewelopera aplikacji do sprawdzenia** przez **Apple's Notary Service**. Nie należy mylić tej usługi z App Review. Jest to **zautomatyzowany system**, który analizuje przesłane oprogramowanie pod kątem **złośliwej zawartości** i potencjalnych problemów z podpisywaniem kodu.

Jeśli oprogramowanie **przejdzie** tę kontrolę bez zastrzeżeń, Notary Service generuje bilet notaryzacyjny. Deweloper musi następnie **dołączyć ten bilet do oprogramowania** — proces ten nazywa się „stapling”. Bilet notaryzacyjny jest także publikowany online, skąd Gatekeeper, technologia bezpieczeństwa Apple, może go pobrać.

Podczas pierwszej instalacji lub uruchomienia oprogramowania przez użytkownika obecność biletu notaryzacyjnego — dołączonego do pliku wykonywalnego lub dostępnego online — **informuje Gatekeepera, że oprogramowanie zostało poddane notaryzacji przez Apple**. W rezultacie Gatekeeper wyświetla w początkowym oknie dialogowym opisową wiadomość informującą, że Apple sprawdziło oprogramowanie pod kątem złośliwej zawartości. Proces ten zwiększa zaufanie użytkowników do bezpieczeństwa oprogramowania instalowanego lub uruchamianego w ich systemach.

### spctl & syspolicyd

> [!CAUTION]
> Należy pamiętać, że od wersji Sequoia **`spctl`** nie pozwala już modyfikować konfiguracji Gatekeepera.

**`spctl`** to narzędzie CLI służące do wyliczania i obsługi Gatekeepera (za pomocą demona `syspolicyd` poprzez komunikaty XPC). Można na przykład sprawdzić **stan** GateKeepera za pomocą:

```bash
# Check the status
spctl --status
```

> [!CAUTION]
> Pamiętaj, że GateKeeper sprawdza podpisy tylko **plików z atrybutem Quarantine**, a nie wszystkich plików.

GateKeeper sprawdzi, czy zgodnie z **preferencjami i podpisem** można uruchomić plik binarny:

<figure><img src="../../../images/image (1150).png" alt=""><figcaption></figcaption></figure>

**`syspolicyd`** to główny daemon odpowiedzialny za egzekwowanie zasad Gatekeeper. Utrzymuje bazę danych w lokalizacji `/var/db/SystemPolicy`. Kod obsługujący tę [bazę danych znajdziesz tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/policydb.cpp), a [szablon SQL tutaj](https://opensource.apple.com/source/Security/Security-58286.240.4/OSX/libsecurity_codesigning/lib/syspolicy.sql). Pamiętaj, że baza danych nie jest objęta ochroną SIP i może być zapisywana przez root. Baza danych `/var/db/.SystemPolicy-default` służy jako kopia zapasowa na wypadek uszkodzenia właściwej bazy.

Ponadto pakiety **`/var/db/gke.bundle`** i **`/var/db/gkopaque.bundle`** zawierają pliki z regułami, które są dodawane do bazy danych. Możesz sprawdzić tę bazę danych jako root za pomocą:

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

**`syspolicyd`** udostępnia również serwer XPC z różnymi operacjami, takimi jak `assess`, `update`, `record` i `cancel`, do których można uzyskać dostęp także za pomocą API **`SecAssessment*` z `Security.framework`**. **`spctl`** komunikuje się z **`syspolicyd`** przez XPC.

Zwróć uwagę, że pierwsza reguła kończyła się na „**App Store**”, a druga na „**Developer ID**”. Na poprzednim obrazie było widać, że **włączono możliwość uruchamiania aplikacji z App Store oraz od zidentyfikowanych deweloperów**.\
Jeśli **zmienisz** to ustawienie na App Store, reguły „**Notarized Developer ID**” znikną.

Istnieją również tysiące reguł **typu GKE**:

```bash
SELECT requirement,allow,disabled,label from authority where label = 'GKE' limit 5;
cdhash H"b40281d347dc574ae0850682f0fd1173aa2d0a39"|1|0|GKE
cdhash H"5fd63f5342ac0c7c0774ebcbecaf8787367c480f"|1|0|GKE
cdhash H"4317047eefac8125ce4d44cab0eb7b1dff29d19a"|1|0|GKE
cdhash H"0a71962e7a32f0c2b41ddb1fb8403f3420e1d861"|1|0|GKE
cdhash H"8d0d90ff23c3071211646c4c9c607cdb601cb18f"|1|0|GKE
```

To hashe pochodzące z:

- `/var/db/SystemPolicyConfiguration/gke.bundle/Contents/Resources/gke.auth`
- `/var/db/gke.bundle/Contents/Resources/gk.db`
- `/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db`

Możesz też wyświetlić powyższe informacje za pomocą:

```bash
sudo spctl --list
```

Opcje **`--master-disable`** i **`--global-disable`** programu **`spctl`** całkowicie **wyłączają** te kontrole podpisów:

```bash
# Disable GateKeeper
spctl --global-disable
spctl --master-disable

# Enable it
spctl --global-enable
spctl --master-enable
```

Po pełnym włączeniu pojawi się nowa opcja:

<figure><img src="../../../images/image (1151).png" alt=""><figcaption></figcaption></figure>

Można **sprawdzić, czy GateKeeper zezwoli na uruchomienie aplikacji**, używając:

```bash
spctl --assess -v /Applications/App.app
```

W systemie macOS 14 i nowszych **`syspolicy_check`** to przydatne narzędzie do przeprowadzania bardziej zaawansowanej kontroli pakietu aplikacji przed jego dystrybucją. Dostarcza bardziej praktycznych informacji diagnostycznych dotyczących zaufanego wykonywania niż sam wynik `spctl`, choć Apple nadal zaleca testowanie rzeczywistej ścieżki pobierania, rozpakowywania i pierwszego uruchomienia, ponieważ obejmuje ona również propagację kwarantanny.<sup>[[14]](#references)</sup>

```bash
# Check the complete app bundle before distribution
syspolicy_check distribution /path/to/App.app

# Keep the lower-level assessment when comparing policy outcomes
spctl --assess --type execute -vv /path/to/App.app
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

Regarding **rozszerzeń jądra**, folder `/var/db/SystemPolicyConfiguration` zawiera pliki z listami kextów, których ładowanie jest dozwolone. Ponadto `spctl` ma entitlement `com.apple.private.iokit.nvram-csr`, ponieważ może dodawać nowe, wstępnie zatwierdzone rozszerzenia jądra. Muszą być one również zapisane w NVRAM pod kluczem `kext-allowed-teams`.

#### Zarządzanie Gatekeeperem w macOS 15 (Sequoia) i nowszych wersjach

- Od dawna dostępny sposób obejścia zabezpieczeń w Finderze **Ctrl+Otwórz / kliknięcie prawym przyciskiem myszy → Otwórz** został usunięty. Po pierwszym komunikacie o zablokowaniu aplikacji użytkownicy muszą jawnie zezwolić na jej uruchomienie, wybierając **Ustawienia systemowe → Prywatność i ochrona → Otwórz mimo to**.<sup>[[4]](#references)</sup>
- `spctl --master-disable/--global-disable` nie są już akceptowane jako niezależne od użytkownika zmiany zasad. Operacje modyfikujące bazę reguł lub globalny stan oceny są przestarzałe, dlatego używaj `spctl` do oceny, a wymuszanie zasad konfiguruj przez interfejs lub MDM.

Od macOS 15 Sequoia użytkownicy końcowi nie mogą już przełączać zasad Gatekeepera za pomocą `spctl`. Zarządzanie odbywa się w Ustawieniach systemowych lub przez wdrożenie profilu konfiguracyjnego MDM z payloadem `com.apple.systempolicy.control`. Przykładowy fragment profilu zezwalający na aplikacje z App Store i od zidentyfikowanych deweloperów (ale nie z „Dowolnego miejsca”):

<details>
<summary>Profil MDM zezwalający na aplikacje z App Store i od zidentyfikowanych deweloperów</summary>

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

Podczas **pobierania** aplikacji lub pliku niektóre **aplikacje** macOS, takie jak przeglądarki internetowe czy klienty poczty e-mail, **dołączają atrybut rozszerzony pliku**, powszechnie znany jako „**flaga kwarantanny**”, do pobranego pliku. Ten atrybut pełni funkcję zabezpieczenia — **oznacza plik** jako pochodzący z niezaufanego źródła (internetu) i potencjalnie niebezpieczny. Nie wszystkie aplikacje dołączają ten atrybut; na przykład popularne klienty BitTorrent zwykle pomijają ten proces.

**Obecność flagi kwarantanny informuje funkcję bezpieczeństwa Gatekeeper w macOS, gdy użytkownik próbuje uruchomić plik**.

Jeśli **flaga kwarantanny nie jest obecna** (jak w przypadku plików pobranych za pomocą niektórych klientów BitTorrent), **sprawdzenie przez Gatekeeper może nie zostać wykonane**. Dlatego użytkownicy powinni zachować ostrożność podczas otwierania plików pobranych z mniej bezpiecznych lub nieznanych źródeł.

> [!NOTE] > **Sprawdzanie** **ważności** podpisów kodu jest procesem **wymagającym dużych zasobów**; obejmuje generowanie kryptograficznych **hashes** kodu i wszystkich dołączonych do niego zasobów. Ponadto sprawdzanie ważności certyfikatu wymaga wykonania **sprawdzenia online** na serwerach Apple, aby ustalić, czy certyfikat został unieważniony po wydaniu. Z tych powodów pełne sprawdzenie podpisu kodu i notaryzacji jest **niepraktyczne przy każdym uruchomieniu aplikacji**.
>
> Dlatego te kontrole są **wykonywane tylko podczas uruchamiania aplikacji z atrybutem kwarantanny**.

> [!WARNING]
> Ten atrybut musi zostać **ustawiony przez aplikację tworzącą/pobierającą** plik.
>
> Jednak pliki tworzone w sandboxie będą miały ustawiony ten atrybut. Aplikacje spoza sandboxa mogą ustawić go samodzielnie lub określić klucz [**LSFileQuarantineEnabled**](https://developer.apple.com/documentation/bundleresources/information_property_list/lsfilequarantineenabled?language=objc) w **Info.plist**, co spowoduje, że system ustawi rozszerzony atrybut `com.apple.quarantine` dla tworzonych plików.

Ponadto wszystkie pliki utworzone przez proces wywołujący **`qtn_proc_apply_to_self`** są obejmowane kwarantanną. Alternatywnie API **`qtn_file_apply_to_path`** dodaje atrybut kwarantanny do wskazanej ścieżki pliku.

Można **sprawdzić stan i włączyć/wyłączyć** tę funkcję (wymagane uprawnienia root) za pomocą:

```bash
spctl --status
assessments enabled

spctl --enable
spctl --disable
#You can also allow nee identifies to execute code using the binary "spctl"
```

Możesz także **sprawdzić, czy plik ma rozszerzony atrybut kwarantanny** za pomocą:

```bash
xattr file.png
com.apple.macl
com.apple.quarantine
```

Sprawdź **wartość** **rozszerzonych** **atrybutów** i ustal, która aplikacja zapisała atrybut kwarantanny, używając:

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

W rzeczywistości proces „może ustawiać flagi kwarantanny plików, które tworzy” (próbowałem już ustawić flagę USER_APPROVED w utworzonym pliku, ale nie da się jej ustawić):

<details>

<summary>Kod źródłowy ustawiający flagi kwarantanny</summary>

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

Informacje o kwarantannie są również przechowywane w centralnej bazie danych zarządzanej przez LaunchServices w **`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`**, która pozwala interfejsowi GUI uzyskać dane o pochodzeniu pliku. Ponadto aplikacje zainteresowane ukryciem pochodzenia plików mogą nadpisywać te informacje. Można to również zrobić za pomocą API LaunchServices.

#### **libquarantine.dylib**

Ta biblioteka eksportuje kilka funkcji umożliwiających modyfikowanie pól atrybutów rozszerzonych.

API `qtn_file_*` obsługują zasady kwarantanny plików, a API `qtn_proc_*` są stosowane do procesów (plików utworzonych przez dany proces). Nieeksportowane funkcje `__qtn_syscall_quarantine*` stosują zasady, wywołując `mac_syscall` z argumentem `"Quarantine"` jako pierwszym, co przesyła żądania do `Quarantine.kext`.

#### **Quarantine.kext**

To rozszerzenie jądra jest dostępne tylko w **kernel cache w systemie**; można jednak pobrać **Kernel Debug Kit ze strony** [**https://developer.apple.com/**](https://developer.apple.com/), który zawiera wersję rozszerzenia z symbolami.

Ten Kext używa MACF do przechwytywania kilku wywołań, aby rejestrować wszystkie zdarzenia cyklu życia plików: tworzenie, otwieranie, zmianę nazwy, tworzenie hard linków... a nawet `setxattr`, aby uniemożliwić ustawienie atrybutu rozszerzonego `com.apple.quarantine`.

Używa również kilku MIB-ów:

- `security.mac.qtn.sandbox_enforce`: Wymusza kwarantannę wraz z Sandbox
- `security.mac.qtn.user_approved_exec`: Procesy objęte kwarantanną mogą uruchamiać tylko zatwierdzone pliki

#### Atrybut rozszerzony Provenance (Ventura i nowsze)

macOS 13 Ventura wprowadził osobny mechanizm provenance, który jest inicjowany przy pierwszym zezwoleniu na uruchomienie aplikacji objętej kwarantanną.<sup>[[2]](#references)</sup> Tworzone są dwa artefakty:

- Atrybut rozszerzony `com.apple.provenance` w katalogu pakietu `.app` (wartość binarna o stałym rozmiarze, zawierająca klucz główny i flagi).
- Wiersz w tabeli `provenance_tracking` w bazie danych ExecPolicy w `/var/db/SystemPolicyConfiguration/ExecPolicy/`, przechowujący cdhash aplikacji i metadane.

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

XProtect to wbudowana w macOS funkcja **ochrony przed malware**. XProtect **sprawdza każdą aplikację przy jej pierwszym uruchomieniu lub modyfikacji, porównując ją z bazą danych** znanego malware i niebezpiecznych typów plików. Gdy pobierzesz plik za pomocą niektórych aplikacji, takich jak Safari, Mail lub Messages, XProtect automatycznie go skanuje. Jeśli plik pasuje do znanego malware znajdującego się w bazie danych, XProtect **uniemożliwi jego uruchomienie** i powiadomi Cię o zagrożeniu.

Apple **regularnie aktualizuje** bazę danych XProtect, dodając nowe sygnatury malware. Aktualizacje te są automatycznie pobierane i instalowane na Macu. Dzięki temu XProtect jest zawsze aktualny i rozpoznaje najnowsze znane zagrożenia.

Warto jednak pamiętać, że **XProtect nie jest w pełni funkcjonalnym rozwiązaniem antywirusowym**. Sprawdza tylko określoną listę znanych zagrożeń i nie skanuje plików przy dostępie do nich, jak większość programów antywirusowych.

Informacje o najnowszej aktualizacji XProtect możesz uzyskać, uruchamiając:

```bash
system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A 4 "XProtectPlistConfigData" | tail -n 5
```

XProtect znajduje się w chronionej przez SIP lokalizacji **/Library/Apple/System/Library/CoreServices/XProtect.bundle**, a wewnątrz pakietu można znaleźć informacje używane przez XProtect:

- **`XProtect.bundle/Contents/Resources/LegacyEntitlementAllowlist.plist`**: Umożliwia kodowi z tymi cdhashami korzystanie ze starszych entitlements.
- **`XProtect.bundle/Contents/Resources/XProtect.meta.plist`**: Lista pluginów i rozszerzeń, których ładowanie jest zabronione na podstawie BundleID i TeamID, lub wskazanie minimalnej wersji.
- **`XProtect.bundle/Contents/Resources/XProtect.yara`**: Reguły Yara do wykrywania malware.
- **`XProtect.bundle/Contents/Resources/gk.db`**: Baza danych SQLite3 zawierająca hashe zablokowanych aplikacji i TeamID.

Zwróć uwagę, że istnieje też inna aplikacja w **`/Library/Apple/System/Library/CoreServices/XProtect.app`** powiązana z XProtect, która nie bierze udziału w procesie Gatekeeper.

> XProtect Remediator: We współczesnym macOS Apple udostępnia skanery uruchamiane na żądanie (XProtect Remediator), które okresowo uruchamiają się za pośrednictwem launchd, aby wykrywać i usuwać rodziny malware. Możesz obserwować te skanowania w unified logs:
>
> ```bash
> log show --last 2h --predicate 'subsystem == "com.apple.XProtectFramework" || category CONTAINS "XProtect"' --style syslog
> ```

### Nie Gatekeeper

> [!CAUTION]
> Pamiętaj, że Gatekeeper **nie jest uruchamiany za każdym razem**, gdy uruchamiasz aplikację. Tylko _**AppleMobileFileIntegrity**_ (AMFI) **weryfikuje podpisy kodu wykonywalnego**, gdy uruchamiasz aplikację, która została już wcześniej uruchomiona i zweryfikowana przez Gatekeeper.

Dlatego wcześniej można było uruchomić aplikację, aby Gatekeeper zapisał ją w pamięci podręcznej, a następnie **zmodyfikować pliki aplikacji, które nie są plikami wykonywalnymi** (np. pliki Electron asar lub NIB). Jeśli nie zastosowano innych zabezpieczeń, aplikacja była **uruchamiana** z **dodatkami** zawierającymi złośliwy kod.

Teraz nie jest to jednak możliwe, ponieważ macOS **uniemożliwia modyfikowanie plików** wewnątrz pakietów aplikacji. Jeśli więc spróbujesz przeprowadzić atak [Dirty NIB](../macos-proces-abuse/macos-dirty-nib.md), przekonasz się, że nie można go już wykorzystać: po uruchomieniu aplikacji, aby Gatekeeper zapisał ją w pamięci podręcznej, nie będziesz w stanie zmodyfikować pakietu. Jeśli na przykład zmienisz nazwę katalogu Contents na NotCon (jak opisano w exploitcie), a następnie uruchomisz główny plik binarny aplikacji, aby Gatekeeper zapisał ją w pamięci podręcznej, wystąpi błąd i aplikacja nie zostanie uruchomiona.

## Gatekeeper Bypasses

Każda metoda obejścia Gatekeeper (umożliwiająca nakłonienie użytkownika do pobrania czegoś i uruchomienia tego, mimo że Gatekeeper powinien na to nie zezwolić) jest uznawana za lukę w macOS. Oto CVE przypisane do technik, które w przeszłości pozwalały obejść Gatekeeper:

### [CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)

Zaobserwowano, że podczas rozpakowywania plików za pomocą **Archive Utility** pliki o **ścieżkach dłuższych niż 886 znaków** nie otrzymują atrybutu rozszerzonego com.apple.quarantine. W rezultacie pliki te mogą nieumyślnie **ominąć** kontrole bezpieczeństwa Gatekeeper.<sup>[[5]](#references)</sup>

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810).<sup>[[5]](#references)</sup>

### [CVE-2021-30990](https://ronmasas.com/posts/bypass-macos-gatekeeper)

Gdy aplikacja jest tworzona za pomocą **Automator**, informacje o tym, co ma zostać uruchomione, znajdują się w `application.app/Contents/document.wflow`, a nie w pliku wykonywalnym. Plik wykonywalny to jedynie ogólny plik binarny Automator o nazwie **Automator Application Stub**.

Dlatego można było ustawić `application.app/Contents/MacOS/Automator\ Application\ Stub` jako **dowiązanie symboliczne do innego Automator Application Stub znajdującego się w systemie**. Spowodowałoby to wykonanie zawartości `document.wflow` (skryptu) **bez uruchamiania Gatekeeper**, ponieważ właściwy plik wykonywalny nie ma atrybutu rozszerzonego quarantine.<sup>[[6]](#references)</sup>

Przykładowa oczekiwana lokalizacja: `/System/Library/CoreServices/Automator\ Application\ Stub.app/Contents/MacOS/Automator\ Application\ Stub`

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://ronmasas.com/posts/bypass-macos-gatekeeper).<sup>[[6]](#references)</sup>

### [CVE-2022-22616](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)

W tym obejściu utworzono plik zip z aplikacją, rozpoczynając kompresowanie od `application.app/Contents` zamiast od `application.app`. W rezultacie atrybut **quarantine** został zastosowany do wszystkich **plików z `application.app/Contents`**, ale **nie do `application.app`**, który sprawdzał Gatekeeper. Dzięki temu udało się obejść Gatekeeper, ponieważ po uruchomieniu `application.app` **nie miał on atrybutu quarantine.**<sup>[[7]](#references)</sup>

```bash
zip -r test.app/Contents test.zip
```

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/).<sup>[[7]](#references)</sup>

### [CVE-2022-32910](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-32910)

Mimo że komponenty są różne, wykorzystanie tej luki jest bardzo podobne do poprzedniego. W tym przypadku wygenerujemy archiwum Apple Archive z **`application.app/Contents`**, dzięki czemu **`application.app` nie otrzyma atrybutu kwarantanny** po rozpakowaniu przez **Archive Utility**.<sup>[[8]](#references)</sup>

```bash
aa archive -d test.app/Contents -o test.app.aar
```

Sprawdź [**oryginalny raport**](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/), aby uzyskać więcej informacji.<sup>[[8]](#references)</sup>

### [CVE-2022-42821](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)

ACL **`writeextattr`** można użyć, aby uniemożliwić komukolwiek zapisanie atrybutu w pliku:

```bash
touch /tmp/no-attr
chmod +a "everyone deny writeextattr" /tmp/no-attr
xattr -w attrname vale /tmp/no-attr
xattr: [Errno 13] Permission denied: '/tmp/no-attr'
```

Ponadto format plików **AppleDouble** kopiuje plik wraz z jego ACE.<sup>[[9]](#references)</sup>

W [**kodzie źródłowym**](https://opensource.apple.com/source/Libc/Libc-391/darwin/copyfile.c.auto.html) można zobaczyć, że tekstowa reprezentacja ACL przechowywana w xattr o nazwie **`com.apple.acl.text`** zostanie ustawiona jako ACL w zdekompresowanym pliku. Jeśli więc skompresujesz aplikację do pliku zip w formacie **AppleDouble** z ACL, który uniemożliwia zapisanie w niej innych xattr... xattr kwarantanny nie zostanie ustawiony dla aplikacji:

```bash
chmod +a "everyone deny write,writeattr,writeextattr" /tmp/test
ditto -c -k test test.zip
python3 -m http.server
# Download the zip from the browser and decompress it, the file should be without a quarantine xattr
```

Więcej informacji znajdziesz w [**oryginalnym raporcie**](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/).<sup>[[9]](#references)</sup> Zobacz [odtworzenie AppleDouble/ACL](macos-fs-tricks/macos-xattr-acls-extra-stuff.md), aby poznać kroki tworzenia i walidacji pliku sidecar.

Należy pamiętać, że tę podatność można było również wykorzystać za pomocą AppleArchives:

```bash
mkdir app
touch app/test
chmod +a "everyone deny write,writeattr,writeextattr" app/test
aa archive -d app -o test.aar
```

### [CVE-2023-27943](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)

Odkryto, że **Google Chrome nie ustawiał atrybutu kwarantanny** pobieranym plikom z powodu pewnych wewnętrznych problemów z macOS.<sup>[[10]](#references)</sup>

### [CVE-2023-27951](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)

AppleDouble przechowuje atrybuty pliku w osobnym pliku, którego nazwa zaczyna się od `._`; ułatwia to kopiowanie atrybutów **między komputerami z macOS**. Jednak po rozpakowaniu pliku AppleDouble plik zaczynający się od `._` **nie otrzymywał atrybutu kwarantanny**.<sup>[[11]](#references)</sup>

```bash
mkdir test
echo a > test/a
echo b > test/b
echo ._a > test/._a
aa archive -d test/ -o test.aar

# If you download and decompress the resulting test.aar, test/._a won't have a quarantine attribute
```

Mając możliwość utworzenia pliku bez atrybutu kwarantanny, **można było ominąć Gatekeepera.** Sztuczka polegała na utworzeniu **aplikacji w pliku DMG** z użyciem konwencji nazw AppleDouble (nazwa zaczyna się od `._`) oraz utworzeniu **widocznego pliku będącego dowiązaniem symbolicznym do tego ukrytego** pliku bez atrybutu kwarantanny.\
Gdy **plik DMG zostanie uruchomiony**, ponieważ nie ma atrybutu kwarantanny, **ominie Gatekeepera**.

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

Apple naprawiło błąd logiczny w LaunchServices w macOS Sonoma 14.0, wprowadzając dokładniejsze kontrole. Publiczny komunikat informuje jedynie, że aplikacja mogła ominąć Gatekeeper, więc na podstawie samego wpisu CVE nie należy wnioskować o konkretnym formacie nośnika ani łańcuchu wykorzystania podatności.<sup>[[13]](#references)</sup>

### [CVE-2024-27853]

Błąd w Gatekeeper w macOS 14.4 (wydanym w marcu 2024 r.), wynikający ze sposobu, w jaki `libarchive` obsługiwał złośliwe archiwa ZIP, pozwalał aplikacjom uniknąć oceny. Zaktualizuj system do wersji 14.4 lub nowszej, w której Apple naprawiło ten problem.<sup>[[1]](#references)</sup>

### [CVE-2024-44128](https://support.apple.com/en-us/121234)

Osadzony w pobranej aplikacji **workflow Automator Quick Action** mógł uruchomić się bez oceny Gatekeeper, ponieważ workflowy traktowano jako dane, a helper Automatora wykonywał je poza standardową ścieżką wyświetlania monitu o notaryzację. W związku z tym spreparowany plik `.app` zawierający Quick Action uruchamiający skrypt powłoki (np. w `Contents/PlugIns/*.workflow/Contents/document.wflow`) mógł wykonać go natychmiast po uruchomieniu aplikacji. Apple dodało dodatkowe okno dialogowe z prośbą o zgodę i naprawiło ścieżkę oceny w Ventura **13.7**, Sonoma **14.7** i Sequoia **15**.<sup>[[3]](#references)</sup>

### Błędy propagacji kwarantanny podczas rozpakowywania i kopiowania

Badanie z 2024 r. wykazało luki w propagacji kwarantanny w testowanych wersjach programów iZip (ZIP/TAR/7Z), Archiver (ARCHIVER/ZIP/TAR/7Z), BetterZip (ZIP/TAR/7Z), WinRAR (ZIP/TAR/7Z) i 7z Utility (DMG/ZIP/7Z). Zaobserwowano również utratę tego atrybutu podczas kopiowania z hosta do maszyny wirtualnej za pomocą VMware Tools. Kilku dostawców ogłosiło później poprawki, dlatego traktuj te nazwy jako wskazówki do **ponownego testowania konkretnych wersji**, a nie jako stałą listę podatnego oprogramowania. Ten sam problem z granicą zaufania dotyczy natywnych procesów Unix: `curl`/`scp` nie dodają kwarantanny, a narzędzia wiersza poleceń `tar`/`unzip` nie dziedziczą jej automatycznie z archiwum-nośnika.<sup>[[15]](#references)</sup>

Podczas testów ofensywnych porównuj nośnik i końcową aplikację po **każdym** przejściu przez przeglądarkę, klienta poczty, archiwizator, obraz dysku, usługę synchronizacji z chmurą, folder współdzielony i kopiowanie maszyna wirtualna–host. Jawne odrzucenie przez `spctl` nie naprawia braku xattr: bez kwarantanny standardowa ścieżka Gatekeeper przy pierwszym otwarciu może w ogóle nie zażądać takiej oceny.<sup>[[15]](#references)</sup>

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

### uchg (z tego [wystąpienia](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf))

- Utwórz katalog zawierający aplikację.
- Dodaj uchg do aplikacji.
- Skompresuj aplikację do pliku tar.gz.
- Wyślij plik tar.gz do ofiary.
- Ofiara otwiera plik tar.gz i uruchamia aplikację.
- Gatekeeper nie sprawdza aplikacji.<sup>[[12]](#references)</sup>

### Zapobieganie dodaniu xattr kwarantanny

Jeśli do pakietu „.app” nie zostanie dodany atrybut xattr kwarantanny, podczas jego uruchamiania **Gatekeeper nie zostanie uruchomiony**.

Zobacz [macOS FS Tricks](macos-fs-tricks/README.md#avoid-quarantine-xattrs-tricks), gdzie opisano mechanizmy oparte na systemie plików, flagach, ACL i AppleDouble, które mogą zapobiegać dodaniu lub usuwać atrybuty rozszerzone.





## References

- [1] [Apple Platform Security: Informacje o zawartości zabezpieczeń macOS Sonoma 14.4 (w tym CVE-2024-27853)](https://support.apple.com/en-us/HT214084)
- [2] [Eclectic Light: Jak macOS śledzi teraz pochodzenie aplikacji](https://eclecticlight.co/2023/05/10/how-macos-now-tracks-the-provenance-of-apps/)
- [3] [Apple: Informacje o zawartości zabezpieczeń macOS Sonoma 14.7 / Ventura 13.7 (CVE-2024-44128)](https://support.apple.com/en-us/121234)
- [4] [MacRumors: macOS 15 Sequoia usuwa obejście Gatekeepera przez kliknięcie z wciśniętym Control i wybranie opcji „Otwórz”](https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/)
- [5] [WithSecure Labs: Odkrycie CVE-2021-1810](https://labs.withsecure.com/publications/the-discovery-of-cve-2021-1810)
- [6] [CVE-2021-30990, omijanie Gatekeepera w macOS](https://ronmasas.com/posts/bypass-macos-gatekeeper)
- [7] [Jamf Threat Labs wykrywa lukę w Safari umożliwiającą obejście Gatekeepera](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
- [8] [Jamf Threat Labs wykrywa lukę w Archive Utility w macOS umożliwiającą obejście Gatekeepera (CVE-2022-32910)](https://www.jamf.com/blog/jamf-threat-labs-macos-archive-utility-vulnerability/)
- [9] [Pięta achillesowa Gatekeepera: odkrycie luki w macOS](https://www.microsoft.com/en-us/security/blog/2022/12/19/gatekeepers-achilles-heel-unearthing-a-macos-vulnerability/)
- [10] [F-Secure: Odkrycie obejścia Gatekeepera (CVE-2023-27943)](https://blog.f-secure.com/discovery-of-gatekeeper-bypass-cve-2023-27943/)
- [11] [Odkrycie i zgłoszenie exploita omijającego Gatekeepera z pomocą Mac Monitor](https://redcanary.com/blog/gatekeeper-bypass-vulnerabilities/)
- [12] [CODE BLUE 2023: Omijanie mechanizmów bezpieczeństwa i prywatności macOS — od Gatekeepera po System Integrity Protection (Koh Nakagawa)](https://codeblue.jp/2023/result/pdf/cb23-bypassing-macos-security-and-privacy-mechanisms-from-gatekeeper-to-system-integrity-protection-by-koh-nakagawa.pdf)
- [13] [Apple: Informacje o zawartości zabezpieczeń macOS Sonoma 14 (CVE-2023-41067)](https://support.apple.com/en-us/HT213940)
- [14] [Apple Developer Forums: Testowanie produktu po notaryzacji](https://developer.apple.com/forums/thread/130560)
- [15] [Unit 42: Obejście Gatekeepera — odkrywanie słabości mechanizmu bezpieczeństwa macOS](https://unit42.paloaltonetworks.com/gatekeeper-bypass-macos/)
{{#include ../../../banners/hacktricks-training.md}}

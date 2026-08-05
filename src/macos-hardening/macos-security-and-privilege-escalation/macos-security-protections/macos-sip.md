# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Podstawowe informacje**

**System Integrity Protection (SIP)** w systemie macOS to mechanizm zaprojektowany w celu uniemożliwienia nawet najbardziej uprzywilejowanym użytkownikom wprowadzania nieautoryzowanych zmian w kluczowych folderach systemowych. Funkcja ta odgrywa kluczową rolę w utrzymaniu integralności systemu, ograniczając działania takie jak dodawanie, modyfikowanie lub usuwanie plików w chronionych lokalizacjach. Główne foldery chronione przez SIP to:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Reguły określające działanie SIP są zdefiniowane w pliku konfiguracyjnym znajdującym się pod adresem **`/System/Library/Sandbox/rootless.conf`**. W tym pliku ścieżki poprzedzone gwiazdką (\*) są oznaczone jako wyjątki od pozostałych rygorystycznych ograniczeń SIP.

Rozważ poniższy przykład:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ten fragment sugeruje, że chociaż SIP zasadniczo zabezpiecza katalog **`/usr`**, istnieją określone podkatalogi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`), w których modyfikacje są dozwolone, co wskazuje gwiazdka (\*) poprzedzająca ich ścieżki.

Aby sprawdzić, czy katalog lub plik jest chroniony przez SIP, możesz użyć polecenia **`ls -lOd`** w celu sprawdzenia obecności flagi **`restricted`** lub **`sunlnk`**. Na przykład:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
W tym przypadku flaga **`sunlnk`** oznacza, że samego katalogu `/usr/libexec/cups` **nie można usunąć**, choć można w nim tworzyć, modyfikować i usuwać pliki.

Z drugiej strony:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Tutaj flaga **`restricted`** wskazuje, że katalog `/usr/libexec` jest chroniony przez SIP. W katalogu chronionym przez SIP nie można tworzyć, modyfikować ani usuwać plików.

Ponadto, jeśli plik zawiera rozszerzony **atrybut** **`com.apple.rootless`**, ten plik również będzie **chroniony przez SIP**.

> [!TIP]
> Należy pamiętać, że hook **Sandbox** **`hook_vnode_check_setextattr`** uniemożliwia każdą próbę modyfikacji rozszerzonego atrybutu **`com.apple.rootless`.**

**SIP ogranicza również inne działania root**, takie jak:

- Ładowanie niezaufanych rozszerzeń kernela
- Uzyskiwanie task-ports dla procesów podpisanych przez Apple
- Modyfikowanie zmiennych NVRAM
- Zezwalanie na debugging kernela

Opcje są przechowywane w zmiennej nvram jako bitflag (`csr-active-config` na Intel, a `lp-sip0` jest odczytywana z uruchomionego Device Tree na ARM). Flagi można znaleźć w kodzie źródłowym XNU, w `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status SIP

Możesz sprawdzić, czy SIP jest włączony w systemie, za pomocą następującego polecenia:
```bash
csrutil status
```
Jeśli musisz wyłączyć SIP, uruchom ponownie komputer w trybie odzyskiwania (naciskając Command+R podczas uruchamiania), a następnie wykonaj następujące polecenie:
```bash
csrutil disable
```
Jeśli chcesz zachować włączony SIP, ale usunąć zabezpieczenia debugowania, możesz to zrobić za pomocą:
```bash
csrutil enable --without debug
```
### Inne ograniczenia

- **Nie zezwala na ładowanie niepodpisanych rozszerzeń jądra** (kexts), zapewniając, że tylko zweryfikowane rozszerzenia mogą współdziałać z jądrem systemu.
- **Uniemożliwia debugowanie** procesów systemowych macOS, chroniąc kluczowe komponenty systemu przed nieautoryzowanym dostępem i modyfikacją.
- **Uniemożliwia narzędziom** takim jak dtrace inspekcję procesów systemowych, dodatkowo chroniąc integralność działania systemu.

[**Dowiedz się więcej o SIP w tym wystąpieniu**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**<sup>[1]</sup>

### **Uprawnienia związane z SIP**

- `com.apple.rootless.xpc.bootstrap`: Kontrolowanie launchd
- `com.apple.rootless.install[.heritable]`: Dostęp do systemu plików
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Zarządzanie UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Możliwości konfiguracji XPC
- `com.apple.rootless.xpc.effective-root`: Root przez launchd XPC
- `com.apple.rootless.restricted-block-devices`: Dostęp do surowych urządzeń blokowych
- `com.apple.rootless.internal.installer-equivalent`: Nieograniczony dostęp do systemu plików
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Pełny dostęp do NVRAM
- `com.apple.rootless.storage.label`: Modyfikowanie plików ograniczonych przez xattr com.apple.rootless z odpowiednią etykietą
- `com.apple.rootless.volume.VM.label`: Utrzymywanie wymiany VM na woluminie

## Obejścia SIP

Obejście SIP umożliwia atakującemu:

- **Dostęp do danych użytkowników**: Odczytywanie poufnych danych użytkowników, takich jak poczta, wiadomości i historia Safari ze wszystkich kont użytkowników.
- **TCC Bypass**: Bezpośrednie manipulowanie bazą danych TCC (Transparency, Consent, and Control) w celu przyznania nieautoryzowanego dostępu do kamery internetowej, mikrofonu i innych zasobów.
- **Ustanowienie persistence**: Umieszczanie malware w lokalizacjach chronionych przez SIP, dzięki czemu jest ono odporne na usunięcie, nawet przy uprawnieniach root. Obejmuje to również możliwość manipulowania Malware Removal Tool (MRT).
- **Ładowanie rozszerzeń jądra**: Mimo że istnieją dodatkowe zabezpieczenia, obejście SIP upraszcza proces ładowania niepodpisanych rozszerzeń jądra.

### Pakiety instalacyjne

**Pakiety instalacyjne podpisane certyfikatem Apple** mogą omijać jego zabezpieczenia. Oznacza to, że nawet pakiety podpisane przez standardowych developerów zostaną zablokowane, jeśli będą próbowały modyfikować katalogi chronione przez SIP.

### Nieistniejący plik SIP

Jedną z potencjalnych luk jest sytuacja, w której plik określony w **`rootless.conf` nie istnieje obecnie** — wówczas można go utworzyć. Malware może wykorzystać to do **ustanowienia persistence** w systemie. Przykładowo złośliwy program może utworzyć plik .plist w `/System/Library/LaunchDaemons`, jeśli jest on wymieniony w `rootless.conf`, ale nie istnieje.

### com.apple.rootless.install.heritable

> [!CAUTION]
> Uprawnienie **`com.apple.rootless.install.heritable`** umożliwia obejście SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Odkryto, że możliwa była **zamiana pakietu instalacyjnego po zweryfikowaniu przez system jego** podpisu code, a następnie system instalował złośliwy pakiet zamiast oryginalnego. Ponieważ działania te były wykonywane przez **`system_installd`**, umożliwiało to obejście SIP.<sup>[2]</sup>

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Jeśli pakiet został zainstalowany z zamontowanego obrazu lub zewnętrznego dysku, **installer** **wykonywał** binary z **tego systemu plików** (zamiast z lokalizacji chronionej przez SIP), przez co **`system_installd`** wykonywał dowolny binary.<sup>[3]</sup]

#### CVE-2021-30892 - Shrootless

[**Badacze z tego wpisu na blogu**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) odkryli podatność w mechanizmie System Integrity Protection (SIP) systemu macOS, nazwaną podatnością „Shrootless”. Podatność ta dotyczy daemona **`system_installd`**, który posiada uprawnienie **`com.apple.rootless.install.heritable`**, umożliwiające wszystkim jego procesom potomnym obejście ograniczeń systemu plików SIP.<sup>[4]</sup>

Daemon **`system_installd`** instaluje pakiety, które zostały podpisane przez **Apple**.

Badacze odkryli, że podczas instalacji pakietu podpisanego przez Apple (pliku .pkg) **`system_installd`** **uruchamia** wszystkie skrypty **post-install** zawarte w pakiecie. Skrypty te są wykonywane przez domyślną powłokę, **`zsh`**, która automatycznie **uruchamia** polecenia z pliku **`/etc/zshenv`**, jeśli ten istnieje, nawet w trybie nieinteraktywnym. To zachowanie mogło zostać wykorzystane przez atakujących: tworząc złośliwy plik `/etc/zshenv` i czekając, aż **`system_installd` wywoła `zsh`**, mogli wykonywać dowolne operacje na urządzeniu.<sup>[4]</sup>

Ponadto odkryto, że **`/etc/zshenv` można było wykorzystać jako ogólną technikę ataku**, a nie tylko do obejścia SIP. Każdy profil użytkownika zawiera plik `~/.zshenv`, który działa tak samo jak `/etc/zshenv`, ale nie wymaga uprawnień root. Plik ten można było wykorzystać jako mechanizm persistence, uruchamiany za każdym razem, gdy startuje `zsh`, lub jako mechanizm privilege escalation. Jeśli użytkownik administracyjny podniesie uprawnienia do root za pomocą `sudo -s` lub `sudo <command>`, plik `~/.zshenv` zostanie uruchomiony, skutecznie podnosząc uprawnienia do root.<sup>[4]</sup>

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

W [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) odkryto, że ten sam proces **`system_installd`** nadal można było wykorzystać, ponieważ umieszczał **skrypt post-install w losowo nazwanym katalogu chronionym przez SIP wewnątrz `/tmp`**. Problem polegał na tym, że **`/tmp` sam nie jest chroniony przez SIP**, więc możliwe było **zamontowanie** na nim **wirtualnego obrazu**, po czym **installer** umieszczał w nim **skrypt post-install**, następnie **odmontowywał** wirtualny obraz, **ponownie tworzył** wszystkie **katalogi** i **dodawał** skrypt **post-install** z **payloadem** do wykonania.<sup>[5]</sup>

#### [Narzędzie fsck_cs](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Zidentyfikowano podatność, w której **fsck_cs** zostało nakłonione do uszkodzenia kluczowego pliku ze względu na możliwość podążania za **symbolic links**. Atakujący utworzyli link z _`/dev/diskX`_ do pliku `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Wykonanie **`fsck_cs`** na _`/dev/diskX`_ prowadziło do uszkodzenia `Info.plist`. Integralność tego pliku ma kluczowe znaczenie dla SIP (System Integrity Protection) systemu operacyjnego, które kontroluje ładowanie rozszerzeń jądra. Po uszkodzeniu możliwość zarządzania przez SIP wykluczeniami jądra zostaje naruszona.<sup>[6]</sup>

Polecenia umożliwiające wykorzystanie tej podatności to:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Eksploatacja tej podatności ma poważne konsekwencje. Plik `Info.plist`, który zwykle odpowiada za zarządzanie uprawnieniami rozszerzeń jądra, staje się nieskuteczny. Obejmuje to brak możliwości umieszczenia na czarnej liście określonych rozszerzeń, takich jak `AppleHWAccess.kext`. W rezultacie, gdy mechanizm kontroli SIP przestaje działać, to rozszerzenie może zostać załadowane, zapewniając nieautoryzowany dostęp do odczytu i zapisu pamięci RAM systemu.<sup>[6]</sup>

#### [Montowanie systemu plików na folderach chronionych przez SIP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Możliwe było zamontowanie nowego systemu plików na **folderach chronionych przez SIP w celu obejścia ochrony**.<sup>[1]</sup>
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Upgrader bypass (2016)](https://objective-see.org/blog/blog_0x14.html)

System jest ustawiony na uruchamianie z wbudowanego obrazu dysku instalatora znajdującego się w `Install macOS Sierra.app` w celu uaktualnienia systemu operacyjnego przy użyciu narzędzia `bless`. Użyte polecenie jest następujące:<sup>[7]</sup>
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezpieczeństwo tego procesu może zostać naruszone, jeśli attacker zmodyfikuje obraz upgrade (`InstallESD.dmg`) przed jego uruchomieniem. Strategia polega na zastąpieniu dynamic loadera (dyld) złośliwą wersją (`libBaseIA.dylib`). Ta zamiana powoduje wykonanie kodu attackera po uruchomieniu instalatora.<sup>[7]</sup>

Kod attackera uzyskuje kontrolę podczas procesu upgrade, wykorzystując zaufanie systemu do instalatora. Atak polega na zmodyfikowaniu obrazu `InstallESD.dmg` za pomocą method swizzling, w szczególności przez zaatakowanie metody `extractBootBits`. Umożliwia to wstrzyknięcie złośliwego kodu przed użyciem obrazu dysku.<sup>[7]</sup>

Ponadto w obrazie `InstallESD.dmg` znajduje się `BaseSystem.dmg`, który pełni funkcję root file systemu dla kodu upgrade. Wstrzyknięcie dynamic library do tego obrazu umożliwia złośliwemu kodowi działanie w procesie zdolnym do modyfikowania plików na poziomie systemu operacyjnego, znacząco zwiększając potencjał kompromitacji systemu.<sup>[7]</sup>

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

W tym wystąpieniu z [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) pokazano, jak **`systemmigrationd`** (który może ominąć SIP) wykonuje skrypt **bash** i skrypt **perl**, co można wykorzystać za pośrednictwem zmiennych środowiskowych **`BASH_ENV`** i **`PERL5OPT`**.<sup>[8]</sup>

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Jak [**szczegółowo opisano w tym wpisie na blogu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), skrypt `postinstall` z pakietu `InstallAssistant.pkg` umożliwiał wykonanie:<sup>[9]</sup>
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
i możliwe było utworzenie dowiązania symbolicznego w `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, które pozwalało użytkownikowi **usunąć ograniczenia dowolnego pliku, omijając ochronę SIP**.<sup>[9]</sup>

### **com.apple.rootless.install**

> [!CAUTION]
> Entitlement **`com.apple.rootless.install`** pozwala ominąć SIP

Entitlement `com.apple.rootless.install` jest znany z umożliwiania obejścia System Integrity Protection (SIP) w macOS. Zostało to szczególnie wspomniane w związku z [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).<sup>[10]</sup>

W tym konkretnym przypadku systemowa usługa XPC znajdująca się pod adresem `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` posiada ten entitlement. Pozwala to powiązanemu procesowi ominąć ograniczenia SIP. Ponadto usługa ta udostępnia metodę umożliwiającą przenoszenie plików bez stosowania jakichkolwiek środków bezpieczeństwa.<sup>[10]</sup>

## Sealed System Snapshots

Sealed System Snapshots to funkcja wprowadzona przez Apple w **macOS Big Sur (macOS 11)** jako część mechanizmu **System Integrity Protection (SIP)**, zapewniająca dodatkową warstwę bezpieczeństwa i stabilności systemu. Są to zasadniczo wersje woluminu systemowego tylko do odczytu.

Poniżej znajduje się bardziej szczegółowy opis:

1. **Niemodyfikowalny system**: Sealed System Snapshots sprawiają, że wolumin systemowy macOS jest „niemodyfikowalny”, co oznacza, że nie można go zmienić. Zapobiega to nieautoryzowanym lub przypadkowym zmianom w systemie, które mogłyby zagrozić bezpieczeństwu albo stabilności systemu.
2. **Aktualizacje oprogramowania systemowego**: Podczas instalowania aktualizacji lub uaktualnień macOS tworzy nowy snapshot systemu. Wolumin startowy macOS używa następnie **APFS (Apple File System)** do przełączenia się na ten nowy snapshot. Cały proces stosowania aktualizacji staje się bezpieczniejszy i bardziej niezawodny, ponieważ system może zawsze powrócić do poprzedniego snapshotu, jeśli podczas aktualizacji wystąpi problem.
3. **Separacja danych**: W połączeniu z koncepcją separacji woluminów Data i System, wprowadzoną w macOS Catalina, funkcja Sealed System Snapshot gwarantuje, że wszystkie dane i ustawienia są przechowywane na oddzielnym woluminie „**Data**”. Separacja ta uniezależnia dane od systemu, co upraszcza proces aktualizacji systemu i zwiększa jego bezpieczeństwo.

Pamiętaj, że te snapshoty są automatycznie zarządzane przez macOS i nie zajmują dodatkowego miejsca na dysku dzięki możliwości współdzielenia przestrzeni przez APFS. Należy również pamiętać, że snapshoty te różnią się od **snapshotów Time Machine**, które są dostępnymi dla użytkownika kopiami zapasowymi całego systemu.

### Sprawdzanie snapshotów

Polecenie **`diskutil apfs list`** wyświetla **szczegóły woluminów APFS** oraz ich układ:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-< Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
|   |   -----------------------------------------------------------
|   |   APFS Physical Store Disk:   disk0s2
|   |   Size:                       494384795648 B (494.4 GB)
|   |
|   +-> Volume disk3s1 7A27E734-880F-4D91-A703-FB55861D49B7
|   |   ---------------------------------------------------
<strong>|   |   APFS Volume Disk (Role):   disk3s1 (System)
</strong>|   |   Name:                      Macintosh HD (Case-insensitive)
<strong>|   |   Mount Point:               /System/Volumes/Update/mnt1
</strong>|   |   Capacity Consumed:         12819210240 B (12.8 GB)
|   |   Sealed:                    Broken
|   |   FileVault:                 Yes (Unlocked)
|   |   Encrypted:                 No
|   |   |
|   |   Snapshot:                  FAA23E0C-791C-43FF-B0E7-0E1C0810AC61
|   |   Snapshot Disk:             disk3s1s1
<strong>|   |   Snapshot Mount Point:      /
</strong><strong>|   |   Snapshot Sealed:           Yes
</strong>[...]
+-> Volume disk3s5 281959B7-07A1-4940-BDDF-6419360F3327
|   ---------------------------------------------------
|   APFS Volume Disk (Role):   disk3s5 (Data)
|   Name:                      Macintosh HD - Data (Case-insensitive)
<strong>    |   Mount Point:               /System/Volumes/Data
</strong><strong>    |   Capacity Consumed:         412071784448 B (412.1 GB)
</strong>    |   Sealed:                    No
|   FileVault:                 Yes (Unlocked)
</code></pre>

Na poprzednim wyjściu można zobaczyć, że **lokalizacje dostępne dla użytkownika** są zamontowane pod `/System/Volumes/Data`.

Ponadto **snapshot woluminu systemowego macOS** jest zamontowany w `/` i jest **sealed** (podpisany kryptograficznie przez system operacyjny). Jeśli więc SIP zostanie ominięty i snapshot zostanie zmodyfikowany, **system operacyjny nie uruchomi się ponownie**.

Można również **sprawdzić, czy seal jest włączony**, uruchamiając:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Co więcej, dysk migawki jest również zamontowany jako **tylko do odczytu**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
## Referencje

- [1] [SyScan360 - Stefan Esser - OS X El Capitan sinking the S\H/IP](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)
- [2] [CVE-2019-8561 - Objective-See Blog](https://objective-see.org/blog/blog_0x42.html)
- [3] [CVE-2020–9854: „Unauthd” (three) logic bugs ftw! - Objective-See Blog](https://objective-see.org/blog/blog_0x4D.html)
- [4] [Microsoft finds new macOS vulnerability, Shrootless, that could bypass System Integrity Protection](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/)
- [5] [Technical Analysis: CVE-2022-22583 - Perception Point](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)
- [6] [Apple's fruitless rootless security broken by code that fits in a tweet - The Register](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)
- [7] [\[0day\] Bypassing Apple's System Integrity Protection - Objective-See Blog](https://objective-see.org/blog/blog_0x14.html)
- [8] [DEF CON 31 - Getting a Migraine - Unique SIP Bypass on MacOS - Or, Pearse, Bohra](https://www.youtube.com/watch?v=zxZesAN-TEk)
- [9] [Apple Mitigates Vulnerabilities in Installer Scripts - Kandji Blog](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts)
- [10] [CVE-2022-26712: The POC for SIP-Bypass Is Even Tweetable](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/)

{{#include ../../../banners/hacktricks-training.md}}

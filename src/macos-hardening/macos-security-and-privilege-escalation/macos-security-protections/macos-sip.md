# macOS SIP

{{#include ../../../banners/hacktricks-training.md}}

## **Podstawowe informacje**

**System Integrity Protection (SIP)** w macOS to mechanizm zaprojektowany w celu zapobiegania nawet najbardziej uprzywilejowanym użytkownikom w dokonywaniu nieautoryzowanych zmian w kluczowych folderach systemowych. Ta funkcja odgrywa kluczową rolę w utrzymaniu integralności systemu, ograniczając działania takie jak dodawanie, modyfikowanie lub usuwanie plików w chronionych obszarach. Główne foldery chronione przez SIP to:

- **/System**
- **/bin**
- **/sbin**
- **/usr**

Zasady regulujące zachowanie SIP są zdefiniowane w pliku konfiguracyjnym znajdującym się w **`/System/Library/Sandbox/rootless.conf`**. W tym pliku ścieżki, które są poprzedzone gwiazdką (\*), są oznaczone jako wyjątki od w przeciwnym razie surowych ograniczeń SIP.

Rozważ poniższy przykład:
```javascript
/usr
* /usr/libexec/cups
* /usr/local
* /usr/share/man
```
Ten fragment sugeruje, że chociaż SIP ogólnie zabezpiecza katalog **`/usr`**, istnieją konkretne podkatalogi (`/usr/libexec/cups`, `/usr/local` i `/usr/share/man`), w których modyfikacje są dozwolone, co wskazuje gwiazdka (\*) poprzedzająca ich ścieżki.

Aby sprawdzić, czy katalog lub plik jest chroniony przez SIP, możesz użyć polecenia **`ls -lOd`**, aby sprawdzić obecność flagi **`restricted`** lub **`sunlnk`**. Na przykład:
```bash
ls -lOd /usr/libexec/cups
drwxr-xr-x  11 root  wheel  sunlnk 352 May 13 00:29 /usr/libexec/cups
```
W tym przypadku flaga **`sunlnk`** oznacza, że katalog `/usr/libexec/cups` **nie może być usunięty**, chociaż pliki w nim mogą być tworzone, modyfikowane lub usuwane.

Z drugiej strony:
```bash
ls -lOd /usr/libexec
drwxr-xr-x  338 root  wheel  restricted 10816 May 13 00:29 /usr/libexec
```
Tutaj flaga **`restricted`** wskazuje, że katalog `/usr/libexec` jest chroniony przez SIP. W katalogu chronionym przez SIP pliki nie mogą być tworzone, modyfikowane ani usuwane.

Ponadto, jeśli plik zawiera atrybut **`com.apple.rootless`** jako rozszerzony **atrybut**, ten plik również będzie **chroniony przez SIP**.

> [!TIP]
> Zauważ, że **Sandbox** hook **`hook_vnode_check_setextattr`** zapobiega wszelkim próbom modyfikacji rozszerzonego atrybutu **`com.apple.rootless`.**

**SIP ogranicza również inne działania roota**, takie jak:

- Ładowanie nieufnych rozszerzeń jądra
- Uzyskiwanie portów zadań dla procesów podpisanych przez Apple
- Modyfikowanie zmiennych NVRAM
- Umożliwianie debugowania jądra

Opcje są przechowywane w zmiennej nvram jako bitflag (`csr-active-config` na Intel i `lp-sip0` jest odczytywane z uruchomionego drzewa urządzeń dla ARM). Możesz znaleźć flagi w kodzie źródłowym XNU w `csr.sh`:

<figure><img src="../../../images/image (1192).png" alt=""><figcaption></figcaption></figure>

### Status SIP

Możesz sprawdzić, czy SIP jest włączony w swoim systemie, używając następującego polecenia:
```bash
csrutil status
```
Jeśli musisz wyłączyć SIP, musisz uruchomić komputer w trybie odzyskiwania (naciskając Command+R podczas uruchamiania), a następnie wykonać następujące polecenie:
```bash
csrutil disable
```
Jeśli chcesz zachować włączoną SIP, ale usunąć zabezpieczenia debugowania, możesz to zrobić za pomocą:
```bash
csrutil enable --without debug
```
### Inne Ograniczenia

- **Zabrania ładowania niepodpisanych rozszerzeń jądra** (kexts), zapewniając, że tylko zweryfikowane rozszerzenia wchodzą w interakcję z jądrem systemu.
- **Zapobiega debugowaniu** procesów systemowych macOS, chroniąc podstawowe komponenty systemu przed nieautoryzowanym dostępem i modyfikacją.
- **Hamuje narzędzia** takie jak dtrace przed inspekcją procesów systemowych, dodatkowo chroniąc integralność działania systemu.

[**Dowiedz się więcej o informacji SIP w tej prezentacji**](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)**.**

### **Uprawnienia związane z SIP**

- `com.apple.rootless.xpc.bootstrap`: Kontrola launchd
- `com.apple.rootless.install[.heritable]`: Dostęp do systemu plików
- `com.apple.rootless.kext-management`: `kext_request`
- `com.apple.rootless.datavault.controller`: Zarządzanie UF_DATAVAULT
- `com.apple.rootless.xpc.bootstrap`: Możliwości konfiguracji XPC
- `com.apple.rootless.xpc.effective-root`: Root przez launchd XPC
- `com.apple.rootless.restricted-block-devices`: Dostęp do surowych urządzeń blokowych
- `com.apple.rootless.internal.installer-equivalent`: Nieograniczony dostęp do systemu plików
- `com.apple.rootless.restricted-nvram-variables[.heritable]`: Pełny dostęp do NVRAM
- `com.apple.rootless.storage.label`: Modyfikacja plików ograniczonych przez com.apple.rootless xattr z odpowiednią etykietą
- `com.apple.rootless.volume.VM.label`: Utrzymanie VM swap na woluminie

## Obejścia SIP

Obejście SIP umożliwia atakującemu:

- **Dostęp do danych użytkownika**: Odczyt wrażliwych danych użytkownika, takich jak poczta, wiadomości i historia Safari ze wszystkich kont użytkowników.
- **Obejście TCC**: Bezpośrednia manipulacja bazą danych TCC (Transparentność, Zgoda i Kontrola) w celu przyznania nieautoryzowanego dostępu do kamery internetowej, mikrofonu i innych zasobów.
- **Ustanowienie trwałości**: Umieszczenie złośliwego oprogramowania w lokalizacjach chronionych przez SIP, co czyni je odpornym na usunięcie, nawet przez uprawnienia root. Obejmuje to również możliwość manipulacji Narzędziem Usuwania Złośliwego Oprogramowania (MRT).
- **Ładowanie rozszerzeń jądra**: Chociaż istnieją dodatkowe zabezpieczenia, obejście SIP upraszcza proces ładowania niepodpisanych rozszerzeń jądra.

### Pakiety instalacyjne

**Pakiety instalacyjne podpisane certyfikatem Apple** mogą omijać jego zabezpieczenia. Oznacza to, że nawet pakiety podpisane przez standardowych deweloperów będą blokowane, jeśli będą próbowały modyfikować katalogi chronione przez SIP.

### Nieistniejący plik SIP

Jednym z potencjalnych luk jest to, że jeśli plik jest określony w **`rootless.conf`, ale obecnie nie istnieje**, może zostać utworzony. Złośliwe oprogramowanie mogłoby to wykorzystać do **ustanowienia trwałości** w systemie. Na przykład, złośliwy program mógłby utworzyć plik .plist w `/System/Library/LaunchDaemons`, jeśli jest wymieniony w `rootless.conf`, ale nieobecny.

### com.apple.rootless.install.heritable

> [!OSTRZEŻENIE]
> Uprawnienie **`com.apple.rootless.install.heritable`** pozwala na obejście SIP

#### [CVE-2019-8561](https://objective-see.org/blog/blog_0x42.html) <a href="#cve" id="cve"></a>

Odkryto, że możliwe było **zamienienie pakietu instalacyjnego po tym, jak system zweryfikował jego podpis** kodu, a następnie system zainstalowałby złośliwy pakiet zamiast oryginalnego. Ponieważ te działania były wykonywane przez **`system_installd`**, pozwalałoby to na obejście SIP.

#### [CVE-2020–9854](https://objective-see.org/blog/blog_0x4D.html) <a href="#cve-unauthd-chain" id="cve-unauthd-chain"></a>

Jeśli pakiet był instalowany z zamontowanego obrazu lub zewnętrznego dysku, **instalator** **wykonywałby** binarny plik z **tego systemu plików** (zamiast z lokalizacji chronionej przez SIP), co sprawiało, że **`system_installd`** wykonywałby dowolny binarny plik.

#### CVE-2021-30892 - Shrootless

[**Badacze z tego wpisu na blogu**](https://www.microsoft.com/en-us/security/blog/2021/10/28/microsoft-finds-new-macos-vulnerability-shrootless-that-could-bypass-system-integrity-protection/) odkryli lukę w mechanizmie Ochrony Integralności Systemu (SIP) macOS, nazwaną luką 'Shrootless'. Ta luka koncentruje się na demonie **`system_installd`**, który ma uprawnienie **`com.apple.rootless.install.heritable`**, które pozwala dowolnym jego procesom potomnym na obejście ograniczeń systemu plików SIP.

Demon **`system_installd`** zainstaluje pakiety, które zostały podpisane przez **Apple**.

Badacze odkryli, że podczas instalacji pakietu podpisanego przez Apple (.pkg), **`system_installd`** **uruchamia** wszelkie **skrypty po instalacji** zawarte w pakiecie. Te skrypty są wykonywane przez domyślną powłokę, **`zsh`**, która automatycznie **uruchamia** polecenia z pliku **`/etc/zshenv`**, jeśli istnieje, nawet w trybie nieinteraktywnym. To zachowanie mogłoby być wykorzystane przez atakujących: tworząc złośliwy plik `/etc/zshenv` i czekając na **`system_installd`, aby wywołać `zsh`**, mogliby przeprowadzać dowolne operacje na urządzeniu.

Ponadto odkryto, że **`/etc/zshenv`** mogłoby być używane jako ogólna technika ataku, nie tylko do obejścia SIP. Każdy profil użytkownika ma plik `~/.zshenv`, który zachowuje się tak samo jak `/etc/zshenv`, ale nie wymaga uprawnień root. Plik ten mógłby być używany jako mechanizm trwałości, uruchamiając się za każdym razem, gdy `zsh` się uruchamia, lub jako mechanizm podwyższenia uprawnień. Jeśli użytkownik administracyjny podniesie uprawnienia do roota za pomocą `sudo -s` lub `sudo <polecenie>`, plik `~/.zshenv` zostanie uruchomiony, skutecznie podnosząc uprawnienia do roota.

#### [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/)

W [**CVE-2022-22583**](https://perception-point.io/blog/technical-analysis-cve-2022-22583/) odkryto, że ten sam proces **`system_installd`** mógł być nadal nadużywany, ponieważ umieszczał **skrypt po instalacji w losowo nazwanym folderze chronionym przez SIP w `/tmp`**. Problem polega na tym, że **`/tmp`** sam w sobie nie jest chroniony przez SIP, więc możliwe było **zamontowanie** **obrazu wirtualnego na nim**, a następnie **instalator** umieściłby tam **skrypt po instalacji**, **odmontował** obraz wirtualny, **odtworzył** wszystkie **foldery** i **dodał** **skrypt po instalacji** z **ładunkiem** do wykonania.

#### [fsck_cs utility](https://www.theregister.com/2016/03/30/apple_os_x_rootless/)

Zidentyfikowano lukę, w której **`fsck_cs`** został wprowadzony w błąd do uszkodzenia kluczowego pliku, z powodu jego zdolności do podążania za **linkami symbolicznymi**. Konkretnie, atakujący stworzyli link z _`/dev/diskX`_ do pliku `/System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist`. Wykonanie **`fsck_cs`** na _`/dev/diskX`_ doprowadziło do uszkodzenia `Info.plist`. Integralność tego pliku jest kluczowa dla SIP (Ochrony Integralności Systemu) systemu operacyjnego, który kontroluje ładowanie rozszerzeń jądra. Po uszkodzeniu, zdolność SIP do zarządzania wykluczeniami jądra jest zagrożona.

Polecenia do wykorzystania tej luki to:
```bash
ln -s /System/Library/Extensions/AppleKextExcludeList.kext/Contents/Info.plist /dev/diskX
fsck_cs /dev/diskX 1>&-
touch /Library/Extensions/
reboot
```
Wykorzystanie tej luki ma poważne konsekwencje. Plik `Info.plist`, normalnie odpowiedzialny za zarządzanie uprawnieniami dla rozszerzeń jądra, staje się nieskuteczny. Obejmuje to niemożność dodania do czarnej listy niektórych rozszerzeń, takich jak `AppleHWAccess.kext`. W konsekwencji, gdy mechanizm kontrolny SIP jest uszkodzony, to rozszerzenie może być załadowane, co daje nieautoryzowany dostęp do odczytu i zapisu pamięci RAM systemu.

#### [Mount over SIP protected folders](https://www.slideshare.net/i0n1c/syscan360-stefan-esser-os-x-el-capitan-sinking-the-ship)

Możliwe było zamontowanie nowego systemu plików nad **folderami chronionymi przez SIP, aby obejść ochronę**.
```bash
mkdir evil
# Add contento to the folder
hdiutil create -srcfolder evil evil.dmg
hdiutil attach -mountpoint /System/Library/Snadbox/ evil.dmg
```
#### [Obejście upgradera (2016)](https://objective-see.org/blog/blog_0x14.html)

System jest ustawiony na uruchamianie z wbudowanego obrazu dysku instalacyjnego w `Install macOS Sierra.app`, aby zaktualizować system operacyjny, wykorzystując narzędzie `bless`. Używana komenda jest następująca:
```bash
/usr/sbin/bless -setBoot -folder /Volumes/Macintosh HD/macOS Install Data -bootefi /Volumes/Macintosh HD/macOS Install Data/boot.efi -options config="\macOS Install Data\com.apple.Boot" -label macOS Installer
```
Bezpieczeństwo tego procesu może być zagrożone, jeśli atakujący zmieni obraz aktualizacji (`InstallESD.dmg`) przed uruchomieniem. Strategia polega na zastąpieniu dynamicznego loadera (dyld) złośliwą wersją (`libBaseIA.dylib`). To zastąpienie skutkuje wykonaniem kodu atakującego, gdy instalator zostaje uruchomiony.

Kod atakującego przejmuje kontrolę podczas procesu aktualizacji, wykorzystując zaufanie systemu do instalatora. Atak postępuje poprzez modyfikację obrazu `InstallESD.dmg` za pomocą metody swizzling, szczególnie celując w metodę `extractBootBits`. Umożliwia to wstrzyknięcie złośliwego kodu przed użyciem obrazu dysku.

Ponadto, w obrębie `InstallESD.dmg` znajduje się `BaseSystem.dmg`, który służy jako system plików dla kodu aktualizacji. Wstrzyknięcie dynamicznej biblioteki do tego pozwala złośliwemu kodowi działać w procesie zdolnym do modyfikacji plików na poziomie systemu operacyjnego, znacznie zwiększając potencjał kompromitacji systemu.

#### [systemmigrationd (2023)](https://www.youtube.com/watch?v=zxZesAN-TEk)

W tym wystąpieniu z [**DEF CON 31**](https://www.youtube.com/watch?v=zxZesAN-TEk) pokazano, jak **`systemmigrationd`** (który może omijać SIP) wykonuje skrypt **bash** i **perl**, które mogą być nadużywane za pomocą zmiennych środowiskowych **`BASH_ENV`** i **`PERL5OPT`**.

#### CVE-2023-42860 <a href="#cve-a-detailed-look" id="cve-a-detailed-look"></a>

Jak [**szczegółowo opisano w tym wpisie na blogu**](https://blog.kandji.io/apple-mitigates-vulnerabilities-installer-scripts), skrypt `postinstall` z pakietów `InstallAssistant.pkg` pozwalał na wykonanie:
```bash
/usr/bin/chflags -h norestricted "${SHARED_SUPPORT_PATH}/SharedSupport.dmg"
```
i możliwe było utworzenie symlink w `${SHARED_SUPPORT_PATH}/SharedSupport.dmg`, który pozwalałby użytkownikowi na **zniesienie ograniczeń dla dowolnego pliku, omijając ochronę SIP**.

### **com.apple.rootless.install**

> [!CAUTION]
> Uprawnienie **`com.apple.rootless.install`** pozwala na ominięcie SIP

Uprawnienie `com.apple.rootless.install` jest znane z omijania Ochrony Integralności Systemu (SIP) w macOS. Zostało to szczególnie wspomniane w związku z [**CVE-2022-26712**](https://jhftss.github.io/CVE-2022-26712-The-POC-For-SIP-Bypass-Is-Even-Tweetable/).

W tym konkretnym przypadku, usługa XPC systemu znajdująca się w `/System/Library/PrivateFrameworks/ShoveService.framework/Versions/A/XPCServices/SystemShoveService.xpc` posiada to uprawnienie. Pozwala to powiązanemu procesowi na obejście ograniczeń SIP. Ponadto, ta usługa wyraźnie przedstawia metodę, która umożliwia przenoszenie plików bez egzekwowania jakichkolwiek środków bezpieczeństwa.

## Zatwierdzone Zrzuty Systemu

Zatwierdzone Zrzuty Systemu to funkcja wprowadzona przez Apple w **macOS Big Sur (macOS 11)** jako część mechanizmu **Ochrony Integralności Systemu (SIP)**, aby zapewnić dodatkową warstwę bezpieczeństwa i stabilności systemu. Są to zasadniczo wersje tylko do odczytu wolumenu systemowego.

Oto bardziej szczegółowy opis:

1. **Niemodyfikowalny System**: Zatwierdzone Zrzuty Systemu sprawiają, że wolumen systemowy macOS jest "niemodyfikowalny", co oznacza, że nie może być zmieniany. Zapobiega to wszelkim nieautoryzowanym lub przypadkowym zmianom w systemie, które mogłyby zagrozić bezpieczeństwu lub stabilności systemu.
2. **Aktualizacje Oprogramowania Systemowego**: Gdy instalujesz aktualizacje lub ulepszenia macOS, macOS tworzy nowy zrzut systemu. Wolumen startowy macOS następnie używa **APFS (Apple File System)** do przełączenia się na ten nowy zrzut. Cały proces stosowania aktualizacji staje się bezpieczniejszy i bardziej niezawodny, ponieważ system zawsze może wrócić do poprzedniego zrzutu, jeśli coś pójdzie nie tak podczas aktualizacji.
3. **Separacja Danych**: W połączeniu z koncepcją separacji danych i wolumenu systemowego wprowadzoną w macOS Catalina, funkcja Zatwierdzonego Zrzutu Systemu zapewnia, że wszystkie twoje dane i ustawienia są przechowywane na oddzielnym wolumenie "**Dane**". Ta separacja sprawia, że twoje dane są niezależne od systemu, co upraszcza proces aktualizacji systemu i zwiększa bezpieczeństwo systemu.

Pamiętaj, że te zrzuty są automatycznie zarządzane przez macOS i nie zajmują dodatkowego miejsca na twoim dysku, dzięki możliwościom współdzielenia przestrzeni APFS. Ważne jest również, aby zauważyć, że te zrzuty różnią się od **zrzutów Time Machine**, które są kopią zapasową całego systemu dostępną dla użytkownika.

### Sprawdź Zrzuty

Polecenie **`diskutil apfs list`** wyświetla **szczegóły wolumenów APFS** i ich układ:

<pre><code>+-- Container disk3 966B902E-EDBA-4775-B743-CF97A0556A13
|   ====================================================
|   APFS Container Reference:     disk3
|   Size (Capacity Ceiling):      494384795648 B (494.4 GB)
|   Capacity In Use By Volumes:   219214536704 B (219.2 GB) (44.3% used)
|   Capacity Not Allocated:       275170258944 B (275.2 GB) (55.7% free)
|   |
|   +-&#x3C; Physical Store disk0s2 86D4B7EC-6FA5-4042-93A7-D3766A222EBE
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

W poprzednim wyjściu można zobaczyć, że **lokacje dostępne dla użytkownika** są zamontowane pod `/System/Volumes/Data`.

Ponadto, **zrzut wolumenu systemowego macOS** jest zamontowany w `/` i jest **zatwierdzony** (podpisany kryptograficznie przez system operacyjny). Tak więc, jeśli SIP zostanie ominięty i zmodyfikowany, **system operacyjny nie uruchomi się więcej**.

Możliwe jest również **zweryfikowanie, że pieczęć jest włączona**, uruchamiając:
```bash
csrutil authenticated-root status
Authenticated Root status: enabled
```
Ponadto, dysk migawki jest również montowany jako **tylko do odczytu**:
```bash
mount
/dev/disk3s1s1 on / (apfs, sealed, local, read-only, journaled)
```
{{#include ../../../banners/hacktricks-training.md}}

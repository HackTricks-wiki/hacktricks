# Ograniczenia macOS Launch/Environment Constraints i Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informacje podstawowe

Launch constraints w macOS zostały wprowadzone w celu zwiększenia bezpieczeństwa poprzez **regulowanie sposobu, osoby oraz miejsca, z którego można uruchomić proces**. Wprowadzone w macOS Ventura, zapewniają framework kategoryzujący **każdy system binary do odrębnych kategorii constraints**, które są zdefiniowane w **trust cache** — liście zawierającej system binaries oraz odpowiadające im hashe. Ograniczenia te dotyczą każdego executable binary w systemie i obejmują zestaw **reguł** określających wymagania dotyczące **uruchomienia konkretnego binary**. Reguły obejmują self constraints, które binary musi spełniać, parent constraints, które musi spełniać jego parent process, oraz responsible constraints, których muszą przestrzegać inne odpowiednie entities.

Mechanizm obejmuje również aplikacje third-party poprzez **Environment Constraints**, począwszy od macOS Sonoma, umożliwiając developerom ochronę aplikacji przez określenie **zestawu keys i values dla environment constraints.**

Definiujesz **launch environment i library constraints** w constraint dictionaries, które zapisujesz w plikach property list `launchd` albo w **oddzielnych plikach property list**, używanych podczas code signing.

Istnieją 4 typy constraints:

- **Self Constraints**: Constraints stosowane do **uruchomionego** binary.
- **Parent Process**: Constraints stosowane do **parent procesu** (na przykład **`launchd`** uruchamiającego usługę XP)
- **Responsible Constraints**: Constraints stosowane do **procesu wywołującego usługę** w komunikacji XPC.
- **Library load constraints**: Library load constraints służą do selektywnego opisania code, który może zostać załadowany.

Gdy więc proces próbuje uruchomić inny proces — wywołując `execve(_:_:_:)` lub `posix_spawn(_:_:_:_:_:)` — operating system sprawdza, czy plik **executable** spełnia jego **własny self constraint**. Sprawdza również, czy executable procesu **parent** spełnia **parent constraint** executable, a także czy executable procesu **responsible** spełnia responsible process constraint executable. Jeśli którykolwiek z tych launch constraints nie zostanie spełniony, operating system nie uruchomi programu.

Jeśli podczas ładowania library dowolna część **library constraint** nie jest spełniona, proces **nie załaduje** library.

## Kategorie LC

LC składa się z **facts** oraz **operacji logicznych** (and, or itd.), które łączą facts.

[**Facts, których może używać LC, są udokumentowane**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Na przykład:

- is-init-proc: Wartość Boolean wskazująca, czy executable musi być procesem inicjalizacyjnym operating system (`launchd`).
- is-sip-protected: Wartość Boolean wskazująca, czy executable musi być plikiem chronionym przez System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Wartość Boolean wskazująca, czy operating system załadował executable z autoryzowanego, uwierzytelnionego volume APFS.
- `on-authorized-authapfs-volume`: Wartość Boolean wskazująca, czy operating system załadował executable z autoryzowanego, uwierzytelnionego volume APFS.
- Cryptexes volume
- `on-system-volume:`Wartość Boolean wskazująca, czy operating system załadował executable z aktualnie uruchomionego system volume.
- Wewnątrz /System...
- ...

Gdy Apple binary jest podpisywany, **przypisuje go do kategorii LC** wewnątrz **trust cache**.

- **Kategorie LC w iOS 16** zostały [**odtworzone i udokumentowane tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[[6]](#references)</sup>
- Aktualne **kategorie LC (macOS 14** - Somona) zostały odtworzone, a ich [**opisy można znaleźć tutaj**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[[7]](#references)</sup>

Na przykład Category 1 to:<sup>[[7]](#references)</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Musi znajdować się na woluminie System lub Cryptexes.
- `launch-type == 1`: Musi być usługą systemową (plist w LaunchDaemons).
- `validation-category == 1`: Plik wykonywalny systemu operacyjnego.
- `is-init-proc`: Launchd

### Odwracanie kategorii LC

Więcej informacji znajdziesz [**tutaj**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ale zasadniczo są one zdefiniowane w **AMFI (AppleMobileFileIntegrity)**, dlatego musisz pobrać Kernel Development Kit, aby uzyskać **KEXT**. Symbole zaczynające się od **`kConstraintCategory`** są **interesujące**. Po ich wyodrębnieniu otrzymasz strumień zakodowany w DER (ASN.1), który należy zdekodować za pomocą [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) albo biblioteki python-asn1 i jej skryptu `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), co zwróci bardziej zrozumiały tekst.<sup>[[3]](#references)</sup>

## Ograniczenia środowiskowe

Są to Launch Constraints skonfigurowane w **aplikacjach firm trzecich**. Deweloper może wybrać **fakty** i **operandy logiczne**, które mają być używane w jego aplikacji do ograniczenia dostępu do niej.

Możliwe jest wyliczenie ograniczeń środowiskowych aplikacji za pomocą:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

W **macOS** istnieje kilka trust caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

W iOS wygląda na to, że znajduje się on w **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> W systemie macOS działającym na urządzeniach z Apple Silicon, jeśli podpisany przez Apple binary nie znajduje się w trust cache, AMFI odmówi jego załadowania.

### Enumerating Trust Caches

Wspomniane wcześniej pliki trust cache mają format **IMG4** i **IM4P**, przy czym IM4P jest sekcją payload formatu IMG4.

Możesz użyć [**pyimg4**](https://github.com/m1stadev/PyIMG4), aby wyodrębnić payload baz danych:
```bash
# Installation
python3 -m pip install pyimg4

# Extract payloads data
cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/BaseSystemTrustCache.img4 -p /tmp/BaseSystemTrustCache.im4p
pyimg4 im4p extract -i /tmp/BaseSystemTrustCache.im4p -o /tmp/BaseSystemTrustCache.data

cp /System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4 /tmp
pyimg4 img4 extract -i /tmp/StaticTrustCache.img4 -p /tmp/StaticTrustCache.im4p
pyimg4 im4p extract -i /tmp/StaticTrustCache.im4p -o /tmp/StaticTrustCache.data

pyimg4 im4p extract -i /System/Library/Security/OSLaunchPolicyData -o /tmp/OSLaunchPolicyData.data
```
(Inną opcją może być użycie narzędzia [**img4tool**](https://github.com/tihmstar/img4tool), które będzie działać nawet na M1, mimo że wydanie jest stare, oraz na x86_64, jeśli zainstalujesz je we właściwych lokalizacjach).

Teraz możesz użyć narzędzia [**trustcache**](https://github.com/CRKatri/trustcache), aby uzyskać informacje w czytelnym formacie:
```bash
# Install
wget https://github.com/CRKatri/trustcache/releases/download/v2.0/trustcache_macos_arm64
sudo mv ./trustcache_macos_arm64 /usr/local/bin/trustcache
xattr -rc /usr/local/bin/trustcache
chmod +x /usr/local/bin/trustcache

# Run
trustcache info /tmp/OSLaunchPolicyData.data | head
trustcache info /tmp/StaticTrustCache.data | head
trustcache info /tmp/BaseSystemTrustCache.data | head

version = 2
uuid = 35EB5284-FD1E-4A5A-9EFB-4F79402BA6C0
entry count = 969
0065fc3204c9f0765049b82022e4aa5b44f3a9c8 [none] [2] [1]
00aab02b28f99a5da9b267910177c09a9bf488a2 [none] [2] [1]
0186a480beeee93050c6c4699520706729b63eff [none] [2] [2]
0191be4c08426793ff3658ee59138e70441fc98a [none] [2] [3]
01b57a71112235fc6241194058cea5c2c7be3eb1 [none] [2] [2]
01e6934cb8833314ea29640c3f633d740fc187f2 [none] [2] [2]
020bf8c388deaef2740d98223f3d2238b08bab56 [none] [2] [3]
```
Pamięć podręczna zaufania ma następującą strukturę, więc kategoria **LC jest 4. kolumną**.
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Następnie możesz użyć skryptu takiego jak [**ten**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30), aby wyodrębnić dane.

Na podstawie tych danych możesz sprawdzić aplikacje z **wartością launch constraints `0`**, czyli te, które nie są objęte ograniczeniami ([**sprawdź tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), co oznacza każda wartość).<sup>[[6]](#references)</sup>

## Ograniczanie skutków ataków

Launch Constraints ograniczyłyby kilka starszych ataków, **zapewniając, że proces nie zostanie wykonany w nieoczekiwanych warunkach:** na przykład z nieoczekiwanych lokalizacji lub po wywołaniu przez nieoczekiwany proces nadrzędny (jeśli powinien go uruchamiać wyłącznie launchd).

Ponadto Launch Constraints **ograniczają ataki downgrade**.

Nie ograniczają jednak typowych nadużyć **XPC**, wstrzyknięć kodu **Electron** ani **wstrzyknięć dylib** bez library validation (chyba że znane są team IDs, które mogą ładować biblioteki).<sup>[[3]](#references)</sup>

### Ochrona XPC Daemon

W wydaniu Sonoma istotnym elementem jest **konfiguracja odpowiedzialności** usługi XPC daemon. Usługa XPC odpowiada sama za siebie, zamiast przekazującego klienta, który byłby odpowiedzialny. Jest to udokumentowane w raporcie feedback FB13206884. Taka konfiguracja może wydawać się wadliwa, ponieważ pozwala na określone interakcje z usługą XPC:

- **Uruchamianie usługi XPC**: Jeśli uznać to za błąd, taka konfiguracja nie pozwala na zainicjowanie usługi XPC przez code atakującego.
- **Łączenie się z aktywną usługą**: Jeśli usługa XPC już działa (prawdopodobnie została aktywowana przez swoją pierwotną aplikację), nie ma przeszkód, aby się z nią połączyć.

Zastosowanie constraints do usługi XPC może być korzystne, ponieważ **ogranicza okno potencjalnych ataków**, ale nie rozwiązuje głównego problemu. Zapewnienie bezpieczeństwa usługi XPC wymaga przede wszystkim **skutecznej walidacji łączącego się klienta**. Jest to jedyna metoda wzmocnienia bezpieczeństwa usługi. Warto również zauważyć, że wspomniana konfiguracja odpowiedzialności jest obecnie aktywna, co może nie być zgodne z zamierzonym projektem.<sup>[[3]](#references)</sup>

### Ochrona Electron

Nawet jeśli wymagane jest, aby aplikacja była **otwierana przez LaunchService** (w constraints procesu nadrzędnego), można to osiągnąć za pomocą **`open`** (który może ustawiać zmienne środowiskowe) lub przy użyciu **Launch Services API** (w którym można wskazać zmienne środowiskowe).<sup>[[3]](#references)</sup>

### CVE-2025-43253 - Nadpisywanie wbudowanych constraints w czasie spawn

Launch constraints (oficjalnie **lightweight code requirements**, *LWCR*) są wymuszane przez **AMFI MAC policy**. `posix_spawn` pozwala wywołującemu przekazać dowolny blob do MAC policy za pośrednictwem **`posix_spawnattr_setmacpolicyinfo_np()`**, a AMFI akceptowało dostarczony przez wywołującego słownik LWCR tą ścieżką. Błąd polegał na tym, że **constraints dostarczone przez atakującego zastępowały wbudowane constraints pliku binarnego**, zamiast być sprawdzane dodatkowo:

- Zbuduj minimalny (nawet pusty) słownik launch-constraints.
- Ustaw **kategorię constraint na `127`** — wartość, którą AMFI dopuszcza w spawn attributes, ale której **nie wymusza**; zamiast blokować wykonanie, jedynie loguje `Launch Constraint Violation (not enforcing)`.
- Przekaż go za pomocą spawn attributes, a proces uruchomi się w kontekście, którego zabroniłyby jego rzeczywiste constraints self/parent.

Po wprowadzeniu poprawki walidowane są **zarówno constraints wbudowane, jak i dostarczone**, więc dostarczony słownik nie może już osłabiać wbudowanych constraints.<sup>[[2]](#references)</sup>

> [!TIP]
> Jest to ogólny schemat, którego należy szukać podczas audytowania egzekwowania constraints: API pozwalające niezaufanym danym *dostarczyć* policy jest zwykle interesujące, gdy silnik policy traktuje dostarczoną wartość jako zamiennik, a nie dodatkowe wymaganie.

## References

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (Live-Stream)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Bypassing Launch Constraints on macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Why won't a system app or command tool run? Launch constraints and trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Protect your Mac app with environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Description of the Launch Constraints introduced in iOS 16 (LinusHenze gist)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (theevilbit gist)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}

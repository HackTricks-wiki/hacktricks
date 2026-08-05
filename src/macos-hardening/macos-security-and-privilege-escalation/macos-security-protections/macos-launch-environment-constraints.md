# Ograniczenia uruchamiania/środowiska macOS i Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Informacje podstawowe

Ograniczenia uruchamiania w macOS wprowadzono w celu zwiększenia bezpieczeństwa poprzez **regulowanie sposobu, osoby oraz miejsca, z którego można zainicjować proces**. Wprowadzone w macOS Ventura, zapewniają framework kategoryzujący **każdy systemowy binary do odrębnych kategorii ograniczeń**, które są definiowane w **trust cache** — liście zawierającej systemowe binary oraz odpowiadające im hashe. Ograniczenia te obejmują każdy wykonywalny binary w systemie i określają zestaw **reguł** definiujących wymagania dotyczące **uruchomienia konkretnego binary**. Reguły obejmują self constraints, które binary musi spełniać, parent constraints, których musi przestrzegać jego proces nadrzędny, oraz responsible constraints, których muszą przestrzegać inne odpowiednie encje.

Mechanizm ten obejmuje również aplikacje third-party poprzez **Environment Constraints**, począwszy od macOS Sonoma, umożliwiając deweloperom ochronę aplikacji przez określenie **zestawu kluczy i wartości dla environment constraints.**

**Launch environment and library constraints** definiuje się w słownikach ograniczeń, które zapisuje się w plikach property list `launchd` albo w **oddzielnych plikach property list**, używanych podczas code signing.

Istnieją 4 typy ograniczeń:

- **Self Constraints**: Ograniczenia stosowane do **uruchomionego** binary.
- **Parent Process**: Ograniczenia stosowane do **procesu nadrzędnego procesu** (na przykład **`launchd`** uruchamiającego usługę XP)
- **Responsible Constraints**: Ograniczenia stosowane do **procesu wywołującego usługę** w komunikacji XPC
- **Library load constraints**: Library load constraints służą do selektywnego opisywania kodu, który może zostać załadowany

Gdy proces próbuje uruchomić inny proces — wywołując `execve(_:_:_:)` lub `posix_spawn(_:_:_:_:_:_:)` — system operacyjny sprawdza, czy plik **wykonywalny** spełnia swoje **własne self constraint**. Sprawdza również, czy binary procesu **nadrzędnego** spełnia **parent constraint** binary oraz czy binary procesu **odpowiedzialnego** spełnia **responsible process constraint** binary. Jeśli którekolwiek z tych launch constraints nie zostanie spełnione, system operacyjny nie uruchomi programu.

Jeśli podczas ładowania biblioteki dowolna część **library constraint** nie jest spełniona, proces **nie załaduje** biblioteki.

## Kategorie LC

LC składa się z **faktów** oraz **operacji logicznych** (and, or itd.), które łączą fakty.

[**Fakty, których może używać LC, są udokumentowane**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Na przykład:

- is-init-proc: Wartość Boolean określająca, czy executable musi być procesem inicjalizacyjnym systemu operacyjnego (`launchd`).
- is-sip-protected: Wartość Boolean określająca, czy executable musi być plikiem chronionym przez System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Wartość Boolean określająca, czy system operacyjny załadował executable z autoryzowanego, uwierzytelnionego woluminu APFS.
- `on-authorized-authapfs-volume`: Wartość Boolean określająca, czy system operacyjny załadował executable z autoryzowanego, uwierzytelnionego woluminu APFS.
- Wolumin Cryptexes
- `on-system-volume:`Wartość Boolean określająca, czy system operacyjny załadował executable z aktualnie uruchomionego woluminu systemowego.
- Wewnątrz /System...
- ...

Gdy Apple binary jest podpisywany, **przypisuje się go do kategorii LC** w ramach **trust cache**.

- **Kategorie LC w iOS 16** zostały [**odwrócone i udokumentowane tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056).<sup>[6]</sup>
- Aktualne **kategorie LC (macOS 14** - Somona) zostały odwrócone, a ich [**opisy można znaleźć tutaj**](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53).<sup>[7]</sup>

Przykładowo Kategoria 1 to:<sup>[7]</sup>
```
Category 1:
Self Constraint: (on-authorized-authapfs-volume || on-system-volume) && launch-type == 1 && validation-category == 1
Parent Constraint: is-init-proc
```
- `(on-authorized-authapfs-volume || on-system-volume)`: Musi znajdować się na woluminie System lub Cryptexes.
- `launch-type == 1`: Musi być usługą systemową (plist w LaunchDaemons).
- `validation-category == 1`: Plik wykonywalny systemu operacyjnego.
- `is-init-proc`: Launchd

### Reverse engineering kategorii LC

Więcej informacji znajdziesz [**tutaj**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ale zasadniczo są one zdefiniowane w **AMFI (AppleMobileFileIntegrity)**, więc musisz pobrać Kernel Development Kit, aby uzyskać **KEXT**. Symbole zaczynające się od **`kConstraintCategory`** są tymi **interesującymi**. Po ich wyodrębnieniu otrzymasz strumień zakodowany w formacie DER (ASN.1), który należy zdekodować za pomocą [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) lub biblioteki python-asn1 i jej skryptu `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), co pozwoli uzyskać bardziej zrozumiały tekst.<sup>[3]</sup>

## Ograniczenia środowiska

Są to skonfigurowane Launch Constraints ustawione w **aplikacjach innych firm**. Deweloper może wybrać **fakty** i **operandy logiczne**, które mają być używane w jego aplikacji do ograniczenia dostępu do niej.

Możliwe jest wyliczenie Environment Constraints aplikacji za pomocą:
```bash
codesign -d -vvvv app.app
```
## Trust Caches

W **macOS** znajduje się kilka trust caches:

- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/BaseSystemTrustCache.img4`**
- **`/System/Volumes/Preboot/*/boot/*/usr/standalone/firmware/FUD/StaticTrustCache.img4`**
- **`/System/Library/Security/OSLaunchPolicyData`**

W iOS wygląda na to, że znajduje się on w **`/usr/standalone/firmware/FUD/StaticTrustCache.img4`**.

> [!WARNING]
> W systemie macOS działającym na urządzeniach Apple Silicon, jeśli podpisany przez Apple plik binarny nie znajduje się w trust cache, AMFI odmówi jego załadowania.

### Enumerating Trust Caches

Wspomniane wcześniej pliki trust cache mają format **IMG4** i **IM4P**, przy czym IM4P jest sekcją payloadu formatu IMG4.

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
(Inną opcją może być użycie narzędzia [**img4tool**](https://github.com/tihmstar/img4tool), które uruchomi się nawet na M1, mimo że wydanie jest stare, oraz na x86_64, jeśli zainstalujesz je w odpowiednich lokalizacjach).

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
Pamięć podręczna zaufania ma następującą strukturę, więc **kategoria LC znajduje się w 4. kolumnie**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Następnie możesz użyć skryptu takiego jak [**ten**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30) do wyodrębnienia danych.

Na podstawie tych danych możesz sprawdzić aplikacje z **wartością launch constraints równą `0`**, czyli te, które nie mają ograniczeń ([**sprawdź tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), aby zobaczyć znaczenie poszczególnych wartości).<sup>[6]</sup>

## Łagodzenie ataków

Launch Constraints ograniczyłyby kilka starszych ataków, **zapewniając, że proces nie zostanie wykonany w nieoczekiwanych warunkach:** na przykład z nieoczekiwanych lokalizacji lub po wywołaniu przez nieoczekiwany proces nadrzędny (jeśli powinien go uruchamiać wyłącznie launchd).

Ponadto Launch Constraints również **ograniczają downgrade attacks**.

Nie ograniczają jednak typowych nadużyć **XPC**, wstrzykiwania kodu **Electron** ani **dylib injections** bez library validation (chyba że znane są team IDs, które mogą ładować biblioteki).<sup>[3]</sup>

### Ochrona daemonów XPC

W wydaniu Sonoma istotną kwestią jest **konfiguracja odpowiedzialności** usługi XPC daemon. Usługa XPC odpowiada sama za siebie, w przeciwieństwie do sytuacji, w której odpowiedzialność ponosi łączący się klient. Zostało to udokumentowane w raporcie feedback FB13206884. Taka konfiguracja może wydawać się wadliwa, ponieważ pozwala na określone interakcje z usługą XPC:

- **Uruchamianie usługi XPC**: Jeśli uznać to za błąd, taka konfiguracja nie pozwala na zainicjowanie usługi XPC za pomocą kodu atakującego.
- **Łączenie się z aktywną usługą**: Jeśli usługa XPC już działa (prawdopodobnie została aktywowana przez swoją oryginalną aplikację), nie ma żadnych przeszkód, aby się z nią połączyć.

Wdrożenie ograniczeń dla usługi XPC może być korzystne, ponieważ **zawężałoby okno potencjalnych ataków**, ale nie rozwiązuje głównego problemu. Zapewnienie bezpieczeństwa usługi XPC wymaga przede wszystkim **skutecznej walidacji łączącego się klienta**. Pozostaje to jedynym sposobem na wzmocnienie bezpieczeństwa usługi. Warto również zauważyć, że wspomniana konfiguracja odpowiedzialności jest obecnie aktywna, co może nie być zgodne z zamierzonym projektem.<sup>[3]</sup>

### Ochrona Electron

Nawet jeśli wymagane jest, aby aplikacja była **otwierana przez LaunchService** (w constraints procesu nadrzędnego), można to osiągnąć za pomocą **`open`** (które może ustawiać zmienne środowiskowe) lub przy użyciu **Launch Services API** (w którym można wskazać zmienne środowiskowe).<sup>[3]</sup>

### CVE-2025-43253 - Nadpisywanie wbudowanych constraints podczas spawn

Launch constraints (oficjalnie **lightweight code requirements**, *LWCR*) są egzekwowane przez **AMFI MAC policy**. `posix_spawn` pozwala wywołującemu przekazać dowolny blob do MAC policy za pośrednictwem **`posix_spawnattr_setmacpolicyinfo_np()`**, a AMFI akceptowało dostarczony przez wywołującego słownik LWCR tą ścieżką. Błąd polegał na tym, że **constraints dostarczone przez atakującego zastępowały wbudowane constraints pliku binarnego**, zamiast być sprawdzane dodatkowo:

- Utwórz minimalny (nawet pusty) słownik launch-constraints.
- Ustaw **kategorię constraint na `127`**, czyli wartość, którą AMFI akceptuje w spawn attributes, ale której **nie egzekwuje** — zamiast blokować wykonanie, jedynie rejestruje `Launch Constraint Violation (not enforcing)`.
- Przekaż go za pomocą spawn attributes, a proces uruchomi się w kontekście, którego rzeczywiste constraints self/parent by mu zabroniły.

Po wprowadzeniu poprawki walidowane są **zarówno wbudowane constraints, jak i dostarczone constraints**, więc dostarczony słownik nie może już osłabiać wbudowanych constraints.<sup>[2]</sup>

> [!TIP]
> Jest to ogólny schemat, którego należy szukać podczas audytowania egzekwowania constraints: API umożliwiające niezaufanym danym *dostarczenie* policy jest zwykle interesujące, gdy silnik policy traktuje dostarczoną wartość jako zastępstwo, a nie dodatkowy wymóg.

## Referencje

- [1] [Objective by the Sea #OBTS v6.0 Day 2 (transmisja na żywo)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Omijanie Launch Constraints w macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Dlaczego aplikacja systemowa lub narzędzie command nie chce się uruchomić? Launch constraints i trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Chroń swoją aplikację Mac za pomocą environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Opis Launch Constraints wprowadzonych w iOS 16 (gist LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (gist theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)

{{#include ../../../banners/hacktricks-training.md}}

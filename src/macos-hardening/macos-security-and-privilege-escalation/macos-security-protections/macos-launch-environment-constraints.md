# Ograniczenia Launch/Environment i Trust Cache

{{#include ../../../banners/hacktricks-training.md}}

## Podstawowe informacje

Ograniczenia launch w macOS zostały wprowadzone w celu zwiększenia bezpieczeństwa poprzez **regulowanie sposobu, osoby oraz miejsca, z którego proces może zostać uruchomiony**. Wprowadzone w macOS Ventura, zapewniają framework kategoryzujący **każdy systemowy binary do odrębnych kategorii ograniczeń**, które są zdefiniowane w **trust cache** — liście zawierającej systemowe binaries i odpowiadające im hashe. Ograniczenia te obejmują każdy wykonywalny binary w systemie i określają zestaw **reguł** definiujących wymagania dotyczące **uruchomienia konkretnego binary**. Reguły obejmują self constraints, które binary musi spełniać, parent constraints, których musi przestrzegać jego proces nadrzędny, oraz responsible constraints, których muszą przestrzegać inne odpowiednie encje.<sup>[[1]](#references)[[4]](#references)</sup>

Mechanizm ten został rozszerzony na aplikacje third-party poprzez **Environment Constraints**, począwszy od macOS Sonoma, umożliwiając developerom ochronę aplikacji przez określenie **zestawu kluczy i wartości dla environment constraints.**<sup>[[5]](#references)</sup>

**Launch environment and library constraints** definiuje się w słownikach constraints, które można zapisać w **plikach property list `launchd`** lub w **oddzielnych plikach property list**, używanych podczas code signing.<sup>[[5]](#references)</sup>

Istnieją 4 typy constraints:

- **Self Constraints**: Constraints stosowane do **uruchomionego** binary.
- **Parent Process**: Constraints stosowane do **procesu nadrzędnego procesu** (na przykład **`launchd`** uruchamiającego usługę XP)
- **Responsible Constraints**: Constraints stosowane do **procesu wywołującego usługę** w komunikacji XPC
- **Library load constraints**: Library load constraints służą do selektywnego opisywania kodu, który może zostać załadowany

Gdy proces próbuje uruchomić inny proces — poprzez wywołanie `execve(_:_:_:)` lub `posix_spawn(_:_:_:_:_:_:)` — system operacyjny sprawdza, czy plik **executable** **spełnia własne self constraint**. Sprawdza również, czy **executable** procesu **parent** **spełnia parent constraint executable**, a także czy **executable** procesu **responsible** **spełnia responsible process constraint executable**. Jeśli którekolwiek z tych launch constraints nie jest spełnione, system operacyjny nie uruchamia programu.

Jeśli podczas ładowania library dowolna część **library constraint nie jest spełniona**, proces **nie załaduje** library.

## Kategorie LC

LC składa się z **facts** oraz **operacji logicznych** (and, or...), które łączą facts.

[**Facts, których może używać LC, są udokumentowane**](https://developer.apple.com/documentation/security/defining_launch_environment_and_library_constraints). Na przykład:

- is-init-proc: Wartość Boolean określająca, czy executable musi być procesem inicjalizacyjnym systemu operacyjnego (`launchd`).
- is-sip-protected: Wartość Boolean określająca, czy executable musi być plikiem chronionym przez System Integrity Protection (SIP).
- `on-authorized-authapfs-volume:` Wartość Boolean określająca, czy system operacyjny załadował executable z autoryzowanego, uwierzytelnionego woluminu APFS.
- `on-authorized-authapfs-volume`: Wartość Boolean określająca, czy system operacyjny załadował executable z autoryzowanego, uwierzytelnionego woluminu APFS.
- Cryptexes volume
- `on-system-volume:`Wartość Boolean określająca, czy system operacyjny załadował executable z aktualnie uruchomionego system volume.
- Inside /System...
- ...

Podczas podpisywania Apple binary **przypisuje go do kategorii LC** w ramach **trust cache**.

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

Więcej informacji znajdziesz [**tutaj**](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints), ale zasadniczo są one zdefiniowane w **AMFI (AppleMobileFileIntegrity)**, więc musisz pobrać Kernel Development Kit, aby uzyskać **KEXT**. Symbole rozpoczynające się od **`kConstraintCategory`** są tymi **interesującymi**. Po ich wyodrębnieniu otrzymasz strumień zakodowany w DER (ASN.1), który musisz zdekodować za pomocą [ASN.1 Decoder](https://holtstrom.com/michael/tools/asn1decoder.php) lub biblioteki python-asn1 i jej skryptu `dump.py`, [andrivet/python-asn1](https://github.com/andrivet/python-asn1/tree/master), co zwróci bardziej zrozumiały ciąg znaków.<sup>[[3]](#references)[[8]](#references)</sup>

## Ograniczenia środowiskowe

Są to Launch Constraints skonfigurowane w **aplikacjach third-party**. Deweloper może wybrać **fakty** i **operandy logiczne**, które mają być używane w jego aplikacji, aby ograniczyć dostęp do niej.

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
> W systemie macOS działającym na urządzeniach Apple Silicon, jeśli podpisany przez Apple binary nie znajduje się w trust cache, AMFI odmówi jego załadowania.

### Enumerating Trust Caches

Wspomniane wcześniej pliki trust cache są w formacie **IMG4** i **IM4P**, przy czym IM4P jest sekcją payload formatu IMG4.

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
(Inną opcją może być użycie narzędzia [**img4tool**](https://github.com/tihmstar/img4tool), które uruchomi się nawet na M1, mimo że wydanie jest stare, a także na x86_64, jeśli zainstalujesz je we właściwych lokalizacjach).

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
Trust cache ma następującą strukturę, więc **kategoria LC to 4. kolumna**
```c
struct trust_cache_entry2 {
uint8_t cdhash[CS_CDHASH_LEN];
uint8_t hash_type;
uint8_t flags;
uint8_t constraintCategory;
uint8_t reserved0;
} __attribute__((__packed__));
```
Następnie możesz użyć skryptu, takiego jak [**ten**](https://gist.github.com/xpn/66dc3597acd48a4c31f5f77c3cc62f30), aby wyodrębnić dane.

Na podstawie tych danych możesz sprawdzić aplikacje z **wartością launch constraints równą `0`** — są to aplikacje, które nie są objęte ograniczeniami ([**sprawdź tutaj**](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056), co oznacza każda wartość).<sup>[[6]](#references)</sup>

## Ograniczanie ataków

Launch Constraints ograniczyłyby kilka starszych ataków, **upewniając się, że proces nie zostanie uruchomiony w nieoczekiwanych warunkach:** na przykład z nieoczekiwanych lokalizacji lub przez nieoczekiwany proces nadrzędny (jeśli powinien go uruchamiać wyłącznie launchd).

Ponadto Launch Constraints **ograniczają również ataki downgrade.**

Nie ograniczają jednak typowych nadużyć **XPC**, wstrzykiwania kodu **Electron** ani **wstrzykiwania dylib** bez library validation (chyba że znane są team IDs, które mogą ładować biblioteki).<sup>[[3]](#references)</sup>

### Ochrona demona XPC

W wydaniu Sonoma istotną kwestią jest **konfiguracja odpowiedzialności** usługi XPC demona. Usługa XPC odpowiada sama za siebie, zamiast pozostawiać odpowiedzialność po stronie łączącego się klienta. Zostało to opisane w raporcie feedback FB13206884. Taka konfiguracja może wydawać się wadliwa, ponieważ pozwala na określone interakcje z usługą XPC:

- **Uruchamianie usługi XPC**: Jeśli uznać to za błąd, taka konfiguracja nie pozwala na zainicjowanie usługi XPC za pomocą kodu atakującego.
- **Łączenie się z aktywną usługą**: Jeśli usługa XPC już działa (być może została aktywowana przez swoją pierwotną aplikację), nie ma przeszkód, aby się z nią połączyć.

Wdrożenie ograniczeń dla usługi XPC może być korzystne, ponieważ **zawęża okno potencjalnych ataków**, ale nie rozwiązuje głównego problemu. Zapewnienie bezpieczeństwa usługi XPC wymaga przede wszystkim **skutecznej walidacji łączącego się klienta**. Jest to jedyna metoda wzmocnienia bezpieczeństwa usługi. Warto również zauważyć, że wspomniana konfiguracja odpowiedzialności jest obecnie aktywna, co może nie być zgodne z zamierzonym projektem.<sup>[[3]](#references)</sup>

### Ochrona Electron

Nawet jeśli wymagane jest, aby aplikacja była **otwierana przez LaunchService** (w ograniczeniach procesów nadrzędnych), można to osiągnąć za pomocą **`open`** (które może ustawiać zmienne środowiskowe) lub przy użyciu **Launch Services API** (w którym można określić zmienne środowiskowe).<sup>[[3]](#references)</sup>

### CVE-2025-43253 — Nadpisywanie wbudowanych ograniczeń w czasie tworzenia procesu

Launch constraints (oficjalnie **lightweight code requirements**, *LWCR*) są egzekwowane przez **politykę MAC AMFI**. `posix_spawn` pozwala wywołującemu przekazać dowolny blob do polityki MAC za pośrednictwem **`posix_spawnattr_setmacpolicyinfo_np()`**, a AMFI akceptowało przekazany przez wywołującego słownik LWCR tą ścieżką. Błąd polegał na tym, że **ograniczenia dostarczone przez atakującego zastępowały wbudowane ograniczenia pliku binarnego**, zamiast być sprawdzane dodatkowo względem nich:

- Utwórz minimalny (nawet pusty) słownik launch constraints.
- Ustaw **kategorię ograniczenia na `127`** — wartość, którą AMFI dopuszcza w atrybutach spawn, ale której **nie egzekwuje**; zamiast blokować wykonanie, jedynie rejestruje `Launch Constraint Violation (not enforcing)`.
- Przekaż go za pomocą atrybutów spawn, a proces zostanie uruchomiony w kontekście, na który jego rzeczywiste ograniczenia self/parent nie pozwoliłyby.

Po zastosowaniu poprawki sprawdzane są **zarówno wbudowane, jak i dostarczone ograniczenia**, dlatego dostarczony słownik nie może już osłabić wbudowanego słownika.<sup>[[2]](#references)</sup>

> [!TIP]
> Podczas audytowania egzekwowania ograniczeń należy szukać następującego ogólnego schematu: API, które pozwala niezaufanym danym wejściowym *dostarczać* politykę, jest zwykle interesujące, gdy silnik polityk traktuje dostarczoną wartość jako zastępstwo, a nie dodatkowy wymóg.

## Odnośniki

- [1] [Objective by the Sea #OBTS v6.0, dzień 2 (transmisja na żywo)](https://youtu.be/f1HA5QhLQ7Y?t=24146)
- [2] [CVE-2025-43253: Omijanie Launch Constraints w macOS (wts.dev)](https://wts.dev/posts/bypassing-launch-constraints/)
- [3] [Launch and Environment Constraints Deep Dive - theevilbit](https://theevilbit.github.io/posts/launch_constraints_deep_dive/)
- [4] [Dlaczego aplikacja systemowa lub narzędzie poleceń się nie uruchamia? Launch constraints i trust caches - The Eclectic Light Company](https://eclecticlight.co/2023/06/13/why-wont-a-system-app-or-command-tool-run-launch-constraints-and-trust-caches/)
- [5] [Chroń aplikację Mac za pomocą environment constraints - WWDC23](https://developer.apple.com/videos/play/wwdc2023/10266/)
- [6] [Opis Launch Constraints wprowadzonych w iOS 16 (gist LinusHenze)](https://gist.github.com/LinusHenze/4cd5d7ef057a144cda7234e2c247c056)
- [7] [macOS Sonoma (14) Launch Constraints (gist theevilbit)](https://gist.github.com/theevilbit/a6fef1e0397425a334d064f7b6e1be53)
- [8] [Beyond the good ol` LaunchAgents - about it in here](https://theevilbit.github.io/posts/launch_constraints_deep_dive/#reversing-constraints)

{{#include ../../../banners/hacktricks-training.md}}

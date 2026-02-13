# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ta strona dokumentuje praktyczne złamanie secure-boot na wielu platformach MediaTek przez wykorzystanie luki w weryfikacji, gdy konfiguracja bootloadera urządzenia (seccfg) jest ustawiona na "unlocked". Błąd pozwala uruchomić zmodyfikowany bl2_ext na ARM EL3, aby wyłączyć weryfikację podpisów downstream, zniszczyć łańcuch zaufania i umożliwić ładowanie dowolnych niepodpisanych obrazów TEE/GZ/LK/Kernel.

> Ostrzeżenie: Modyfikacje wykonywane we wczesnej fazie rozruchu mogą trwale uszkodzić urządzenia, jeśli przesunięcia są nieprawidłowe. Zawsze zachowuj pełne zrzuty i niezawodną ścieżkę odzyskiwania.

## Dotknięty przebieg rozruchu (MediaTek)

- Normalna ścieżka: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ścieżka podatna: Gdy seccfg jest ustawiony na unlocked, Preloader może pominąć weryfikację bl2_ext. Preloader nadal skacze do bl2_ext na EL3, więc spreparowany bl2_ext może następnie załadować nieweryfikowane komponenty.

Kluczowa granica zaufania:
- bl2_ext wykonuje się na EL3 i odpowiada za weryfikację TEE, GenieZone, LK/AEE oraz kernela. Jeśli sam bl2_ext nie jest uwierzytelniony, reszta łańcucha jest trywialnie pomijalna.

## Przyczyna

Na dotkniętych urządzeniach Preloader nie wymusza uwierzytelniania partycji bl2_ext, gdy seccfg wskazuje stan "unlocked". Pozwala to na wgranie kontrolowanego przez atakującego bl2_ext, który uruchamia się na EL3.

Wewnątrz bl2_ext funkcję polityki weryfikacji można spatchować tak, aby bezwarunkowo zwracała, że weryfikacja nie jest wymagana (lub zawsze się powodzi), zmuszając łańcuch rozruchowy do akceptacji niepodpisanych obrazów TEE/GZ/LK/Kernel. Ponieważ ta modyfikacja działa na EL3, jest skuteczna nawet jeśli downstreamowe komponenty implementują własne kontrole.

## Praktyczny łańcuch ataku

1. Zdobądź partycje bootloadera (Preloader, bl2_ext, LK/AEE, itd.) przez OTA/firmware packages, EDL/DA readback lub zrzut sprzętowy.
2. Zidentyfikuj routine weryfikującą w bl2_ext i spatchuj ją, aby zawsze pominąć/zaakceptować weryfikację.
3. Wgraj zmodyfikowany bl2_ext używając fastboot, DA lub podobnych kanałów serwisowych, które nadal są dostępne na urządzeniach z unlocked seccfg.
4. Zrestartuj; Preloader skacze do spatchowanego bl2_ext na EL3, który następnie ładuje niepodpisane downstream obrazy (zmodyfikowane TEE/GZ/LK/Kernel) i wyłącza egzekwowanie podpisów.

Jeśli urządzenie jest skonfigurowane jako locked (seccfg locked), oczekuje się, że Preloader zweryfikuje bl2_ext. W takiej konfiguracji atak ten zawiedzie, chyba że istnieje inna luka pozwalająca na załadowanie niepodpisanego bl2_ext.

## Triage (expdb boot logs)

Zrób zrzut logów boot/expdb w okolicach ładowania bl2_ext. Jeśli `img_auth_required = 0` i czas weryfikacji certyfikatu wynosi ~0 ms, weryfikacja najprawdopodobniej jest pomijana.

Przykładowy wycinek logu:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Niektóre urządzenia pomijają weryfikację bl2_ext nawet gdy bootloader jest zablokowany; ścieżki wtórnego bootloadera lk2 wykazały tę samą lukę. Jeśli post-OTA Preloader loguje `img_auth_required = 1` dla bl2_ext podczas gdy urządzenie jest odblokowane, to najprawdopodobniej egzekwowanie zostało przywrócone.

## Miejsca logiki weryfikacji

- Odpowiednia kontrola zwykle znajduje się wewnątrz obrazu bl2_ext w funkcjach o nazwach podobnych do `verify_img` lub `sec_img_auth`.
- Wersja patched wymusza, aby funkcja zwracała sukces albo całkowicie pomija wywołanie weryfikacji.

Przykładowe podejście do patcha (konceptualnie):
- Zlokalizuj funkcję, która wywołuje `sec_img_auth` dla obrazów TEE, GZ, LK i kernel.
- Zastąp jej ciało stubem, który natychmiast zwraca sukces, lub nadpisz warunkowy branch obsługujący niepowodzenie weryfikacji.

Upewnij się, że patch zachowuje konfigurację stosu/ramki i zwraca oczekiwane kody statusu do wywołujących.

## Fenrir PoC workflow (Nothing/CMF)

Fenrir is a reference patching toolkit for this issue (Nothing Phone (2a) fully supported; CMF Phone 1 partially). High level:
- Place the device bootloader image as `bin/<device>.bin`.
- Build a patched image that disables the bl2_ext verification policy.
- Flash the resulting payload (fastboot helper provided).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Użyj innego kanału flashowania, jeśli fastboot jest niedostępny.

## Notatki o patchowaniu EL3

- bl2_ext wykonuje się w ARM EL3. Awaria tutaj może zbrickować urządzenie do momentu ponownego flashowania przez EDL/DA lub punkty testowe.
- Korzystaj z logowania specyficznego dla płyty/UART, aby zweryfikować ścieżkę wykonania i diagnozować awarie.
- Zachowaj kopie zapasowe wszystkich modyfikowanych partycji i testuj najpierw na sprzęcie jednorazowym.

## Implikacje

- Wykonanie kodu w EL3 po Preloaderze i całkowite złamanie łańcucha zaufania dla reszty ścieżki rozruchu.
- Możliwość uruchamiania niepodpisanego TEE/GZ/LK/Kernel, omijając mechanizmy secure/verified boot i umożliwiając trwałe przejęcie.

## Notatki o urządzeniach

- Potwierdzone obsługiwane: Nothing Phone (2a) (Pacman)
- Działa (obsługa niepełna): CMF Phone 1 (Tetris)
- Zaobserwowano: Vivo X80 Pro podobno nie weryfikował bl2_ext nawet gdy był zablokowany
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ponownie włączyło weryfikację bl2_ext; fenrir `pacman-v2.0` przywraca obejście przez zmieszanie beta Preloader z załatanym LK
- Relacje branżowe wskazują dodatkowych dostawców opartych na lk2 wysyłających ten sam błąd logiczny, więc spodziewaj się większego nakładania się w wydaniach MTK w latach 2024–2025.

## MTK DA odczyt i manipulacja seccfg za pomocą Penumbra

Penumbra is a Rust crate/CLI/TUI that automates interaction with MTK preloader/bootrom over USB for DA-mode operations. Mając fizyczny dostęp do podatnego urządzenia (zezwolone rozszerzenia DA), może wykryć port USB MTK, załadować blob Download Agent (DA) i wydać uprzywilejowane polecenia takie jak przełączanie blokady seccfg i odczyt partycji.

- **Środowisko/konfiguracja sterowników**: Na Linuxie zainstaluj `libudev`, dodaj użytkownika do grupy `dialout` i utwórz reguły udev lub uruchom z `sudo`, jeśli węzeł urządzenia nie jest dostępny. Obsługa Windows jest niestabilna; czasami działa tylko po zastąpieniu sterownika MTK WinUSB za pomocą Zadig (zgodnie z wytycznymi projektu).
- **Workflow**: Odczytaj payload DA (np. `std::fs::read("../DA_penangf.bin")`), sondować port MTK za pomocą `find_mtk_port()`, i zbudować sesję używając `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Po tym jak `init()` zakończy handshake i zbierze informacje o urządzeniu, sprawdź zabezpieczenia przez bitfield `dev_info.target_config()` (bit 0 ustawiony → SBC włączony). Wejdź w tryb DA i spróbuj `set_seccfg_lock_state(LockFlag::Unlock)` — to powiedzie się tylko jeśli urządzenie akceptuje rozszerzenia. Partycje można zrzucić przy użyciu `read_partition("lk_a", &mut progress_cb, &mut writer)` do analizy offline lub patchowania.
- **Wpływ na bezpieczeństwo**: Udane odblokowanie seccfg ponownie otwiera ścieżki flashowania dla niepodpisanych obrazów rozruchowych, umożliwiając trwałe kompromitacje, takie jak opisane powyżej patchowanie bl2_ext w EL3. Odczyt partycji dostarcza artefaktów firmware do reverse engineering i tworzenia zmodyfikowanych obrazów.

<details>
<summary>Sesja Rust DA + odblokowanie seccfg + zrzut partycji (Penumbra)</summary>
```rust
use tokio::fs::File;
use anyhow::Result;
use penumbra::{DeviceBuilder, LockFlag, find_mtk_port};
use tokio::io::{AsyncWriteExt, BufWriter};

#[tokio::main]
async fn main() -> Result<()> {
let da = std::fs::read("../DA_penangf.bin")?;
let mtk_port = loop {
if let Some(port) = find_mtk_port().await {
break port;
}
};

let mut dev = DeviceBuilder::default()
.with_mtk_port(mtk_port)
.with_da_data(da)
.build()?;

dev.init().await?;
let cfg = dev.dev_info.target_config().await;
println!("SBC: {}", (cfg & 0x1) != 0);

dev.set_seccfg_lock_state(LockFlag::Unlock).await?;

let mut progress = |_read: usize, _total: usize| {};
let mut writer = BufWriter::new(File::create("lk_a.bin")?);
dev.read_partition("lk_a", &mut progress, &mut writer).await?;
writer.flush().await?;
Ok(())
}
```
</details>

## Źródła

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [Penumbra – MTK DA flash/readback & seccfg tooling](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}

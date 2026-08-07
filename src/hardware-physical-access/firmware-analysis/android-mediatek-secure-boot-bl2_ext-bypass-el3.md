# Ominięcie Secure-Boot bl2_ext MediaTek (wykonanie kodu EL3)

{{#include ../../banners/hacktricks-training.md}}

Ta strona opisuje praktyczne przełamanie Secure-Boot na wielu platformach MediaTek poprzez wykorzystanie luki w procesie weryfikacji, występującej, gdy konfiguracja bootloadera urządzenia (seccfg) ma stan „unlocked”. Luka umożliwia uruchomienie zmodyfikowanego bl2_ext na poziomie ARM EL3 w celu wyłączenia dalszej weryfikacji podpisów, co łamie łańcuch zaufania i pozwala na ładowanie dowolnych niepodpisanych obrazów TEE/GZ/LK/Kernel.<sup>[[1]](#references)</sup>

> Uwaga: modyfikowanie wczesnego etapu uruchamiania może trwale zbrickować urządzenie, jeśli offsety będą nieprawidłowe. Zawsze zachowuj pełne dumpy i niezawodną metodę odzyskiwania.

## Podatny przebieg uruchamiania (MediaTek)

- Normalna ścieżka: BootROM → Preloader → bl2_ext (EL3, zweryfikowany) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Podatna ścieżka: Gdy seccfg ma stan unlocked, Preloader może pominąć weryfikację bl2_ext. Preloader nadal wykonuje skok do bl2_ext na poziomie EL3, dlatego spreparowany bl2_ext może następnie ładować niezweryfikowane komponenty.

Kluczowa granica zaufania:
- bl2_ext działa na poziomie EL3 i odpowiada za weryfikację TEE, GenieZone, LK/AEE oraz kernela. Jeśli sam bl2_ext nie jest uwierzytelniony, pozostałą część łańcucha można łatwo ominąć.<sup>[[1]](#references)</sup>

## Przyczyna źródłowa

Na podatnych urządzeniach Preloader nie wymusza uwierzytelniania partycji bl2_ext, gdy seccfg wskazuje stan „unlocked”. Umożliwia to sflashowanie kontrolowanego przez atakującego bl2_ext, który działa na poziomie EL3.

Wewnątrz bl2_ext funkcję odpowiedzialną za politykę weryfikacji można zmodyfikować tak, aby bezwarunkowo zwracała informację, że weryfikacja nie jest wymagana (lub że zawsze kończy się powodzeniem), zmuszając łańcuch uruchamiania do akceptowania niepodpisanych obrazów TEE/GZ/LK/Kernel. Ponieważ ta modyfikacja działa na poziomie EL3, jest skuteczna nawet wtedy, gdy dalsze komponenty implementują własne kontrole.<sup>[[1]](#references)</sup>

## Praktyczny łańcuch wykorzystania

1. Uzyskaj partycje bootloadera (Preloader, bl2_ext, LK/AEE itd.) za pośrednictwem pakietów OTA/firmware, odczytu EDL/DA lub dumpowania sprzętowego.
2. Zidentyfikuj procedurę weryfikacji bl2_ext i zmodyfikuj ją tak, aby zawsze pomijała lub akceptowała weryfikację.
3. Sflashuj zmodyfikowany bl2_ext za pomocą fastboot, DA lub podobnych kanałów serwisowych, które nadal są dozwolone na odblokowanych urządzeniach.
4. Uruchom ponownie urządzenie; Preloader wykonuje skok do zmodyfikowanego bl2_ext na poziomie EL3, a ten ładuje następnie niepodpisane obrazy (zmodyfikowane TEE/GZ/LK/Kernel) i wyłącza wymuszanie podpisów.<sup>[[1]](#references)</sup>

Jeśli urządzenie jest skonfigurowane jako zablokowane (seccfg locked), Preloader powinien zweryfikować bl2_ext. W tej konfiguracji atak zakończy się niepowodzeniem, chyba że inna luka umożliwi załadowanie niepodpisanego bl2_ext.

## Triage (logi uruchamiania expdb)

- Zrzuć logi boot/expdb dotyczące ładowania bl2_ext. Jeśli `img_auth_required = 0`, a czas weryfikacji certyfikatu wynosi około 0 ms, weryfikacja prawdopodobnie została pominięta.<sup>[[1]](#references)</sup>

Przykładowy fragment logu:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
- Niektóre urządzenia pomijają weryfikację bl2_ext nawet po zablokowaniu; ścieżki wtórnego bootloadera lk2 wykazywały tę samą lukę. Jeśli Preloader po OTA loguje `img_auth_required = 1` dla bl2_ext, gdy urządzenie jest odblokowane, prawdopodobnie przywrócono egzekwowanie.<sup>[[1]](#references)[[2]](#references)</sup>

## Lokalizacje logiki weryfikacji

- Odpowiednie sprawdzenie zazwyczaj znajduje się wewnątrz obrazu bl2_ext, w funkcjach o nazwach podobnych do `verify_img` lub `sec_img_auth`.
- Spatchowana wersja wymusza, aby funkcja zwracała sukces, albo całkowicie pomija wywołanie weryfikacji.<sup>[[1]](#references)</sup>

Przykładowe podejście do patchowania (koncepcyjne):
- Zlokalizuj funkcję, która wywołuje `sec_img_auth` dla obrazów TEE, GZ, LK i kernela.
- Zastąp jej ciało stubem, który natychmiast zwraca sukces, albo nadpisz gałąź warunkową obsługującą niepowodzenie weryfikacji.

Upewnij się, że patch zachowuje konfigurację stosu/ramki oraz zwraca oczekiwane kody statusu do funkcji wywołujących.<sup>[[1]](#references)</sup>

## Workflow Fenrir PoC (Nothing/CMF)

Fenrir to referencyjny toolkit do patchowania tego problemu (Nothing Phone (2a) jest w pełni obsługiwany; CMF Phone 1 częściowo).<sup>[[1]](#references)</sup> W skrócie:
- Umieść obraz bootloadera urządzenia jako `bin/<device>.bin`.
- Zbuduj spatchowany obraz, który wyłącza politykę weryfikacji bl2_ext.
- Sflashuj wynikowy payload (dostępny jest helper fastboot).
```bash
./build.sh pacman                    # build from bin/pacman.bin
./build.sh pacman /path/to/boot.bin  # build from a custom bootloader path
./flash.sh                           # flash via fastboot
```
Użyj innego kanału flashowania, jeśli fastboot jest niedostępny.

## Uwagi dotyczące patchowania EL3

- bl2_ext wykonuje się w ARM EL3. Crashe w tym miejscu mogą zbrickować urządzenie do czasu ponownego flashowania przez EDL/DA lub test points.
- Użyj logowania/UART specyficznego dla płyty, aby zweryfikować ścieżkę wykonania i diagnozować crashe.
- Zachowaj backupy wszystkich modyfikowanych partycji i najpierw testuj na sprzęcie przeznaczonym do takich prób.<sup>[[1]](#references)</sup>

## Implikacje

- Wykonywanie kodu EL3 po Preloaderze oraz całkowite załamanie chain-of-trust dla pozostałej części ścieżki bootowania.
- Możliwość uruchamiania niepodpisanych TEE/GZ/LK/Kernel, z pominięciem założeń secure/verified boot i umożliwieniem persistent compromise.<sup>[[1]](#references)</sup>

## Uwagi dotyczące urządzeń

- Potwierdzone wsparcie: Nothing Phone (2a) (Pacman)
- Znane działające urządzenie (niepełne wsparcie): CMF Phone 1 (Tetris)
- Zaobserwowano: Vivo X80 Pro podobno nie weryfikował bl2_ext nawet po zablokowaniu<sup>[[1]](#references)</sup>
- NothingOS 4 stable (BP2A.250605.031.A3, listopad 2025) ponownie włączył weryfikację bl2_ext; fenrir `pacman-v2.0` przywraca bypass, mieszając beta Preloader z patched LK<sup>[[3]](#references)</sup>
- Omówienie branżowe wskazuje na dodatkowych vendorów opartych na lk2, którzy dostarczają ten sam logic flaw, więc należy spodziewać się dalszego nakładania się problemu w wydaniach MTK z lat 2024–2025.<sup>[[2]](#references)[[4]](#references)</sup>

## Odczyt MTK DA i manipulacja seccfg za pomocą Penumbra

Penumbra to crate/CLI/TUI w Rust, który automatyzuje interakcję z MTK preloader/bootrom przez USB na potrzeby operacji w trybie DA. Przy fizycznym dostępie do podatnego handsetu (z dozwolonymi rozszerzeniami DA) może wykryć port MTK USB, załadować blob Download Agent (DA) i wykonywać uprzywilejowane polecenia, takie jak przełączanie blokady seccfg oraz odczyt partycji.<sup>[[5]](#references)</sup>

- **Konfiguracja środowiska/sterownika**: W systemie Linux zainstaluj `libudev`, dodaj użytkownika do grupy `dialout` i utwórz reguły udev lub uruchom program z `sudo`, jeśli node urządzenia jest niedostępny. Wsparcie systemu Windows jest zawodne; czasami działa dopiero po zastąpieniu sterownika MTK przez WinUSB za pomocą Zadig (zgodnie ze wskazówkami projektu).
- **Workflow**: Odczytaj payload DA (np. `std::fs::read("../DA_penangf.bin")`), odpytywać port MTK za pomocą `find_mtk_port()` i zbudować sesję używając `DeviceBuilder::with_mtk_port(...).with_da_data(...)`. Po zakończeniu przez `init()` handshake'u i zebraniu informacji o urządzeniu sprawdź zabezpieczenia za pomocą pól bitowych `dev_info.target_config()` (ustawiony bit 0 → SBC włączone). Wejdź w tryb DA i spróbuj wykonać `set_seccfg_lock_state(LockFlag::Unlock)` — powiedzie się to tylko wtedy, gdy urządzenie akceptuje rozszerzenia. Partycje można zrzucać za pomocą `read_partition("lk_a", &mut progress_cb, &mut writer)` w celu przeprowadzenia offline analysis lub patchowania.
- **Wpływ na bezpieczeństwo**: Pomyślne odblokowanie seccfg ponownie otwiera ścieżki flashowania dla niepodpisanych boot images, umożliwiając persistent compromises, takie jak opisane powyżej patchowanie bl2_ext EL3. Odczyt partycji dostarcza artefaktów firmware do reverse engineeringu i tworzenia zmodyfikowanych obrazów.

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

## References

- [1] [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [2] [Cyber Security News – Wydano PoC Exploit dla podatności umożliwiającej wykonanie kodu w Nothing Phone](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [3] [Wydanie Fenrir pacman-v2.0 (pakiet bypass dla NothingOS 4)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [4] [The Cyber Express – PoC Fenrir łamie secure boot w Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)
- [5] [Penumbra – narzędzia MTK DA do flash/readback i seccfg](https://github.com/shomykohai/penumbra)

{{#include ../../banners/hacktricks-training.md}}

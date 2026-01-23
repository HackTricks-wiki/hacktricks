# MediaTek bl2_ext — obejście Secure-Boot (wykonanie kodu w EL3)

{{#include ../../banners/hacktricks-training.md}}

Ta strona dokumentuje praktyczne złamanie secure-boot na wielu platformach MediaTek poprzez nadużycie luki w weryfikacji, gdy konfiguracja bootloadera urządzenia (seccfg) jest ustawiona na "odblokowany". Błąd pozwala uruchomić zmodyfikowany bl2_ext na ARM EL3 w celu wyłączenia dalszej weryfikacji podpisów, co załamuje łańcuch zaufania i umożliwia wczytywanie dowolnych, niepodpisanych TEE/GZ/LK/Kernel.

> Uwaga: Łatanie wczesnego etapu bootowania może trwale uszkodzić urządzenia, jeśli offsety są błędne. Zawsze zachowaj pełne zrzuty i niezawodną ścieżkę odzyskiwania.

## Dotknięty proces bootowania (MediaTek)

- Normalna ścieżka: BootROM → Preloader → bl2_ext (EL3, zweryfikowany) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ścieżka podatna: Gdy seccfg jest ustawiony jako odblokowany, Preloader może pominąć weryfikację bl2_ext. Preloader nadal skacze do bl2_ext na EL3, więc spreparowany bl2_ext może następnie załadować nieweryfikowane komponenty.

Kluczowa granica zaufania:
- bl2_ext wykonuje się na EL3 i odpowiada za weryfikację TEE, GenieZone, LK/AEE i kernela. Jeśli sam bl2_ext nie jest uwierzytelniony, reszta łańcucha jest trywialnie obejściem.

## Przyczyna

Na dotkniętych urządzeniach Preloader nie wymusza uwierzytelnienia partycji bl2_ext, gdy seccfg wskazuje stan "odblokowany". To pozwala na wgranie kontrolowanego przez atakującego bl2_ext, który uruchamia się na EL3.

W samym bl2_ext funkcję polityki weryfikacji można załatać tak, by bezwarunkowo zgłaszała, że weryfikacja nie jest wymagana. Minimalna koncepcyjna łatka to:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
W wyniku tej zmiany wszystkie późniejsze obrazy (TEE, GZ, LK/AEE, Kernel) są akceptowane bez weryfikacji kryptograficznej, gdy są ładowane przez załatany bl2_ext działający w EL3.

## Jak przeprowadzić triage celu (expdb logs)

Zrzutuj/przeanalizuj logi rozruchu (np. expdb) w okolicach ładowania bl2_ext. Jeśli img_auth_required = 0 i czas weryfikacji certyfikatu wynosi ~0 ms, wymuszanie prawdopodobnie jest wyłączone i urządzenie jest podatne.

Przykładowy fragment logu:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Note: Niektóre urządzenia podobno pomijają weryfikację bl2_ext nawet przy locked bootloader, co potęguje skutki.

Urządzenia, które są dostarczane z lk2 secondary bootloader, zostały zaobserwowane z tą samą luką logiczną, więc pobierz expdb logs dla partycji bl2_ext i lk2, aby potwierdzić, czy którakolwiek ścieżka egzekwuje podpisy zanim podejmiesz porting.

Jeśli post-OTA Preloader teraz loguje img_auth_required = 1 dla bl2_ext nawet gdy seccfg jest unlocked, dostawca najprawdopodobniej zamknął lukę — zobacz uwagi o OTA persistence poniżej.

## Praktyczny proces eksploatacji (Fenrir PoC)

Fenrir is a reference exploit/patching toolkit dla tej klasy problemów. Obsługuje Nothing Phone (2a) (Pacman) i wiadomo, że działa (incompletely supported) na CMF Phone 1 (Tetris). Porting do innych modeli wymaga reverse engineering device-specific bl2_ext.

Ogólny proces:
- Pobierz device bootloader image dla docelowego codename i umieść go jako `bin/<device>.bin`
- Zbuduj patched image, który wyłącza politykę weryfikacji bl2_ext
- Flash the resulting payload na urządzenie (skrypt pomocniczy zakłada fastboot)

Commands:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
Jeśli fastboot jest niedostępny, musisz użyć odpowiedniej alternatywnej metody flashowania dla swojej platformy.

### OTA-patched firmware: utrzymanie bypassu przy życiu (NothingOS 4, koniec 2025)

Nothing załatało Preloader w stabilnym OTA NothingOS 4 z listopada 2025 (build BP2A.250605.031.A3), aby wymusić weryfikację bl2_ext nawet gdy seccfg jest odblokowany. Fenrir `pacman-v2.0` działa ponownie, mieszając podatny Preloader z NOS 4 beta ze stabilnym LK payload:
```bash
# on Nothing Phone (2a), unlocked bootloader, in bootloader (not fastbootd)
fastboot flash preloader_a preloader_raw.img   # beta Preloader bundled with fenrir release
fastboot flash lk pacman-fenrir.bin            # patched LK containing stage hooks
fastboot reboot                                # factory reset may be needed
```
Important:
- Flash the provided Preloader **only** to the matching device/slot; a wrong preloader is an instant hard brick.
- Check expdb after flashing; img_auth_required should drop back to 0 for bl2_ext, confirming that the vulnerable Preloader is executing before your patched LK.
- If future OTAs patch both Preloader and LK, keep a local copy of a vulnerable Preloader to re‑introduce the gap.

### Build automation & payload debugging

- `build.sh` now auto-downloads and exports the Arm GNU Toolchain 14.2 (aarch64-none-elf) the first time you run it, so you do not have to juggle cross-compilers manually.
- Export `DEBUG=1` before invoking `build.sh` to compile payloads with verbose serial prints, which greatly helps when you are blind-patching EL3 code paths.
- Successful builds drop both `lk.patched` and `<device>-fenrir.bin`; the latter already has the payload injected and is what you should flash/boot-test.

## Runtime payload capabilities (EL3)

A patched bl2_ext payload can:
- Register custom fastboot commands
- Control/override boot mode
- Dynamically call built‑in bootloader functions at runtime
- Spoof “lock state” as locked while actually unlocked to pass stronger integrity checks (some environments may still require vbmeta/AVB adjustments)

Limitation: Current PoCs note that runtime memory modification may fault due to MMU constraints; payloads generally avoid live memory writes until this is resolved.

## Payload staging patterns (EL3)

Fenrir splits its instrumentation into three compile-time stages: stage1 runs before `platform_init()`, stage2 runs before LK signals fastboot entry, and stage3 executes immediately before LK loads Linux. Each device header under `payload/devices/` provides the addresses for these hooks plus fastboot helper symbols, so keep those offsets synchronized with your target build.

Stage2 is a convenient location to register arbitrary `fastboot oem` verbs:
```c
void cmd_r0rt1z2(const char *arg, void *data, unsigned int sz) {
video_printf("r0rt1z2 was here...\n");
fastboot_info("pwned by r0rt1z2");
fastboot_okay("");
}

__attribute__((section(".text.main"))) void main(void) {
fastboot_register("oem r0rt1z2", cmd_r0rt1z2, true, false);
notify_enter_fastboot();
}
```
Stage3 demonstruje, jak tymczasowo zmodyfikować atrybuty tablicy stron, aby zmienić niemodyfikowalne ciągi znaków, takie jak ostrzeżenie Androida “Orange State”, bez potrzeby dostępu do downstream kernel:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Ponieważ stage1 wykonuje się przed bring-up platformy, jest to odpowiednie miejsce na wywołanie OEM power/reset primitives lub dodanie dodatkowego logowania integralności, zanim verified boot chain zostanie przerwana.

## Wskazówki przy portowaniu

- Zrewersuj device-specific bl2_ext, aby zlokalizować logikę polityki weryfikacji (np. sec_get_vfy_policy).
- Zidentyfikuj miejsce zwrotu polityki lub gałąź decyzyjną i załatuj je tak, by zwracały „no verification required” (return 0 / unconditional allow).
- Zachowaj offsets całkowicie specyficzne dla urządzenia i firmware; nie używaj ponownie adresów między wariantami.
- Najpierw waliduj na jednostce poświęconej. Przygotuj plan odzyskiwania (np. EDL/BootROM loader/SoC-specific download mode) przed wgraniem.
- Urządzenia używające lk2 jako secondary bootloader lub raportujące „img_auth_required = 0” dla bl2_ext nawet będąc zablokowanymi powinny być traktowane jako wrażliwe egzemplarze tej klasy błędu; Vivo X80 Pro już był obserwowany pomijający weryfikację pomimo zgłaszanego stanu zablokowania.
- Gdy OTA zacznie egzekwować podpisy bl2_ext (img_auth_required = 1) w stanie unlocked, sprawdź, czy można wgrać starszy Preloader (często dostępny w beta OTAs), aby ponownie otworzyć lukę, a następnie uruchom ponownie fenrir z zaktualizowanymi offsets dla nowszego LK.

## Wpływ na bezpieczeństwo

- Wykonanie kodu w EL3 po Preloader oraz całkowite załamanie chain-of-trust dla reszty ścieżki rozruchu.
- Możliwość uruchomienia unsigned TEE/GZ/LK/Kernel, ominięcia oczekiwań secure/verified boot i umożliwienia trwałego kompromisu.

## Uwagi o urządzeniach

- Potwierdzono wsparcie: Nothing Phone (2a) (Pacman)
- Działa (niepełne wsparcie): CMF Phone 1 (Tetris)
- Zaobserwowano: Vivo X80 Pro rzekomo nie weryfikował bl2_ext nawet gdy był zablokowany
- NothingOS 4 stable (BP2A.250605.031.A3, Nov 2025) ponownie włączył weryfikację bl2_ext; fenrir `pacman-v2.0` przywraca bypass przez wgranie beta Preloader oraz poprawionego LK jak pokazano powyżej
- Relacje z branży wskazują na dodatkowych vendorów opartych na lk2 dostarczających ten sam błąd logiczny, więc spodziewaj się dalszego pokrycia w wydaniach MTK z lat 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)
- [Fenrir pacman-v2.0 release (NothingOS 4 bypass bundle)](https://github.com/R0rt1z2/fenrir/releases/tag/pacman-v2.0)
- [The Cyber Express – Fenrir PoC breaks secure boot on Nothing Phone 2a/CMF1](https://thecyberexpress.com/fenrir-poc-for-nothing-phone-2a-cmf1/)

{{#include ../../banners/hacktricks-training.md}}

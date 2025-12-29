# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ta strona dokumentuje praktyczne złamanie secure-boot na wielu platformach MediaTek przez wykorzystanie luki w weryfikacji, gdy konfiguracja bootloadera urządzenia (seccfg) jest "unlocked". Błąd pozwala uruchomić zmodyfikowany bl2_ext na ARM EL3 w celu wyłączenia późniejszej weryfikacji podpisów, co załamuje łańcuch zaufania i umożliwia ładowanie dowolnych niesygnowanych TEE/GZ/LK/Kernel.

> Ostrzeżenie: Wczesne łatanie procesu bootowania może trwale uszkodzić urządzenia, jeśli offsety są nieprawidłowe. Zawsze zachowuj pełne zrzuty i niezawodną ścieżkę odzyskiwania.

## Dotknięty przebieg bootowania (MediaTek)

- Normalna ścieżka: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ścieżka podatna: Gdy seccfg ustawiony jest na "unlocked", Preloader może pominąć weryfikację bl2_ext. Preloader nadal przeskakuje do bl2_ext na EL3, więc spreparowany bl2_ext może następnie załadować nieweryfikowane komponenty.

Kluczowa granica zaufania:
- bl2_ext uruchamia się na EL3 i odpowiada za weryfikację TEE, GenieZone, LK/AEE i kernela. Jeśli sam bl2_ext nie jest uwierzytelniony, reszta łańcucha jest trywialnie pomijalna.

## Przyczyna

W dotkniętych urządzeniach Preloader nie wymusza uwierzytelniania partycji bl2_ext, gdy seccfg wskazuje stan "unlocked". Pozwala to na wgranie przez atakującego bl2_ext, który uruchamia się na EL3.

W samym bl2_ext funkcję odpowiedzialną za politykę weryfikacji można załatać tak, by bezwarunkowo zgłaszała, że weryfikacja nie jest wymagana. Minimalna koncepcyjna łatka to:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Dzięki tej zmianie wszystkie kolejne obrazy (TEE, GZ, LK/AEE, Kernel) są akceptowane bez sprawdzeń kryptograficznych przy ładowaniu przez załatany bl2_ext działający na EL3.

## Jak przeprowadzić triage celu (logi expdb)

Zrzucić/przeanalizować logi rozruchowe (np. expdb) w okolicach ładowania bl2_ext. Jeśli img_auth_required = 0 i czas weryfikacji certyfikatu wynosi ~0 ms, egzekwowanie jest prawdopodobnie wyłączone i urządzenie jest podatne.

Przykładowy wycinek logu:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Uwaga: W niektórych urządzeniach podobno pomijana jest weryfikacja bl2_ext nawet przy zablokowanym bootloaderze, co potęguje skutki.

Zaobserwowano urządzenia dostarczane z secondary bootloaderem lk2 z tą samą luką logiczną, więc pobierz logi expdb dla partycji bl2_ext i lk2, aby potwierdzić, czy któraś ze ścieżek wymusza podpisy, zanim spróbujesz portować.

## Praktyczny przebieg eksploatacji (Fenrir PoC)

Fenrir jest referencyjnym exploit/patching toolkit dla tej klasy problemu. Obsługuje Nothing Phone (2a) (Pacman) i jest znany z działania (nie w pełni wspierany) na CMF Phone 1 (Tetris). Portowanie na inne modele wymaga reverse engineeringu specyficznego dla urządzenia bl2_ext.

Proces w skrócie:
- Pobierz obraz bootloadera urządzenia dla docelowej nazwy kodowej i umieść go jako `bin/<device>.bin`
- Zbuduj zmodyfikowany obraz, który wyłącza politykę weryfikacji bl2_ext
- Wgraj wynikowy payload na urządzenie (skrypt pomocniczy zakłada fastboot)

Polecenia:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by the helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

### Automatyzacja budowy i debugowanie payloadów

- `build.sh` teraz przy pierwszym uruchomieniu automatycznie pobiera i eksportuje Arm GNU Toolchain 14.2 (aarch64-none-elf), więc nie musisz ręcznie żonglować cross-kompilatorami.
- Eksportuj `DEBUG=1` przed wywołaniem `build.sh`, aby skompilować payloady z rozbudowanymi wydrukami na serialu, co bardzo pomaga przy blind-patchowaniu ścieżek kodu EL3.
- Pomyślne buildy generują zarówno `lk.patched`, jak i `<device>-fenrir.bin`; ten ostatni ma już wstrzyknięty payload i to on powinien być flashowany/testowany na boot.

## Możliwości payloadu w czasie wykonywania (EL3)

Zmodyfikowany payload bl2_ext może:
- Rejestrować niestandardowe polecenia fastboot
- Kontrolować/przesłonić tryb bootowania
- Dynamicznie wywoływać wbudowane funkcje bootloadera w czasie wykonywania
- Podszywać się pod “lock state” jako locked, podczas gdy w rzeczywistości jest unlocked, aby przejść silniejsze sprawdzanie integralności (w niektórych środowiskach nadal mogą być wymagane modyfikacje vbmeta/AVB)

Ograniczenie: Obecne PoCs odnotowują, że modyfikacja pamięci w czasie wykonywania może powodować faulty z powodu ograniczeń MMU; payloady zazwyczaj unikają zapisywania w pamięci na żywo, dopóki to nie zostanie rozwiązane.

## Wzorce stagingu payloadu (EL3)

Fenrir dzieli swoją instrumentację na trzy etapy wykonywane w czasie kompilacji: stage1 uruchamia się przed `platform_init()`, stage2 uruchamia się przed sygnalizacją wejścia do fastboot przez LK, a stage3 wykonuje się tuż przed załadowaniem Linux przez LK. Każdy nagłówek urządzenia w `payload/devices/` podaje adresy tych hooków oraz symbole pomocnicze fastboot, więc utrzymuj te offsety zsynchronizowane z docelowym buildem.

Stage2 to wygodne miejsce, aby zarejestrować dowolne `fastboot oem` polecenia:
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
Stage3 demonstruje, jak tymczasowo przełączyć atrybuty tabeli stron, aby załatać niemodyfikowalne ciągi, takie jak Android’s “Orange State” warning, bez konieczności dostępu do downstream kernel:
```c
set_pte_rwx(0xFFFF000050f9E3AE);
strcpy((char *)0xFFFF000050f9E3AE, "Patched by stage3");
```
Ponieważ stage1 uruchamia się przed startem platformy, jest to właściwe miejsce, aby wywołać OEM-owe prymitywy zasilania/resetu lub wstawić dodatkowe logowanie integralności zanim zweryfikowany łańcuch rozruchowy zostanie zniszczony.

## Wskazówki dotyczące portowania

- Reverse engineer specyficzny dla urządzenia bl2_ext, aby zlokalizować logikę polityki weryfikacji (np. sec_get_vfy_policy).
- Zidentyfikuj punkt zwrotu polityki lub gałąź decyzyjną i popraw ją tak, aby ustawić “no verification required” (return 0 / unconditional allow).
- Zachowaj offsety w pełni specyficzne dla urządzenia i firmware’u; nie używaj ponownie adresów między wariantami.
- Najpierw przetestuj na jednostce poświęconej. Przygotuj plan odzyskiwania (np. EDL/BootROM loader/SoC-specific download mode) zanim wgrasz (flash).
- Urządzenia używające sekundarnego bootloadera lk2 lub zgłaszające “img_auth_required = 0” dla bl2_ext nawet gdy są zablokowane powinny być traktowane jako podatne kopie tej klasy błędu; Vivo X80 Pro już odnotowano, że pomijał weryfikację pomimo zgłaszanego stanu zablokowania.
- Porównaj logi expdb z obu stanów — zablokowanego i odblokowanego — jeśli czasowanie certyfikatu skacze z 0 ms do wartości niezerowej po ponownym zablokowaniu, prawdopodobnie załatałeś właściwy punkt decyzyjny, ale nadal musisz wzmocnić spoofing stanu blokady, żeby ukryć modyfikację.

## Wpływ na bezpieczeństwo

- Wykonanie kodu w EL3 po Preloaderze i całkowite załamanie łańcucha zaufania dla reszty ścieżki rozruchu.
- Możliwość uruchomienia niepodpisanego TEE/GZ/LK/Kernel, omijając mechanizmy secure/verified boot i umożliwiając trwałe przejęcie.

## Uwagi o urządzeniach

- Potwierdzone: Nothing Phone (2a) (Pacman)
- Znane działające (niepełne wsparcie): CMF Phone 1 (Tetris)
- Zaobserwowano: Vivo X80 Pro podobno nie weryfikował bl2_ext nawet gdy był zablokowany
- Zasięg w branży wskazuje na dodatkowych dostawców opartych na lk2 wysyłających ten sam błąd logiczny, więc spodziewaj się dalszego nakładania się w wydaniach MTK w latach 2024–2025.

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)
- [Cyber Security News – PoC Exploit Released For Nothing Phone Code Execution Vulnerability](https://cybersecuritynews.com/nothing-phone-code-execution-vulnerability/)

{{#include ../../banners/hacktricks-training.md}}

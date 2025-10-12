# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ta strona dokumentuje praktyczne złamanie secure-boot na wielu platformach MediaTek poprzez wykorzystanie luki w weryfikacji, gdy konfiguracja bootloadera urządzenia (seccfg) jest ustawiona na "unlocked". Błąd pozwala uruchomić zmodyfikowany bl2_ext na ARM EL3, aby wyłączyć weryfikację podpisów downstream, zniszczyć łańcuch zaufania i umożliwić ładowanie dowolnych niepodpisanych komponentów TEE/GZ/LK/Kernel.

> Uwaga: Wczesne poprawki rozruchu mogą trwale uszkodzić urządzenia, jeśli offsety są nieprawidłowe. Zawsze zachowuj pełne zrzuty oraz niezawodną ścieżkę odzyskiwania.

## Dotknięty przebieg rozruchu (MediaTek)

- Normalny przebieg: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ścieżka podatna: Gdy seccfg jest ustawione na "unlocked", Preloader może pominąć weryfikację bl2_ext. Preloader nadal przeskakuje do bl2_ext na EL3, więc spreparowany bl2_ext może następnie załadować nieweryfikowane komponenty.

Kluczowa granica zaufania:
- bl2_ext wykonuje się na EL3 i odpowiada za weryfikację TEE, GenieZone, LK/AEE oraz kernela. Jeśli sam bl2_ext nie jest uwierzytelniony, resztę łańcucha zaufania można w prosty sposób obejść.

## Przyczyna

W dotkniętych urządzeniach Preloader nie wymusza uwierzytelniania partycji bl2_ext, gdy seccfg wskazuje stan "unlocked". To pozwala wgrać bl2_ext kontrolowany przez atakującego, który działa na EL3.

Wewnątrz bl2_ext funkcję polityki weryfikacji można załatać tak, aby bezwarunkowo zgłaszała, że weryfikacja nie jest wymagana. Minimalna konceptualna poprawka wygląda następująco:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Z tą zmianą wszystkie kolejne obrazy (TEE, GZ, LK/AEE, Kernel) są akceptowane bez kontroli kryptograficznych przy ładowaniu przez załatany bl2_ext działający na EL3.

## How to triage a target (expdb logs)

Zrzuć / sprawdź logi rozruchu (np. expdb) wokół ładowania bl2_ext. Jeśli img_auth_required = 0 i certificate verification time ≈ 0 ms, wymuszanie prawdopodobnie jest wyłączone i urządzenie jest podatne.

Example log excerpt:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Uwaga: Niektóre urządzenia podobno pomijają weryfikację bl2_ext nawet przy zablokowanym bootloaderze, co potęguje skutki.

## Praktyczny przebieg eksploatacji (Fenrir PoC)

Fenrir jest referencyjnym zestawem narzędzi exploit/patching dla tej klasy problemu. Obsługuje Nothing Phone (2a) (Pacman) i jest znany jako działający (nie w pełni wspierany) na CMF Phone 1 (Tetris). Portowanie na inne modele wymaga reverse engineering specyficznego dla danego urządzenia bl2_ext.

High-level process:
- Pobierz obraz bootloadera urządzenia dla docelowego codename i umieść go jako bin/<device>.bin
- Zbuduj załatany obraz, który wyłącza politykę weryfikacji bl2_ext
- Wgraj powstały payload na urządzenie (skrypt pomocniczy zakłada użycie fastboot)

Polecenia:
```bash
# Build patched image (default path bin/[device].bin)
./build.sh pacman

# Build from a custom bootloader path
./build.sh pacman /path/to/your/bootloader.bin

# Flash the resulting lk.patched (fastboot required by helper script)
./flash.sh
```
If fastboot is unavailable, you must use a suitable alternative flashing method for your platform.

## Możliwości payloadu w czasie wykonania (EL3)

A patched bl2_ext payload can:
- Rejestrować niestandardowe polecenia fastboot
- Kontrolować/nadpisywać tryb rozruchu
- Dynamicznie wywoływać wbudowane funkcje bootloadera w czasie wykonania
- Fałszować “lock state” jako locked podczas gdy faktycznie jest unlocked, aby przejść silniejsze kontrole integralności (w niektórych środowiskach mogą być nadal wymagane dostosowania vbmeta/AVB)

Ograniczenie: Obecne PoCs zauważają, że modyfikacja pamięci w czasie wykonania może powodować błędy z powodu ograniczeń MMU; payloady generalnie unikają zapisywania pamięci na żywo, dopóki to nie zostanie rozwiązane.

## Wskazówki dotyczące portowania

- Wykonaj reverse engineering specyficznego dla urządzenia bl2_ext, aby zlokalizować logikę polityki weryfikacji (np. sec_get_vfy_policy).
- Zidentyfikuj miejsce zwrotu polityki lub gałąź decyzyjną i zapatchuj ją na “no verification required” (return 0 / unconditional allow).
- Utrzymuj offsety całkowicie specyficzne dla urządzenia i firmware; nie używaj ponownie adresów między wariantami.
- Najpierw zweryfikuj na jednostce testowej. Przygotuj plan odzyskiwania (np. EDL/BootROM loader/SoC-specific download mode) zanim wykonasz flash.

## Wpływ na bezpieczeństwo

- Wykonanie kodu w EL3 po Preloader i całkowite złamanie chain-of-trust dla pozostałej ścieżki rozruchu.
- Możliwość uruchomienia unsigned TEE/GZ/LK/Kernel, omijając oczekiwania secure/verified boot i umożliwiając trwałe przejęcie.

## Pomysły na wykrywanie i utwardzanie

- Upewnij się, że Preloader weryfikuje bl2_ext niezależnie od stanu seccfg.
- Wymuszaj wyniki uwierzytelniania i zbieraj dowody audytu (czasy > 0 ms, surowe błędy przy niezgodności).
- Fałszowanie lock-state powinno być nieskuteczne względem attestation (powiąż lock state z decyzjami weryfikacji AVB/vbmeta oraz stanem opartym na fuse).

## Notatki dotyczące urządzeń

- Potwierdzone obsługiwane: Nothing Phone (2a) (Pacman)
- Znane działające (wsparcie niepełne): CMF Phone 1 (Tetris)
- Zaobserwowano: Vivo X80 Pro podobno nie weryfikował bl2_ext nawet gdy był locked

## Referencje

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}

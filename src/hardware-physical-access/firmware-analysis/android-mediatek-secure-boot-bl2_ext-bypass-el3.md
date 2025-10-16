# MediaTek bl2_ext Secure-Boot Bypass (EL3 Code Execution)

{{#include ../../banners/hacktricks-training.md}}

Ta strona dokumentuje praktyczne obejście secure-boutu na wielu platformach MediaTek przez nadużycie luki w weryfikacji, gdy konfiguracja bootloadera (seccfg) jest "unlocked". Błąd pozwala na uruchomienie zmodyfikowanego bl2_ext na ARM EL3 w celu wyłączenia dalszej weryfikacji podpisów, co załamuje łańcuch zaufania i umożliwia ładowanie dowolnych niepodpisanych TEE/GZ/LK/Kernel.

> Uwaga: Wczesne łatanie bootu może trwale uszkodzić urządzenia, jeśli offsety są błędne. Zawsze zachowuj pełne zrzuty i niezawodną ścieżkę odzyskiwania.

## Dotknięty przebieg rozruchu (MediaTek)

- Normalna ścieżka: BootROM → Preloader → bl2_ext (EL3, verified) → TEE → GenieZone (GZ) → LK/AEE → Linux kernel (EL1)
- Ścieżka podatna: When seccfg is set to unlocked, Preloader may skip verifying bl2_ext. Preloader still jumps into bl2_ext at EL3, so a crafted bl2_ext can load unverified components thereafter.

Główna granica zaufania:
- bl2_ext wykonuje się na EL3 i odpowiada za weryfikację TEE, GenieZone, LK/AEE i kernela. Jeśli sam bl2_ext nie jest uwierzytelniony, reszta łańcucha jest trywialnie obejściem.

## Przyczyna

Na dotkniętych urządzeniach Preloader nie wymusza uwierzytelnienia partycji bl2_ext, gdy seccfg wskazuje stan "unlocked". Pozwala to na wgranie kontrolowanego przez atakującego bl2_ext, który działa na EL3.

W samym bl2_ext funkcja polityki weryfikacji może zostać zpatchowana, aby bezwarunkowo zgłaszać, że weryfikacja nie jest wymagana. Minimalny konceptualny patch to:
```c
// inside bl2_ext
int sec_get_vfy_policy(...) {
return 0; // always: "no verification required"
}
```
Dzięki tej zmianie wszystkie kolejne obrazy (TEE, GZ, LK/AEE, Kernel) są akceptowane bez weryfikacji kryptograficznej podczas ładowania przez załatany bl2_ext działający na EL3.

## Jak przeanalizować cel (logi expdb)

Zrzut/przegląd logów rozruchu (np. expdb) wokół momentu ładowania bl2_ext. Jeśli img_auth_required = 0 i czas weryfikacji certyfikatu to ~0 ms, mechanizm wymuszania prawdopodobnie jest wyłączony i urządzenie jest podatne.

Przykładowy fragment logu:
```
[PART] img_auth_required = 0
[PART] Image with header, name: bl2_ext, addr: FFFFFFFFh, mode: FFFFFFFFh, size:654944, magic:58881688h
[PART] part: lk_a img: bl2_ext cert vfy(0 ms)
```
Uwaga: Niektóre urządzenia podobno pomijają weryfikację bl2_ext nawet przy zablokowanym bootloaderze, co pogłębia skutki.

## Practical exploitation workflow (Fenrir PoC)

Fenrir to referencyjny exploit/patching toolkit dla tej klasy problemu. Obsługuje Nothing Phone (2a) (Pacman) i jest znany jako działający (częściowo obsługiwany) na CMF Phone 1 (Tetris). Portowanie na inne modele wymaga reverse engineeringu specyficznego dla urządzenia bl2_ext.

High-level process:
- Pobierz obraz bootloadera urządzenia dla docelowego codename i umieść go jako bin/<device>.bin
- Zbuduj poprawiony obraz, który wyłącza politykę weryfikacji bl2_ext
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
If fastboot jest niedostępny, musisz użyć odpowiedniej alternatywnej metody flashowania dla swojej platformy.

## Możliwości payloadu w czasie działania (EL3)

Patched bl2_ext payload może:
- Zarejestrować niestandardowe polecenia fastboot
- Kontrolować/nadpisywać boot mode
- Dynamicznie wywoływać wbudowane funkcje bootloadera w czasie działania
- Podszyć się pod "lock state" jako zablokowany, podczas gdy faktycznie jest odblokowany, aby przejść silniejsze kontrole integralności (w niektórych środowiskach nadal mogą być potrzebne korekty vbmeta/AVB)

Ograniczenie: Obecne PoCs wskazują, że modyfikacja pamięci w czasie działania może powodować błędy z powodu ograniczeń MMU; payloady zazwyczaj unikają zapisu do żywej pamięci, dopóki to nie zostanie rozwiązane.

## Wskazówki dotyczące portowania

- Zreverse'uj urządzeniowy bl2_ext, aby zlokalizować logikę polityki weryfikacji (np. sec_get_vfy_policy).
- Zidentyfikuj miejsce zwrotu polityki lub gałąź decyzyjną i załatuj ją tak, aby wymagała „no verification required” (return 0 / unconditional allow).
- Zachowaj offsety specyficzne dla urządzenia i firmware; nie używaj ponownie adresów między wariantami.
- Waliduj na urządzeniu do testów najpierw. Przygotuj plan awaryjny (np. EDL/BootROM loader/SoC-specific download mode) zanim flashujesz.

## Wpływ na bezpieczeństwo

- Wykonanie kodu w EL3 po Preloader i całkowity collapse chain-of-trust dla reszty ścieżki bootowania.
- Możliwość uruchomienia unsigned TEE/GZ/LK/Kernel, obejście secure/verified boot oraz umożliwienie trwałego kompromisu.

## Pomysły na wykrywanie i hardening

- Zapewnij, że Preloader weryfikuje bl2_ext niezależnie od stanu seccfg.
- Egzekwuj wyniki uwierzytelniania i zbieraj dowody audytu (timings > 0 ms, strict errors on mismatch).
- Lock-state spoofing powinien być nieskuteczny dla attestation (powiąż lock state z decyzjami weryfikacji AVB/vbmeta oraz fuse-backed state).

## Informacje o urządzeniach

- Potwierdzone wspierane: Nothing Phone (2a) (Pacman)
- Znane działające (wsparcie niepełne): CMF Phone 1 (Tetris)
- Zaobserwowane: Vivo X80 Pro podobno nie weryfikował bl2_ext nawet gdy był zablokowany

## References

- [Fenrir – MediaTek bl2_ext secure‑boot bypass (PoC)](https://github.com/R0rt1z2/fenrir)

{{#include ../../banners/hacktricks-training.md}}

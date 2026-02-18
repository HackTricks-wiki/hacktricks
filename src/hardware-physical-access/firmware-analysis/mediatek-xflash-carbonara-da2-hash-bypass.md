# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Podsumowanie

"Carbonara" nadużywa ścieżki pobierania XFlash od MediaTek, aby uruchomić zmodyfikowany Download Agent stage 2 (DA2) pomimo kontroli integralności DA1. DA1 przechowuje oczekiwany SHA-256 DA2 w RAM i porównuje go przed skokiem. W wielu loaderach host w pełni kontroluje adres/rozmiar ładowania DA2, co daje niezabezpieczony zapis do pamięci, który może nadpisać ten hash w pamięci i przekierować wykonanie do dowolnych payloadów (kontekst przed-OS, z unieważnianiem cache obsługiwanym przez DA).

## Granica zaufania w XFlash (DA1 → DA2)

- **DA1** jest podpisany/ładowany przez BootROM/Preloader. Gdy Download Agent Authorization (DAA) jest włączone, powinien uruchamiać się tylko podpisany DA1.
- **DA2** jest przesyłany przez USB. DA1 otrzymuje **size**, **load address**, i **SHA-256** i hashuje otrzymany DA2, porównując go do **oczekiwanego hasha osadzonego w DA1** (skopiowanego do RAM).
- **Słabość:** W niezałatanych loaderach DA1 nie sanityzuje adresu/rozmiaru ładowania DA2 i pozostawia oczekiwany hash zapisywalny w pamięci, umożliwiając hostowi manipulację sprawdzeniem.

## Przebieg Carbonara ("two BOOT_TO" trick)

1. **Pierwszy `BOOT_TO`:** Wejście w etap przygotowania DA1→DA2 (DA1 alokuje, przygotowuje DRAM i udostępnia w RAM bufor z oczekiwanym hashem).
2. **Nadpisanie slotu hasha:** Wyślij mały payload, który skanuje pamięć DA1 w poszukiwaniu przechowywanego oczekiwanego hasha DA2 i nadpisuje go SHA-256 zmodyfikowanego przez atakującego DA2. Wykorzystuje to kontrolowane przez użytkownika ładowanie, aby umieścić payload tam, gdzie znajduje się hash.
3. **Drugi `BOOT_TO` + digest:** Wywołaj kolejny `BOOT_TO` z załatanymi metadanymi DA2 i wyślij surowy 32-bajtowy digest odpowiadający zmodyfikowanemu DA2. DA1 ponownie oblicza SHA-256 dla otrzymanego DA2, porównuje go z obecnie załatanym oczekiwanym hashem i skok do kodu atakującego się udaje.

Ponieważ adres/rozmiar ładowania są kontrolowane przez atakującego, ten sam prymityw może zapisywać w dowolnym miejscu w pamięci (nie tylko w buforze hasha), umożliwiając implanty działające na wczesnym etapie bootu, narzędzia do obejścia secure-boot lub złośliwe rootkity.

## Minimalny wzorzec PoC (w stylu mtkclient)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- `payload` replikuje blob z paid-tool, który patchuje bufor expected-hash wewnątrz DA1.
- `sha256(...).digest()` wysyła surowe bajty (nie hex), więc DA1 porównuje je z zapatchowanym buforem.
- DA2 może być dowolnym obrazem stworzonym przez atakującego; wybór adresu/rozmiaru ładowania pozwala na arbitralne umieszczenie w pamięci, przy czym invalidacja cache jest obsługiwana przez DA.

## Krajobraz poprawek (zabezpieczone loadery)

- **Mitigacja**: Zaktualizowane DAs na stałe ustawiają adres ładowania DA2 na `0x40000000` i ignorują adres dostarczany przez hosta, więc zapisy nie mogą dotrzeć do slotu hasza DA1 (w przybliżeniu zakres ~0x200000). Hasz nadal jest obliczany, ale nie jest już zapisywalny przez atakującego.
- **Wykrywanie załatanych DAs**: mtkclient/penumbra skanują DA1 w poszukiwaniu wzorców wskazujących na utwardzenie adresów; jeśli zostanie wykryte, Carbonara jest pomijana. Stare DAs ujawniają zapisywalne sloty hasza (zwykle wokół offsetów takich jak `0x22dea4` w V5 DA1) i pozostają podatne.
- **V5 vs V6**: Niektóre V6 (XML) loadery wciąż akceptują adresy podane przez użytkownika; nowsze binaria V6 zwykle egzekwują stały adres i są odporne na Carbonara, chyba że zostaną cofnięte do starszej wersji.

## Uwaga po Carbonara (heapb8)

MediaTek załatał Carbonara; nowsza podatność, **heapb8**, celuje w handler pobierania plików USB DA2 w załatanych loaderach V6, umożliwiając wykonanie kodu nawet gdy `boot_to` jest utwardzone. Wykorzystuje przepełnienie heap podczas transferów plików podzielonych na kawałki, aby przejąć przepływ sterowania DA2. Exploit jest publiczny w Penumbra/mtk-payloads i pokazuje, że poprawki Carbonara nie zamykają całej powierzchni ataku DA.

## Notatki dla triage i hardeningu

- Urządzenia, w których adres/rozmiar DA2 nie są sprawdzane i DA1 utrzymuje oczekiwany hash jako zapisywalny, są podatne. Jeśli późniejszy Preloader/DA wymusza granice adresów lub utrzymuje hash jako niezmienny, Carbonara jest załatwiona.
- Włączenie DAA oraz zapewnienie, że DA1/Preloader walidują parametry BOOT_TO (granice + autentyczność DA2), zamyka tę prymitywną możliwość. Zamknięcie jedynie łatki hasza bez ograniczenia ładowania nadal pozostawia ryzyko arbitralnego zapisu.

## Referencje

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}

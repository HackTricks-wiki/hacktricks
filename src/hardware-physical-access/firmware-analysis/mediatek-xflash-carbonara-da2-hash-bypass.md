# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Podsumowanie

"Carbonara" wykorzystuje ścieżkę pobierania XFlash firmy MediaTek, aby uruchomić zmodyfikowany Download Agent stage 2 (DA2) pomimo kontroli integralności DA1. DA1 przechowuje oczekiwany SHA-256 DA2 w RAM i porównuje go przed rozgałęzieniem. W wielu loaderach host w pełni kontroluje adres ładowania/rozmiar DA2, co daje niesprawdzony zapis do pamięci, który może nadpisać ten hash w pamięci i przekierować wykonanie do dowolnego payloadu (kontekst pre-OS z cache invalidation obsługiwanym przez DA).

## Granica zaufania w XFlash (DA1 → DA2)

- **DA1** jest podpisany/załadowany przez BootROM/Preloader. Gdy Download Agent Authorization (DAA) jest włączone, powinien uruchamiać się tylko podpisany DA1.
- **DA2** jest wysyłany przez USB. DA1 otrzymuje **size**, **load address**, i **SHA-256** oraz haszuje otrzymany DA2, porównując go z **oczekiwanym hashem osadzonym w DA1** (skopiowanym do RAM).
- **Słabość:** W niezałatanych loaderach DA1 nie weryfikuje adresu/rozmiaru ładowania DA2 i pozostawia oczekiwany hash możliwym do zapisu w pamięci, umożliwiając hostowi manipulację tym sprawdzeniem.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Wejście do przepływu staging DA1→DA2 (DA1 alokuje, przygotowuje DRAM i udostępnia bufor oczekiwanego hasha w RAM).
2. **Hash-slot overwrite:** Wyślij mały payload, który skanuje pamięć DA1 w poszukiwaniu przechowywanego oczekiwanego hasha DA2 i nadpisuje go SHA-256 zmodyfikowanego przez atakującego DA2. Wykorzystuje to kontrolowane przez hosta ładowanie, aby umieścić payload tam, gdzie znajduje się hash.
3. **Second `BOOT_TO` + digest:** Wywołaj kolejny `BOOT_TO` z załatanymi metadanymi DA2 i wyślij surowy 32-bajtowy digest odpowiadający zmodyfikowanemu DA2. DA1 ponownie oblicza SHA-256 na otrzymanym DA2, porównuje go z teraz załatanym oczekiwanym hashem i skok wykonuje się do kodu atakującego.

Ponieważ adres/rozmiar ładowania są kontrolowane przez atakującego, ten sam prymityw może zapisywać w dowolnym miejscu w pamięci (nie tylko w buforze hasha), umożliwiając implanty na wczesnym etapie bootu, pomocniki do obejścia secure-boot lub złośliwe rootkity.

## Minimal PoC pattern (mtkclient-style)
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
- `payload` replikuje blob z płatnego narzędzia, który modyfikuje bufor expected-hash wewnątrz DA1.
- `sha256(...).digest()` wysyła surowe bajty (nie hex), więc DA1 porównuje je z załatanym buforem.
- DA2 może być dowolnym obrazem stworzonym przez atakującego; wybór adresu/rozmiaru ładowania pozwala na dowolne umieszczenie w pamięci, przy czym unieważnianie pamięci podręcznej jest obsługiwane przez DA.

## Uwagi dotyczące triage i hardeningu

- Urządzenia, w których adres/rozmiar DA2 nie są sprawdzane, a DA1 pozostawia expected hash zapisywalnym, są podatne. Jeśli późniejszy Preloader/DA wymusza ograniczenia adresów lub utrzymuje hash jako niezmienny, Carbonara jest złagodzona.
- Włączenie DAA i zapewnienie, że DA1/Preloader walidują parametry BOOT_TO (bounds + autentyczność DA2) zamyka tę prymitywę. Zablokowanie tylko modyfikacji hasha bez ograniczenia ładowania nadal pozostawia ryzyko arbitrary write.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}

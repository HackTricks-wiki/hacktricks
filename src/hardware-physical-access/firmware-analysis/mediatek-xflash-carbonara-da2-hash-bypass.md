# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Podsumowanie

„Carbonara” wykorzystuje ścieżkę pobierania MediaTek XFlash do uruchomienia zmodyfikowanego etapu 2 Download Agent (DA2) pomimo kontroli integralności DA1. DA1 przechowuje w RAM oczekiwany SHA-256 DA2 i porównuje go przed wykonaniem skoku. W wielu loaderach host w pełni kontroluje adres i rozmiar ładowania DA2, co zapewnia niezabezpieczony zapis do pamięci, który może nadpisać ten hash znajdujący się w RAM i przekierować wykonanie do dowolnych payloadów (w kontekście pre-OS, z unieważnianiem cache obsługiwanym przez DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Granica zaufania w XFlash (DA1 → DA2)

- **DA1** jest podpisywany/ładowany przez BootROM/Preloader. Gdy funkcja Download Agent Authorization (DAA) jest włączona, powinien zostać uruchomiony wyłącznie podpisany DA1.
- **DA2** jest przesyłany przez USB. DA1 odbiera **rozmiar**, **adres ładowania** i **SHA-256**, a następnie oblicza hash odebranego DA2 i porównuje go z **oczekiwanym hashem osadzonym w DA1** (skopiowanym do RAM).
- **Słabość:** W niezałatanych loaderach DA1 nie weryfikuje adresu ani rozmiaru ładowania DA2 i pozostawia oczekiwany hash jako zapisywalny obszar pamięci, umożliwiając hostowi manipulowanie kontrolą.<sup>[[1]](#references)[[2]](#references)</sup>

## Przebieg Carbonara (sztuczka „two BOOT_TO”)

1. **Pierwszy `BOOT_TO`:** Wejdź w przepływ stagingu DA1→DA2 (DA1 przydziela pamięć, przygotowuje DRAM i udostępnia w RAM bufor oczekiwanego hasha).
2. **Nadpisanie slotu hasha:** Wyślij mały payload, który przeszukuje pamięć DA1 w poszukiwaniu zapisanego oczekiwanego hasha DA2 i nadpisuje go wartością SHA-256 zmodyfikowanego przez atakującego DA2. Wykorzystuje to kontrolowane przez użytkownika ładowanie, aby umieścić payload w miejscu, w którym znajduje się hash.
3. **Drugi `BOOT_TO` + digest:** Wyzwól kolejny `BOOT_TO` ze zmodyfikowanymi metadanymi DA2 i wyślij surowy 32-bajtowy digest odpowiadający zmodyfikowanemu DA2. DA1 ponownie oblicza SHA-256 odebranego DA2, porównuje go z teraz zmodyfikowanym oczekiwanym hashem, a następnie pomyślnie wykonuje skok do kodu atakującego.

Ponieważ adres i rozmiar ładowania są kontrolowane przez atakującego, ten sam prymityw może zapisywać w dowolnym miejscu pamięci (nie tylko w buforze hasha), umożliwiając implanty uruchamiane na wczesnym etapie bootowania, helpery omijające secure boot lub złośliwe rootkity.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` odtwarza blob płatnego narzędzia, który patchuje bufor oczekiwanego hash wewnątrz DA1.
- `sha256(...).digest()` wysyła surowe bajty (nie hex), dzięki czemu DA1 porównuje je ze spatchowanym buforem.
- DA2 może być dowolnym obrazem utworzonym przez atakującego; wybór adresu/rozmiaru ładowania umożliwia umieszczenie danych w dowolnym miejscu pamięci, a DA zajmuje się unieważnieniem cache.<sup>[[3]](#references)</sup>

## Krajobraz patchy (zahardenowane loadery)

- **Mitigation**: Zaktualizowane DA wpisują na stałe adres ładowania DA2 jako `0x40000000` i ignorują adres dostarczony przez hosta, więc zapisy nie mogą dotrzeć do slotu hash DA1 (zakres około `0x200000`). Hash nadal jest obliczany, ale nie można go już modyfikować przez atakującego.
- **Wykrywanie spatchowanych DA**: mtkclient/penumbra skanują DA1 pod kątem wzorców wskazujących na zahardenowanie adresu; jeśli je znajdą, Carbonara jest pomijany. Stare DA udostępniają zapisywalne sloty hash (często w okolicach offsetów takich jak `0x22dea4` w V5 DA1) i pozostają podatne na exploit.
- **V5 vs V6**: Niektóre loadery V6 (XML) nadal akceptują adresy podane przez użytkownika; nowsze binaria V6 zwykle wymuszają stały adres i są odporne na Carbonara, chyba że zostaną downgraded.<sup>[[2]](#references)[[3]](#references)</sup>

## Uwaga dotycząca okresu po Carbonara (heapb8)

MediaTek załatał Carbonara; nowsza podatność, **heapb8**, atakuje handler pobierania plików przez USB w spatchowanych loaderach V6, zapewniając wykonanie kodu nawet wtedy, gdy `boot_to` jest zahardenowane. Wykorzystuje przepełnienie sterty podczas transferów plików w chunkach, aby przejąć przepływ sterowania DA2. Exploit jest publicznie dostępny w Penumbra/mtk-payloads i pokazuje, że poprawki Carbonara nie zamykają całej powierzchni ataku DA.<sup>[[4]](#references)</sup>

## Uwagi dotyczące triage i hardeningu

- Urządzenia, w których adres/rozmiar DA2 nie są sprawdzane, a DA1 zachowuje zapisywalny expected hash, są podatne. Jeśli późniejszy Preloader/DA wymusza ograniczenia adresu lub utrzymuje hash jako niemodyfikowalny, Carbonara jest mitigated.
- Włączenie DAA oraz zapewnienie, że DA1/Preloader weryfikują parametry BOOT_TO (zakresy + autentyczność DA2), zamyka ten primitive. Samo zamknięcie możliwości patchowania hash bez ograniczenia miejsca ładowania nadal pozostawia ryzyko dowolnego zapisu.

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}

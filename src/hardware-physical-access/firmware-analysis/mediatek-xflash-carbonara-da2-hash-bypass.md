# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Podsumowanie

„Carbonara” wykorzystuje ścieżkę pobierania MediaTek XFlash do uruchomienia zmodyfikowanego etapu 2 Download Agent (DA2) pomimo kontroli integralności DA1. DA1 przechowuje w RAM oczekiwany SHA-256 DA2 i porównuje go przed przekazaniem wykonania. W wielu loaderach host w pełni kontroluje adres i rozmiar ładowania DA2, co daje niekontrolowany zapis do pamięci, umożliwiający nadpisanie znajdującego się w pamięci hasha i przekierowanie wykonania do dowolnych payloadów (kontekst pre-OS z unieważnianiem cache obsługiwanym przez DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Granica zaufania w XFlash (DA1 → DA2)

- **DA1** jest podpisywany/ładowany przez BootROM/Preloader. Gdy włączone jest Download Agent Authorization (DAA), powinien uruchomić się wyłącznie podpisany DA1.
- **DA2** jest przesyłany przez USB. DA1 otrzymuje **rozmiar**, **adres ładowania** i **SHA-256**, a następnie oblicza hash odebranego DA2, porównując go z **oczekiwanym hashem osadzonym w DA1** (skopiowanym do RAM).
- **Słabość:** W niezałatanych loaderach DA1 nie sanitizuje adresu ani rozmiaru ładowania DA2 i pozostawia oczekiwany hash zapisywalny w pamięci, umożliwiając hostowi manipulację kontrolą.<sup>[[1]](#references)[[2]](#references)</sup>

## Przebieg Carbonara (trik „two BOOT_TO”)

1. **Pierwsze `BOOT_TO`:** Wejście w ścieżkę stagingu DA1→DA2 (DA1 alokuje pamięć, przygotowuje DRAM i udostępnia bufor oczekiwanego hasha w RAM).
2. **Nadpisanie slotu hasha:** Wyślij mały payload, który skanuje pamięć DA1 w poszukiwaniu zapisanego oczekiwanego hasha DA2 i nadpisuje go wartością SHA-256 zmodyfikowanego przez atakującego DA2. Wykorzystuje to kontrolowane przez użytkownika ładowanie, aby umieścić payload w miejscu, w którym znajduje się hash.
3. **Drugie `BOOT_TO` + digest:** Wyzwól kolejne `BOOT_TO` ze zmodyfikowanymi metadanymi DA2 i wyślij surowy 32-bajtowy digest odpowiadający zmodyfikowanemu DA2. DA1 ponownie oblicza SHA-256 odebranego DA2, porównuje go z teraz zmodyfikowanym oczekiwanym hashem, a następnie pomyślnie przekazuje wykonanie do kodu atakującego.

W zaatakowanych loaderach niekontrolowany adres i rozmiar mogą zapewnić atakującemu wybraną przez niego pre-OS prymitywę zapisu do pamięci wykraczającą poza slot hasha. W zależności od mapy pamięci SoC i kolejnych etapów weryfikacji może to umożliwiać implanty wczesnego rozruchu, helpery do omijania secure boot lub payloady w stylu rootkita. Samo wykonanie kodu DA nie zapewnia automatycznie persistence ani kompletnego obejścia secure boot; nadal wymagany jest oddzielny mechanizm persistence i zgodny łańcuch weryfikacji.<sup>[[1]](#references)[[2]](#references)</sup>

## Minimalny schemat PoC (w stylu mtkclient)
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
- 16-bajtowy `payload` odtwarza blob zaobserwowany w workflow płatnego narzędzia i używany przez opublikowaną implementację do patchowania bufora oczekiwanego hasha. Jest specyficzny dla loadera, a nie przenośnym patchem slotu hasha dla każdego SoC lub DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` wysyła surowe bajty (nie hex), aby DA1 porównał je ze spatchowanym buforem.
- W podatnym, dopasowanym loaderze DA2 może być obrazem utworzonym przez atakującego, a wybrane metadane ładowania kontrolują jego rozmieszczenie w pamięci. Przed transmisją należy zweryfikować kombinację DA/SoC, ponieważ nieprawidłowe adresy mogą zawiesić lub uszkodzić cel.<sup>[[3]](#references)</sup>

## Krajobraz patchy (hardened loaders)

- **Zaobserwowana mitigacja**: Zbadane przez badaczy hardened DAs wymuszają adres ładowania DA2 `0x40000000` i ignorują adres dostarczony przez hosta, zapobiegając zapisom do zaobserwowanego obszaru hasha DA1 w pobliżu `0x200000`. Oba adresy należy traktować jako specyficzne dla implementacji, a nie jako stałe architektoniczne.
- **Wykrywanie patched DAs**: mtkclient/penumbra skanują DA1 pod kątem wzorców wskazujących na address-hardening; jeśli zostaną znalezione, Carbonara jest pomijana. Stare DAs udostępniają zapisywalne sloty hasha (zwykle w pobliżu offsetów takich jak `0x22dea4` w V5 DA1) i nadal są exploitable.
- **V5 vs V6**: Niektóre loadery V6 (XML) nadal akceptują adresy dostarczone przez użytkownika; nowsze binaria V6 zwykle wymuszają stały adres i są odporne na Carbonara, chyba że zostaną downgraded.<sup>[[2]](#references)[[3]](#references)</sup>

## Uwaga post-Carbonara (heapb8)

MediaTek spatchował Carbonara; nowsza podatność, **heapb8**, atakuje handler pobierania plików DA2 przez USB w patched V6 loaders, zapewniając code execution nawet wtedy, gdy `boot_to` jest hardened. Wykorzystuje heap overflow podczas transferów plików w chunkach, aby przejąć control flow DA2. Exploit jest publicznie dostępny w Penumbra/mtk-payloads i pokazuje, że poprawki Carbonara nie zamykają całej powierzchni ataku DA.<sup>[[4]](#references)</sup>

## Uwagi dotyczące triage i hardeningu

- Urządzenia, w których adres/rozmiar DA2 nie są sprawdzane, a DA1 zachowuje zapisywalny oczekiwany hash, są podatne. Jeśli późniejszy Preloader/DA wymusza ograniczenia adresów lub utrzymuje hash jako immutable, Carbonara jest mitigowane.
- Włączenie DAA i zapewnienie, że DA1/Preloader weryfikują parametry BOOT_TO (bounds + autentyczność DA2), zamyka primitive. Zamknięcie wyłącznie patchowania hasha bez ograniczenia ładowania nadal pozostawia ryzyko arbitrary write.

## References

- [1] [Carbonara: Exploit MediaTek, którego nikt nie obsłużył](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Dokumentacja Carbonara exploit](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Kod źródłowy Penumbra Carbonara](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploitowanie patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}

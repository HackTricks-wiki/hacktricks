# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara" missbraucht MediaTek's XFlash download path, um einen modifizierten Download Agent stage 2 (DA2) trotz DA1-Integritätsprüfungen auszuführen. DA1 speichert den erwarteten SHA-256 von DA2 im RAM und vergleicht ihn vor dem Branch. Bei vielen Loadern kontrolliert der Host vollständig die DA2 load address/size, was einen ungeprüften memory write ermöglicht, der den In-Memory-Hash überschreiben und die Ausführung auf beliebige payloads umleiten kann (pre-OS context mit cache invalidation, vom DA gehandhabt).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** wird von BootROM/Preloader signiert und geladen. Wenn Download Agent Authorization (DAA) aktiviert ist, darf nur signierter DA1 ausgeführt werden.
- **DA2** wird über USB gesendet. DA1 erhält **size**, **load address**, und **SHA-256** und hasht das empfangene DA2, vergleicht es mit einem **expected hash embedded in DA1** (in RAM kopiert).
- **Weakness:** Auf unpatched Loadern validiert DA1 die DA2 load address/size nicht und lässt den expected hash im Speicher schreibbar, wodurch der Host die Prüfung manipulieren kann.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Betritt den DA1→DA2 Staging-Flow (DA1 alloziert, bereitet DRAM vor und legt den expected-hash buffer im RAM offen).
2. **Hash-slot overwrite:** Sende eine kleine payload, die den DA1 memory nach dem gespeicherten DA2-expected hash durchsucht und diesen mit dem SHA-256 des vom Angreifer modifizierten DA2 überschreibt. Das nutzt den user-controlled load, um die payload genau dort zu platzieren, wo der Hash liegt.
3. **Second `BOOT_TO` + digest:** Löst einen weiteren `BOOT_TO` mit den gepatchten DA2-Metadaten aus und sende den rohen 32-Byte digest, der zum modifizierten DA2 passt. DA1 berechnet SHA-256 über das empfangene DA2 neu, vergleicht es mit dem jetzt gepatchten expected hash, und der Sprung in den Angreifercode gelingt.

Da load address/size vom Angreifer kontrolliert werden, kann dieselbe Primitive überall im Speicher schreiben (nicht nur in den Hash-Buffer) und so early-boot implants, secure-boot bypass helpers oder bösartige rootkits ermöglichen.

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
- `payload` repliziert den Blob des kostenpflichtigen Tools, das den expected-hash buffer innerhalb von DA1 patcht.
- `sha256(...).digest()` sendet rohe Bytes (nicht hex), sodass DA1 gegen den gepatchten Puffer vergleicht.
- DA2 kann beliebiges vom Angreifer erstelltes Image sein; die Wahl der Ladeadresse/-größe erlaubt beliebige Speicherplatzierung, wobei die Cache-Invalidierung von DA übernommen wird.

## Hinweise zur Triage und Härtung

- Geräte, bei denen DA2-Adresse/-größe nicht überprüft werden und DA1 den expected hash schreibbar belässt, sind verwundbar. Wenn ein späterer Preloader/DA Adressgrenzen durchsetzt oder den Hash unveränderlich macht, ist Carbonara mitigiert.
- Das Aktivieren von DAA und das Sicherstellen, dass DA1/Preloader die BOOT_TO-Parameter validieren (Grenzen + Authentizität von DA2), schließt das Primitive. Das bloße Schließen des Hash-Patchs ohne Begrenzung des Loads lässt weiterhin ein Risiko für willkürliche Schreibzugriffe bestehen.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}

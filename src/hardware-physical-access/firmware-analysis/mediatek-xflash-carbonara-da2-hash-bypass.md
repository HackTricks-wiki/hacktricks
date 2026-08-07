# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Vertrauensgrenze in XFlash (DA1 → DA2)

- **DA1** wird von BootROM/Preloader signiert/geladen. Wenn Download Agent Authorization (DAA) aktiviert ist, sollte nur signiertes DA1 ausgeführt werden.
- **DA2** wird über USB gesendet. DA1 empfängt **Größe**, **Ladeadresse** und **SHA-256**, hasht das empfangene DA2 und vergleicht es mit einem **erwarteten Hash**, der in DA1 eingebettet ist (und in den RAM kopiert wird).
- **Schwachstelle:** Bei ungepatchten Loadern validiert DA1 die Ladeadresse/Größe von DA2 nicht und hält den erwarteten Hash im Speicher beschreibbar, sodass der Host die Prüfung manipulieren kann.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara-Ablauf („Two-BOOT_TO“-Trick)

1. **Erstes `BOOT_TO`:** Den DA1→DA2-Staging-Ablauf starten (DA1 reserviert Speicher, bereitet DRAM vor und stellt den Puffer mit dem erwarteten Hash im RAM bereit).
2. **Überschreiben des Hash-Slots:** Ein kleines Payload senden, das den DA1-Speicher nach dem gespeicherten erwarteten DA2-Hash durchsucht und ihn mit dem SHA-256-Hash des vom Angreifer modifizierten DA2 überschreibt. Dabei wird das vom Benutzer kontrollierte Laden ausgenutzt, um das Payload an der Stelle abzulegen, an der sich der Hash befindet.
3. **Zweites `BOOT_TO` + Digest:** Ein weiteres `BOOT_TO` mit den gepatchten DA2-Metadaten auslösen und den rohen 32-Byte-Digest senden, der dem modifizierten DA2 entspricht. DA1 berechnet SHA-256 über das empfangene DA2 erneut, vergleicht es mit dem nun gepatchten erwarteten Hash, und der Sprung in den Code des Angreifers gelingt.

Da Ladeadresse und Größe vom Angreifer kontrolliert werden, kann dieselbe Primitive an eine beliebige Stelle im Speicher schreiben (nicht nur in den Hash-Puffer). Dadurch werden Early-Boot-Implants, Helfer zum Umgehen von Secure Boot oder bösartige Rootkits ermöglicht.<sup>[[1]](#references)[[2]](#references)</sup>

## Minimales PoC-Muster (mtkclient-Stil)
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
- `payload` repliziert den Blob des kostenpflichtigen Tools, der den erwarteten Hash-Puffer innerhalb von DA1 patcht.
- `sha256(...).digest()` sendet rohe Bytes (nicht hexadezimal), sodass DA1 sie mit dem gepatchten Puffer vergleicht.
- DA2 kann ein beliebiges vom Angreifer erstelltes Image sein; durch Auswahl von Ladeadresse und Größe ist eine beliebige Speicherplatzierung möglich, wobei die Cache-Invalidierung von DA übernommen wird.<sup>[[3]](#references)</sup>

## Patch-Landschaft (gehärtete Loader)

- **Gegenmaßnahme**: Aktualisierte DAs hardcodieren die DA2-Ladeadresse auf `0x40000000` und ignorieren die vom Host bereitgestellte Adresse, sodass Schreibvorgänge den DA1-Hash-Slot (~0x200000-Range) nicht erreichen können. Der Hash wird weiterhin berechnet, ist aber nicht mehr vom Angreifer beschreibbar.
- **Gepatchte DAs erkennen**: mtkclient/penumbra durchsuchen DA1 nach Mustern, die auf die Adresshärtung hinweisen; wenn sie gefunden werden, wird Carbonara übersprungen. Alte DAs stellen beschreibbare Hash-Slots bereit (häufig bei Offsets wie `0x22dea4` in V5-DA1) und bleiben ausnutzbar.
- **V5 vs. V6**: Einige V6-Loader (XML) akzeptieren weiterhin vom Benutzer bereitgestellte Adressen; neuere V6-Binaries erzwingen gewöhnlich die feste Adresse und sind gegen Carbonara immun, sofern kein Downgrade durchgeführt wird.<sup>[[2]](#references)[[3]](#references)</sup>

## Hinweis zu Post-Carbonara (heapb8)

MediaTek hat Carbonara gepatcht; eine neuere Schwachstelle namens **heapb8** zielt auf den DA2-USB-Datei-Download-Handler in gepatchten V6-Loadern und ermöglicht Code Execution, selbst wenn `boot_to` gehärtet ist. Sie missbraucht einen Heap Overflow während chunkbasierter Dateiübertragungen, um die Kontrolle über den DA2-Control-Flow zu übernehmen. Der Exploit ist in Penumbra/mtk-payloads öffentlich verfügbar und zeigt, dass Carbonara-Fixes nicht die gesamte DA-Angriffsfläche schließen.<sup>[[4]](#references)</sup>

## Hinweise für Triage und Hardening

- Geräte, bei denen DA2-Adresse/-Größe nicht geprüft werden und DA1 den erwarteten Hash beschreibbar hält, sind gefährdet. Wenn ein späterer Preloader/DA Adressgrenzen erzwingt oder den Hash unveränderlich hält, wird Carbonara mitigiert.
- Das Aktivieren von DAA und das Sicherstellen, dass DA1/Preloader die BOOT_TO-Parameter (Grenzen + Authentizität von DA2) validieren, schließt das Primitive. Nur den Hash-Patch zu schließen, ohne das Laden zu begrenzen, lässt weiterhin ein Risiko beliebiger Schreibvorgänge bestehen.

## Referenzen

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}

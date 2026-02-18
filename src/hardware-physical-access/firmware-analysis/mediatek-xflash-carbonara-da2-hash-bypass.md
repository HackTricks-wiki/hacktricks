# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Zusammenfassung

"Carbonara" missbraucht MediaTek's XFlash download path, um trotz DA1-Integritätsprüfungen eine modifizierte Download Agent stage 2 (DA2) auszuführen. DA1 speichert den erwarteten SHA-256 von DA2 im RAM und vergleicht diesen vor dem Branch. Bei vielen Loadern kontrolliert der Host die DA2 load address/size vollständig, wodurch ein unkontrollierter Speicherwrite möglich ist, der diesen im Speicher befindlichen Hash überschreiben und die Ausführung auf beliebige Payloads umleiten kann (pre-OS context with cache invalidation handled by DA).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** is signed/loaded by BootROM/Preloader. When Download Agent Authorization (DAA) is enabled, only signed DA1 should run.
- **DA2** is sent over USB. DA1 receives **size**, **load address**, and **SHA-256** and hashes the received DA2, comparing it to an **expected hash embedded in DA1** (copied into RAM).
- **Weakness:** On unpatched loaders, DA1 does not sanitize the DA2 load address/size and keeps the expected hash writable in memory, enabling the host to tamper with the check.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** Enter the DA1→DA2 staging flow (DA1 allocates, prepares DRAM, and exposes the expected-hash buffer in RAM).
2. **Hash-slot overwrite:** Send a small payload that scans DA1 memory for the stored DA2-expected hash and overwrites it with the SHA-256 of the attacker-modified DA2. This leverages the user-controlled load to land the payload where the hash resides.
3. **Second `BOOT_TO` + digest:** Trigger another `BOOT_TO` with the patched DA2 metadata and send the raw 32-byte digest matching the modified DA2. DA1 recomputes SHA-256 over the received DA2, compares it against the now-patched expected hash, and the jump succeeds into attacker code.

Because load address/size are attacker-controlled, the same primitive can write anywhere in memory (not just the hash buffer), enabling early-boot implants, secure-boot bypass helpers, or malicious rootkits.

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
- `payload` repliziert den Blob des kostenpflichtigen Tools, das den expected-hash-Buffer innerhalb von DA1 patcht.
- `sha256(...).digest()` sendet Rohbytes (nicht hex), sodass DA1 gegen den gepatchten Buffer vergleicht.
- DA2 kann jedes vom Angreifer erstellte Image sein; die Wahl von Ladeadresse/-größe erlaubt beliebige Speicherplatzierung, wobei die Cache-Invalidierung vom DA übernommen wird.

## Patch landscape (hardened loaders)

- **Abhilfemaßnahme**: Aktualisierte DAs hardcoden die DA2-Ladeadresse auf `0x40000000` und ignorieren die vom Host übergebene Adresse, sodass Schreibzugriffe nicht den DA1-Hash-Slot (etwa im Bereich `0x200000`) erreichen können. Der Hash wird weiterhin berechnet, ist aber nicht mehr vom Angreifer beschreibbar.
- **Erkennung gepatchter DAs**: mtkclient/penumbra scannen DA1 nach Mustern, die auf die Adress-Härtung hinweisen; wenn diese gefunden werden, wird Carbonara übersprungen. Alte DAs geben beschreibbare Hash-Slots preis (häufig um Offset wie `0x22dea4` in V5 DA1) und bleiben ausnutzbar.
- **V5 vs V6**: Manche V6 (XML) Loader akzeptieren weiterhin benutzerübergebene Adressen; neuere V6-Binaries erzwingen in der Regel die feste Adresse und sind gegen Carbonara immun, sofern sie nicht downgraded werden.

## Post-Carbonara (heapb8) Hinweis

MediaTek hat Carbonara gepatcht; eine neuere Schwachstelle, **heapb8**, zielt auf den DA2 USB File-Download-Handler in gepatchten V6-Loadern ab und ermöglicht Codeausführung selbst wenn `boot_to` gehärtet ist. Sie missbraucht einen Heap-Overflow während segmentierter Dateiübertragungen, um die Kontrolle über den DA2-Kontrollfluss zu übernehmen. Der Exploit ist öffentlich in Penumbra/mtk-payloads und zeigt, dass Carbonara-Fixes nicht die gesamte Angriffsfläche der DAs schließen.

## Hinweise zur Triage und Härtung

- Geräte, bei denen DA2-Adresse/-größe nicht validiert werden und DA1 den expected-hash weiterhin beschreibbar lässt, sind verwundbar. Wenn ein späterer Preloader/DA Adressgrenzen durchsetzt oder den Hash unveränderlich macht, ist Carbonara mitigiert.
- DAA zu aktivieren und sicherzustellen, dass DA1/Preloader BOOT_TO-Parameter validieren (Grenzen und Authentizität von DA2) schließt die Primitive. Nur den Hash-Patch zu schließen, ohne die Ladegrenzen zu begrenzen, lässt weiterhin das Risiko beliebiger Writes bestehen.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}

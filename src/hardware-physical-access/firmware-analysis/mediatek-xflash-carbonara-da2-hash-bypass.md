# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Zusammenfassung

„Carbonara“ missbraucht den MediaTek-XFlash-Downloadpfad, um trotz der Integritätsprüfungen von DA1 eine modifizierte Download Agent Stage 2 (DA2) auszuführen. DA1 speichert den erwarteten SHA-256-Hash von DA2 im RAM und vergleicht ihn vor dem Verzweigen. Bei vielen Loadern kontrolliert der Host die DA2-Ladeadresse und -Größe vollständig. Dadurch entsteht ein ungeprüfter Memory Write, der den im Speicher befindlichen Hash überschreiben und die Ausführung zu beliebigen Payloads umleiten kann (Pre-OS-Kontext, wobei die Cache-Invalidierung von DA übernommen wird).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust Boundary in XFlash (DA1 → DA2)

- **DA1** wird von BootROM/Preloader signiert und geladen. Wenn Download Agent Authorization (DAA) aktiviert ist, sollte nur signiertes DA1 ausgeführt werden.
- **DA2** wird über USB gesendet. DA1 empfängt **Größe**, **Ladeadresse** und **SHA-256**, hasht die empfangene DA2 und vergleicht sie mit einem **in DA1 eingebetteten erwarteten Hash**, der in den RAM kopiert wird.
- **Schwachstelle:** Bei ungepatchten Loadern bereinigt DA1 die DA2-Ladeadresse und -Größe nicht und hält den erwarteten Hash im Speicher beschreibbar. Dadurch kann der Host die Prüfung manipulieren.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara-Ablauf („two BOOT_TO“-Trick)

1. **Erstes `BOOT_TO`:** Den DA1→DA2-Staging-Ablauf starten (DA1 reserviert Speicher, bereitet DRAM vor und macht den Puffer mit dem erwarteten Hash im RAM zugänglich).
2. **Überschreiben des Hash-Slots:** Eine kleine Payload senden, die den DA1-Speicher nach dem gespeicherten erwarteten DA2-Hash durchsucht und ihn mit dem SHA-256-Hash der vom Angreifer modifizierten DA2 überschreibt. Dabei wird die benutzerkontrollierte Ladeadresse genutzt, um die Payload dort zu platzieren, wo sich der Hash befindet.
3. **Zweites `BOOT_TO` + Digest:** Ein weiteres `BOOT_TO` mit den gepatchten DA2-Metadaten auslösen und den 32 Byte großen Raw-Digest senden, der zur modifizierten DA2 passt. DA1 berechnet den SHA-256-Hash über die empfangene DA2 erneut, vergleicht ihn mit dem nun gepatchten erwarteten Hash, und der Sprung in den Angreifercode gelingt.

Bei betroffenen Loadern können die ungeprüfte Adresse und Größe eine vom Angreifer ausgewählte Pre-OS-Memory-Write-Primitive über den Hash-Slot hinaus ermöglichen. Abhängig vom SoC-Speicherabbild und späteren Verifizierungsstufen kann dies Early-Boot-Implants, Secure-Boot-Bypass-Hilfsprogramme oder Rootkit-ähnliche Payloads unterstützen. Die Codeausführung in DA allein ermöglicht nicht automatisch Persistenz oder einen vollständigen Secure-Boot-Bypass; eine separate Persistenzmethode und eine kompatible Verifizierungskette sind weiterhin erforderlich.<sup>[[1]](#references)[[2]](#references)</sup>

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
- Der 16-Byte-`payload` reproduziert den im Workflow des kostenpflichtigen Tools beobachteten Blob und wird von der veröffentlichten Implementierung verwendet, um den Buffer mit dem erwarteten Hash zu patchen. Er ist loader-spezifisch und kein portabler Patch für Hash-Slots auf jedem SoC oder DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` sendet rohe Bytes (nicht Hex), damit DA1 den gepatchten Buffer vergleicht.
- Bei einem verwundbaren, passenden Loader kann DA2 ein vom Angreifer erstelltes Image sein, und die ausgewählten Load-Metadaten steuern dessen Speicherplatzierung. Validiere die DA/SoC-Kombination vor der Übertragung, da falsche Adressen das Zielsystem zum Hängen bringen oder beschädigen können.<sup>[[3]](#references)</sup>

## Patch-Landschaft (gehärtete Loader)

- **Beobachtete Mitigation**: Die von den Forschern untersuchten gehärteten DAs erzwingen die DA2-Ladeadresse `0x40000000` und ignorieren die vom Host bereitgestellte Adresse. Dadurch werden Schreibvorgänge in den beobachteten DA1-Hash-Bereich nahe `0x200000` verhindert. Behandle beide Adressen als implementierungsspezifisch und nicht als architektonische Konstanten.
- **Gepatchte DAs erkennen**: mtkclient/penumbra scannt DA1 nach Mustern, die auf die Adress-Härtung hinweisen. Wenn solche Muster gefunden werden, wird Carbonara übersprungen. Alte DAs stellen beschreibbare Hash-Slots bereit (üblicherweise bei Offsets wie `0x22dea4` in V5 DA1) und bleiben ausnutzbar.
- **V5 vs. V6**: Einige V6- (XML-)Loader akzeptieren weiterhin vom Benutzer bereitgestellte Adressen. Neuere V6-Binaries erzwingen üblicherweise die feste Adresse und sind gegen Carbonara immun, sofern kein Downgrade durchgeführt wird.<sup>[[2]](#references)[[3]](#references)</sup>

## Hinweis zu Post-Carbonara (heapb8)

MediaTek hat Carbonara gepatcht. Eine neuere Schwachstelle namens **heapb8** zielt auf den DA2-USB-Handler für Dateidownloads in gepatchten V6-Loadern ab und ermöglicht Codeausführung, selbst wenn `boot_to` gehärtet ist. Sie missbraucht einen Heap Overflow während chunkbasierter Dateiübertragungen, um den Kontrollfluss von DA2 zu übernehmen. Der Exploit ist in Penumbra/mtk-payloads öffentlich verfügbar und zeigt, dass Carbonara-Fixes nicht die gesamte DA-Angriffsfläche schließen.<sup>[[4]](#references)</sup>

## Hinweise für Triage und Härtung

- Geräte, bei denen DA2-Adresse/-Größe nicht geprüft werden und DA1 den erwarteten Hash beschreibbar hält, sind verwundbar. Wenn ein späterer Preloader/DA Adressgrenzen erzwingt oder den Hash unveränderlich hält, ist Carbonara mitigiert.
- Das Aktivieren von DAA und das Sicherstellen, dass DA1/Preloader die BOOT_TO-Parameter (Grenzen + Authentizität von DA2) validieren, schließt das Primitive. Wird nur der Hash-Patch geschlossen, ohne das Laden zu begrenzen, bleibt das Risiko beliebiger Schreibvorgänge bestehen.

## References

- [1] [Carbonara: Der MediaTek-Exploit, den niemand serviert hat](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Dokumentation zum Carbonara-Exploit](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra-Quellcode von Carbonara](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: Gepatchte V6 Download Agents ausnutzen](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}

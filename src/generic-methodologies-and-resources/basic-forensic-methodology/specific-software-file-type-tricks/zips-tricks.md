# ZIP-Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Befehlszeilenwerkzeuge** zur Verwaltung von **ZIP-Dateien** sind für die Diagnose, Reparatur und das Knacken von ZIP-Dateien unverzichtbar. Hier sind einige wichtige Dienstprogramme:<sup>[[1]](#references)</sup>

- **`unzip`**: Zeigt, warum eine ZIP-Datei möglicherweise nicht entpackt werden kann.
- **`zipdetails -v`**: Bietet eine detaillierte Analyse der Felder im ZIP-Dateiformat.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Listet den Inhalt einer ZIP-Datei auf, ohne ihn zu extrahieren.
- **`zip -F input.zip --out output.zip`** und **`zip -FF input.zip --out output.zip`**: Versuchen, beschädigte ZIP-Dateien zu reparieren.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Ein Tool für Wörterbuch- und Brute-Force-Angriffe auf ZIP-Passwörter; die Durchführbarkeit hängt vom Passwort-Suchraum ab.<sup>[[15]](#references)</sup>

Die [Spezifikation des Zip-Dateiformats](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) enthält umfassende Details zur Struktur und zu den Standards von ZIP-Dateien.<sup>[[4]](#references)</sup>

Bei herkömmlichen passwortgeschützten ZIP-Dateien bleiben Dateinamen und Dateigrößen in der Regel sichtbar, anders als bei den von RAR und 7z unterstützten Header-Verschlüsselungsmodi. Ein ZipCrypto Known-Plaintext-Angriff gewinnt **interne Verschlüsselungsschlüssel** zurück, nicht unbedingt das ursprüngliche Passwort; die Schlüssel reichen aus, um Einträge zu entschlüsseln, die mit demselben Passwort verschlüsselt wurden.<sup>[[13]](#references)</sup> Für den Angriff werden bekannte Bytes des Datenstroms **vor der Verschlüsselung** benötigt: Bei einem gespeicherten Eintrag sind das die ursprünglichen Dateibytes, bei einem DEFLATE-Eintrag hingegen die komprimierten Bytes, wofür möglicherweise die exakte Komprimierungsausgabe reproduziert werden muss.<sup>[[13]](#references)[[14]](#references)</sup> Einen praktischen Ablauf findest du unter [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack). Hintergrund zur Kryptoanalyse findest du in [diesem Paper](https://math.ucr.edu/~mike/zipattacks.pdf) und in [dieser Schritt-für-Schritt-Anleitung](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Dieser ZipCrypto-Angriff funktioniert nicht bei AES-verschlüsselten ZIP-Einträgen.<sup>[[13]](#references)</sup>

---

## Anti-Reversing-Tricks in APKs mithilfe manipulierter ZIP-Header

Moderne Android-Malware-Dropper nutzen fehlerhafte ZIP-Metadaten, um statische Tools (jadx/apktool/unzip) zu stören, während die APK auf dem Gerät installierbar bleibt. Die häufigsten Tricks sind:<sup>[[2]](#references)</sup>

- Eine Verschlüsselung vortäuschen, indem das Bit 0 des ZIP General Purpose Bit Flag (GPBF) gesetzt wird
- Große oder benutzerdefinierte Extra-Felder missbrauchen, um Parser zu verwirren
- Namenskollisionen zwischen Dateien und Verzeichnissen ausnutzen, um echte Artefakte zu verbergen (z. B. ein Verzeichnis namens `classes.dex/` neben der echten `classes.dex`)

### 1) Verschlüsselung vortäuschen (GPBF-Bit 0 gesetzt), ohne echte Kryptografie

Symptome:
- `jadx-gui` schlägt mit Fehlern wie den folgenden fehl:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` fragt nach einem Passwort für zentrale APK-Dateien, obwohl eine gültige APK keine verschlüsselten `classes*.dex`-, `resources.arsc`- oder `AndroidManifest.xml`-Dateien enthalten kann:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

Erkennung mit zipdetails:

```bash
zipdetails -v sample.apk | less
```

Achten Sie auf das General Purpose Bit Flag in lokalen und zentralen Headern. Ein verräterischer Wert ist ein gesetztes Bit 0 (Verschlüsselung), selbst bei Core-Einträgen:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heuristik: Wenn sich ein APK installieren lässt und auf dem Gerät läuft, zentrale Einträge für Tools jedoch „verschlüsselt“ erscheinen, wurde das GPBF manipuliert.

Behebe dies, indem du Bit 0 des GPBF sowohl in den Local File Headers (LFH) als auch in den Central Directory (CD)-Einträgen löschst. Minimaler Byte-Patcher:

<details>
<summary>Minimaler Patcher zum Löschen des GPBF-Bits</summary>

```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
    out = bytearray(buf)
    i = 0
    patched = 0
    while True:
        i = out.find(sig, i)
        if i == -1:
            break
        flags, = struct.unpack_from('<H', out, i + flag_off)
        if flags & 1:  # encryption bit set
            struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
            patched += 1
        i += 4  # move past signature to continue search
    return bytes(out), patched

if __name__ == '__main__':
    inp, outp = sys.argv[1], sys.argv[2]
    data = open(inp, 'rb').read()
    data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
    data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
    open(outp, 'wb').write(data)
    print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```

</details>

Verwendung:

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

Nur Bit 0 sollte geändert werden: `0A09` wird beispielsweise zu `0A08`, nicht zu `0000`. Dieser minimale Patcher sucht in den Rohbytes nach Header-Signaturen. Signaturähnliche Bytes in Dateidaten können daher zu falschen Treffern führen. Arbeite mit einer Kopie und überprüfe die resultierende Eintragsliste und die Header, bevor du die Ausgabe verwendest.<sup>[[4]](#references)</sup>

### 2) Große/benutzerdefinierte Extra-Felder, um Parser zu stören

Angreifer füllen Header mit übergroßen Extra-Feldern und ungewöhnlichen IDs, um Decompiler aus dem Tritt zu bringen. In freier Wildbahn können benutzerdefinierte Marker auftauchen (z. B. Zeichenfolgen wie `JADXBLOCK`), die darin eingebettet sind.

Untersuchung:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Beobachtete Beispiele: Unbekannte IDs wie `0xCAFE` („Java Executable“) oder `0x414A` („JA:“) mit großen Payloads.<sup>[[2]](#references)</sup>

DFIR-Heuristiken:
- Warnen, wenn Extra-Felder bei zentralen Einträgen (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`) ungewöhnlich groß sind.
- Unbekannte Extra-IDs bei diesen Einträgen als verdächtig einstufen.

Praktische Gegenmaßnahme: Das Archiv neu erstellen (z. B. die extrahierten Dateien erneut zippen), um schädliche Extra-Felder zu entfernen. Falls Tools wegen einer gefälschten Verschlüsselung die Extraktion verweigern, zuerst wie oben beschrieben Bit 0 im GPBF löschen und anschließend neu verpacken:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Datei-/Verzeichnisnamen-Kollisionen (echte Artefakte verbergen)

Ein ZIP kann sowohl eine Datei `X` als auch ein Verzeichnis `X/` enthalten. Einige Entpacker und Decompiler kommen damit durcheinander und können die echte Datei mit einem Verzeichniseintrag überlagern oder verbergen. Dies wurde bei Einträgen beobachtet, die mit zentralen APK-Namen wie `classes.dex` kollidieren.

Triage und sichere Extraktion:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

Programmatische Erkennung nach dem Fix:

```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
    names = z.namelist()

collisions = defaultdict(list)
for n in names:
    base = n[:-1] if n.endswith('/') else n
    collisions[base].append(n)

for base, variants in collisions.items():
    if len(variants) > 1:
        print('COLLISION', base, '->', variants)
```

Blue-Team-Erkennungsideen:
- APKs markieren, deren lokale Header Verschlüsselung kennzeichnen (GPBF-Bit 0 = 1), die sich aber installieren/ausführen lassen.
- Große/unbekannte Extra-Felder bei zentralen Einträgen markieren (auf Marker wie `JADXBLOCK` achten).
- Pfadkollisionen (`X` und `X/`) speziell bei `AndroidManifest.xml`, `resources.arsc`, `classes*.dex` markieren.

---

## Weitere schädliche ZIP-Tricks (2024–2026)

### Verkettete zentrale Verzeichnisse (Umgehung durch mehrere EOCDs)

Bei einer Phishing-Kampagne im Jahr 2024 versendeten Angreifer einen einzelnen Blob, der tatsächlich aus **zwei verketteten ZIP-Dateien** bestand. Jede hatte ihren eigenen End-of-Central-Directory-Eintrag (EOCD) und ihr eigenes zentrales Verzeichnis. Verschiedene Entpacker lasen unterschiedliche Verzeichnisse (7-Zip das erste, WinRAR das letzte). So konnten Angreifer Payloads verbergen, die nur manche Tools anzeigten. Scanner, die nur ein Verzeichnis untersuchen, können das andere Archiv übersehen.<sup>[[5]](#references)[[6]](#references)</sup>

**Triage-Befehle**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Wenn mehr als ein EOCD auftritt oder Warnungen zu „data after payload“ erscheinen, teilen Sie den Blob auf und untersuchen Sie jeden Teil:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap-ZIP-Bombs erstellen einen winzigen **Kernel** (einen stark komprimierten DEFLATE-Block) und verwenden ihn in überlappenden Einträgen wieder. Full-overlap-Varianten verweisen mit mehreren Einträgen im zentralen Verzeichnis auf denselben lokalen Header, während Quoted-overlap-Varianten lokale Header in DEFLATE-Streams zitieren; die veröffentlichte Konstruktion erreicht ohne verschachtelte Archive ein Verhältnis von mehr als 28M:1.<sup>[[7]](#references)</sup>

**Schnellerkennung (doppelte LFH-Offsets)**

```python
# detect full-overlap variants by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
    i = buf.find(b'PK\x01\x02', off)
    if i<0: break
    rel = struct.unpack_from('<I', buf, i+42)[0]
    if rel in seen:
        print('OVERLAP at offset', rel)
        break
    seen.add(rel); off = i+4
```

**Handhabung**
- Führe einen Trockenlauf durch: `zipdetails -v file.zip | grep -n "Local Header Offset"` und vergleiche die referenzierten Local-Header-Offsets und komprimierten Datenbereiche; doppelte Offsets weisen auf Varianten mit vollständiger Überlappung hin.<sup>[[7]](#references)[[8]](#references)</sup>
- Begrenze vor dem Entpacken die akzeptierte Gesamtgröße nach dem Dekomprimieren und die Anzahl der Einträge mithilfe eines Parsers; `zipinfo -t file.zip` meldet die Gesamtwerte, setzt aber keine Sicherheitsgrenzen durch.<sup>[[8]](#references)</sup>
- Wenn du entpacken musst, tue dies in einer cgroup/VM mit CPU- und Festplattenlimits (um Abstürze durch unbeschränkte Dekomprimierung zu vermeiden).<sup>[[8]](#references)</sup>

---

### Verwirrung durch unterschiedliche Parser für Local Header und Central Directory

Aktuelle Forschung zu Parser-Differenzen hat gezeigt, dass Mehrdeutigkeiten in ZIP-Dateien auch in modernen Toolchains noch ausnutzbar sind. Die Grundidee ist einfach: Manche Software vertraut dem **Local File Header (LFH)**, während andere dem **Central Directory (CD)** vertrauen. Dadurch kann ein Archiv verschiedenen Tools unterschiedliche Dateinamen, Pfade, Kommentare, Offsets oder Eintragsmengen präsentieren.<sup>[[9]](#references)</sup>

Praktische offensive Einsatzmöglichkeiten:
- Sorge dafür, dass ein Upload-Filter, ein AV-Pre-Scan oder ein Paketvalidator eine harmlose Datei im CD sieht, während der Extraktor einen anderen LFH-Namen oder -Pfad berücksichtigt.
- Nutze doppelte Namen, Einträge, die nur in einer der Strukturen vorkommen, oder mehrdeutige Unicode-Pfadmetadaten (zum Beispiel das Info-ZIP Unicode Path Extra Field `0x7075`), sodass verschiedene Parser unterschiedliche Verzeichnisstrukturen rekonstruieren.
- Kombiniere dies mit Path Traversal, um eine „harmlose“ Archivansicht beim Entpacken in eine Schreibmöglichkeit zu verwandeln. Informationen zur Seite des Entpackens findest du unter [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR-Triage:

```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
    n, e = struct.unpack_from('<HH', b, i + 26)
    lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
    i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
    n = struct.unpack_from('<H', b, i + 28)[0]
    off = struct.unpack_from('<I', b, i + 42)[0]
    cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
    if off in lfh and cd != lfh[off]:
        print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
    i += 4
```

Ergänze es mit:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Heuristiken:
- Bei sicherheitssensibler Verarbeitung Archive mit abweichenden LFH/CD-Namen, doppelten Dateinamen, mehreren EOCD-Einträgen oder nach dem letzten EOCD-Eintrag folgenden Bytes ablehnen oder isolieren.<sup>[[9]](#references)[[10]](#references)</sup>
- ZIP-Dateien mit ungewöhnlichen Unicode-Pfad-Extra-Feldern oder inkonsistenten Kommentaren als verdächtig behandeln, wenn verschiedene Tools beim extrahierten Verzeichnisbaum zu unterschiedlichen Ergebnissen kommen.<sup>[[4]](#references)[[9]](#references)</sup>
- Wenn die Analyse wichtiger ist als der Erhalt der ursprünglichen Bytes, das Archiv nach dem Entpacken in einer Sandbox mit einem strikten Parser neu packen und die resultierende Dateiliste mit den ursprünglichen Metadaten vergleichen.

Das ist nicht nur für Paket-Ökosysteme relevant: Dieselbe Art von Mehrdeutigkeit kann Payloads vor Mail-Gateways, statischen Scannern und benutzerdefinierten Verarbeitungspipelines verbergen, die einen Blick auf den ZIP-Inhalt werfen, bevor ein anderer Entpacker das Archiv verarbeitet.<sup>[[9]](#references)</sup>

---





## References

- [1] [CTF-Forensik-Feldhandbuch (Mike's Blog, CTF-Kategorie)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Teil 1 – Ein mehrstufiger Dropper (APK-ZIP-Anti-Reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (IO::Compress-Skript)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [ZIP-Dateiformatspezifikation (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Struktur von ZIP-Archiven ausgenutzt, um Malware unentdeckt zu verbergen (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hacker verstecken Malware in einem neuen ZIP-Dateiangriff – verkettete ZIP-Zentralverzeichnisse](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Eine bessere ZIP-Bombe (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [ZIP-Bomben verstehen: überlappende/überlappend zitierte Kernel-Konstruktion](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Mein ZIP ist nicht dein ZIP: Semantische Lücken zwischen ZIP-Parsern identifizieren und ausnutzen (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Angriffe durch ZIP-Parser-Verwirrung bei Python-Paketinstallern verhindern](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP-Angriffe mit reduziertem Klartextwissen (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Realistische Webmission, Level 15 (ZIP-Angriff mit bekanntem Klartext)](https://www.hackthissite.org/articles/read/793)
- [13] [bkcrack-Verwendung](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [bkcrack-Tutorial zu bekanntem Klartext](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [fcrackzip-Repository](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}

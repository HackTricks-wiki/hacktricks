# Text-Steganografie

{{#include ../../banners/hacktricks-training.md}}

## Praktischer Ablauf

Wenn sich Klartext unerwartet verhält, bewahren Sie die ursprünglichen Belege auf, untersuchen Sie seine Codepoints und normalisieren Sie nur eine Kopie.

### Technik

Text-Steganografie beruht häufig auf Zeichen, die identisch dargestellt werden oder unsichtbar sind:

- Homoglyphen: verschiedene Unicode-Codepoints, die ähnlich aussehen (zum Beispiel das lateinische `a` und das kyrillische `а`)<sup>[[1]](#references)</sup>
- Zero-Width-Zeichen: Joiner, Non-Joiner und Zero-Width-Spaces<sup>[[2]](#references)</sup>
- Leerraumkodierungen: Leerzeichen gegenüber Tabulatoren, Muster mit nachgestellten Leerzeichen und gezielte Zeilenlängenmuster<sup>[[3]](#references)[[4]](#references)</sup>

Weitere Fälle mit hoher Signalstärke:

- Bidirektionale Steuerzeichen, die Text visuell umordnen können<sup>[[1]](#references)</sup>
- Variation Selectors und kombinierende Zeichen, die verborgene Zustände enthalten können, während der sichtbare Text nahezu unverändert bleibt<sup>[[1]](#references)</sup>

### Dekodierhilfen

- [Unicode-Homoglyphen- und Zero-Width-Zeichen-Encoder/Decoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Codepoints untersuchen

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## CSS-`unicode-range`-Kanäle

`@font-face`-Regeln können missbraucht werden, um Bytes in `unicode-range: U+..`-Einträgen zu kodieren. Extrahiere die Codepoints, verkette die hexadezimalen Werte und dekodiere sie:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Wenn Bereiche mehrere Werte pro Deklaration enthalten, zuerst an Kommas aufteilen und normalisieren (`tr ',+' '\n'`). Python kann die Bytes parsen und ausgeben, wenn die Formatierung uneinheitlich ist.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Unicode-Sicherheitsüberlegungen](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Unicode-Steganografie mit Zero-Width-Zeichen und Homoglyphen](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Santa's Wunschliste](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian-Handbuch: `stegsnow`-Whitespace-Steganografie](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

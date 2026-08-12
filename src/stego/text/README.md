# Steganografia del testo

{{#include ../../banners/hacktricks-training.md}}

## Percorso pratico

Se il testo normale si comporta in modo imprevisto, conserva le prove originali, ispeziona i relativi codepoint e normalizza solo una copia.

### Tecnica

La steganografia del testo si basa spesso su caratteri che vengono visualizzati in modo identico o invisibile:

- Homoglyphs: codepoint Unicode diversi che sembrano uguali (ad esempio, la `a` latina e la `а` cirillica)<sup>[[1]](#references)</sup>
- Caratteri zero-width: joiner, non-joiner e spazi zero-width<sup>[[2]](#references)</sup>
- Codifiche degli spazi bianchi: spazi rispetto a tab, pattern di spazi finali e pattern deliberati della lunghezza delle righe<sup>[[3]](#references)[[4]](#references)</sup>

Casi aggiuntivi ad alto valore diagnostico:

- Controlli bidirezionali, che possono riordinare visivamente il testo<sup>[[1]](#references)</sup>
- Variation selectors e caratteri combinanti, che possono trasportare uno stato nascosto lasciando il testo visibile quasi invariato<sup>[[1]](#references)</sup>

### Strumenti di decodifica

- [Encoder/decoder di Unicode homoglyph e caratteri zero-width](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Ispeziona i codepoint
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canali CSS `unicode-range`

Le regole `@font-face` possono essere sfruttate per codificare byte nelle voci `unicode-range: U+..`. Estrai i codepoint, concatena i valori esadecimali e decodificali:<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se gli intervalli contengono più valori per dichiarazione, dividili prima sulle virgole e normalizzali (`tr ',+' '\n'`). Python può analizzare ed emettere i byte quando la formattazione è incoerente.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Technical Report #36: Considerazioni sulla sicurezza Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Steganografia Unicode con caratteri a larghezza zero e omoglifi](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Lista dei desideri di Babbo Natale](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manuale Debian: steganografia degli spazi bianchi con `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

# Steganografia del testo

{{#include ../../banners/hacktricks-training.md}}

Cerca:

- Unicode homoglyphs
- Caratteri zero-width
- Pattern di whitespace (spazi vs tab)

## Percorso pratico

Se il plain text si comporta in modo imprevisto, ispeziona i codepoint e normalizza con attenzione (non distruggere le prove).

### Tecnica

La stego del testo si basa spesso su caratteri che vengono visualizzati in modo identico (o invisibile):

- Homoglyphs: codepoint Unicode diversi che hanno lo stesso aspetto (`a` latina vs `а` cirillica)
- Caratteri zero-width: joiner, non-joiner, spazi zero-width
- Encoding degli spazi bianchi: spazi vs tab, spazi finali, pattern della lunghezza delle righe<sup>[[1]](#references)</sup>

Casi aggiuntivi ad alto segnale:

- Caratteri di override/controllo bidirezionali (possono riordinare visivamente il testo)
- Variation selectors e caratteri combining usati come covert channel

### Helper per il decoding

- Playground per Unicode homoglyph/zero-width: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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

Le regole `@font-face` possono codificare byte nelle voci `unicode-range: U+..`. Estrai i codepoint, concatena i valori esadecimali e decodifica:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se gli intervalli contengono più bytes per dichiarazione, dividili prima sulle virgole e normalizzali (`tr ',+' '\n'`). Python semplifica l'analisi e l'emissione dei bytes quando la formattazione è incoerente.<sup>[[1]](#references)</sup>

## Riferimenti

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}

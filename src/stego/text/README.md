# Steganografia del testo

{{#include ../../banners/hacktricks-training.md}}

Cerca:

- Homoglyph Unicode
- Caratteri zero-width
- Pattern di spaziatura (spazi rispetto a tab)

## Percorso pratico

Se il testo semplice si comporta in modo imprevisto, ispeziona i codepoint e normalizza con attenzione (non distruggere le prove).

### Tecnica

Lo stego testuale si basa frequentemente su caratteri che vengono visualizzati in modo identico (o invisibile):

- Homoglyph: codepoint Unicode diversi che hanno lo stesso aspetto (`a` latina rispetto a `а` cirillica)
- Caratteri zero-width: joiner, non-joiner, spazi zero-width
- Codifiche basate sugli spazi: spazi rispetto a tab, spazi finali, pattern della lunghezza delle righe<sup>[[1]](#references)</sup>

Altri casi ad alto segnale:

- Caratteri di override/controllo bidirezionali (possono riordinare visivamente il testo)
- Variation selector e caratteri combining usati come covert channel

### Strumenti di decodifica

- Playground per homoglyph Unicode/zero-width: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Ispezionare i codepoint
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canali `unicode-range` CSS

Le regole `@font-face` possono codificare byte nelle voci `unicode-range: U+..`. Estrai i codepoint, concatena i valori esadecimali e decodifica:
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Se gli intervalli contengono più byte per dichiarazione, dividili prima sulle virgole e normalizzali (`tr ',+' '\n'`). Python semplifica l'analisi e la generazione dei byte quando la formattazione è incoerente.

## Riferimenti

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}

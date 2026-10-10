# Steganografia nel testo

{{#include ../../banners/hacktricks-training.md}}

## Percorso pratico

Se il testo semplice si comporta in modo inatteso, conserva le prove originali, esamina i suoi codepoint e normalizza solo una copia.

### Tecnica

La steganografia testuale si basa spesso su caratteri che vengono visualizzati in modo identico o invisibile:

- Omoglifi: codepoint Unicode diversi che sembrano uguali (ad esempio, `a` latina e `а` cirillica)<sup>[[1]](#references)</sup>
- Caratteri a larghezza zero: joiner, non-joiner e spazi a larghezza zero<sup>[[2]](#references)</sup>
- Codifiche basate sugli spazi: spazi rispetto a tabulazioni, schemi di spazi finali e schemi deliberati di lunghezza delle righe<sup>[[3]](#references)[[4]](#references)</sup>

Altri casi ad alto segnale:

- Controlli bidirezionali, che possono riordinare visivamente il testo<sup>[[1]](#references)</sup>
- Selettori di variazione e caratteri combinanti, che possono contenere informazioni nascoste lasciando il testo visibile quasi invariato<sup>[[1]](#references)</sup>

### Strumenti di decodifica

- [Encoder/decoder di omoglifi Unicode e caratteri a larghezza zero](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Esaminare i codepoint

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

Le regole `@font-face` possono essere abusate per codificare byte nelle voci `unicode-range: U+..`. Estrai i codepoint, concatena i valori esadecimali e decodificali:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Se gli intervalli contengono più valori per dichiarazione, separali prima in corrispondenza delle virgole e normalizzali (`tr ',+' '\n'`). Python può analizzarli e generare i byte quando la formattazione è incoerente.<sup>[[3]](#references)</sup>

## References

- [1] [Rapporto tecnico Unicode #36: considerazioni sulla sicurezza Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: steganografia Unicode con caratteri a larghezza zero e omoglifi](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Lista dei desideri di Babbo Natale](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manuale Debian: steganografia tramite spazi bianchi con `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

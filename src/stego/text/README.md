# Tekssteganografie

{{#include ../../banners/hacktricks-training.md}}

## Praktiese benadering

As gewone teks onverwags optree, bewaar die oorspronklike bewysmateriaal, inspekteer die kodepunte daarvan en normaliseer slegs ’n kopie.

### Tegniek

Tekssteganografie maak dikwels staat op karakters wat identies of onsigbaar vertoon word:

- Homogliewe: verskillende Unicode-kodepunte wat eenders lyk (byvoorbeeld Latynse `a` en Cyrilliese `а`)<sup>[[1]](#references)</sup>
- Nulwydtekarakters: verbindings, nie-verbindings en spasies met nulwydte<sup>[[2]](#references)</sup>
- Witspasiekodering: spasies teenoor tabkarakters, patrone met spasies aan die einde van reëls en doelbewuste reëllengtepatrone<sup>[[3]](#references)[[4]](#references)</sup>

Bykomende gevalle met sterk aanduidings:

- Tweerigtingkontroles, wat teks visueel kan herrangskik<sup>[[1]](#references)</sup>
- Variasiekiesers en kombinerende karakters, wat verborge toestand kan dra terwyl die sigbare teks byna onveranderd bly<sup>[[1]](#references)</sup>

### Dekoderingshulpmiddels

- [Unicode-homoglief- en nulwydtekarakter-enkodeerder/dekodeerder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Inspekteer kodepunte

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## CSS `unicode-range`-kanale

`@font-face`-reëls kan misbruik word om grepe in `unicode-range: U+..`-inskrywings te enkodeer. Onttrek die kodepunte, voeg die heksadesimale waardes saam en dekodeer hulle:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

As reekse verskeie waardes per verklaring bevat, skei dit eers op kommas en normaliseer dit (`tr ',+' '\n'`). Python kan die grepe ontleed en uitvoer wanneer die formatering inkonsekwent is.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode Tegniese Verslag #36: Unicode-sekuriteitsoorwegings](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Unicode-steganografie met zero-width-karakters en homoglife](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (Medium) — Kersvader se wenslys](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian-handleiding: `stegsnow`-whitespace-steganografie](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

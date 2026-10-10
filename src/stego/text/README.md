# Tekstualna steganografija

{{#include ../../banners/hacktricks-training.md}}

## Praktični pristup

Ako se običan tekst ponaša neočekivano, sačuvajte originalne dokaze, pregledajte njegove kodne tačke i normalizujte samo kopiju.

### Tehnika

Tekstualna steganografija često se oslanja na znakove koji se prikazuju identično ili nevidljivo:

- Homoglifi: različite Unicode kodne tačke koje izgledaju slično (na primer, latinično `a` i ćirilično `а`)<sup>[[1]](#references)</sup>
- Znakovi nulte širine: spojnice, razdelnici i razmaci nulte širine<sup>[[2]](#references)</sup>
- Kodiranja belim prostorom: razmaci umesto tabulatora, obrasci završnih razmaka i namerni obrasci dužine redova<sup>[[3]](#references)[[4]](#references)</sup>

Dodatni slučajevi sa visokim signalom:

- Kontrole dvosmernog teksta, koje mogu vizuelno da promene redosled teksta<sup>[[1]](#references)</sup>
- Selektori varijanti i kombinovani znakovi, koji mogu nositi skriveno stanje, a da vidljivi tekst ostane gotovo nepromenjen<sup>[[1]](#references)</sup>

### Pomoćni alati za dekodiranje

- [Unicode enkoder/dekoder homoglifskih znakova i znakova nulte širine](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Pregled kodnih tačaka

```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
  if ord(ch) > 127 or ch.isspace():
    print(i, hex(ord(ch)), repr(ch))
PY
```

## CSS `unicode-range` kanali

`@font-face` pravila mogu se zloupotrebiti za kodiranje bajtova u unosima `unicode-range: U+..`. Izdvojite kodne tačke, spojite heksadecimalne vrednosti i dekodirajte ih:<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Ako opsezi sadrže više vrednosti po deklaraciji, prvo ih razdvojte po zarezima i normalizujte (`tr ',+' '\n'`). Python može da parsira i ispiše bajtove kada formatiranje nije dosledno.<sup>[[3]](#references)</sup>

## References

- [1] [Unicode tehnički izveštaj br. 36: Bezbednosna razmatranja za Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek: Unicode steganografija pomoću znakova nulte širine i homoglifâ](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf: Flagvent 2025 (srednji nivo) — Deda Mrazova lista želja](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Debian priručnik: `stegsnow` steganografija pomoću belina](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

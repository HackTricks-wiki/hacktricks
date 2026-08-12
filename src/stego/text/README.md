# Stéganographie textuelle

{{#include ../../banners/hacktricks-training.md}}

## Parcours pratique

Si du texte brut se comporte de manière inattendue, conservez les éléments originaux, inspectez leurs points de code et ne normalisez qu'une copie.

### Technique

La stéganographie textuelle repose fréquemment sur des caractères qui s'affichent de manière identique ou invisible :

- Homoglyphes : différents points de code Unicode qui se ressemblent (par exemple, `a` latin et `а` cyrillique)<sup>[[1]](#references)</sup>
- Caractères de largeur nulle : joiners, non-joiners et espaces de largeur nulle<sup>[[2]](#references)</sup>
- Encodages par espaces blancs : espaces par opposition aux tabulations, motifs d'espaces en fin de ligne et longueurs de ligne délibérées<sup>[[3]](#references)[[4]](#references)</sup>

Cas supplémentaires à fort signal :

- Contrôles bidirectionnels, qui peuvent réordonner visuellement le texte<sup>[[1]](#references)</sup>
- Sélecteurs de variation et caractères combinants, qui peuvent transporter un état caché tout en laissant le texte visible presque inchangé<sup>[[1]](#references)</sup>

### Assistants de décodage

- [Encodeur/décodeur Unicode d'homoglyphes et de caractères de largeur nulle](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

### Inspecter les points de code
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
## Canaux CSS `unicode-range`

Les règles `@font-face` peuvent être détournées pour encoder des octets dans les entrées `unicode-range: U+..`. Extrayez les codepoints, concaténez les valeurs hexadécimales, puis décodez-les :<sup>[[3]](#references)</sup>
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Si les plages contiennent plusieurs valeurs par déclaration, séparez-les d'abord sur les virgules et normalisez (`tr ',+' '\n'`). Python peut analyser et produire les octets lorsque le formatage est incohérent.<sup>[[3]](#references)</sup>

## References

- [1] [Rapport technique Unicode #36 : Considérations de sécurité Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek : Steganography Unicode avec des caractères de largeur nulle et des homoglyphes](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf : Flagvent 2025 (Medium) — Liste de souhaits du père Noël](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manuel Debian : steganography d'espaces blancs avec `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

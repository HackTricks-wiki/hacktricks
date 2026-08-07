# Stéganographie textuelle

{{#include ../../banners/hacktricks-training.md}}

Recherchez :

- Homoglyphes Unicode
- Caractères de largeur nulle
- Motifs d'espaces (espaces contre tabulations)

## Approche pratique

Si du texte brut se comporte de manière inattendue, inspectez les points de code et normalisez avec précaution (ne détruisez pas les preuves).

### Technique

La stéganographie textuelle repose fréquemment sur des caractères qui s'affichent de manière identique (ou qui sont invisibles) :

- Homoglyphes : différents points de code Unicode qui se ressemblent (le `a` latin contre le `а` cyrillique)
- Caractères de largeur nulle : jointures, non-jointures et espaces de largeur nulle
- Encodages par espaces blancs : espaces contre tabulations, espaces en fin de ligne, motifs de longueur de ligne<sup>[[1]](#references)</sup>

Autres cas à haut signal :

- Caractères de contrôle/de remplacement bidirectionnels (peuvent réordonner visuellement le texte)
- Sélecteurs de variation et caractères combinatoires utilisés comme covert channel

### Outils de décodage

- Terrain d'expérimentation pour les homoglyphes Unicode et les caractères de largeur nulle : https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

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

Les règles `@font-face` peuvent encoder des octets dans les entrées `unicode-range: U+..`. Extrayez les codepoints, concaténez les valeurs hexadécimales, puis décodez-les :
```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```
Si les plages contiennent plusieurs octets par déclaration, séparez-les d’abord sur les virgules et normalisez-les (`tr ',+' '\n'`). Python facilite l’analyse et l’émission des octets lorsque le formatage est incohérent.<sup>[[1]](#references)</sup>

## Références

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}

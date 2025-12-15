# Text Steganography

{{#include ../../banners/hacktricks-training.md}}

Rechercher :

- Unicode homoglyphs
- Zero-width characters
- Modèles d'espacement (espaces vs tabulations)

## Approche pratique

Si le texte brut se comporte de façon inattendue, inspectez les codepoints et normalisez soigneusement (ne pas détruire les preuves).

### Technique

Text stego s'appuie fréquemment sur des caractères qui s'affichent de manière identique (ou invisiblement) :

- Homoglyphs : différents codepoints Unicode qui ont le même rendu (Latin `a` vs Cyrillic `а`)
- Caractères zero-width : joiners, non-joiners, zero-width spaces
- Encodages d'espaces blancs : espaces vs tabulations, espaces en fin de ligne, motifs de longueur de ligne

Cas additionnels à fort signal :

- Caractères de contrôle/override bidirectionnels (peuvent réordonner visuellement le texte)
- Sélecteurs de variation et caractères combinants utilisés comme canal caché

### Aides au décodage

- Unicode homoglyph/zero-width playground: https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder

### Inspecter les codepoints
```bash
python3 - <<'PY'
import sys
s=sys.stdin.read()
for i,ch in enumerate(s):
if ord(ch) > 127 or ch.isspace():
print(i, hex(ord(ch)), repr(ch))
PY
```
{{#include ../../banners/hacktricks-training.md}}

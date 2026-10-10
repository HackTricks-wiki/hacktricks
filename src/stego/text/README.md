# Stéganographie textuelle

{{#include ../../banners/hacktricks-training.md}}

## Approche pratique

Si du texte brut se comporte de façon inattendue, préservez les éléments originaux, examinez ses points de code et ne normalisez qu’une copie.

### Technique

La stéganographie textuelle repose souvent sur des caractères qui s’affichent de manière identique ou invisible :

- Homoglyphes : points de code Unicode différents qui se ressemblent (par exemple, le `a` latin et le `а` cyrillique)<sup>[[1]](#references)</sup>
- Caractères de largeur nulle : caractères de jonction, de non-jonction et espaces de largeur nulle<sup>[[2]](#references)</sup>
- Encodages par espaces blancs : espaces plutôt que tabulations, motifs d’espaces en fin de ligne et motifs délibérés de longueur de ligne<sup>[[3]](#references)[[4]](#references)</sup>

Autres cas particulièrement révélateurs :

- Contrôles bidirectionnels, qui peuvent réordonner visuellement le texte<sup>[[1]](#references)</sup>
- Sélecteurs de variation et caractères combinants, qui peuvent transporter un état caché tout en laissant le texte visible presque inchangé<sup>[[1]](#references)</sup>

### Outils de décodage

- [Encodeur/décodeur d’homoglyphes Unicode et de caractères de largeur nulle](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)<sup>[[2]](#references)</sup>

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

Les règles `@font-face` peuvent être détournées pour encoder des octets dans des entrées `unicode-range: U+..`. Extrayez les points de code, concaténez les valeurs hexadécimales et décodez-les :<sup>[[3]](#references)</sup>

```bash
grep -o "U+[0-9A-Fa-f]\+" styles.css | tr -d 'U+\n' | xxd -r -p
```

Si les plages contiennent plusieurs valeurs par déclaration, séparez-les d’abord sur les virgules, puis normalisez (`tr ',+' '\n'`). Python peut analyser et produire les octets lorsque la mise en forme est incohérente.<sup>[[3]](#references)</sup>

## References

- [1] [Rapport technique Unicode nº 36 : considérations de sécurité Unicode](https://www.unicode.org/reports/tr36/)
- [2] [Irongeek : stéganographie Unicode avec des caractères de largeur nulle et des homoglyphes](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)
- [3] [0xdf : Flagvent 2025 (Medium) — La liste de souhaits du Père Noël](https://0xdf.gitlab.io/flagvent2025/medium)
- [4] [Manuel Debian : stéganographie par espaces avec `stegsnow`](https://manpages.debian.org/trixie/stegsnow/stegsnow.1.en.html)
{{#include ../../banners/hacktricks-training.md}}

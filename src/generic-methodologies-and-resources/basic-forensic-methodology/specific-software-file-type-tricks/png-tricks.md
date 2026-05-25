# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

Les **fichiers PNG** sont très courants dans les **CTFs**, la **réponse à incident**, et le **malware staging** car ils sont **sans perte**, **basés sur des chunks**, et de nombreux outils les afficheront volontiers même lorsqu'ils contiennent des **métadonnées supplémentaires**, des **payloads ajoutés en fin de fichier**, ou des **chunks partiellement corrompus**.

Considérez un PNG comme un **container**, pas seulement comme une image.

## Quick triage

Commencez par des vérifications au niveau du container avant de passer au stego LSB. Pour le workflow bit-plane/LSB, consultez [la page dédiée au stego d'images](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Choses utiles à rechercher :

- **Chunks annexes inattendus** tels que `tEXt`, `zTXt`, `iTXt`, `eXIf` ou `iCCP`
- **Erreurs CRC** ou longueurs de chunks malformées
- **Données supplémentaires après `IEND`**
- **Plusieurs marqueurs `IEND`** ou des fragments `IDAT` récupérables après la fin formelle du fichier
- Un fichier qui est un PNG valide **et** qui ressemble aussi à un ZIP/PDF/script une fois extrait

Rappelez-vous que la structure valide minimale est généralement :

- `IHDR` (doit être en premier)
- `IDAT` (un ou plusieurs chunks consécutifs)
- `IEND` (doit être le dernier)

## Données résiduelles après `IEND`

Un des artefacts PNG les plus révélateurs est **des données ajoutées après le chunk final `IEND`**. Beaucoup de décodeurs les ignorent, ce qui le rend utile pour :

- **Stégo simple / charge utile cachée**
- **PNG polyglots**
- **Malware staging**
- **Récupération d’anciennes données d’image** depuis des éditeurs défectueux

Détection rapide :
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Si vous voulez extraire tout ce qui se trouve après le `IEND` final :
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Essayez aussi directement des parseurs d’archives génériques contre le PNG ou le trailer carved :
```bash
7z l suspect.png
unzip -l suspect.png
```
## Récupération de style Acropalypse de captures d’écran recadrées/redactées

Une astuce forensic PNG très pratique et récente consiste à vérifier si un éditeur de captures d’écran a **écrit par-dessus** un PNG sans **tronquer** d’abord l’ancien fichier. Dans ces cas-là, des octets de l’**image précédente** peuvent rester après `IEND`, et parfois des données `IDAT` supplémentaires peuvent être partiellement reconstruites.

Cela est devenu bien connu avec **aCropalypse** (Google Pixel Markup) et le problème مرتبط de **Windows Snipping Tool**. En pratique, si un PNG « recadré » ou « redacted » contient encore d’anciennes données en fin de fichier, vous pouvez peut-être récupérer une partie de la capture d’écran originale.

Workflow pratique :
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Signes qui justifient fortement une analyse plus poussée :

- `pngcheck` signale des **données supplémentaires après `IEND`**
- Vous trouvez **plus d’un `IEND`**
- Vous trouvez des **chunks `IDAT` supplémentaires** après la fin apparente de l’image
- La capture d’écran provient d’un appareil/éditeur connu pour avoir été affecté

Si cela se produit, passez le fichier dans un **outil de récupération aCropalypse** avant de considérer la redaction comme fiable.

## Chunk abuse qui compte en pratique

Les chunks PNG les plus intéressants pour les investigations ne sont généralement pas les chunks d’image évidents, mais les chunks qui peuvent contenir du **texte**, des **métadonnées** ou des **bytes de payload** :

- `tEXt` / `zTXt` / `iTXt` – métadonnées textuelles et texte compressé
- `eXIf` – données EXIF dans PNG
- `iCCP` – profil ICC intégré
- `PLTE` – données de palette dans les images indexées, mais aussi utile dans des scénarios de dissimulation de payload

Extrayez-les avec :
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Pour la persistance de payload offensifs à l’intérieur de chunks PNG (par exemple les tricks **PLTE**, **IDAT**, ou **tEXt** qui survivent à certaines transformations d’images PHP), consultez les notes plus détaillées centrées sur les uploads ici :

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Réparation d’un PNG corrompu

Pour vérifier l’intégrité et localiser la zone exactement cassée, **pngcheck** reste l’un des meilleurs premiers outils :

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Si le fichier est endommagé plutôt que volontairement malveillant, **PCRT** peut être utile dans les CTFs et les travaux de laboratoire pour corriger des problèmes courants tels que des en-têtes invalides, de mauvaises valeurs IHDR, des problèmes CRC ou des layouts de chunks malformés.

Si votre objectif est de **sanitize** un PNG qui contient des données de trailer suspectes tout en préservant l’image visible, ExifTool peut explicitement supprimer le trailer :
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Pour des preuves sensibles, travaillez toujours sur une **copie** et conservez les hashes de l'original avant de tenter des réparations.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}

# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Patrons courants:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triage rapide

Avant les outils spécialisés :

- Confirmer les détails du codec/conteneur et les anomalies :
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si l'audio contient un contenu de type bruit ou une structure tonale, inspectez un spectrogram dès le début.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego dissimule des données en modulant l'énergie dans le temps/fréquence afin qu'elles deviennent visibles uniquement dans un tracé temps-fréquence (souvent inaudible ou perçu comme du bruit).

### Sonic Visualiser

Outil principal pour l'inspection des spectrogrammes :

- https://www.sonicvisualiser.org/

### Alternatives

- Audacity (affichage spectrogramme, filtres): https://www.audacityteam.org/
- `sox` peut générer des spectrogrammes depuis la CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Technique

Pour le PCM non compressé (WAV), chaque échantillon est un entier. Modifier les bits de poids faible change très légèrement la forme d'onde, donc les attaquants peuvent cacher :

- 1 bit par échantillon (ou plus)
- Intercalé entre les canaux
- Avec un stride/permutation

Autres familles de dissimulation audio que vous pouvez rencontrer :

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Source : https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / tonalités de numérotation

### Technique

Le DTMF encode les caractères sous forme de paires de fréquences fixes (clavier téléphonique). Si l'audio ressemble à des tonalités de clavier ou à des bips réguliers à double fréquence, testez le décodage DTMF en priorité.

Décodeurs en ligne:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}

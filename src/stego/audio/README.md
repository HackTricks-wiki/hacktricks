# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Modèles courants :

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triage rapide

Avant les outils spécialisés :

- Confirmer les détails du codec/conteneur et les anomalies :
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si l'audio contient du contenu ressemblant à du bruit ou une structure tonale, inspecter un spectrogramme dès le début.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Technique

Spectrogram stego dissimule des données en modulant l'énergie dans le domaine temps/fréquence afin qu'elles deviennent visibles uniquement dans une représentation temps-fréquence (souvent inaudible ou perçues comme du bruit).

### Sonic Visualiser

Outil principal pour l'inspection des spectrogrammes :

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (vue spectrogramme, filtres): https://www.audacityteam.org/
- `sox` peut générer des spectrogrammes depuis la CLI :
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / décodage de modem

L'audio Frequency-shift keyed ressemble souvent à des tons simples alternés dans un spectrogramme. Une fois que vous avez une estimation approximative du centre/décalage et du baud, brute force avec `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` gère automatiquement le gain et détecte automatiquement les tons mark/space ; ajustez `--rx-invert` ou `--samplerate` si la sortie est brouillée.

## WAV LSB

### Technique

Pour le PCM non compressé (WAV), chaque échantillon est un entier. Modifier les bits de faible poids change très légèrement la forme d'onde, donc les attaquants peuvent cacher :

- 1 bit par échantillon (ou plus)
- Intercalé entre les canaux
- Avec un stride/permutation

Other audio-hiding families you may encounter:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / dial tones

### Technique

DTMF encode des caractères sous forme de paires de fréquences fixes (clavier téléphonique). Si l'audio ressemble à des tonalités du clavier ou à des bips réguliers à double fréquence, testez le décodage DTMF dès le début.

Décodeurs en ligne :

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Références

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}

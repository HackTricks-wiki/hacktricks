# Stéganographie audio

{{#include ../../banners/hacktricks-training.md}}

Motifs courants :

- Messages dans un spectrogramme
- Insertion LSB dans un fichier WAV
- Encodage DTMF / tonalités de numérotation
- Charges utiles dans les métadonnées

## Triage rapide

Avant d'utiliser des outils spécialisés :

- Vérifiez les détails du codec/conteneur et les anomalies :
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si l'audio contient un contenu semblable à du bruit ou une structure tonale, examinez rapidement un spectrogramme.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Stéganographie par spectrogramme

### Technique

La stéganographie par spectrogramme dissimule des données en modelant l'énergie au fil du temps et des fréquences afin qu'elles ne deviennent visibles que dans un graphique temps-fréquence (souvent inaudibles ou perçues comme du bruit).

### Sonic Visualiser

Outil principal pour l'inspection des spectrogrammes :

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (vue du spectrogramme, filtres) : https://www.audacityteam.org/
- `sox` peut générer des spectrogrammes depuis la CLI :
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Décodage FSK / modem

Un signal audio Frequency-shift keyed ressemble souvent à une alternance de tonalités simples dans un spectrogramme.<sup>[[1]](#references)</sup> Une fois que vous disposez d'une estimation approximative de la fréquence centrale, du shift et du baud, utilisez la force brute avec `minimodem` :
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` effectue automatiquement le gain et détecte automatiquement les tonalités mark/space ; ajustez `--rx-invert` ou `--samplerate` si la sortie est illisible.

## WAV LSB

### Technique

Pour le PCM non compressé (WAV), chaque échantillon est un entier. La modification des bits de poids faible change très légèrement la forme d’onde, ce qui permet aux attackers de dissimuler :

- 1 bit par échantillon (ou davantage)
- Des données entrelacées entre les canaux
- Avec un stride/permutation

Autres familles de dissimulation audio que vous pouvez rencontrer :

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (dépendant du format et de l’outil)

### WavSteg

Source : https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonalités de numérotation

### Technique

Le DTMF encode les caractères sous forme de paires de fréquences fixes (clavier téléphonique). Si l’audio ressemble à des tonalités de clavier ou à des bips réguliers à double fréquence, testez rapidement le décodage DTMF.

Décodeurs en ligne :

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Références

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}

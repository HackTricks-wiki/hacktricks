# Stéganographie audio

{{#include ../../banners/hacktricks-training.md}}

Motifs courants :

- Messages dans un spectrogramme
- WAV LSB embedding
- Encodage DTMF / dial tones
- Charges utiles dans les métadonnées

## Triage rapide

Avant d'utiliser des outils spécialisés :

- Vérifiez les détails du codec/conteneur et les anomalies :
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si l'audio contient un contenu ressemblant à du bruit ou une structure tonale, inspectez rapidement un spectrogramme.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Stéganographie par spectrogramme

### Technique

La stéganographie par spectrogramme dissimule des données en modelant l’énergie au fil du temps et des fréquences, de sorte qu’elles deviennent visibles uniquement dans un graphique temps-fréquence (souvent inaudibles ou perçues comme du bruit).

### Sonic Visualiser

Outil principal pour l’inspection des spectrogrammes :

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternatives

- Audacity (vue spectrogramme, filtres) : https://www.audacityteam.org/
- `sox` peut générer des spectrogrammes depuis la CLI :
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## Décodage FSK / modem

Un audio modulé par déplacement de fréquence ressemble souvent à une alternance de tonalités simples dans un spectrogramme. Une fois que vous disposez d'une estimation approximative de la fréquence centrale, du décalage et du débit en bauds, utilisez `minimodem` par force brute :<sup>[[1]](#references)</sup>
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` ajuste automatiquement le gain et détecte automatiquement les tonalités mark/space ; ajustez `--rx-invert` ou `--samplerate` si la sortie est brouillée.

## WAV LSB

### Technique

Pour le PCM non compressé (WAV), chaque échantillon est un entier. Modifier les bits de poids faible change très légèrement la forme d’onde, ce qui permet aux attackers de dissimuler :

- 1 bit par échantillon (ou davantage)
- Répartis entre les canaux
- Avec un stride/une permutation

Autres familles de dissimulation audio que vous pouvez rencontrer :

- Codage de phase
- Dissimulation par écho
- Embedding à étalement de spectre
- Canaux côté codec (dépendants du format et de l’outil)

### WavSteg

De : https://github.com/ragibson/Steganography#WavSteg<sup>[[2]](#references)</sup>
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / sonorités de numérotation

### Technique

Le DTMF encode des caractères sous forme de paires de fréquences fixes (clavier téléphonique). Si l’audio ressemble à des tonalités de clavier ou à des bips réguliers à double fréquence, testez rapidement un décodage DTMF.

Décodeurs en ligne :

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Références

- [1] [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)

{{#include ../../banners/hacktricks-training.md}}

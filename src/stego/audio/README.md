# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Patrones comunes:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Evaluación rápida

Antes de usar herramientas especializadas:

- Confirma detalles y anomalías del codec/container:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si el audio contiene contenido similar a ruido o estructura tonal, inspecciona un spectrogram temprano.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Técnica

Spectrogram stego oculta datos modelando la energía en el dominio tiempo/frecuencia para que sea visible solo en un diagrama tiempo-frecuencia (a menudo inaudible o percibido como ruido).

### Sonic Visualiser

Herramienta principal para la inspección de espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (vista de espectrograma, filtros): https://www.audacityteam.org/
- `sox` puede generar espectrogramas desde la CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Técnica

Para PCM no comprimido (WAV), cada muestra es un entero. Modificar los bits bajos cambia la forma de onda muy ligeramente, por lo que los atacantes pueden ocultar:

- 1 bit por muestra (o más)
- Intercalado entre canales
- Con un paso/permutación

Otras familias de audio-hiding que podrías encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (dependiente del formato y de la herramienta)

### WavSteg

Fuente: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tonos de marcado

### Técnica

DTMF codifica caracteres como pares de frecuencias fijas (teclado telefónico). Si el audio recuerda a tonos de marcado o a pitidos regulares de doble frecuencia, prueba la decodificación DTMF lo antes posible.

Decodificadores en línea:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}

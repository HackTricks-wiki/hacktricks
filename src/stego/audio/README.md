# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Patrones comunes:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Evaluación rápida

Antes de usar herramientas especializadas:

- Confirma los detalles del codec/contenedor y las anomalías:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Si el audio contiene contenido similar a ruido o estructura tonal, inspecciona un spectrogram lo antes posible.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Técnica

Spectrogram stego oculta datos modelando la energía en el tiempo/frecuencia para que se vuelva visible solo en una representación tiempo-frecuencia (a menudo inaudible o percibida como ruido).

### Sonic Visualiser

Herramienta principal para la inspección de espectrogramas:

- https://www.sonicvisualiser.org/

### Alternativas

- Audacity (vista de espectrograma, filtros): https://www.audacityteam.org/
- `sox` puede generar espectrogramas desde la CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Técnica

Para PCM sin comprimir (WAV), cada muestra es un entero. Modificar los bits bajos cambia la forma de onda muy ligeramente, por lo que los atacantes pueden ocultar:

- 1 bit por muestra (o más)
- Intercalado entre canales
- Con un desplazamiento/permutación

Otras familias de ocultamiento de audio que puedes encontrar:

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

- http://jpinsoft.net/deepsound/download.aspx

## DTMF / dial tones

### Técnica

DTMF codifica caracteres como pares de frecuencias fijas (teclado telefónico). Si el audio se asemeja a tonos de teclado o pitidos regulares de doble frecuencia, prueba la decodificación DTMF desde el principio.

Decodificadores online:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}

# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Padrões comuns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triagem rápida

Antes de ferramentas especializadas:

- Confirmar detalhes do codec/container e anomalias:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se o áudio contiver conteúdo semelhante a ruído ou estrutura tonal, inspecione um spectrogram o quanto antes.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Técnica

Spectrogram stego esconde dados ao moldar a energia no domínio tempo/frequência, tornando-os visíveis apenas em um espectrograma (frequentemente inaudível ou percebido como ruído).

### Sonic Visualiser

Ferramenta principal para inspeção de espectrogramas:

- https://www.sonicvisualiser.org/

### Alternativas

- Audacity (visualização de espectrograma, filtros): https://www.audacityteam.org/
- `sox` pode gerar espectrogramas a partir da CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Técnica

Para PCM (WAV) não comprimido, cada amostra é um inteiro. Modificar os bits menos significativos altera a forma de onda muito levemente, então atacantes podem ocultar:

- 1 bit por amostra (ou mais)
- Intercalado entre canais
- Com um stride/permutação

Outras famílias de ocultação de áudio que você pode encontrar:

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

## DTMF / tons de discagem

### Técnica

DTMF codifica caracteres como pares de frequências fixas (teclado telefônico). Se o áudio se assemelha a tons de teclado ou bipes regulares de dupla frequência, teste a decodificação DTMF o quanto antes.

Decodificadores online:

- https://unframework.github.io/dtmf-detect/
- http://dialabc.com/sound/detect/index.html

{{#include ../../banners/hacktricks-training.md}}

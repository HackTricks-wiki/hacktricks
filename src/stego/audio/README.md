# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Padrões comuns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triagem rápida

Antes de ferramentas especializadas:

- Confirme detalhes de codec/container e possíveis anomalias:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se o áudio contiver conteúdo parecido com ruído ou estrutura tonal, inspecione um spectrogram logo no início.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Técnica

Spectrogram stego oculta dados moldando a energia ao longo do tempo/frequência de modo que se torne visível apenas em um gráfico tempo-frequência (frequentemente inaudível ou percebido como ruído).

### Sonic Visualiser

Ferramenta principal para inspeção de espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (visualização de espectrograma, filtros): https://www.audacityteam.org/
- `sox` pode gerar espectrogramas a partir da CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## WAV LSB

### Técnica

Para PCM não comprimido (WAV), cada amostra é um inteiro. Modificar os bits menos significativos altera a forma de onda muito levemente, então atacantes podem ocultar:

- 1 bit por amostra (ou mais)
- Intercalado entre canais
- Com um stride/permutação

Outras famílias de ocultação em áudio que você pode encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (dependente do formato e da ferramenta)

### WavSteg

From: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tons de discagem

### Técnica

DTMF codifica caracteres como pares de frequências fixas (teclado do telefone). Se o áudio se assemelhar a tons do teclado ou bipes regulares de dupla frequência, teste a decodificação DTMF cedo.

Decodificadores online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

{{#include ../../banners/hacktricks-training.md}}

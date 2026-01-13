# Audio Steganography

{{#include ../../banners/hacktricks-training.md}}

Padrões comuns:

- Spectrogram messages
- WAV LSB embedding
- DTMF / dial tones encoding
- Metadata payloads

## Triagem rápida

Antes de ferramentas especializadas:

- Confirme detalhes do codec/container e quaisquer anomalias:
- `file audio`
- `ffmpeg -v info -i audio -f null -`
- Se o áudio contiver conteúdo semelhante a ruído ou estrutura tonal, inspecione um spectrogram desde cedo.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
## Spectrogram steganography

### Técnica

Spectrogram stego esconde dados modelando energia ao longo do tempo/frequência para que se torne visível apenas em um gráfico tempo-frequência (frequentemente inaudível ou percebido como ruído).

### Sonic Visualiser

Ferramenta principal para inspeção de espectrogramas:

- [https://www.sonicvisualiser.org/](https://www.sonicvisualiser.org/)

### Alternativas

- Audacity (visualização de espectrograma, filtros): https://www.audacityteam.org/
- `sox` pode gerar espectrogramas via CLI:
```bash
sox input.wav -n spectrogram -o spectrogram.png
```
## FSK / modem decoding

Frequency-shift keyed áudio frequentemente aparece como tons únicos alternados em um espectrograma. Depois de obter uma estimativa aproximada do center/shift e do baud, brute force com `minimodem`:
```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```
`minimodem` ajusta ganho automaticamente e detecta automaticamente tons mark/space; ajuste `--rx-invert` ou `--samplerate` se a saída estiver distorcida.

## WAV LSB

### Técnica

Para PCM não comprimido (WAV), cada amostra é um inteiro. Modificar os bits menos significativos altera a forma de onda muito levemente, então atacantes podem esconder:

- 1 bit por amostra (ou mais)
- Intercalado entre canais
- Com um stride/permutação

Outras famílias de ocultação de áudio que você pode encontrar:

- Phase coding
- Echo hiding
- Spread-spectrum embedding
- Codec-side channels (format-dependent and tool-dependent)

### WavSteg

Fonte: https://github.com/ragibson/Steganography#WavSteg
```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```
### DeepSound

- [http://jpinsoft.net/deepsound/download.aspx](http://jpinsoft.net/deepsound/download.aspx)

## DTMF / tons de discagem

### Técnica

DTMF codifica caracteres como pares de frequências fixas (teclado telefônico). Se o áudio se assemelhar a tons de teclado ou bipes regulares de dupla frequência, teste a decodificação DTMF o quanto antes.

Decodificadores online:

- [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
- [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Referências

- [Flagvent 2025 (Medium) — pink, Santa’s Wishlist, Christmas Metadata, Captured Noise](https://0xdf.gitlab.io/flagvent2025/medium)

{{#include ../../banners/hacktricks-training.md}}

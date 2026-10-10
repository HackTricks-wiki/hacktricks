# Esteganografia de áudio

{{#include ../../banners/hacktricks-training.md}}

Padrões comuns:

- Mensagens em espectrogramas
- Incorporação LSB em WAV
- Codificação por DTMF / tons de discagem
- Payloads em metadados

## Triagem rápida

Antes de usar ferramentas especializadas:

- Confirme os detalhes do codec/contêiner e verifique anomalias:
  - `file audio`
  - `ffmpeg -v info -i audio -f null -`
- Se o áudio contiver conteúdo semelhante a ruído ou estrutura tonal, inspecione um espectrograma logo no início.

```bash
ffmpeg -v info -i stego.mp3 -f null -
```

## Esteganografia em espectrogramas

### Técnica

A esteganografia em espectrogramas oculta dados moldando a energia ao longo do tempo e da frequência para que fiquem visíveis em um gráfico tempo-frequência, enquanto o áudio pode soar como tons ou ruído.<sup>[[3]](#references)</sup>

### Sonic Visualiser

Ferramenta principal para inspecionar espectrogramas:

- [Sonic Visualiser](https://www.sonicvisualiser.org/)<sup>[[3]](#references)</sup>

### Alternativas

- Audacity (visualização de espectrograma e filtros).<sup>[[6]](#references)</sup>
- `sox` pode gerar espectrogramas pela CLI:

```bash
sox input.wav -n spectrogram -o spectrogram.png
```

## Decodificação FSK / de modem

Áudio com modulação por deslocamento de frequência geralmente aparece como tons únicos alternados em um espectrograma. Depois de estimar aproximadamente a frequência central, o deslocamento e a taxa de baud, faça uma busca exaustiva com `minimodem`:<sup>[[1]](#references)</sup>

```bash
# Visualize the band to pick baud/frequency
sox noise.wav -n spectrogram -o spec.png

# Try common bauds until printable text appears
minimodem -f noise.wav 45
minimodem -f noise.wav 300
minimodem -f noise.wav 1200
minimodem -f noise.wav 2400
```

`minimodem` oferece suporte aos modos Bell e outros modos FSK, além de frequências mark/space personalizadas; consulte as opções em vez de presumir que toda gravação possa ser autodetectada. Tente `--rx-invert`, um modo de baud explícito ou `--samplerate <Hz>` quando a saída estiver distorcida.<sup>[[4]](#references)</sup>

## WAV LSB

### Técnica

Em PCM não compactado (WAV), cada amostra é um número inteiro. Modificar bits menos significativos altera muito pouco a forma de onda, então atacantes podem ocultar dados:

- 1 bit por amostra (ou mais)
- Intercalados entre canais
- Com um passo ou uma permutação

Outras técnicas de ocultação de áudio que você pode encontrar:

- Codificação de fase
- Ocultação por eco
- Incorporação por espalhamento espectral
- Canais laterais no codec (dependentes do formato e da ferramenta)

### WavSteg

Os comandos a seguir usam o WavSteg do toolkit `ragibson/Steganography`.<sup>[[2]](#references)</sup>

```bash
python3 WavSteg.py -r -b 1 -s sound.wav -o out.bin
python3 WavSteg.py -r -b 2 -s sound.wav -o out.bin
```

### DeepSound

- Repositório oficial e versões do DeepSound.<sup>[[7]](#references)</sup>

## DTMF / tons de discagem

### Técnica

O DTMF representa cada sinal do teclado usando uma frequência de um grupo baixo e uma de um grupo alto. Se o áudio se parecer com tons de teclado ou bipes regulares de dupla frequência, teste a decodificação DTMF logo no início.<sup>[[5]](#references)</sup>

Decodificadores online:

- Ferramenta de navegador `dtmf-detect`.<sup>[[8]](#references)</sup>
- `ribt/dtmf-decoder`, um decodificador de arquivos de áudio offline.<sup>[[9]](#references)</sup>

## References

- [1] [Flagvent 2025 (Medium) — pink, Lista de desejos do Papai Noel, Metadados de Natal, Ruído capturado](https://0xdf.gitlab.io/flagvent2025/medium)
- [2] [ragibson/Steganography](https://github.com/ragibson/Steganography#WavSteg)
- [3] [Sonic Visualiser — documentação](https://www.sonicvisualiser.org/documentation.html)
- [4] [kamalmostafa/minimodem — modem FSK de linha de comando](https://github.com/kamalmostafa/minimodem)
- [5] [Recomendação ITU-T Q.23 — características técnicas de aparelhos telefônicos com teclado](https://www.itu.int/rec/T-REC-Q.23/en)
- [6] [Audacity](https://www.audacityteam.org/)
- [7] [Jpinsoft/DeepSound — repositório oficial e versões](https://github.com/Jpinsoft/DeepSound)
- [8] [`dtmf-detect`](https://unframework.github.io/dtmf-detect/)
- [9] [ribt/dtmf-decoder](https://github.com/ribt/dtmf-decoder)
{{#include ../../banners/hacktricks-training.md}}

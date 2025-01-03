{{#include ../../../banners/hacktricks-training.md}}

**Manipulação de arquivos de áudio e vídeo** é um elemento básico em **desafios de forense CTF**, aproveitando **esteganografia** e análise de metadados para ocultar ou revelar mensagens secretas. Ferramentas como **[mediainfo](https://mediaarea.net/en/MediaInfo)** e **`exiftool`** são essenciais para inspecionar metadados de arquivos e identificar tipos de conteúdo.

Para desafios de áudio, **[Audacity](http://www.audacityteam.org/)** se destaca como uma ferramenta de primeira linha para visualizar formas de onda e analisar espectrogramas, essenciais para descobrir texto codificado em áudio. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** é altamente recomendado para análise detalhada de espectrogramas. **Audacity** permite manipulação de áudio, como desacelerar ou inverter faixas para detectar mensagens ocultas. **[Sox](http://sox.sourceforge.net/)**, uma utilidade de linha de comando, se destaca na conversão e edição de arquivos de áudio.

A manipulação de **Bits Menos Significativos (LSB)** é uma técnica comum em esteganografia de áudio e vídeo, explorando os blocos de tamanho fixo de arquivos de mídia para embutir dados discretamente. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** é útil para decodificar mensagens ocultas como **tons DTMF** ou **código Morse**.

Desafios de vídeo frequentemente envolvem formatos de contêiner que agrupam fluxos de áudio e vídeo. **[FFmpeg](http://ffmpeg.org/)** é a escolha ideal para analisar e manipular esses formatos, capaz de desmultiplexar e reproduzir conteúdo. Para desenvolvedores, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integra as capacidades do FFmpeg ao Python para interações avançadas e scriptáveis.

Essa variedade de ferramentas destaca a versatilidade necessária em desafios CTF, onde os participantes devem empregar um amplo espectro de técnicas de análise e manipulação para descobrir dados ocultos em arquivos de áudio e vídeo.

## Referências

- [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

{{#include ../../../banners/hacktricks-training.md}}

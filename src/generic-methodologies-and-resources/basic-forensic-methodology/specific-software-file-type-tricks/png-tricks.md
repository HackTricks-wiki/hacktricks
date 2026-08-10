# Truques com PNG

**Arquivos PNG** são muito comuns em **CTFs**, **resposta a incidentes** e **preparação de malware** porque são **sem perdas**, **baseados em chunks**, e muitas ferramentas os renderizam sem problemas mesmo quando contêm **metadados extras**, **payloads anexados** ou **chunks parcialmente corrompidos**.

Trate um PNG como um **container**, não apenas como uma imagem.

## Triagem rápida

Comece com verificações no nível do container antes de partir para LSB stego. Para o fluxo de trabalho de bit-plane/LSB, consulte [a página dedicada a image stego](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Coisas úteis para procurar:

- **Chunks auxiliares inesperados**, como `tEXt`, `zTXt`, `iTXt`, `eXIf` ou `iCCP`
- **Erros de CRC** ou comprimentos de chunks malformados
- **Dados adicionais após `IEND`**
- **Vários marcadores `IEND`** ou fragmentos `IDAT` recuperáveis após o fim formal do arquivo
- Um arquivo que seja um PNG válido **e** que também pareça um ZIP/PDF/script quando submetido a carving

Lembre-se de que a estrutura mínima válida normalmente é:

- `IHDR` (deve ser o primeiro)
- `IDAT` (um ou mais chunks consecutivos)
- `IEND` (deve ser o último)

## Dados após `IEND`

Um dos artefatos PNG com maior sinal é a **existência de dados anexados após o chunk `IEND` final**. Muitos decoders ignoram esses dados, o que os torna úteis para:

- **Simple stego / payloads ocultos**
- **PNG polyglots**
- **Malware staging**
- **Recuperação de dados de imagem antigos** de editores com bugs

Detecção rápida:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Se quiser extrair tudo após o `IEND` final:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Também tente analisadores genéricos de arquivos diretamente no PNG ou no trailer extraído:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recuperação no estilo Acropalypse de screenshots cortadas/redacted

Um truque forense de PNG muito prático e recente é verificar se um editor de screenshots **sobrescreveu** um PNG sem **truncar** o arquivo antigo primeiro. Nesses casos, bytes da **imagem anterior** podem permanecer após `IEND`, e, às vezes, dados `IDAT` adicionais podem ser parcialmente reconstruídos.

Isso ficou conhecido com o **aCropalypse** (Google Pixel Markup) e o problema relacionado do **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Na prática, se um PNG "cortado" ou "redacted" ainda contiver dados antigos no final, talvez seja possível recuperar parte do screenshot original.<sup>[[1]](#references)</sup>

Fluxo de trabalho prático:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Sinais que justificam fortemente uma análise mais aprofundada:

- `pngcheck` relata **dados adicionais após `IEND`**
- Você encontra **mais de um `IEND`**
- Você encontra **chunks `IDAT` extras** após o fim aparente da imagem
- A captura de tela veio de um dispositivo/editor conhecido por ter sido afetado

Se isso acontecer, passe o arquivo por uma **aCropalypse recovery tool** antes de considerar a ocultação confiável.

## Abuso de chunks importante na prática

Os chunks PNG mais interessantes para investigações geralmente não são os chunks óbvios da imagem, mas os que podem transportar **texto**, **metadados** ou **bytes de payload**:

- `tEXt` / `zTXt` / `iTXt` – metadados de texto e texto compactado
- `eXIf` – dados EXIF dentro de PNG
- `iCCP` – perfil ICC incorporado
- `PLTE` – dados da paleta em imagens indexadas, mas também úteis em cenários de payload-smuggling.<sup>[[2]](#references)</sup>

Extraia-os com:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Para persistência de payloads ofensivos dentro de chunks PNG (por exemplo, truques com **PLTE**, **IDAT** ou **tEXt** que sobrevivem a algumas transformações de imagem em PHP), consulte as notas mais detalhadas focadas em upload aqui:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Reparo de PNG corrompido

Para verificar a integridade e localizar a área exata danificada, **pngcheck** continua sendo uma das melhores ferramentas iniciais:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se o arquivo estiver danificado, em vez de ser intencionalmente malicioso, **PCRT** pode ser útil em CTFs e trabalhos de laboratório para corrigir problemas comuns, como headers inválidos, valores IHDR incorretos, problemas de CRC ou layouts de chunks malformados.

Se o objetivo for **sanitizar** um PNG que contenha dados suspeitos no trailer, preservando a imagem visível, o ExifTool pode remover explicitamente o trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Para evidências sensíveis, sempre trabalhe em uma **cópia** e mantenha os hashes do original antes de tentar reparos.

## References

- [1] [Explorando o aCropalypse: Recuperando PNGs truncados](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payloads PHP persistentes em PNGs: Como injetar código PHP em uma imagem — e mantê-lo lá](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}

# Truques de PNG

{{#include ../../../banners/hacktricks-training.md}}

**Arquivos PNG** são muito comuns em **CTFs**, **resposta a incidentes** e **malware staging** porque são **sem perdas**, **baseados em chunks**, e muitas ferramentas os renderizam sem problemas mesmo quando contêm **metadados extras**, **payloads anexados** ou **chunks parcialmente corrompidos**.

Trate um PNG como um **container**, não apenas como uma imagem.

## Triagem rápida

Comece pelas verificações no nível do container antes de partir para LSB stego. Para o fluxo de trabalho de bit-plane/LSB, consulte [a página dedicada sobre image stego](../../../stego/images/README.md).
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
- Um arquivo que seja um PNG válido **e** também se pareça com um ZIP/PDF/script ao ser carved

Lembre-se de que a estrutura mínima válida geralmente é:

- `IHDR` (deve ser o primeiro)
- `IDAT` (um ou mais chunks consecutivos)
- `IEND` (deve ser o último)

## Dados posteriores a `IEND`

Um dos artefatos PNG com maior sinal é **a existência de dados anexados após o chunk `IEND` final**. Muitos decoders ignoram esses dados, o que os torna úteis para:

- **Stego simples / payloads ocultos**
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
Também tente analisadores genéricos de arquivos compactados diretamente no PNG ou no trailer extraído:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recuperação no estilo Acropalypse de screenshots cortados/redigidos

Um truque forense muito prático e recente para PNG é verificar se um editor de screenshots **sobrescreveu** um PNG sem **truncar** o arquivo antigo primeiro. Nesses casos, bytes da **imagem anterior** podem permanecer após `IEND`, e, às vezes, dados `IDAT` adicionais podem ser parcialmente reconstruídos.

Isso se tornou conhecido com o **aCropalypse** (Google Pixel Markup) e o problema relacionado do **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Na prática, se um PNG "cortado" ou "redigido" ainda contiver dados antigos no final, talvez seja possível recuperar parte do screenshot original.<sup>[[1]](#references)</sup>

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

Se isso acontecer, passe o arquivo por uma **ferramenta de recuperação aCropalypse** antes de considerar a ocultação confiável.

## Abuso de chunks que importa na prática

Os chunks PNG mais interessantes para investigações geralmente não são os óbvios da imagem, mas os chunks que podem transportar **texto**, **metadados** ou **bytes de payload**:

- `tEXt` / `zTXt` / `iTXt` – metadados de texto e texto compactado
- `eXIf` – dados EXIF dentro de PNG
- `iCCP` – perfil ICC incorporado
- `PLTE` – dados da paleta em imagens indexadas, mas também úteis em cenários de ocultação de payload.<sup>[[2]](#references)</sup>

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

Para verificar a integridade e localizar a área exata que está corrompida, **pngcheck** continua sendo uma das melhores ferramentas iniciais:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se o arquivo estiver danificado, e não for intencionalmente malicioso, **PCRT** pode ser útil em CTFs e trabalhos de laboratório para corrigir problemas comuns, como cabeçalhos incorretos, valores IHDR errados, problemas de CRC ou estruturas de chunks malformadas.

Se o seu objetivo for **sanitizar** um PNG que contenha dados suspeitos no trailer, preservando a imagem visível, o ExifTool pode remover explicitamente o trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Para evidências sensíveis, sempre trabalhe em uma **cópia** e mantenha hashes do original antes de tentar reparos.

## References

- [1] [Explorando o aCropalypse: Recuperando PNGs truncados](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payloads persistentes de PHP em PNGs: Como injetar código PHP em uma imagem — e mantê-lo nela](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
{{#include ../../../banners/hacktricks-training.md}}

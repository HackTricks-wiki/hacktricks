# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Arquivos PNG** são muito comuns em **CTFs**, **incident response** e **malware staging** porque são **lossless**, **chunk-based**, e muitas ferramentas os renderizam sem problemas mesmo quando contêm **extra metadata**, **appended payloads** ou **partially corrupted chunks**.

Trate um PNG como um **container**, não apenas como uma imagem.

## Quick triage

Comece com verificações no nível do container antes de partir para LSB stego. Para o fluxo de trabalho de bit-plane/LSB, consulte [a página dedicada de stego de imagens](../../../stego/images/README.md).
```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```
Coisas úteis para procurar:

- **Chunks ancilares inesperados** como `tEXt`, `zTXt`, `iTXt`, `eXIf` ou `iCCP`
- **Erros de CRC** ou tamanhos de chunk malformados
- **Dados adicionais após `IEND`**
- **Múltiplos marcadores `IEND`** ou fragmentos `IDAT` recuperáveis após o fim formal do arquivo
- Um arquivo que seja um PNG válido **e** também pareça um ZIP/PDF/script quando extraído

Lembre-se de que a estrutura válida mínima geralmente é:

- `IHDR` (deve ser o primeiro)
- `IDAT` (um ou mais chunks consecutivos)
- `IEND` (deve ser o último)

## Dados residuais após `IEND`

Um dos artefatos PNG de maior sinal é **dados anexados após o chunk final `IEND`**. Muitos decoders o ignoram, o que o torna útil para:

- **Stego simples / payload oculto**
- **PNG polyglots**
- **Staging de malware**
- **Recuperar dados antigos da imagem** de editores com bugs

Detecção rápida:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Se você quiser cortar tudo após o `IEND` final:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Também tente parsers genéricos de archive diretamente contra o PNG ou contra o trailer carveado:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recuperação no estilo Acropalypse de screenshots recortadas/redigidas

Um truque forense de PNG muito prático e recente é verificar se um editor de screenshots **sobrescreveu** um PNG sem **truncar** primeiro o arquivo antigo. Nesses casos, bytes da **imagem anterior** podem permanecer após o `IEND`, e às vezes dados extras de `IDAT` podem ser parcialmente reconstruídos.

Isso ficou amplamente conhecido com **aCropalypse** (Google Pixel Markup) e o problema relacionado do **Windows Snipping Tool**. Na prática, se um PNG "recortado" ou "redigido" ainda contiver dados antigos no final, você pode conseguir recuperar parte da screenshot original.

Fluxo de trabalho prático:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Sinais que justificam fortemente uma análise mais profunda:

- `pngcheck` reporta **additional data after `IEND`**
- Você encontra **mais de um `IEND`**
- Você encontra **chunks `IDAT` extras** depois do aparente fim da imagem
- A screenshot veio de um device/editor conhecido por ter sido afetado

Se isso acontecer, alimente o arquivo em uma **aCropalypse recovery tool** antes de tratar a redaction como confiável.

## Chunk abuse que importa na prática

Os chunks PNG mais interessantes para investigações geralmente não são os chunks de imagem óbvios, mas os chunks que podem carregar **text**, **metadata** ou **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – text metadata e compressed text
- `eXIf` – EXIF data inside PNG
- `iCCP` – embedded ICC profile
- `PLTE` – palette data em indexed images, mas também útil em payload-smuggling scenarios

Dump them with:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Para persistência de payload ofensivo dentro de chunks PNG (por exemplo, truques em **PLTE**, **IDAT** ou **tEXt** que sobrevivem a algumas transformações de imagens em PHP), veja as notas mais detalhadas focadas em upload aqui:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Reparação de PNG corrompido

Para verificar a integridade e localizar a área exata quebrada, **pngcheck** continua sendo uma das melhores ferramentas iniciais:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se o arquivo estiver danificado em vez de intencionalmente malicioso, **PCRT** pode ser útil em CTFs e trabalho de laboratório para corrigir problemas comuns como headers ruins, valores IHDR incorretos, problemas de CRC ou layouts de chunks malformados.

Se seu objetivo for **sanitizar** um PNG que contenha dados suspeitos no trailer enquanto preserva a imagem visível, o ExifTool pode remover explicitamente o trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Para evidências sensíveis, sempre trabalhe em uma **cópia** e mantenha hashes do original antes de tentar reparos.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}

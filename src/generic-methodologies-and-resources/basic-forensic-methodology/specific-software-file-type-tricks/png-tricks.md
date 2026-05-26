# PNG Tricks

{{#include ../../../banners/hacktricks-training.md}}

**Arquivos PNG** são muito comuns em **CTFs**, **resposta a incidentes** e **malware staging** porque são **lossless**, **chunk-based**, e muitas ferramentas os renderizam sem problemas mesmo quando contêm **extra metadata**, **appended payloads** ou **partially corrupted chunks**.

Trate um PNG como um **container**, não apenas como uma imagem.

## Triagem rápida

Comece com verificações no nível do container antes de partir para LSB stego. Para o workflow de bit-plane/LSB, veja [a página dedicada de image stego](../../../stego/images/README.md).
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
- Um arquivo que é um PNG válido **e** também parece um ZIP/PDF/script quando extraído

Lembre-se de que a estrutura mínima válida normalmente é:

- `IHDR` (deve ser o primeiro)
- `IDAT` (um ou mais chunks consecutivos)
- `IEND` (deve ser o último)

## Dados após `IEND`

Um dos artefatos PNG de maior sinal é **dados anexados após o chunk final `IEND`**. Muitos decoders ignoram isso, o que o torna útil para:

- **Stego simples / payload oculto**
- **PNG polyglots**
- **Malware staging**
- **Recuperar dados antigos de imagem** de editores bugados

Detecção rápida:
```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```
Se você quiser extrair tudo após o `IEND` final:
```bash
IEND_OFF=$(grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png | tail -n1 | cut -d: -f1)
dd if=suspect.png of=png-trailer.bin bs=1 skip=$((IEND_OFF+8))
file png-trailer.bin
binwalk -eM png-trailer.bin
```
Também tente parsers genéricos de arquivos diretamente contra o PNG ou o trailer carved:
```bash
7z l suspect.png
unzip -l suspect.png
```
## Recuperação no estilo Acropalypse de screenshots recortadas/redigidas

Um truque forense de PNG recente e muito prático é verificar se um editor de screenshots **sobrescreveu** um PNG sem primeiro **truncar** o arquivo antigo. Nesses casos, bytes da **imagem anterior** podem permanecer após `IEND`, e às vezes dados extras de `IDAT` podem ser parcialmente reconstruídos.

Isso ficou amplamente conhecido com **aCropalypse** (Google Pixel Markup) e o problema relacionado do **Windows Snipping Tool**. Na prática, se um PNG "recortado" ou "redigido" ainda contiver dados antigos no final, você pode conseguir recuperar parte da screenshot original.

Fluxo de trabalho prático:
```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```
Sinais que justificam fortemente uma análise mais profunda:

- `pngcheck` reporta **dados adicionais após `IEND`**
- Você encontra **mais de um `IEND`**
- Você encontra **chunks `IDAT` extras** após o fim aparente da imagem
- A screenshot veio de um dispositivo/editor conhecido por ter sido afetado

Se isso acontecer, passe o arquivo por uma **ferramenta de recuperação aCropalypse** antes de tratar a redação como confiável.

## Abuso de chunks que importa na prática

Os chunks PNG mais interessantes para investigações geralmente não são os chunks óbvios da imagem, mas os chunks que podem carregar **text**, **metadata** ou **payload bytes**:

- `tEXt` / `zTXt` / `iTXt` – metadata de texto e texto comprimido
- `eXIf` – dados EXIF dentro do PNG
- `iCCP` – perfil ICC embutido
- `PLTE` – dados de paleta em imagens indexadas, mas também útil em cenários de smuggling de payload

Extraia-os com:
```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```
Para persistência de payload ofensivo dentro de chunks PNG (por exemplo, truques **PLTE**, **IDAT** ou **tEXt** que sobrevivem a algumas transformações de imagem em PHP), veja as notas mais detalhadas focadas em upload aqui:

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Reparação de PNG corrompido

Para verificar a integridade e localizar a área exata quebrada, **pngcheck** continua sendo uma das melhores primeiras ferramentas:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se o arquivo estiver danificado em vez de intencionalmente malicioso, **PCRT** pode ser útil em CTFs e trabalho de laboratório para corrigir problemas comuns como headers inválidos, valores IHDR errados, problemas de CRC ou layouts de chunk malformados.

Se seu objetivo for **sanitizar** um PNG que contém dados suspeitos no trailer enquanto preserva a imagem visível, o ExifTool pode remover explicitamente o trailer:
```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```
Para evidência sensível, sempre trabalhe em uma **cópia** e mantenha hashes do original antes de tentar reparos.

## References

- [https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)

{{#include ../../../banners/hacktricks-training.md}}

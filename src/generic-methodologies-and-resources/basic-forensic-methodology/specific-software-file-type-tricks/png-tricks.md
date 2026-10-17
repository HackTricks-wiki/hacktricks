# Truques de PNG

{{#include ../../../banners/hacktricks-training.md}}

**Arquivos PNG** são muito comuns em **CTFs**, **resposta a incidentes** e **staging de malware**, pois são **sem perda**, **baseados em chunks**, e muitas ferramentas os renderizam sem problemas, mesmo quando contêm **metadados extras**, **payloads anexados** ou **chunks parcialmente corrompidos**.

Trate um PNG como um **contêiner**, não apenas como uma imagem.

## Triagem rápida

Comece pelas verificações no nível do contêiner antes de partir para esteganografia LSB. Para o fluxo de trabalho de bit-plane/LSB, consulte [a página dedicada à esteganografia em imagens](../../../stego/images/).

```bash
file suspect.png
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
strings -n 6 suspect.png | head
binwalk -eM suspect.png
```

Coisas úteis para procurar:

- **Chunks auxiliares inesperados** como `tEXt`, `zTXt`, `iTXt`, `eXIf` ou `iCCP`
- **Erros de CRC** ou comprimentos de chunk malformados
- **Dados adicionais após `IEND`**
- **Vários marcadores `IEND`** ou fragmentos `IDAT` recuperáveis após o fim formal do arquivo
- Um arquivo que seja um PNG válido **e** também pareça um ZIP/PDF/script quando extraído

Lembre-se: a estrutura mínima válida geralmente é:

- `IHDR` (deve ser o primeiro)
- `IDAT` (um ou mais chunks consecutivos)
- `IEND` (deve ser o último)

## Dados posteriores a `IEND`

Um dos artefatos PNG com maior valor de sinal é **dados anexados após o chunk `IEND` final**. Muitos decodificadores os ignoram, o que os torna úteis para:

- **Stego simples / payloads ocultos**
- **PNG polyglots**
- **Preparação de malware**
- **Recuperar dados de imagem mais antigos** de editores com bugs

Detecção rápida:

```bash
pngcheck -v suspect.png
# Look for: "additional data after IEND chunk"

exiftool suspect.png
# ExifTool usually warns about trailer data after PNG IEND

grep -aboa $'IEND\xAE\x42\x60\x82' suspect.png
# More than one hit is suspicious
```

Uma busca por bytes de `IEND` é apenas uma pista: os mesmos bytes podem ocorrer nos dados de um chunk ou em um trailer forjado. Para fazer carving de forma confiável, percorra os chunks prefixados por comprimento a partir da assinatura PNG e pare no primeiro `IEND` estrutural; o [parser de chunks abaixo](#extract-ancillary-chunk-payloads) também salva o trailer.<sup>[[6]](#references)</sup>

Também tente usar parsers genéricos de arquivos diretamente no PNG ou no trailer extraído:

```bash
7z l suspect.png
unzip -l suspect.png
```

## Recuperação no estilo aCropalypse de capturas de tela cortadas/ocultadas

Um truque forense de PNG muito prático e recente é verificar se um editor de capturas de tela **sobrescreveu** um PNG sem antes **truncar** o arquivo antigo. Nesses casos, bytes da **imagem anterior** podem permanecer após `IEND`, e, às vezes, dados `IDAT` adicionais podem ser parcialmente reconstruídos.

Isso ficou bastante conhecido com o **aCropalypse** (Google Pixel Markup) e o problema relacionado do **Windows Snipping Tool**.<sup>[[3]](#references)</sup> Na prática, se um PNG "cortado" ou "ocultado" ainda contiver dados antigos no final, talvez seja possível recuperar parte da captura de tela original.<sup>[[1]](#references)</sup>

Fluxo de trabalho prático:

```bash
pngcheck -v screenshot.png
exiftool screenshot.png | grep -i trailer
grep -aboa 'IDAT' screenshot.png
grep -aboa $'IEND\xAE\x42\x60\x82' screenshot.png
```

Sinais que justificam fortemente uma análise mais aprofundada:

- `pngcheck` informa **dados adicionais após `IEND`**
- Você encontra **mais de um `IEND`**
- Você encontra **chunks `IDAT` extras** após o aparente fim da imagem
- A captura de tela veio de um dispositivo/editor que se sabe ter sido afetado

Se isso acontecer, passe o arquivo por uma **ferramenta de recuperação aCropalypse** antes de considerar a tarja confiável.

## Abuso de chunks relevante na prática

Os chunks PNG mais interessantes para investigações geralmente não são os óbvios, relacionados à imagem, mas aqueles que podem conter **texto**, **metadados** ou **bytes de payload**:

- `tEXt` / `zTXt` / `iTXt` – metadados de texto e texto comprimido
- `eXIf` – dados EXIF dentro de PNG
- `iCCP` – perfil ICC incorporado
- `PLTE` – dados de paleta em imagens indexadas, mas também úteis em cenários de ocultação de payload.<sup>[[2]](#references)</sup>

Despeje-os com:

```bash
pngcheck -vp suspect.png
exiftool -a -u -g1 suspect.png
```

Para persistência de payloads ofensivos dentro de chunks PNG (por exemplo, truques com **PLTE**, **IDAT** ou **tEXt** que sobrevivem a algumas transformações de imagens em PHP), consulte as notas mais detalhadas voltadas a uploads aqui:<sup>[[2]](#references)</sup>

{{#ref}}
../../../pentesting-web/file-upload/README.md
{{#endref}}

## Extrair payloads de chunks auxiliares

Um atacante pode inserir bytes arbitrários em um **chunk auxiliar desconhecido antes de `IEND`**. Decodificadores PNG comuns podem ignorar um chunk auxiliar desconhecido, enquanto um script que busca a imagem como bytes pode ler e usar o payload; abrir o PNG por si só não o executa.<sup>[[4]](#references)[[6]](#references)</sup> A pesquisa original demonstrou um chunk personalizado comprimido e criptografado.<sup>[[4]](#references)</sup> Um exemplo posterior em navegador usou os bytes extraídos para fornecer HTML ou um download.<sup>[[5]](#references)</sup>

Uma primeira letra minúscula no tipo do chunk significa *auxiliar*; uma segunda letra minúscula significa *privado*. Por exemplo, `paMP` é privado, enquanto `pAMP` usa o namespace público, embora este último tenha sido inventado para a demonstração.<sup>[[4]](#references)[[6]](#references)</sup> Um chunk tem a estrutura `comprimento (4 bytes, big-endian) | tipo (4 bytes) | dados | CRC (4 bytes)`; o CRC cobre o tipo e os dados. Analise essa estrutura em vez de procurar um nome de tipo dentro dos dados `IDAT` comprimidos. O iterador a seguir valida os limites e os CRCs, exporta os payloads dos chunks auxiliares como bytes brutos e grava todos os bytes após o `IEND` estrutural em `png-trailer.bin`.<sup>[[6]](#references)</sup>

<details>
<summary>Extrair chunks auxiliares e o trailer PNG</summary>

```bash
python3 - suspect.png <<'PY'
from pathlib import Path
import sys, zlib

png = Path(sys.argv[1]).read_bytes()
assert png[:8] == b"\x89PNG\r\n\x1a\n", "not a PNG"
off = 8
while off + 12 <= len(png):
    size = int.from_bytes(png[off:off + 4], "big")
    kind = png[off + 4:off + 8]
    if not all(65 <= c <= 90 or 97 <= c <= 122 for c in kind):
        raise ValueError(f"invalid chunk type at {off:#x}")
    end = off + 12 + size
    if size >= 2**31 or end > len(png):
        raise ValueError(f"invalid chunk length at {off:#x}")
    body = png[off + 8:end - 4]
    crc = int.from_bytes(png[end - 4:end], "big")
    if zlib.crc32(kind + body) & 0xffffffff != crc:
        raise ValueError(f"bad CRC at {off:#x}")
    print(f"{off:#010x} {kind.decode('ascii', 'replace')} {size} bytes")
    if 97 <= kind[0] <= 122:
        Path(f"chunk-{kind.decode('ascii')}-{off:x}.bin").write_bytes(body)
    off = end
    if kind == b"IEND":
        if size != 0:
            raise ValueError("IEND must be empty")
        Path("png-trailer.bin").write_bytes(png[off:])
        break
else:
    raise ValueError("no complete IEND chunk")
PY
for f in chunk-*.bin png-trailer.bin; do [ -f "$f" ] && file "$f"; done
```

</details>

Inspecione os bytes extraídos com `file`, `strings` ou `binwalk`; descompacte apenas se o arquivo portador estiver realmente compactado.<sup>[[4]](#references)</sup> A recodificação pode remover o arquivo portador, então compare os bytes enviados e recuperados antes de confiar nele.<sup>[[2]](#references)[[6]](#references)</sup>

## Reparo de PNG corrompido

Para verificar a integridade e localizar a área exata danificada, **pngcheck** continua sendo uma das melhores ferramentas iniciais:

- [pngcheck](http://libpng.org/pub/png/apps/pngcheck.html)

Se o arquivo estiver danificado, e não for malicioso de propósito, o **PCRT** pode ser útil em CTFs e trabalhos de laboratório para corrigir problemas comuns, como cabeçalhos inválidos, valores IHDR incorretos, problemas de CRC ou layouts de chunks malformados.

Se o seu objetivo for **sanitizar** um PNG que contenha dados suspeitos no trailer, preservando a imagem visível, o ExifTool pode remover explicitamente o trailer:

```bash
exiftool -Trailer:All= -overwrite_original suspect.png
```

Para evidências sensíveis, trabalhe sempre em uma **cópia** e mantenha hashes do original antes de tentar repará-lo.



## References

- [1] [Explorando aCropalypse: Recuperação de PNGs truncados](https://www.da.vidbuchanan.co.uk/blog/exploiting-acropalypse.html)
- [2] [Payloads persistentes de PHP em PNGs: como injetar código PHP em uma imagem — e mantê-lo lá](https://www.synacktiv.com/en/publications/persistent-php-payloads-in-pngs-how-to-inject-php-code-in-an-image-and-keep-it-there)
- [3] [NVD - CVE-2023-28303](https://nvd.nist.gov/vuln/detail/CVE-2023-28303)
- [4] [Chunks auxiliares são o lugar perfeito para guardar informações confidenciais](https://ignifexlabs.com/blog/hiding-data-in-png-ancillary-chunks.html)
- [5] [Usando chunks auxiliares válidos para contrabandear dados até um endpoint](https://ignifexlabs.com/blog/png-data-smuggling.html)
- [6] [Especificação Portable Network Graphics (PNG) (Terceira edição)](https://www.w3.org/TR/png-3/)
{{#include ../../../banners/hacktricks-training.md}}

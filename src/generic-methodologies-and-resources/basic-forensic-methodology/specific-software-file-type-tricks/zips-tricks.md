# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Ferramentas de linha de comando** para gerenciar **arquivos zip** são essenciais para diagnosticar, reparar e quebrar arquivos zip. Aqui estão alguns utilitários importantes:<sup>[[1]](#references)</sup>

- **`unzip`**: Revela por que um arquivo zip pode não ser descompactado.
- **`zipdetails -v`**: Oferece uma análise detalhada dos campos do formato de arquivo zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Lista o conteúdo de um arquivo zip sem extraí-lo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar arquivos zip corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para ataques de dicionário e brute-force contra senhas de ZIP; a viabilidade depende do espaço de busca da senha.<sup>[[15]](#references)</sup>

A [especificação do formato de arquivo Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões dos arquivos zip.<sup>[[4]](#references)</sup>

Arquivos ZIP tradicionais protegidos por senha geralmente deixam visíveis os nomes e tamanhos dos arquivos, ao contrário dos modos de criptografia de cabeçalho compatíveis com RAR e 7z. Um ataque de known-plaintext contra ZipCrypto recupera **chaves internas de criptografia**, não necessariamente a senha original; essas chaves são suficientes para descriptografar entradas criptografadas com a mesma senha.<sup>[[13]](#references)</sup> O ataque precisa de bytes conhecidos do fluxo **antes da criptografia**: para um membro armazenado, são os bytes do arquivo original; para um membro DEFLATE, são os bytes comprimidos, cuja obtenção pode exigir a recriação exata da saída da compressão.<sup>[[13]](#references)[[14]](#references)</sup> Consulte [Known plaintext ZIP attack](../../../generic-hacking/brute-force.md#known-plaintext-zip-attack) para um fluxo de trabalho prático. Para informações básicas sobre criptoanálise, consulte [o artigo](https://math.ucr.edu/~mike/zipattacks.pdf) e [o passo a passo](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> Este ataque contra ZipCrypto não se aplica a entradas ZIP criptografadas com AES.<sup>[[13]](#references)</sup>

---

## Truques anti-reversing em APKs que usam cabeçalhos ZIP manipulados

Droppers modernos de malware para Android usam metadados ZIP malformados para quebrar ferramentas estáticas (jadx/apktool/unzip), mantendo o APK instalável no dispositivo. Os truques mais comuns são:<sup>[[2]](#references)</sup>

- Simular criptografia definindo o bit 0 do ZIP General Purpose Bit Flag (GPBF)
- Abusar de campos Extra grandes/personalizados para confundir parsers
- Colisões de nomes de arquivos/diretórios para ocultar artefatos reais (por exemplo, um diretório chamado `classes.dex/` junto ao `classes.dex` real)

### 1) Criptografia falsa (bit 0 do GPBF definido) sem criptografia real

Sintomas:
- `jadx-gui` falha com erros como:
  
  ```
  java.util.zip.ZipException: invalid CEN header (encrypted entry)
  ```
- `unzip` solicita uma senha para arquivos essenciais do APK, embora um APK válido não possa ter `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` criptografados:
  
  ```bash
  unzip sample.apk
  [sample.apk] classes3.dex password:
    skipping: classes3.dex                          incorrect password
    skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
    skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
    skipping: classes2.dex                          incorrect password
  ```

Detecção com zipdetails:

```bash
zipdetails -v sample.apk | less
```

Observe o General Purpose Bit Flag nos cabeçalhos local e central. Um valor revelador é o bit 0 definido (Criptografia), mesmo para entradas principais:

```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
  [Bit 0]   1 'Encryption'
  [Bits 1-2] 1 'Maximum Compression'
  [Bit 3]   1 'Streamed'
  [Bit 11]  1 'Language Encoding'
```

Heurística: Se um APK instala e funciona no aparelho, mas as entradas principais aparecem como "encrypted" nas ferramentas, o GPBF foi adulterado.

Corrija limpando o bit 0 do GPBF nas entradas dos Local File Headers (LFH) e do Central Directory (CD). Patch mínimo de bytes:

<details>
<summary>Patch mínimo para limpar o bit do GPBF</summary>

```python
# gpbf_clear.py – clear encryption bit (bit 0) in ZIP local+central headers
import struct, sys

SIG_LFH = b"\x50\x4b\x03\x04"  # Local File Header
SIG_CDH = b"\x50\x4b\x01\x02"  # Central Directory Header

def patch_flags(buf: bytes, sig: bytes, flag_off: int):
    out = bytearray(buf)
    i = 0
    patched = 0
    while True:
        i = out.find(sig, i)
        if i == -1:
            break
        flags, = struct.unpack_from('<H', out, i + flag_off)
        if flags & 1:  # encryption bit set
            struct.pack_into('<H', out, i + flag_off, flags & 0xFFFE)
            patched += 1
        i += 4  # move past signature to continue search
    return bytes(out), patched

if __name__ == '__main__':
    inp, outp = sys.argv[1], sys.argv[2]
    data = open(inp, 'rb').read()
    data, p_lfh = patch_flags(data, SIG_LFH, 6)  # LFH flag at +6
    data, p_cdh = patch_flags(data, SIG_CDH, 8)  # CDH flag at +8
    open(outp, 'wb').write(data)
    print(f'Patched: LFH={p_lfh}, CDH={p_cdh}')
```

</details>

Uso:

```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```

Somente o bit 0 deve mudar: por exemplo, `0A09` se torna `0A08`, não `0000`. Este patcher mínimo procura assinaturas de cabeçalho em bytes brutos, então bytes semelhantes a assinaturas dentro dos dados do arquivo podem causar correspondências falsas; trabalhe em uma cópia e confirme a lista de entradas e os cabeçalhos resultantes antes de usar a saída.<sup>[[4]](#references)</sup>

### 2) Campos Extra grandes/personalizados para quebrar parsers

Atacantes inserem campos Extra grandes demais e IDs incomuns nos cabeçalhos para fazer decompilers falharem. No mundo real, você pode encontrar marcadores personalizados (por exemplo, strings como `JADXBLOCK`) inseridos nesses campos.

Inspeção:

```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```

Exemplos observados: IDs desconhecidos como `0xCAFE` ("Executável Java") ou `0x414A` ("JA:") transportando payloads grandes.<sup>[[2]](#references)</sup>

Heurísticas de DFIR:
- Gere um alerta quando os campos Extra forem excepcionalmente grandes em entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Trate IDs Extra desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, compactar novamente os arquivos extraídos) remove os campos Extra maliciosos. Se as ferramentas se recusarem a extrair devido à criptografia falsa, primeiro limpe o bit 0 do GPBF, conforme acima, e depois reempacote:

```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```

### 3) Colisões de nomes de arquivos/diretórios (ocultando artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extratores e decompiladores ficam confusos e podem sobrepor ou ocultar o arquivo real com uma entrada de diretório. Isso já foi observado em entradas que colidem com nomes centrais de APKs, como `classes.dex`.

Triagem e extração segura:

```bash
# List potential collisions (names that differ only by trailing slash)
zipinfo -1 sample.apk | awk '{n=$0; sub(/\/$/,"",n); print n}' | sort | uniq -d

# Extract while preserving the real files by renaming on conflict
unzip normalized.apk -d outdir
# When prompted:
# replace outdir/classes.dex? [y]es/[n]o/[A]ll/[N]one/[r]ename: r
# new name: unk_classes.dex
```

Detecção programática após a correção:

```python
from zipfile import ZipFile
from collections import defaultdict

with ZipFile('normalized.apk') as z:
    names = z.namelist()

collisions = defaultdict(list)
for n in names:
    base = n[:-1] if n.endswith('/') else n
    collisions[base].append(n)

for base, variants in collisions.items():
    if len(variants) > 1:
        print('COLLISION', base, '->', variants)
```

Ideias de detecção para a equipe defensiva:
- Sinalize APKs cujos cabeçalhos locais indicam criptografia (GPBF bit 0 = 1), mas que ainda podem ser instalados/executados.
- Sinalize campos Extra grandes/desconhecidos em entradas essenciais (procure marcadores como `JADXBLOCK`).
- Sinalize colisões de caminho (`X` e `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Outros truques maliciosos com ZIP (2024–2026)

### Diretórios centrais concatenados (evasão com múltiplos EOCD)

Em uma campanha de phishing de 2024, os atacantes enviaram um único blob que, na verdade, era composto por **dois arquivos ZIP concatenados**. Cada um tinha seu próprio registro End of Central Directory (EOCD) e diretório central. Extratores diferentes analisavam diretórios diferentes (o 7-Zip lia o primeiro, enquanto o WinRAR lia o último), permitindo que os atacantes ocultassem payloads que apenas algumas ferramentas exibiam; scanners que inspecionam apenas um diretório podem não detectar o outro arquivo.<sup>[[5]](#references)[[6]](#references)</sup>

**Comandos de triagem**

```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Show EOCD records and their central-directory offsets
zipdetails --scan -v suspect.zip | grep -ni -A2 "end central"
```

Se aparecer mais de um EOCD ou houver avisos de "data after payload", divida o blob e inspecione cada parte:

```bash
# Recover the second archive from its first local-file-header offset.
binwalk -R "PK\x03\x04" suspect.zip
# Adjust OFF to the second archive's local-header offset from that output.
OFF=123456
dd if=suspect.zip bs=1 skip="$OFF" of=tail.zip
7z l tail.zip   # list hidden content
```

### Quoted-overlap / overlapping-entry bombs (non-recursive)

Quoted-overlap ZIP bombs constroem um pequeno **kernel** (um bloco DEFLATE altamente comprimido) e o reutilizam em entradas sobrepostas. Variantes de full-overlap apontam várias entradas do diretório central para um único cabeçalho local, enquanto variantes de quoted-overlap incluem cabeçalhos locais dentro de fluxos DEFLATE; a construção publicada alcança mais de 28M:1 sem arquivos aninhados.<sup>[[7]](#references)</sup>

**Detecção rápida (offsets LFH duplicados)**

```python
# detect full-overlap variants by identical relative offsets
import struct, sys
buf=open(sys.argv[1],'rb').read()
off=0; seen=set()
while True:
    i = buf.find(b'PK\x01\x02', off)
    if i<0: break
    rel = struct.unpack_from('<I', buf, i+42)[0]
    if rel in seen:
        print('OVERLAP at offset', rel)
        break
    seen.add(rel); off = i+4
```

**Tratamento**
- Faça uma análise simulada: `zipdetails -v file.zip | grep -n "Local Header Offset"` e compare os offsets dos cabeçalhos locais referenciados e os intervalos dos dados comprimidos; offsets duplicados indicam variantes de sobreposição total.<sup>[[7]](#references)[[8]](#references)</sup>
- Limite o tamanho total descomprimido aceito e a quantidade de entradas antes da extração usando um parser; `zipinfo -t file.zip` informa os totais, mas não impõe um limite de segurança.<sup>[[8]](#references)</sup>
- Quando precisar extrair, faça isso dentro de um cgroup/VM com limites de CPU e disco (evite falhas por descompressão sem limites).<sup>[[8]](#references)</sup>

---

### Confusão entre parser de cabeçalho local e de diretório central

Pesquisas recentes sobre parsers diferenciais mostraram que a ambiguidade de ZIP ainda pode ser explorada em toolchains modernos. A ideia principal é simples: alguns softwares confiam no **Local File Header (LFH)**, enquanto outros confiam no **Central Directory (CD)**, então um arquivo pode apresentar nomes de arquivo, caminhos, comentários, offsets ou conjuntos de entradas diferentes para ferramentas diferentes.<sup>[[9]](#references)</sup>

Usos ofensivos práticos:
- Fazer com que um filtro de upload, uma verificação prévia de AV ou um validador de pacotes veja um arquivo benigno no CD, enquanto o extrator respeita um nome/caminho diferente no LFH.
- Explorar nomes duplicados, entradas presentes apenas em uma das estruturas ou metadados ambíguos de caminho Unicode (por exemplo, Info-ZIP Unicode Path Extra Field `0x7075`) para que parsers diferentes reconstruam árvores diferentes.
- Combinar isso com path traversal para transformar uma visualização de arquivo "inofensiva" em uma primitiva de escrita durante a extração. Para o lado da extração, consulte [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triagem de DFIR:

```python
# compare Central Directory names against the referenced Local File Header names
import struct, sys
b = open(sys.argv[1], 'rb').read()
lfh = {}
i = 0
while (i := b.find(b'PK\x03\x04', i)) != -1:
    n, e = struct.unpack_from('<HH', b, i + 26)
    lfh[i] = b[i + 30:i + 30 + n].decode('utf-8', 'replace')
    i += 4
i = 0
while (i := b.find(b'PK\x01\x02', i)) != -1:
    n = struct.unpack_from('<H', b, i + 28)[0]
    off = struct.unpack_from('<I', b, i + 42)[0]
    cd = b[i + 46:i + 46 + n].decode('utf-8', 'replace')
    if off in lfh and cd != lfh[off]:
        print(f'NAME_MISMATCH off={off} cd={cd!r} lfh={lfh[off]!r}')
    i += 4
```

Complemente com:

```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```

Heurísticas:
- Para ingestão sensível à segurança, rejeite ou isole arquivos com nomes LFH/CD divergentes, nomes de arquivos duplicados, vários registros EOCD ou bytes adicionais após o EOCD final.<sup>[[9]](#references)[[10]](#references)</sup>
- Considere suspeitos os arquivos ZIP que usam campos extras incomuns de caminho Unicode ou comentários inconsistentes, caso ferramentas diferentes discordem sobre a árvore extraída.<sup>[[4]](#references)[[9]](#references)</sup>
- Se a análise for mais importante do que preservar os bytes originais, reempacote o arquivo com um parser rigoroso após a extração em um sandbox e compare a lista de arquivos resultante com os metadados originais.

Isso é relevante além dos ecossistemas de pacotes: a mesma classe de ambiguidade pode ocultar payloads de gateways de e-mail, scanners estáticos e pipelines de ingestão personalizados que "espiam" o conteúdo ZIP antes que outro extrator processe o arquivo.<sup>[[9]](#references)</sup>

---





## References

- [1] [Guia de campo de CTF Forensics (blog do Mike, categoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Parte 1 – Um dropper em várias etapas (anti-reversing de APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Especificação do formato de arquivo ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Estrutura flexível de arquivos ZIP explorada para ocultar malware sem detecção (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers escondem malware em novo ataque a arquivos ZIP — diretórios centrais ZIP concatenados](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Uma zip bomb melhor (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Entendendo zip bombs: construção de kernel com sobreposição/sobreposição citada](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Meu ZIP não é o seu ZIP: identificando e explorando diferenças semânticas entre parsers ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prevenção de ataques de confusão de parser ZIP em instaladores de pacotes Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Ataques ZIP com texto simples conhecido reduzido (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Missão web realista, nível 15 (ataque ZIP com texto simples conhecido)](https://www.hackthissite.org/articles/read/793)
- [13] [Uso do bkcrack](https://github.com/kimci86/bkcrack/blob/master/readme.md)
- [14] [Tutorial de texto simples conhecido do bkcrack](https://github.com/kimci86/bkcrack/blob/master/example/tutorial.md)
- [15] [Repositório fcrackzip](https://github.com/hyc/fcrackzip)
{{#include ../../../banners/hacktricks-training.md}}

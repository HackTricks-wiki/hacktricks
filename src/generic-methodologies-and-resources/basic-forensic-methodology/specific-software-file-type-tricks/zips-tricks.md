# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

As **ferramentas de linha de comando** para gerenciar **zip files** são essenciais para diagnosticar, reparar e crackear zip files. Aqui estão alguns utilitários importantes:<sup>[[1]](#references)</sup>

- **`unzip`**: Revela por que um zip file pode não ser descompactado.
- **`zipdetails -v`**: Oferece uma análise detalhada dos campos do formato de zip file.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Lista o conteúdo de um zip file sem extraí-lo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar zip files corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para brute-force de senhas de zip files, eficaz para senhas de até aproximadamente 7 caracteres.

A [especificação do formato de zip file](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões de zip files.<sup>[[4]](#references)</sup>

É crucial observar que zip files protegidos por senha **não criptografam os nomes dos arquivos nem os tamanhos dos arquivos** contidos neles, uma falha de segurança não compartilhada por arquivos RAR ou 7z, que criptografam essas informações. Além disso, zip files criptografados com o método ZipCrypto antigo são vulneráveis a um **plaintext attack** caso esteja disponível uma cópia não criptografada de um arquivo compactado.<sup>[[1]](#references)</sup> Esse ataque utiliza o conteúdo conhecido para crackear a senha do zip file, uma vulnerabilidade detalhada no [artigo da HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e explicada posteriormente [neste artigo acadêmico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf).<sup>[[11]](#references)[[12]](#references)</sup> No entanto, zip files protegidos com criptografia **AES-256** são imunes a esse plaintext attack, demonstrando a importância de escolher métodos de criptografia seguros para dados confidenciais.<sup>[[1]](#references)</sup>

---

## Truques anti-reversing em APKs usando cabeçalhos ZIP manipulados

Droppers modernos de malware para Android usam metadados ZIP malformados para quebrar ferramentas estáticas (jadx/apktool/unzip), mantendo o APK instalável no dispositivo. Os truques mais comuns são:<sup>[[2]](#references)</sup>

- Criptografia falsa definindo o bit 0 do ZIP General Purpose Bit Flag (GPBF)
- Abuso de campos Extra grandes/personalizados para confundir parsers
- Colisões entre nomes de arquivos/diretórios para ocultar artefatos reais (por exemplo, um diretório chamado `classes.dex/` ao lado do `classes.dex` real)

### 1) Criptografia falsa (bit 0 do GPBF definido) sem criptografia real

Sintomas:
- `jadx-gui` falha com erros como:

```text
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita uma senha para arquivos principais do APK, embora um APK válido não possa ter `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` criptografados:

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
Observe o General Purpose Bit Flag para os cabeçalhos locais e centrais. Um valor revelador é o bit 0 definido (Encryption), mesmo para entradas principais:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Se um APK instala e executa no dispositivo, mas as entradas principais aparecem "encrypted" para as tools, o GPBF foi adulterado.

Corrija limpando o bit 0 do GPBF tanto nos Local File Headers (LFH) quanto nas entradas do Central Directory (CD). Minimal byte-patcher:

<details>
<summary>Minimal GPBF bit-clear patcher</summary>
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
Agora você deve ver `General Purpose Flag  0000` nas entradas principais, e as tools conseguirão analisar o APK novamente.

### 2) Extra fields grandes/personalizados para quebrar parsers

Attackers inserem Extra fields muito grandes e IDs incomuns nos cabeçalhos para causar falhas em decompilers. No mundo real, você pode encontrar marcadores personalizados (por exemplo, strings como `JADXBLOCK`) incorporados neles.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") carregando payloads grandes.

Heurísticas de DFIR:
- Alertar quando os Extra fields forem excepcionalmente grandes em entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar IDs de Extra desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, compactar novamente os arquivos extraídos) remove os Extra fields maliciosos. Se as ferramentas se recusarem a extrair devido a uma encriptação falsa, primeiro limpe o bit 0 do GPBF conforme descrito acima e, em seguida, reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nomes de arquivos/diretórios (ocultando artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extractors e decompilers ficam confusos e podem sobrepor ou ocultar o arquivo real com uma entrada de diretório. Isso foi observado com entradas que colidem com nomes principais de APK, como `classes.dex`.

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
Detecção programática pós-correção:
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
Ideias de detecção para Blue-team:
- Sinalizar APKs cujos cabeçalhos locais indicam encryption (GPBF bit 0 = 1), mas que ainda assim são instalados/executados.
- Sinalizar campos Extra grandes/desconhecidos em entradas principais (procurar marcadores como `JADXBLOCK`).
- Sinalizar colisões de caminhos (`X` e `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Outras técnicas maliciosas de ZIP (2024–2026)

### Diretórios centrais concatenados (evasão multi-EOCD)

Campanhas recentes de phishing distribuem um único blob que, na realidade, é composto por **dois arquivos ZIP concatenados**. Cada um possui seu próprio End of Central Directory (EOCD) + diretório central. Diferentes extractors analisam diretórios diferentes (7zip lê o primeiro, WinRAR o último), permitindo que atacantes ocultem payloads que apenas algumas ferramentas exibem. Isso também contorna soluções básicas de AV de mail gateway que inspecionam apenas o primeiro diretório.<sup>[[5]](#references)[[6]](#references)</sup>

**Comandos de triagem**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Se aparecer mais de um EOCD ou houver avisos de "data after payload", divida o blob e inspecione cada parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (não recursivas)

As versões modernas de **better zip bomb** constroem um **kernel** minúsculo (bloco DEFLATE altamente comprimido) e o reutilizam por meio de local headers sobrepostos. Cada entrada do central directory aponta para os mesmos dados comprimidos, alcançando taxas superiores a 28M:1 sem aninhar archives. Bibliotecas que confiam nos tamanhos do central directory (`zipfile` do Python, `java.util.zip` do Java, Info-ZIP anterior às versões hardened) podem ser forçadas a alocar petabytes.<sup>[[7]](#references)[[8]](#references)</sup>

**Detecção rápida (offsets LFH duplicados)**
```python
# detect overlapping entries by identical relative offsets
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
- Execute uma verificação dry-run: `zipdetails -v file.zip | grep -n "Rel Off"` e garanta que os offsets sejam estritamente crescentes e únicos.
- Limite o tamanho total descompactado aceito e a quantidade de entradas antes da extração (`zipdetails -t` ou um parser personalizado).
- Quando precisar extrair, faça isso dentro de um cgroup/VM com limites de CPU e disco (evite crashes de inflação não limitada).

---

### Confusão entre parser de Local-header e central-directory

Pesquisas recentes sobre differential-parser mostraram que a ambiguidade de ZIP ainda é explorável em toolchains modernos. A ideia principal é simples: alguns softwares confiam no **Local File Header (LFH)**, enquanto outros confiam no **Central Directory (CD)**, permitindo que um único archive apresente diferentes nomes de arquivo, paths, comentários, offsets ou conjuntos de entradas para diferentes ferramentas.<sup>[[9]](#references)</sup>

Usos ofensivos práticos:
- Fazer com que um upload filter, AV pre-scan ou package validator veja um arquivo benigno no CD, enquanto o extractor respeita um nome/path diferente no LFH.
- Abusar de nomes duplicados, entradas presentes apenas em uma das estruturas ou metadata de caminho Unicode ambígua (por exemplo, o Info-ZIP Unicode Path Extra Field `0x7075`) para que diferentes parsers reconstruam árvores diferentes.
- Combinar isso com path traversal para transformar uma visualização "inofensiva" do archive em uma write-primitive durante a extração. Para o lado da extração, consulte [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Envie o conteúdo que deseja adicionar.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurísticas:
- Rejeite ou isole archives com nomes LFH/CD incompatíveis, filenames duplicados, múltiplos registros EOCD ou bytes após o EOCD final.<sup>[[10]](#references)</sup>
- Trate ZIPs que usam extra fields incomuns de Unicode-path ou comments inconsistentes como suspeitos se diferentes tools discordarem sobre a árvore extraída.<sup>[[9]](#references)</sup>
- Se a análise for mais importante do que preservar os bytes originais, reempacote o archive com um parser rigoroso após a extração em um sandbox e compare a lista de files resultante com os metadados originais.

Isso é importante para além dos package ecosystems: a mesma classe de ambiguidade pode ocultar payloads de mail gateways, static scanners e custom ingestion pipelines que fazem "peek" no conteúdo dos ZIPs antes que um extractor diferente processe o archive.

---



## Referências

- [1] [CTF Forensics Field Guide (Mike's Blog, categoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script Archive::Zip)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [4] [Especificação do ZIP File Format (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Flexible Structure of Zip Archives Exploited to Hide Malware Undetected (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [A better zip bomb (David Fifield, USENIX WOOT 2019)](https://www.bamsoftware.com/hacks/zipbomb/)
- [8] [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [ZIP Attacks with Reduced Known Plaintext (Michael Stay, AccessData Corporation)](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf)
- [12] [Known Plaintext Attack: Cracking ZIP Files](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)

{{#include ../../../banners/hacktricks-training.md}}

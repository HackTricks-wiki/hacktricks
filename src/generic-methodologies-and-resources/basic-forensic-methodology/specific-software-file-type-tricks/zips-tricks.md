# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Ferramentas de linha de comando** para gerenciar **zip files** são essenciais para diagnosticar, reparar e quebrar zip files. Aqui estão algumas utilitárias chave:

- **`unzip`**: Revela por que um zip file pode não descompactar.
- **`zipdetails -v`**: Oferece análise detalhada dos campos do formato de zip file.
- **`zipinfo`**: Lista o conteúdo de um zip file sem extraí-lo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar zip files corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para quebra por força bruta de senhas de zip, eficaz para senhas de até cerca de 7 caracteres.

The [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) provides comprehensive details on the structure and standards of zip files.

É crucial notar que zip files protegidos por senha **não criptografam nomes de arquivos ou tamanhos de arquivo** internamente, uma falha de segurança que não é compartilhada com RAR ou 7z, que criptografam essa informação. Além disso, zip files criptografados com o método mais antigo ZipCrypto são vulneráveis a um **plaintext attack** se uma cópia não encriptada de um arquivo comprimido estiver disponível. Esse ataque utiliza o conteúdo conhecido para quebrar a senha do zip, uma vulnerabilidade detalhada no artigo do [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e explicada com mais profundidade neste [paper acadêmico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Porém, zip files protegidos com criptografia **AES-256** são imunes a esse plaintext attack, mostrando a importância de escolher métodos de criptografia seguros para dados sensíveis.

---

## Truques anti-reversão em APKs usando cabeçalhos ZIP manipulados

Modern Android malware droppers usam metadata ZIP malformado para quebrar ferramentas estáticas (jadx/apktool/unzip) enquanto mantêm o APK instalável no dispositivo. Os truques mais comuns são:

- Fake encryption ao setar o ZIP General Purpose Bit Flag (GPBF) bit 0
- Abuso de Extra fields grandes/customizados para confundir parsers
- Colisões de nomes de arquivo/diretório para esconder artefatos reais (por exemplo, um diretório chamado `classes.dex/` ao lado do real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Sintomas:
- `jadx-gui` falha com erros como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita uma senha para arquivos core do APK mesmo que um APK válido não possa ter `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` encriptados:

```bash
unzip sample.apk
[sample.apk] classes3.dex password:
skipping: classes3.dex                          incorrect password
skipping: AndroidManifest.xml/res/vhpng-xhdpi/mxirm.png  incorrect password
skipping: resources.arsc/res/domeo/eqmvo.xml            incorrect password
skipping: classes2.dex                          incorrect password
```

Detection with zipdetails:
```bash
zipdetails -v sample.apk | less
```
Observe o General Purpose Bit Flag para local and central headers. Um valor revelador é o bit 0 set (Encryption) mesmo para core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Se um APK instala e roda no dispositivo, mas entradas principais aparecem "criptografadas" para ferramentas, o GPBF foi adulterado.

Corrija removendo o bit 0 do GPBF em ambas as entradas Local File Headers (LFH) e Central Directory (CD). Patchador de bytes mínimo:

<details>
<summary>Patchador mínimo para limpar o bit do GPBF</summary>
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
Você agora deve ver `General Purpose Flag  0000` nas entradas principais e as ferramentas irão analisar o APK novamente.

### 2) Campos Extra grandes/personalizados para quebrar parsers

Atacantes inserem campos Extra superdimensionados e IDs estranhos nos cabeçalhos para enganar descompiladores. No mundo real você pode ver marcadores personalizados (e.g., strings like `JADXBLOCK`) inseridos ali.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") carregando grandes payloads.

Heurísticas DFIR:
- Avisar quando Extra fields estiverem incomumente grandes em entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar Extra IDs desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, re-zipping dos arquivos extraídos) remove os Extra fields maliciosos. Se ferramentas se recusarem a extrair devido a criptografia falsa, primeiro limpe GPBF bit 0 como acima, então reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nomes de arquivo/diretório (ocultando artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extractors e decompilers ficam confusos e podem sobrepor ou ocultar o arquivo real com uma entrada de diretório. Isso foi observado com entradas colidindo com nomes principais de APK como `classes.dex`.

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
Sufixo de detecção programática:
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
- Sinalizar APKs cujos cabeçalhos locais indicam encriptação (GPBF bit 0 = 1) mas que ainda instalam/executam.
- Sinalizar campos Extra grandes/desconhecidos nas entradas core (procure por marcadores como `JADXBLOCK`).
- Sinalizar colisões de caminho (`X` e `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Outros truques maliciosos de ZIP (2024–2026)

### Diretórios centrais concatenados (evasão multi-EOCD)

Campanhas de phishing recentes distribuem um único blob que na verdade contém **dois arquivos ZIP concatenados**. Cada um tem seu próprio End of Central Directory (EOCD) + central directory. Diferentes extractors analisam diretórios diferentes (7zip lê o primeiro, WinRAR o último), permitindo que atacantes escondam payloads que apenas algumas ferramentas exibem. Isso também contorna AVs básicos de mail gateway que inspecionam apenas o primeiro diretório.

**Comandos de triagem**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Se aparecer mais de um EOCD ou houver avisos "data after payload", divida o blob e inspecione cada parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

As versões modernas da "better zip bomb" constroem um pequeno **kernel** (bloco DEFLATE altamente comprimido) e o reutilizam através de cabeçalhos locais sobrepostos. Cada entrada do diretório central aponta para os mesmos dados comprimidos, alcançando razões >28M:1 sem aninhar arquivos. Bibliotecas que confiam nos tamanhos do diretório central (Python `zipfile`, Java `java.util.zip`, Info-ZIP em versões anteriores ao hardening) podem ser forçadas a alocar petabytes.

**Detecção rápida (offsets de LFH duplicados)**
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
- Faça uma verificação simulada: `zipdetails -v file.zip | grep -n "Rel Off"` e garanta que os offsets sejam estritamente crescentes e únicos.
- Limite o tamanho total descompactado aceito e a contagem de entradas antes da extração (`zipdetails -t` ou um parser customizado).
- Quando precisar extrair, faça isso dentro de um cgroup/VM com limites de CPU e disco (evite falhas devido a crescimento ilimitado).

---

### Confusão entre parser de Local-header vs central-directory

Pesquisas recentes sobre differential-parser mostraram que a ambiguidade de ZIP ainda é explorável em toolchains modernos. A ideia principal é simples: algum software confia no **Local File Header (LFH)** enquanto outros confiam no **Central Directory (CD)**, então um mesmo arquivo pode apresentar nomes de ficheiros, caminhos, comentários, offsets ou conjuntos de entradas diferentes a ferramentas distintas.

Usos ofensivos práticos:
- Faça um filtro de upload, pré-scan de AV, ou validador de pacotes ver um arquivo benigno no CD enquanto o extrator honra um nome/caminho diferente do LFH.
- Abuse de nomes duplicados, entradas presentes apenas em uma estrutura, ou metadados de caminho Unicode ambíguos (por exemplo, Info-ZIP Unicode Path Extra Field `0x7075`) para que diferentes parsers reconstruam árvores diferentes.
- Combine isso com path traversal para transformar uma visão "inofensiva" do arquivo em uma primitiva de escrita durante a extração. Para o lado da extração, veja [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

Triagem DFIR:
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
Você não incluiu o conteúdo de src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md nem o texto a ser complementado. Por favor, envie o arquivo ou o trecho a traduzir/complementar e especifique o que deseja adicionar.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Rejeitar ou isolar arquivos com nomes LFH/CD incompatíveis, nomes de arquivo duplicados, múltiplos registos EOCD, ou bytes excedentes após o EOCD final.
- Trate ZIPs que usam campos extra de caminho Unicode incomuns ou comentários inconsistentes como suspeitos se diferentes ferramentas discordarem da árvore extraída.
- Se a análise for mais importante do que preservar os bytes originais, reembale o arquivo com um parser estrito após a extração em um sandbox e compare a lista de arquivos resultante com os metadados originais.

This matters beyond package ecosystems: the same ambiguity class can hide payloads from mail gateways, static scanners, and custom ingestion pipelines that "peek" at ZIP contents before a different extractor handles the archive.

---



## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}

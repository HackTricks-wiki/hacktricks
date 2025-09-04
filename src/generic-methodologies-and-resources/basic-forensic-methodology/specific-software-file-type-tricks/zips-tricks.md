# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Ferramentas de linha de comando** para gerenciar **zip files** são essenciais para diagnosticar, reparar e crackear zip files. Aqui estão algumas utilidades-chave:

- **`unzip`**: Revela por que um arquivo zip pode não descompactar.
- **`zipdetails -v`**: Oferece análise detalhada dos campos do formato de arquivo zip.
- **`zipinfo`**: Lista o conteúdo de um arquivo zip sem extraí-lo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar arquivos zip corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para quebra por força bruta de senhas de arquivos zip, eficaz para senhas de até cerca de 7 caracteres.

A [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões dos arquivos zip.

É crucial observar que arquivos zip protegidos por senha **não criptografam nomes de arquivos ou tamanhos de arquivos** internamente, uma falha de segurança que não é compartilhada por arquivos RAR ou 7z, que criptografam essas informações. Além disso, arquivos zip criptografados com o método mais antigo ZipCrypto são vulneráveis a um **plaintext attack** se uma cópia não criptografada de um arquivo comprimido estiver disponível. Esse ataque aproveita o conteúdo conhecido para quebrar a senha do zip, uma vulnerabilidade detalhada no artigo do [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e mais explicada neste [artigo acadêmico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). No entanto, arquivos zip protegidos com criptografia **AES-256** são imunes a esse plaintext attack, demonstrando a importância de escolher métodos de criptografia seguros para dados sensíveis.

---

## Truques anti-reversão em APKs usando cabeçalhos ZIP manipulados

Droppers modernos de malware Android usam metadados ZIP malformados para quebrar ferramentas estáticas (jadx/apktool/unzip) enquanto mantêm o APK instalável no dispositivo. Os truques mais comuns são:

- Criptografia falsa definindo o ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusar de campos Extra grandes/customizados para confundir parsers
- Colisões de nomes de arquivo/diretório para esconder artefatos reais (ex., um diretório chamado `classes.dex/` ao lado do real `classes.dex`)

### 1) Criptografia falsa (GPBF bit 0 set) sem criptografia real

Sintomas:
- `jadx-gui` falha com erros como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita uma senha para arquivos principais do APK mesmo que um APK válido não possa ter `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` criptografados:

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
Observe o General Purpose Bit Flag nos cabeçalhos local e central. Um valor revelador é o bit 0 definido (Encryption) mesmo para entradas core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Se um APK instala e roda no dispositivo, mas entradas principais aparecem "criptografadas" para as ferramentas, o GPBF foi adulterado.

Corrija zerando o bit 0 do GPBF tanto nas Local File Headers (LFH) quanto nas entradas do Central Directory (CD). Byte-patcher mínimo:
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
Uso:
```bash
python3 gpbf_clear.py obfuscated.apk normalized.apk
zipdetails -v normalized.apk | grep -A2 "General Purpose Flag"
```
Você deve agora ver `General Purpose Flag  0000` nas entradas principais e as ferramentas vão parsear o APK novamente.

### 2) Campos Extra grandes/personalizados para quebrar parsers

Atacantes enchem campos Extra superdimensionados e IDs estranhos nos headers para derrubar decompiladores. Na prática, você pode ver marcadores personalizados (por exemplo, strings como `JADXBLOCK`) embutidos ali.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Executável Java") ou `0x414A` ("JA:") carregando grandes payloads.

Heurísticas DFIR:
- Alertar quando os campos Extra estiverem incomumente grandes nas entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar IDs Extra desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, recompactando os arquivos extraídos) remove os campos Extra maliciosos. Se as ferramentas se recusarem a extrair devido a criptografia falsa, primeiro limpe o bit 0 do GPBF como acima, então reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nomes de arquivo/diretório (escondendo artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extractors e decompilers ficam confusos e podem sobrepor ou ocultar o arquivo real com uma entrada de diretório. Isso foi observado com entradas colidindo com nomes principais de APK como `classes.dex`.

Triage e extração segura:
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
- Marcar APKs cujos cabeçalhos locais indicam criptografia (GPBF bit 0 = 1) mas ainda assim instalam/executam.
- Marcar Extra fields grandes/desconhecidos em core entries (procure por marcadores como `JADXBLOCK`).
- Marcar colisões de caminho (`X` e `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Referências

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}

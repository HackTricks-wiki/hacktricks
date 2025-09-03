# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Ferramentas de linha de comando** para gerenciar **arquivos zip** são essenciais para diagnosticar, reparar e quebrar zip files. Aqui estão algumas utilidades chave:

- **`unzip`**: Revela por que um arquivo zip pode não ser descompactado.
- **`zipdetails -v`**: Oferece análise detalhada dos campos do formato de arquivo zip.
- **`zipinfo`**: Lista o conteúdo de um arquivo zip sem extraí-lo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar arquivos zip corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para quebra por força bruta de senhas de zip, efetiva para senhas de até cerca de 7 caracteres.

A [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões de arquivos zip.

É crucial notar que arquivos zip protegidos por senha **não criptografam nomes de arquivos nem tamanhos de arquivo**, uma falha de segurança não presente em arquivos RAR ou 7z, que criptografam essa informação. Além disso, arquivos zip criptografados com o método mais antigo ZipCrypto são vulneráveis a um **plaintext attack** se uma cópia não criptografada de um arquivo compactado estiver disponível. Esse ataque aproveita o conteúdo conhecido para quebrar a senha do zip, uma vulnerabilidade detalhada no [artigo do HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e explicada em [este paper acadêmico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). No entanto, arquivos zip protegidos com criptografia **AES-256** são imunes a esse plaintext attack, demonstrando a importância de escolher métodos de criptografia seguros para dados sensíveis.

---

## Truques anti-reversão em APKs usando cabeçalhos ZIP manipulados

Modern Android malware droppers usam metadados ZIP malformados para quebrar ferramentas estáticas (jadx/apktool/unzip) enquanto mantêm o APK instalável no dispositivo. Os truques mais comuns são:

- Criptografia falsa ajustando o bit 0 do ZIP General Purpose Bit Flag (GPBF)
- Abusar de Extra fields grandes/personalizados para confundir parsers
- Colisões de nomes de arquivo/diretório para esconder artefatos reais (ex.: um diretório chamado `classes.dex/` ao lado do real `classes.dex`)

### 1) Criptografia falsa (GPBF bit 0 set) sem criptografia real

Sintomas:
- `jadx-gui` falha com erros como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` pede uma senha para arquivos principais do APK mesmo que um APK válido não possa ter `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` criptografados:

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
Heurística: Se um APK instala e executa no dispositivo, mas entradas principais aparecem "encrypted" para ferramentas, o GPBF foi adulterado.

Corrija zerando o bit 0 do GPBF nas entradas de Local File Headers (LFH) e Central Directory (CD). Byte-patcher mínimo:
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
Você deve agora ver `General Purpose Flag  0000` nas entradas principais e as ferramentas irão parsear o APK novamente.

### 2) Large/custom Extra fields to break parsers

Atacantes inserem campos Extra superdimensionados e IDs estranhos nos headers para enganar decompilers. No mundo real você pode ver marcadores personalizados (por exemplo, strings como `JADXBLOCK`) embutidos ali.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") contendo payloads grandes.

Heurísticas DFIR:
- Disparar alerta quando Extra fields estiverem incomumente grandes nas entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar Extra IDs desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, recompactando os arquivos extraídos) remove os Extra fields maliciosos. Se ferramentas se recusarem a extrair devido a criptografia falsa, primeiro limpe o GPBF bit 0 como acima, então reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nomes de arquivo/diretório (ocultando artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extratores e decompiladores ficam confusos e podem sobrepor ou esconder o arquivo real com uma entrada de diretório. Isso foi observado com entradas colidindo com nomes centrais de APK como `classes.dex`.

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
Blue-team detection ideas:
- Sinalizar APKs cujos cabeçalhos locais marcam criptografia (GPBF bit 0 = 1) yet install/run.
- Sinalizar large/unknown Extra fields on core entries (look for markers like `JADXBLOCK`).
- Sinalizar path-collisions (`X` and `X/`) specifically para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Referências

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

{{#include ../../../banners/hacktricks-training.md}}

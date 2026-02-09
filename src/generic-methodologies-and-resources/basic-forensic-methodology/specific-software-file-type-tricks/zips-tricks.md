# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Ferramentas de linha de comando** para gerenciar **arquivos zip** são essenciais para diagnosticar, reparar e quebrar zip files. Aqui estão algumas utilidades chave:

- **`unzip`**: Revela por que um arquivo zip pode não descompactar.
- **`zipdetails -v`**: Oferece análise detalhada dos campos do formato zip.
- **`zipinfo`**: Lista o conteúdo de um arquivo zip sem extraí-los.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar arquivos zip corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para quebra de senhas de arquivos zip por força bruta, eficaz para senhas de até cerca de 7 caracteres.

A [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões dos arquivos zip.

É crucial notar que arquivos zip protegidos por senha **não criptografam nomes de arquivos nem tamanhos de arquivos**, uma falha de segurança que não ocorre em RAR ou 7z, que criptografam essa informação. Além disso, arquivos zip criptografados com o método antigo ZipCrypto são vulneráveis a um **plaintext attack** se uma cópia não criptografada de um arquivo comprimido estiver disponível. Esse ataque usa o conteúdo conhecido para quebrar a senha do zip, uma vulnerabilidade detalhada no artigo do [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e explicada em [este paper acadêmico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). No entanto, arquivos zip protegidos com **AES-256** são imunes a esse plaintext attack, evidenciando a importância de escolher métodos de criptografia seguros para dados sensíveis.

---

## Truques anti-reversão em APKs usando cabeçalhos ZIP manipulados

Droppers modernos de malware Android usam metadados ZIP malformados para quebrar ferramentas estáticas (jadx/apktool/unzip) enquanto mantêm o APK instalável no dispositivo. Os truques mais comuns são:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusar de campos Extra grandes/personalizados para confundir parsers
- Colisões de nomes de arquivo/diretório para ocultar artefatos reais (por exemplo, um diretório chamado `classes.dex/` ao lado do real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) sem criptografia real

Sintomas:
- `jadx-gui` falha com erros como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita uma senha para arquivos essenciais do APK, embora um APK válido não possa ter `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` criptografados:

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
Observe o General Purpose Bit Flag nos cabeçalhos locais e centrais. Um valor revelador é o bit 0 definido (Encryption) mesmo para entradas core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Se um APK instala e roda no dispositivo mas entradas core aparecem "encrypted" para ferramentas, o GPBF foi adulterado.

Corrija limpando o bit 0 do GPBF tanto nos Local File Headers (LFH) quanto nas entradas do Central Directory (CD). Byte-patcher mínimo:

<details>
<summary>Patcher mínimo para limpar o bit do GPBF</summary>
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

### 2) Extra fields grandes/personalizados para quebrar parsers

Atacantes inserem Extra fields superdimensionados e IDs estranhos nos cabeçalhos para quebrar decompilers. No mundo real, você pode ver marcadores personalizados (por exemplo, strings como `JADXBLOCK`) incorporados ali.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") contendo grandes payloads.

DFIR heurísticas:
- Gerar alerta quando os campos Extra estiverem incomumente grandes em entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar IDs Extra desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, re-zipar os arquivos extraídos) remove os campos Extra maliciosos. Se ferramentas se recusarem a extrair devido a criptografia falsa, primeiro limpe GPBF bit 0 como indicado acima, então reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nomes de Arquivo/Diretório (ocultando artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extratores e descompiladores ficam confusos e podem sobrepor ou ocultar o arquivo real com uma entrada de diretório. Isso foi observado com entradas colidindo com nomes principais de APK como `classes.dex`.

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
Sufixo para detecção programática:
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
- Sinalizar APKs cujos cabeçalhos locais marcam criptografia (GPBF bit 0 = 1) mas que ainda instalam/executam.
- Sinalizar campos Extra grandes/desconhecidos em entradas principais (procure por marcadores como `JADXBLOCK`).
- Sinalizar colisões de caminho (`X` e `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Outros truques maliciosos com ZIP (2024–2025)

### Diretórios centrais concatenados (evasão multi-EOCD)

Campanhas de phishing recentes entregam um único blob que é, na verdade, **dois arquivos ZIP concatenados**. Cada um tem seu próprio End of Central Directory (EOCD) + diretório central. Diferentes extractors analisam diretórios diferentes (7zip lê o primeiro, WinRAR o último), permitindo que atacantes escondam payloads que apenas algumas ferramentas mostram. Isso também contorna AV de gateway de e-mail básico que inspeciona apenas o primeiro diretório.

**Triage commands**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Se mais de um EOCD aparecer ou houver avisos "data after payload", divida o blob e inspecione cada parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modern "better zip bomb" constrói um pequeno **kernel** (bloco DEFLATE altamente comprimido) e o reutiliza via overlapping local headers. Cada entrada do central directory aponta para os mesmos compressed data, atingindo razões >28M:1 sem aninhar archives. Bibliotecas que confiam nos tamanhos do central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP prior to hardened builds) podem ser forçadas a alocar petabytes.

**Detecção rápida (duplicate LFH offsets)**
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
**Manuseio**
- Faça uma execução de teste (dry-run): `zipdetails -v file.zip | grep -n "Rel Off"` e garanta que os offsets sejam estritamente crescentes e únicos.
- Limite o tamanho total descompactado aceito e a contagem de entradas antes da extração (`zipdetails -t` ou parser personalizado).
- Quando for necessário extrair, faça isso dentro de um cgroup/VM com limites de CPU e disco (evite falhas por inflação ilimitada).

---

## Referências

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}

# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Ferramentas de linha de comando** para gerenciar **zip files** são essenciais para diagnosticar, reparar e quebrar zip files. Aqui estão algumas utilidades-chave:

- **`unzip`**: Revela por que um arquivo zip pode não descompactar.
- **`zipdetails -v`**: Oferece análise detalhada dos campos do formato zip.
- **`zipinfo`**: Lista o conteúdo de um arquivo zip sem extraí-lo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar arquivos zip corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para brute-force de senhas de zip, eficaz para senhas de até cerca de 7 caracteres.

A [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões dos zip files.

É crucial notar que arquivos zip protegidos por senha **não criptografam nomes de arquivos nem tamanhos de arquivo**, uma falha de segurança que não está presente em RAR ou 7z, que criptografam essas informações. Além disso, arquivos zip criptografados com o método mais antigo ZipCrypto são vulneráveis a um **ataque de texto simples (plaintext attack)** se uma cópia não criptografada de um arquivo comprimido estiver disponível. Esse ataque aproveita o conteúdo conhecido para quebrar a senha do zip, uma vulnerabilidade detalhada em [HackThis's article](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e explicada com mais detalhes em [this academic paper](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). No entanto, arquivos zip protegidos com criptografia **AES-256** são imunes a esse ataque de plaintext, o que demonstra a importância de escolher métodos de criptografia seguros para dados sensíveis.

---

## Anti-reversing tricks in APKs using manipulated ZIP headers

Modern Android malware droppers use malformed ZIP metadata to break static tools (jadx/apktool/unzip) while keeping the APK installable on-device. The most common tricks are:

- Fake encryption by setting the ZIP General Purpose Bit Flag (GPBF) bit 0
- Abusing large/custom Extra fields to confuse parsers
- File/directory name collisions to hide real artifacts (e.g., a directory named `classes.dex/` next to the real `classes.dex`)

### 1) Fake encryption (GPBF bit 0 set) without real crypto

Sintomas:
- `jadx-gui` falha com erros como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` solicita uma senha para arquivos core do APK mesmo que um APK válido não possa ter `classes*.dex`, `resources.arsc`, ou `AndroidManifest.xml` criptografados:

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
Observe o General Purpose Bit Flag dos cabeçalhos local e central. Um valor revelador é o bit 0 definido (Encryption) mesmo para entradas core:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Se um APK instala e executa no dispositivo mas entradas core aparecem "encrypted" para ferramentas, o GPBF foi adulterado.

Corrija limpando o bit 0 do GPBF em ambas as entradas Local File Headers (LFH) e Central Directory (CD). Patcher mínimo de bytes:

<details>
<summary>Patcher mínimo para limpar o bit 0 do GPBF</summary>
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

Atacantes inserem Extra fields superdimensionados e IDs estranhos nos headers para confundir decompilers. No mundo real você pode ver marcadores personalizados (por exemplo, strings like `JADXBLOCK`) embutidos ali.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") contendo payloads grandes.

DFIR heuristics:
- Gerar alerta quando os campos Extra estiverem incomumente grandes nas entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Tratar IDs Extra desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, re-zipar os arquivos extraídos) remove os campos Extra maliciosos. Se as ferramentas se recusarem a extrair devido a criptografia falsa, primeiro limpe o bit 0 do GPBF como acima, então reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nome de arquivo/diretório (ocultando artefatos reais)

Um arquivo ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extractors e decompilers ficam confusos e podem sobrepor ou ocultar o arquivo real com uma entrada de diretório. Isso tem sido observado com entradas colidindo com nomes core de APK como `classes.dex`.

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
- Sinalizar APKs cujos cabeçalhos locais marcam criptografia (GPBF bit 0 = 1) mas que ainda assim instalam/executam.
- Sinalizar campos Extra grandes/desconhecidos nas entradas core (procure por marcadores como `JADXBLOCK`).
- Sinalizar colisões de caminho (`X` e `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Other malicious ZIP tricks (2024–2025)

### Concatenated central directories (multi-EOCD evasion)

Campanhas de phishing recentes entregam um único blob que na verdade é **dois arquivos ZIP concatenados**. Cada um tem seu próprio End of Central Directory (EOCD) + central directory. Diferentes extractors analisam diretórios diferentes (7zip lê o primeiro, WinRAR o último), permitindo que atacantes escondam payloads que só algumas ferramentas mostram. Isso também contorna AVs básicos de gateway de e-mail que inspecionam apenas o primeiro diretório.

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
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Modelos modernos de "better zip bomb" constroem um pequeno **kernel** (bloco DEFLATE altamente comprimido) e o reutilizam por meio de cabeçalhos locais sobrepostos. Cada entrada do central directory aponta para os mesmos dados comprimidos, alcançando razões >28M:1 sem aninhar arquivos. Bibliotecas que confiam nos tamanhos do central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP antes de builds hardenizados) podem ser forçadas a alocar petabytes.

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
**Manuseio**
- Execute um dry-run walk: `zipdetails -v file.zip | grep -n "Rel Off"` e garanta que os offsets estejam estritamente crescentes e únicos.
- Limite o tamanho total descompactado aceito e a contagem de entradas antes da extração (`zipdetails -t` ou parser customizado).
- Se for necessário extrair, faça-o dentro de um cgroup/VM com limites de CPU e disco (evite crashes por inflação ilimitada).

---

## Referências

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)

{{#include ../../../banners/hacktricks-training.md}}

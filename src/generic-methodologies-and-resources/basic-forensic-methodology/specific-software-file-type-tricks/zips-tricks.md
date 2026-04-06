# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

**Command-line tools** para gerenciar **zip files** são essenciais para diagnosticar, reparar e quebrar zip files. Aqui estão algumas utilidades-chave:

- **`unzip`**: Revela por que um zip file pode não descomprimir.
- **`zipdetails -v`**: Oferece análise detalhada dos campos do formato zip.
- **`zipinfo`**: Lista o conteúdo de um zip file sem extraí-los.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar zip files corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para brute-force de senhas de zip, eficaz para senhas de até cerca de 7 caracteres.

A [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões dos zip files.

É crucial notar que zip files protegidos por senha **não criptografam nomes de arquivos ou tamanhos de arquivos** internamente, uma falha de segurança que não é compartilhada com RAR ou 7z, que criptografam essa informação. Além disso, zip files criptografados com o método mais antigo ZipCrypto são vulneráveis a um **ataque de texto simples (plaintext attack)** se uma cópia descomprimida de um arquivo compactado estiver disponível. Esse ataque explora o conteúdo conhecido para quebrar a senha do zip, uma vulnerabilidade detalhada no [artigo do HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) e explicada mais a fundo neste [paper acadêmico](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). No entanto, zip files protegidos com **AES-256** são imunes a esse ataque de plaintext, mostrando a importância de escolher métodos de criptografia seguros para dados sensíveis.

---

## Truques anti-reversão em APKs usando cabeçalhos ZIP manipulados

Droppers modernos de malware Android usam metadados ZIP malformados para quebrar ferramentas estáticas (jadx/apktool/unzip) enquanto mantêm o APK instalável no dispositivo. Os truques mais comuns são:

- Criptografia falsa definindo o bit 0 do ZIP General Purpose Bit Flag (GPBF)
- Abuso de Extra fields grandes/personalizados para confundir parsers
- Colisões de nomes de arquivo/diretório para esconder artefatos reais (por exemplo, um diretório chamado `classes.dex/` ao lado do real `classes.dex`)

### 1) Criptografia falsa (GPBF bit 0 set) sem criptografia real

Sintomas:
- `jadx-gui` falha com erros como:

```
java.util.zip.ZipException: invalid CEN header (encrypted entry)
```
- `unzip` pede senha para arquivos centrais do APK mesmo que um APK válido não possa ter `classes*.dex`, `resources.arsc` ou `AndroidManifest.xml` criptografados:

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
Observe o General Purpose Bit Flag para os cabeçalhos locais e centrais. Um valor revelador é o bit 0 ativado (Encryption) mesmo para core entries:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Se um APK instala e é executado no dispositivo, mas entradas core aparecem "encrypted" para ferramentas, o GPBF foi adulterado.

Corrija limpando o bit 0 do GPBF tanto nas entradas Local File Headers (LFH) quanto nas entradas Central Directory (CD). Patcher mínimo de bytes:

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

### 2) Campos Extra grandes/personalizados para quebrar parsers

Atacantes inserem Campos Extra superdimensionados e IDs estranhos nos cabeçalhos para atrapalhar decompiladores. Na prática, você pode ver marcadores customizados (por exemplo, strings como `JADXBLOCK`) embutidos ali.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Executável Java") ou `0x414A` ("JA:") carregando grandes payloads.

Heurísticas DFIR:
- Alerta quando os campos Extra são anormalmente grandes em entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Trate IDs Extra desconhecidos nessas entradas como suspeitos.

Mitigação prática: reconstruir o arquivo (por exemplo, recompactar os arquivos extraídos) remove campos Extra maliciosos. Se ferramentas se recusarem a extrair devido a criptografia falsa, primeiro limpe o bit 0 do GPBF como acima, depois reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nomes de arquivo/diretório (escondendo artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extratores e decompiladores ficam confusos e podem sobrepor ou esconder o arquivo real com uma entrada de diretório. Isso foi observado com entradas colidindo com nomes essenciais de APK como `classes.dex`.

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
- Sinalizar APKs cujos cabeçalhos locais indicam criptografia (GPBF bit 0 = 1) mas ainda são instalados/executados.
- Sinalizar Extra fields grandes/desconhecidos em entradas core (procure por marcadores como `JADXBLOCK`).
- Sinalizar colisões de caminho (`X` and `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Outros truques maliciosos em ZIP (2024–2026)

### Diretórios centrais concatenados (evasão multi-EOCD)

Campanhas de phishing recentes enviam um único blob que na verdade são **dois arquivos ZIP concatenados**. Cada um tem seu próprio End of Central Directory (EOCD) + central directory. Diferentes extractors analisam diretórios diferentes (7zip lê o primeiro, WinRAR o último), permitindo que atacantes escondam payloads que apenas algumas ferramentas mostram. Isso também contorna AVs básicos de gateway de e-mail que inspecionam somente o primeiro diretório.

**Comandos de triagem**
```bash
# Count EOCD signatures
binwalk -R "PK\x05\x06" suspect.zip
# Dump central-directory offsets
zipdetails -v suspect.zip | grep -n "End Central"
```
Se mais de um EOCD aparecer ou houver avisos de "data after payload", divida o blob e inspecione cada parte:
```bash
# recover the second archive (heuristic: start at second EOCD offset)
# adjust OFF based on binwalk output
OFF=123456
dd if=suspect.zip bs=1 skip=$OFF of=tail.zip
7z l tail.zip   # list hidden content
```
### Quoted-overlap / overlapping-entry bombs (non-recursive)

Uma "better zip bomb" moderna constrói um pequeno **kernel** (bloco DEFLATE altamente comprimido) e o reutiliza via overlapping local headers. Cada entrada do central directory aponta para os mesmos dados comprimidos, alcançando razões >28M:1 sem nesting archives. Bibliotecas que confiam nos tamanhos do central directory (Python `zipfile`, Java `java.util.zip`, Info-ZIP antes de hardened builds) podem ser forçadas a alocar petabytes.

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
**Tratamento**
- Faça uma verificação simulada: `zipdetails -v file.zip | grep -n "Rel Off"` e assegure que os offsets estão estritamente crescentes e são únicos.
- Limite o tamanho total descompactado aceito e a contagem de entradas antes da extração (`zipdetails -t` ou um parser customizado).
- Quando for necessário extrair, faça isso dentro de um cgroup/VM com limites de CPU e disco (evite crashes por inflação ilimitada).

---

### Confusão entre parser de local-header e central-directory

Pesquisas recentes sobre differential-parsers mostraram que a ambiguidade do ZIP ainda é explorável em toolchains modernos. A ideia principal é simples: algum software confia no **Local File Header (LFH)** enquanto outros confiam no **Central Directory (CD)**, então um mesmo arquivo pode apresentar nomes de arquivo, caminhos, comentários, offsets ou conjuntos de entradas diferentes para ferramentas distintas.

Usos ofensivos práticos:
- Faça um filtro de upload, pré-scan do AV ou validador de pacotes ver um arquivo benigno no CD enquanto o extrator respeita um nome/caminho diferente no LFH.
- Abuse nomes duplicados, entradas presentes apenas em uma das estruturas, ou metadados de caminho Unicode ambíguos (por exemplo, Info-ZIP Unicode Path Extra Field `0x7075`) para que parsers diferentes reconstruam árvores distintas.
- Combine isso com path traversal para transformar uma visão “inofensiva” do arquivo em um write-primitive durante a extração. Para o lado da extração, veja [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

DFIR triage:
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
Por favor, cole aqui o conteúdo (markdown) que quer que eu complemente e traduza. Preciso do texto original de src/generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/zips-tricks.md e de uma indicação do que significa "Complement it with" (ex.: adicionar exemplos, comandos, casos de uso, notas). 

Confirmo que seguirei as regras: preservo tags/links/paths/código e não traduirei nomes técnicos ou plataformas.
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heuristics:
- Rejeitar ou isolar arquivos com nomes LFH/CD incompatíveis, nomes de arquivo duplicados, múltiplos registros EOCD ou bytes extras após o EOCD final.
- Tratar ZIPs que usam campos extra de caminho Unicode incomuns ou comentários inconsistentes como suspeitos se ferramentas diferentes discordarem sobre a árvore extraída.
- Se a análise for mais importante do que preservar os bytes originais, reempacotar o arquivo com um parser estrito após a extração em uma sandbox e comparar a lista de arquivos resultante com os metadados originais.

Isso importa além dos ecossistemas de pacotes: a mesma classe de ambiguidade pode ocultar payloads de gateways de e-mail, scanners estáticos e pipelines de ingestão customizados que "espiam" o conteúdo dos ZIPs antes que um extractor diferente trate o arquivo.

---



## Referências

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
- [GodFather – Part 1 – A multistage dropper (APK ZIP anti-reversing)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [zipdetails (Archive::Zip script)](https://metacpan.org/pod/distribution/Archive-Zip/scripts/zipdetails)
- [ZIP File Format Specification (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Hackers bury malware in new ZIP file attack — concatenated ZIP central directories](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [Understanding Zip Bombs: overlapping/quoted-overlap kernel construction](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [My ZIP isn't your ZIP: Identifying and Exploiting Semantic Gaps Between ZIP Parsers (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [Preventing ZIP parser confusion attacks on Python package installers](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
{{#include ../../../banners/hacktricks-training.md}}

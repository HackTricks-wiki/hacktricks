# Truques com ZIPs

{{#include ../../../banners/hacktricks-training.md}}

As **ferramentas de linha de comando** para gerenciar **arquivos zip** são essenciais para diagnosticar, reparar e realizar cracking de arquivos zip. Aqui estão alguns utilitários importantes:<sup>[[1]](#references)</sup>

- **`unzip`**: Revela por que um arquivo zip pode não ser descompactado.
- **`zipdetails -v`**: Oferece uma análise detalhada dos campos do formato de arquivo zip.<sup>[[3]](#references)</sup>
- **`zipinfo`**: Lista o conteúdo de um arquivo zip sem extraí-lo.
- **`zip -F input.zip --out output.zip`** e **`zip -FF input.zip --out output.zip`**: Tentam reparar arquivos zip corrompidos.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Uma ferramenta para brute-force cracking de senhas de arquivos zip, eficaz para senhas de até aproximadamente 7 caracteres.

A [especificação do formato de arquivo Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) fornece detalhes abrangentes sobre a estrutura e os padrões dos arquivos zip.<sup>[[4]](#references)</sup>

É crucial observar que arquivos ZIP tradicionais protegidos por senha geralmente deixam os nomes e tamanhos dos arquivos visíveis, ao contrário dos modos de header-encryption suportados por RAR e 7z. Além disso, arquivos ZIP criptografados com o método mais antigo ZipCrypto são vulneráveis a um **plaintext attack** se uma cópia não criptografada de um arquivo comprimido estiver disponível.<sup>[[1]](#references)</sup> Esse ataque utiliza o conteúdo conhecido para crackear a senha do ZIP, conforme explicado [neste artigo acadêmico](https://math.ucr.edu/~mike/zipattacks.pdf) e demonstrado [neste walk-through do Hack This Site](https://www.hackthissite.org/articles/read/793).<sup>[[11]](#references)[[12]](#references)</sup> No entanto, o ataque de known-plaintext do ZipCrypto não se aplica a entradas protegidas com criptografia **AES-256**.<sup>[[1]](#references)</sup>

---

## Truques de anti-reversing em APKs usando headers ZIP manipulados

Droppers modernos de malware Android usam metadados ZIP malformados para quebrar ferramentas estáticas (jadx/apktool/unzip), mantendo o APK instalável no dispositivo. Os truques mais comuns são:<sup>[[2]](#references)</sup>

- Fake encryption definindo o bit 0 do ZIP General Purpose Bit Flag (GPBF)
- Abuso de campos Extra grandes/personalizados para confundir parsers
- Colisões entre nomes de arquivos/diretórios para ocultar artefatos reais (por exemplo, um diretório chamado `classes.dex/` ao lado do `classes.dex` real)

### 1) Fake encryption (bit 0 do GPBF definido) sem crypto real

Sintomas:
- `jadx-gui` falha com erros como:

```
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
Observe o General Purpose Bit Flag dos cabeçalhos local e central. Um valor revelador é o bit 0 definido (Encryption), até mesmo para entradas principais:
```
Extract Zip Spec      2D '4.5'
General Purpose Flag  0A09
[Bit 0]   1 'Encryption'
[Bits 1-2] 1 'Maximum Compression'
[Bit 3]   1 'Streamed'
[Bit 11]  1 'Language Encoding'
```
Heurística: Se um APK instala e é executado no dispositivo, mas as entradas principais aparecem como "encrypted" para as ferramentas, o GPBF foi adulterado.

Corrija limpando o bit 0 do GPBF nas entradas dos Local File Headers (LFH) e do Central Directory (CD). Patcher mínimo de bytes:

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
Agora você deverá ver `General Purpose Flag  0000` nas entradas principais, e as ferramentas conseguirão analisar o APK novamente.

### 2) Extra fields grandes/personalizados para quebrar parsers

Attackers inserem Extra fields excessivamente grandes e IDs incomuns nos headers para fazer os decompilers falharem. No mundo real, você pode encontrar marcadores personalizados (por exemplo, strings como `JADXBLOCK`) incorporados neles.

Inspeção:
```bash
zipdetails -v sample.apk | sed -n '/Extra ID/,+4p' | head -n 50
```
Exemplos observados: IDs desconhecidos como `0xCAFE` ("Java Executable") ou `0x414A` ("JA:") contendo payloads grandes.<sup>[[2]](#references)</sup>

Heurísticas de DFIR:
- Gere um alerta quando os campos Extra forem excepcionalmente grandes em entradas principais (`classes*.dex`, `AndroidManifest.xml`, `resources.arsc`).
- Considere suspeitos os IDs Extra desconhecidos nessas entradas.

Mitigação prática: reconstruir o archive (por exemplo, compactar novamente os arquivos extraídos) remove os campos Extra maliciosos. Se as ferramentas se recusarem a extrair devido a uma encryption falsa, primeiro limpe o bit 0 do GPBF conforme descrito acima e, em seguida, reempacote:
```bash
mkdir /tmp/apk
unzip -qq normalized.apk -d /tmp/apk
(cd /tmp/apk && zip -qr ../clean.apk .)
```
### 3) Colisões de nomes de arquivos/diretórios (ocultando artefatos reais)

Um ZIP pode conter tanto um arquivo `X` quanto um diretório `X/`. Alguns extractors e decompilers ficam confusos e podem sobrepor ou ocultar o arquivo real com uma entrada de diretório. Isso foi observado em entradas que colidem com nomes principais de APK, como `classes.dex`.

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
Ideias de detecção para a equipe defensiva:
- Sinalizar APKs cujos cabeçalhos locais indicam criptografia (GPBF bit 0 = 1), mas que ainda são instalados/executados.
- Sinalizar campos Extra grandes/desconhecidos em entradas principais (procurar marcadores como `JADXBLOCK`).
- Sinalizar colisões de caminhos (`X` e `X/`) especificamente para `AndroidManifest.xml`, `resources.arsc`, `classes*.dex`.

---

## Outras técnicas maliciosas de ZIP (2024–2026)

### Diretórios centrais concatenados (evasão multi-EOCD)

Em uma campanha de phishing de 2024, os atacantes distribuíram um único blob que, na verdade, era formado por **dois arquivos ZIP concatenados**. Cada um tinha seu próprio registro End of Central Directory (EOCD) e diretório central. Diferentes extractors analisaram diretórios diferentes (o 7-Zip leu o primeiro, enquanto o WinRAR leu o último), permitindo que os atacantes ocultassem payloads que apenas algumas ferramentas exibiam; scanners que inspecionam apenas um diretório podem não detectar o outro archive.<sup>[[5]](#references)[[6]](#references)</sup>

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
### Quoted-overlap / overlapping-entry bombs (não recursivas)

As ZIP bombs de **kernel** Quoted-overlap constroem um pequeno **kernel** (um bloco DEFLATE altamente comprimido) e o reutilizam em entradas sobrepostas. As variantes de sobreposição completa apontam várias entradas do diretório central para um único cabeçalho local, enquanto as variantes Quoted-overlap citam cabeçalhos locais dentro de streams DEFLATE; a construção publicada alcança mais de 28M:1 sem archives aninhados.<sup>[[7]](#references)</sup>

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
- Execute uma verificação dry-run: `zipdetails -v file.zip | grep -n "Local Header Offset"` e compare os offsets de cabeçalho local referenciados e os intervalos de dados comprimidos; offsets duplicados indicam variantes com sobreposição total.<sup>[[7]](#references)[[8]](#references)</sup>
- Limite o tamanho total descomprimido aceito e a quantidade de entradas antes da extração usando um parser; `zipinfo -t file.zip` informa os totais, mas não impõe um limite de segurança.<sup>[[8]](#references)</sup>
- Quando precisar extrair, faça isso dentro de um cgroup/VM com limites de CPU e disco (evite crashes causados por descompressão sem limites).<sup>[[8]](#references)</sup>

---

### Confusão entre parser de cabeçalho local e diretório central

Pesquisas recentes sobre differential-parser mostraram que a ambiguidade de ZIP ainda pode ser explorada em toolchains modernas. A ideia principal é simples: alguns softwares confiam no **Local File Header (LFH)**, enquanto outros confiam no **Central Directory (CD)**; assim, um único archive pode apresentar diferentes nomes de arquivo, paths, comentários, offsets ou conjuntos de entradas para ferramentas diferentes.<sup>[[9]](#references)</sup>

Usos ofensivos práticos:
- Fazer com que um upload filter, uma pré-verificação de AV ou um package validator veja um arquivo benigno no CD, enquanto o extractor respeita um nome/path de LFH diferente.
- Explorar nomes duplicados, entradas presentes em apenas uma estrutura ou metadados ambíguos de path Unicode (por exemplo, o Info-ZIP Unicode Path Extra Field `0x7075`), fazendo com que parsers diferentes reconstruam árvores diferentes.
- Combinar isso com path traversal para transformar uma visualização "inofensiva" do archive em um write-primitive durante a extração. Para o lado da extração, consulte [Archive Extraction Path Traversal](../../../generic-hacking/archive-extraction-path-traversal.md).

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
Complemente-o com:
```bash
zipdetails -v suspect.zip | less
zipinfo -v suspect.zip | grep -E "file name|offset|comment"
```
Heurísticas:
- Para ingestão sensível à segurança, rejeite ou isole arquivos com nomes LFH/CD incompatíveis, nomes de arquivo duplicados, vários registros EOCD ou bytes após o EOCD final.<sup>[[9]](#references)[[10]](#references)</sup>
- Considere suspeitos os ZIPs que usam campos extras de caminho Unicode incomuns ou comentários inconsistentes, caso ferramentas diferentes discordem sobre a árvore extraída.<sup>[[4]](#references)[[9]](#references)</sup>
- Se a análise for mais importante do que preservar os bytes originais, reempacote o arquivo com um parser estrito após a extração em um sandbox e compare a lista de arquivos resultante com os metadados originais.

Isso é relevante para além dos ecossistemas de pacotes: a mesma classe de ambiguidade pode ocultar payloads de gateways de e-mail, scanners estáticos e pipelines personalizados de ingestão que "espiam" o conteúdo dos ZIPs antes que um extractor diferente processe o arquivo.<sup>[[9]](#references)</sup>

---



## References

- [1] [Guia de Campo de Forensics para CTFs (Blog do Mike, categoria CTF)](https://michael-myers.github.io/blog/categories/ctf/)
- [2] [GodFather – Parte 1 – Um dropper multistage (anti-reversing de APK ZIP)](https://shindan.io/blog/godfather-part-1-a-multistage-dropper)
- [3] [zipdetails (script IO::Compress)](https://metacpan.org/dist/IO-Compress/view/bin/zipdetails)
- [4] [Especificação do formato de arquivo ZIP (PKWARE APPNOTE.TXT)](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [5] [Estrutura flexível de arquivos ZIP explorada para ocultar malware sem detecção (Perception Point)](https://perception-point.io/news/flexible-structure-of-zip-archives-exploited-to-hide-malware-undetected/)
- [6] [Hackers enterram malware em um novo ataque com arquivos ZIP — diretórios centrais ZIP concatenados](https://www.tomshardware.com/tech-industry/cyber-security/hackers-bury-malware-in-new-zip-file-attack-combining-multiple-zips-into-one-bypasses-antivirus-protections)
- [7] [Um zip bomb melhor (David Fifield, USENIX WOOT 2019)](https://www.usenix.org/system/files/woot19-paper_fifield_0.pdf)
- [8] [Entendendo zip bombs: construção de kernel com sobreposição/sobreposição citada](https://ubos.tech/news/understanding-zip-bombs-construction-risks-and-mitigation-2/)
- [9] [Meu ZIP não é o seu ZIP: identificando e explorando lacunas semânticas entre parsers ZIP (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/you)
- [10] [Prevenindo ataques de confusão de parsers ZIP em instaladores de pacotes Python](https://blog.pypi.org/posts/2025-08-07-wheel-archive-confusion-attacks/)
- [11] [Ataques ZIP com texto simples conhecido reduzido (Michael Stay, AccessData Corporation)](https://math.ucr.edu/~mike/zipattacks.pdf)
- [12] [Hack This Site: Missão Web Realista, Nível 15 (ataque ZIP de texto simples conhecido)](https://www.hackthissite.org/articles/read/793)
{{#include ../../../banners/hacktricks-training.md}}

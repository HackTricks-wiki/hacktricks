# Fluxo de Trabalho Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist de triagem

1. Identifique o que você tem: encoding vs encryption vs hash vs signature vs MAC.
2. Determine o que está sob controle: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classifique: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplique primeiro as verificações de maior probabilidade: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Escale para métodos avançados somente quando necessário: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos online & utilitários

Esses são úteis quando a tarefa é identificação e remoção de camadas, ou quando você precisa de uma confirmação rápida de uma hipótese.

### Consulta de hashes

- Pesquise o hash no Google (surpreendentemente eficaz).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Auxiliares de identificação

- CyberChef (magia, decodificar, converter): https://gchq.github.io/CyberChef/
- dCode (playground de ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Plataformas de prática / referências

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Decodificação automatizada

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (testa muitas bases/encodings): https://github.com/dhondta/python-codext

## Codificações & cifras clássicas

### Técnica

Muitas tarefas de crypto em CTF são transformações em camadas: base encoding + simple substitution + compression. O objetivo é identificar camadas e removê-las com segurança.

### Codificações: tente várias bases

Se você suspeitar de codificação em camadas (base64 → base32 → …), tente:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Sinais comuns:

- Base64: `A-Za-z0-9+/=` (padding `=` é comum)
- Base32: `A-Z2-7=` (frequentemente muito `=` padding)
- Ascii85/Base85: pontuação densa; às vezes envolto em `<~ ~>`

### Substitution / monoalfabética

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

### Bacon cipher

Often appears as groups of 5 bits or 5 letters:
```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```
### Morse
```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```
### Runas

Runas são frequentemente alfabetos de substituição; procure por "futhark cipher" e tente tabelas de mapeamento.

## Compressão em desafios

### Técnica

A compressão aparece constantemente como uma camada extra (zlib/deflate/gzip/xz/zstd), às vezes aninhada. Se a saída quase é analisável mas parece lixo, suspeite de compressão.

### Identificação rápida

- `file <blob>`
- Procure por magic bytes:
- gzip: `1f 8b`
- zlib: often `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, which is often the fastest path when the blob looks compressed but `zlib` fails.

### CLI útil
```bash
python3 - <<'PY'
import sys, zlib
data = sys.stdin.buffer.read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## Construções criptográficas comuns em CTF

### Técnica

Estas aparecem frequentemente porque são erros realistas de desenvolvedores ou bibliotecas comuns usadas incorretamente. O objetivo costuma ser o reconhecimento e a aplicação de um fluxo de trabalho conhecido de extração ou reconstrução.

### Fernet

Typical hint: two Base64 strings (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se vir múltiplas shares e um threshold `t` for mencionado, provavelmente é Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs às vezes fornecem outputs do `openssl enc` (o header frequentemente começa com `Salted__`).

Bruteforce helpers:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### General toolset

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuração local recomendada

Practical CTF stack:

- Python + `pycryptodome` for symmetric primitives and fast prototyping
- SageMath for modular arithmetic, CRT, lattices, and RSA/ECC work
- Z3 for constraint-based challenges (when the crypto reduces to constraints)

Suggested Python packages:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}

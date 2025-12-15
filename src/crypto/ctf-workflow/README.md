# Fluxo de trabalho Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist de triagem

1. Identifique o que você tem: encoding vs encryption vs hash vs signature vs MAC.
2. Determine o que está controlado: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classifique: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplique primeiro as checagens de maior probabilidade: decode layers, known-plaintext XOR, nonce reuse, mode misuse, oracle behavior.
5. Recorr a métodos avançados apenas quando necessário: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos online & utilitários

Estes são úteis quando a tarefa é identificação e remoção de camadas, ou quando você precisa de uma confirmação rápida de uma hipótese.

### Hash lookups

- Pesquise o hash no Google (surpreendentemente eficaz).
- https://crackstation.net/
- https://md5decrypt.net/
- https://hashes.org/search.php
- https://www.onlinehashcrack.com/
- https://gpuhash.me/
- http://hashtoolkit.com/reverse-hash

### Identification helpers

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (ciphers/encodings playground): https://www.dcode.fr/tools-list
- Boxentriq (substitution solvers): https://www.boxentriq.com/code-breaking

### Practice platforms / references

- CryptoHack (hands-on crypto challenges): https://cryptohack.org/
- Cryptopals (classic modern crypto pitfalls): https://cryptopals.com/

### Automated decoding

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tries many bases/encodings): https://github.com/dhondta/python-codext

## Codificações & cifras clássicas

### Técnica

Muitos desafios de crypto em CTF são transformações em camadas: base encoding + simple substitution + compression. O objetivo é identificar as camadas e removê-las com segurança.

### Encodings: tente muitas bases

Se você suspeita de codificação em camadas (base64 → base32 → …), tente:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comuns:

- Base64: `A-Za-z0-9+/=` (o padding `=` é comum)
- Base32: `A-Z2-7=` (frequentemente muitos `=` de padding)
- Ascii85/Base85: pontuação densa; às vezes envolto em `<~ ~>`

### Substituição / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- https://www.dcode.fr/vigenere-cipher
- https://www.guballa.de/vigenere-solver

### Bacon cipher

Frequentemente aparece como grupos de 5 bits ou 5 letras:
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

A compressão aparece constantemente como uma camada extra (zlib/deflate/gzip/xz/zstd), às vezes aninhada. Se a saída quase é analisável, mas parece lixo, suspeite de compressão.

### Identificação rápida

- `file <blob>`
- Procure por bytes mágicos:
- gzip: `1f 8b`
- zlib: frequentemente `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

CyberChef has **Raw Deflate/Raw Inflate**, que costuma ser o caminho mais rápido quando o blob parece comprimido mas `zlib` falha.

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

Aparecem com frequência porque são erros realistas de desenvolvedores ou bibliotecas comuns usadas incorretamente. O objetivo geralmente é reconhecer e aplicar um fluxo de trabalho conhecido de extração ou reconstrução.

### Fernet

Indício típico: duas strings Base64 (token + key).

- Decoder/notes: https://asecuritysite.com/encryption/ferdecode
- In Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se você vir múltiplos shares e um limiar `t` for mencionado, provavelmente é Shamir.

- Online reconstructor (handy for CTFs): http://christian.gen.co/secrets/

### OpenSSL salted formats

CTFs às vezes fornecem saídas de `openssl enc` (o header frequentemente começa com `Salted__`).

Bruteforce helpers:

- https://github.com/glv2/bruteforce-salted-openssl
- https://github.com/carlospolop/easy_BFopensslCTF

### Conjunto de ferramentas geral

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Configuração local recomendada

Pilha prática para CTF:

- Python + `pycryptodome` para primitivas simétricas e prototipagem rápida
- SageMath para aritmética modular, CRT, lattices e trabalho com RSA/ECC
- Z3 para desafios baseados em restrições (quando a criptografia se reduz a restrições)

Pacotes Python sugeridos:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}

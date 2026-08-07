# Fluxo de trabalho de CTF de Crypto

{{#include ../../banners/hacktricks-training.md}}

## Checklist de triagem

1. Identifique o que você tem: encoding vs encryption vs hash vs signature vs MAC.
2. Determine o que é controlado: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), partial leakage.
3. Classifique: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplique primeiro as verificações com maior probabilidade: decode layers, known-plaintext XOR, nonce reuse, mode misuse, comportamento do oracle.
5. Recorra a métodos avançados apenas quando necessário: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos online e utilities

Eles são úteis quando a tarefa é identificar e remover camadas, ou quando você precisa confirmar rapidamente uma hipótese.

### Consultas de hashes

- Pesquise o hash no Google (surpreendentemente eficaz).
- [https://crackstation.net/](https://crackstation.net/)
- [https://md5decrypt.net/](https://md5decrypt.net/)
- [https://hashes.org/search.php](https://hashes.org/search.php)
- [https://www.onlinehashcrack.com/](https://www.onlinehashcrack.com/)
- [https://gpuhash.me/](https://gpuhash.me/)
- [http://hashtoolkit.com/reverse-hash](http://hashtoolkit.com/reverse-hash)

### Auxiliares de identificação

- CyberChef (magic, decode, convert): https://gchq.github.io/CyberChef/
- dCode (playground de ciphers/encodings): https://www.dcode.fr/tools-list
- Boxentriq (solvers de substitution): https://www.boxentriq.com/code-breaking

### Plataformas de prática / referências

- CryptoHack (desafios práticos de crypto): https://cryptohack.org/
- Cryptopals (armadilhas clássicas de crypto moderna): https://cryptopals.com/

### Decoding automatizado

- Ciphey: https://github.com/Ciphey/Ciphey
- python-codext (tenta várias bases/encodings): https://github.com/dhondta/python-codext

## Encodings e ciphers clássicos

### Técnica

Muitas tarefas de crypto em CTF são transformações em camadas: base encoding + simple substitution + compression. O objetivo é identificar as camadas e removê-las com segurança.

### Encodings: tente várias bases

Se você suspeita de encoding em camadas (base64 → base32 → …), tente:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comuns:

- Base64: `A-Za-z0-9+/=` (o padding `=` é comum)
- Base32: `A-Z2-7=` (geralmente há muito padding `=`)
- Ascii85/Base85: pontuação densa; às vezes delimitado por `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver: https://www.boxentriq.com/code-breaking/cryptogram
- quipqiup: https://quipqiup.com/

### Caesar / ROT / Atbash

- Nayuki auto breaker: https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript
- Atbash: http://rumkin.com/tools/cipher/atbash.php

### Vigenère

- [https://www.dcode.fr/vigenere-cipher](https://www.dcode.fr/vigenere-cipher)
- [https://www.guballa.de/vigenere-solver](https://www.guballa.de/vigenere-solver)

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

Runas são frequentemente alfabetos de substituição; pesquise por "futhark cipher" e tente usar tabelas de mapeamento.

## Compressão em challenges

### Técnica

A compressão aparece constantemente como uma camada extra (zlib/deflate/gzip/xz/zstd), às vezes aninhada. Se a saída quase puder ser analisada, mas parecer lixo, suspeite de compressão.

### Identificação rápida

- `file <blob>`
- Procure por magic bytes:
- gzip: `1f 8b`
- zlib: frequentemente `78 01/9c/da`
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

O CyberChef tem **Raw Deflate/Raw Inflate**, que geralmente é o caminho mais rápido quando o blob parece comprimido, mas `zlib` falha.

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

Elas aparecem com frequência porque são erros realistas de desenvolvedores ou bibliotecas comuns usadas incorretamente. O objetivo geralmente é reconhecer o caso e aplicar um workflow conhecido de extração ou reconstrução.

### Fernet

Dica típica: duas strings em Base64 (token + key).

- Decoder/notas: https://asecuritysite.com/encryption/ferdecode
- Em Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se você vir múltiplos shares e um threshold `t` for mencionado, provavelmente é Shamir.

- Reconstructor online (útil para CTFs): http://christian.gen.co/secrets/

### Formatos salted do OpenSSL

Às vezes, CTFs fornecem saídas de `openssl enc` (o header geralmente começa com `Salted__`).

Helpers de bruteforce:

- [https://github.com/glv2/bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [https://github.com/carlospolop/easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)

### Conjunto geral de ferramentas

- RsaCtfTool: https://github.com/Ganapati/RsaCtfTool
- featherduster: https://github.com/nccgroup/featherduster
- cryptovenom: https://github.com/lockedbyte/cryptovenom

## Setup local recomendado

Stack prática para CTF:

- Python + `pycryptodome` para primitivas simétricas e prototipagem rápida
- SageMath para aritmética modular, CRT, lattices e trabalho com RSA/ECC
- Z3 para desafios baseados em constraints (quando a criptografia é reduzida a constraints)

Pacotes Python sugeridos:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
{{#include ../../banners/hacktricks-training.md}}

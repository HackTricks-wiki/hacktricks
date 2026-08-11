# Fluxo de trabalho de Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist de triagem

1. Identifique o que você tem: encoding vs encryption vs hash vs signature vs MAC.
2. Determine o que é controlado: plaintext/ciphertext, IV/nonce, key, oracle (padding/error/timing), leak parcial.
3. Classifique: symmetric (AES/CTR/GCM), public-key (RSA/ECC), hash/MAC (SHA/MD5/HMAC), classical (Vigenere/XOR).
4. Aplique primeiro as verificações com maior probabilidade: decodificar camadas, known-plaintext XOR, reutilização de nonce, uso incorreto do modo, comportamento do oracle.
5. Recorra a métodos avançados somente quando necessário: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos online e utilitários

Eles são úteis quando a tarefa é identificar e remover camadas, ou quando você precisa confirmar rapidamente uma hipótese.

### Consultas de hash

- Pesquise um hash de challenge quando souber que ele é sintético/público.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Pesquisa no hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Não envie hashes de senhas reais nem material confidencial de challenge para serviços de consulta de terceiros. Prefira um ataque offline com wordlist/rule quando houver preocupações relacionadas à divulgação, aos termos de serviço ou às regras da competição.

### Auxiliares de identificação

- CyberChef (Magic, decodificação e conversão).<sup>[[7]](#references)</sup>
- dCode (playground de cipher/encoding).<sup>[[8]](#references)</sup>
- Boxentriq (solvers de substitution).<sup>[[9]](#references)</sup>

### Plataformas de prática / referências

- CryptoHack (challenges práticos de cryptography).<sup>[[10]](#references)</sup>
- Cryptopals (armadilhas clássicas de modern-cryptography).<sup>[[11]](#references)</sup>

### Decodificação automatizada

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (tenta várias bases/encodings).<sup>[[13]](#references)</sup>

## Encodings e classical ciphers

### Técnica

Muitas tarefas de crypto em CTF são transforms em camadas: base encoding + simple substitution + compression. O objetivo é identificar as camadas e removê-las com segurança.

### Encodings: tente várias bases

Se você suspeitar de encoding em camadas (base64 → base32 → …), tente:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indicadores comuns:

- Base64: `A-Za-z0-9+/=` (o padding `=` é comum)
- Base32: `A-Z2-7=` (geralmente contém muito padding `=`)
- Ascii85/Base85: pontuação densa; às vezes envolto em `<~ ~>`

### Substitution / monoalphabetic

- Boxentriq cryptogram solver.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Nayuki automatic Caesar-cipher breaker.<sup>[[15]](#references)</sup>
- Rumkin Atbash tool.<sup>[[16]](#references)</sup>

### Vigenère

- dCode Vigenère tool.<sup>[[8]](#references)</sup>
- Guballa Vigenère solver.<sup>[[17]](#references)</sup>

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
### Runes

Runes são frequentemente alfabetos de substituição; pesquise por "futhark cipher" e tente usar tabelas de mapeamento.

## Compressão em challenges

### Técnica

A compressão aparece constantemente como uma camada adicional (zlib/deflate/gzip/xz/zstd), às vezes aninhada. Se a saída quase puder ser interpretada, mas parecer lixo, suspeite de compressão.

### Identificação rápida

- `file <blob>`
- Procure por magic bytes:
- gzip: `1f 8b`
- zlib: normalmente `78 01`, `78 5e`, `78 9c` ou `78 da` (o segundo byte depende das flags de compressão)
- zip: `50 4b 03 04`
- bzip2: `42 5a 68` (`BZh`)
- xz: `fd 37 7a 58 5a 00`
- zstd: `28 b5 2f fd`

### Raw DEFLATE

O CyberChef tem **Raw Deflate/Raw Inflate**, que costuma ser o caminho mais rápido quando o blob parece comprimido, mas `zlib` falha.

### CLI úteis
```bash
python3 - blob.bin <<'PY'
import sys, zlib
data = open(sys.argv[1], 'rb').read()
for wbits in [zlib.MAX_WBITS, -zlib.MAX_WBITS]:
try:
print(zlib.decompress(data, wbits=wbits)[:200])
except Exception:
pass
PY
```
## Construções comuns de crypto em CTF

### Técnica

Estas aparecem com frequência porque são erros realistas de desenvolvedores ou bibliotecas comuns usadas incorretamente. O objetivo geralmente é reconhecê-las e aplicar um workflow conhecido de extração ou reconstrução.

### Fernet

Dica típica: duas strings Base64 (token + key).

- Decoder/notas: Asecuritysite Fernet decoder.<sup>[[18]](#references)</sup>
- Em Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se você vir vários shares e um threshold `t` for mencionado, provavelmente é Shamir.

- Reconstructor online (somente para shares de CTF não sensíveis).<sup>[[19]](#references)</sup>

### Formatos salted do OpenSSL

Às vezes, os CTFs fornecem outputs de `openssl enc` (o header geralmente começa com `Salted__`).

Helpers de bruteforce:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Conjunto geral de ferramentas

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Setup local recomendado

Stack prática para CTF:

- Python mais `pycryptodome` para primitivas simétricas e prototipagem rápida.<sup>[[25]](#references)</sup>
- SageMath para aritmética modular, CRT, lattices e trabalho com RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 para challenges baseados em constraints (quando o crypto é reduzido a constraints).<sup>[[27]](#references)</sup>

Pacotes Python sugeridos:
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```
## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [pesquisa do hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Kit de ferramentas de hash](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [ferramentas do dCode](https://www.dcode.fr/tools-list)
- [9] [ferramentas de quebra de códigos do Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Quebrador automático de cifra de César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cifra de Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Solucionador de Vigenère do Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decodificador Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Reconstrutor de compartilhamento secreto de Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Documentação do PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}

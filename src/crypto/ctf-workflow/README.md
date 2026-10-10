# Fluxo de trabalho de Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Lista de triagem

1. Identifique o que você tem: codificação vs. criptografia vs. hash vs. assinatura vs. MAC.
2. Determine o que está sob controle: texto simples/cifrado, IV/nonce, chave, oracle (padding/erro/temporização), leakage parcial.
3. Classifique: simétrica (AES/CTR/GCM), chave pública (RSA/ECC), hash/MAC (SHA/MD5/HMAC), clássica (Vigenere/XOR).
4. Comece pelas verificações com maior probabilidade de sucesso: decodificar camadas, XOR com texto conhecido, reutilização de nonce, uso incorreto de modo, comportamento do oracle.
5. Recorra a métodos avançados apenas quando necessário: lattices (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos online e utilitários

São úteis quando a tarefa é identificar e remover camadas, ou quando você precisa confirmar rapidamente uma hipótese.

### Consultas de hashes

- Pesquise um hash de desafio quando ele for conhecido por ser sintético/público.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Busca em hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Não envie hashes de senhas reais nem material confidencial de desafios para serviços de consulta de terceiros. Prefira um ataque offline com wordlist/regras quando houver preocupações com divulgação, termos de serviço ou regras da competição.

### Ferramentas de identificação

- CyberChef (Magic, decodificação e conversão).<sup>[[7]](#references)</sup>
- dCode (ambiente para cifras/codificações).<sup>[[8]](#references)</sup>
- Boxentriq (ferramentas para cifras de substituição).<sup>[[9]](#references)</sup>

### Plataformas de prática / referências

- CryptoHack (desafios práticos de criptografia).<sup>[[10]](#references)</sup>
- Cryptopals (armadilhas clássicas da criptografia moderna).<sup>[[11]](#references)</sup>

### Decodificação automatizada

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (testa várias bases/codificações).<sup>[[13]](#references)</sup>

## Codificações e cifras clássicas

### Técnica

Muitas tarefas de criptografia em CTF são transformações em camadas: codificação em base + substituição simples + compressão. O objetivo é identificar as camadas e removê-las com segurança.

### Codificações: teste várias bases

Se suspeitar de codificação em camadas (base64 → base32 → …), tente:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indícios comuns:

- Base64: `A-Za-z0-9+/=` (o padding `=` é comum)
- Base32: `A-Z2-7=` (muitas vezes com bastante padding `=`)
- Ascii85/Base85: pontuação densa; às vezes delimitada por `<~ ~>`

### Substituição / monoalfabética

- Ferramenta de resolução de criptogramas do Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

### Caesar / ROT / Atbash

- Decifrador automático de cifra Caesar da Nayuki.<sup>[[15]](#references)</sup>
- Ferramenta Atbash do Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Ferramenta Vigenère do dCode.<sup>[[8]](#references)</sup>
- Ferramenta de resolução Vigenère do Guballa.<sup>[[17]](#references)</sup>

### Cifra de Bacon

Costuma aparecer em grupos de 5 bits ou 5 letras:

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

## Compactação em desafios

### Técnica

A compactação aparece constantemente como uma camada extra (zlib/deflate/gzip/xz/zstd), às vezes aninhada. Se a saída quase pode ser analisada, mas parece lixo, suspeite de compactação.

### Identificação rápida

- `file <blob>`
- Procure por bytes mágicos:
  - gzip: `1f 8b`
  - zlib: geralmente `78 01`, `78 5e`, `78 9c` ou `78 da` (o segundo byte depende dos sinalizadores de compactação)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### DEFLATE bruto

O CyberChef tem **Raw Deflate/Raw Inflate**, que costuma ser o caminho mais rápido quando o blob parece compactado, mas `zlib` falha.

### CLI útil

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

## Construções comuns de crypto em CTFs

### Técnica

Elas aparecem com frequência porque são erros realistas de desenvolvedores ou bibliotecas comuns usadas incorretamente. O objetivo costuma ser reconhecê-las e aplicar um workflow conhecido de extração ou reconstrução.

### Fernet

Dica típica: duas strings Base64 (token + chave).

- Decoder/anotações: decoder Fernet da Asecuritysite.<sup>[[18]](#references)</sup>
- Em Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se você vir vários shares e houver menção a um limite `t`, provavelmente é Shamir.

- Reconstrutor online (somente para shares de CTF não sensíveis).<sup>[[19]](#references)</sup>

### Formatos salted do OpenSSL

Às vezes, CTFs fornecem saídas de `openssl enc` (o cabeçalho geralmente começa com `Salted__`).

Auxiliares de brute force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Conjunto geral de ferramentas

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configuração local recomendada

Stack prático para CTF:

- Python com `pycryptodome` para primitivas simétricas e prototipagem rápida.<sup>[[25]](#references)</sup>
- SageMath para aritmética modular, CRT, lattices e trabalho com RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 para desafios baseados em restrições (quando a crypto pode ser reduzida a restrições).<sup>[[27]](#references)</sup>

Pacotes Python sugeridos:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```

## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [busca do hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [ferramentas dCode](https://www.dcode.fr/tools-list)
- [9] [ferramentas de quebra de códigos da Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Quebrador automático de cifra de César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - Cifra Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [Solucionador Vigenère da Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - Decodificador Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [Reconstrutor de compartilhamento de segredo de Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [Documentação do PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
{{#include ../../banners/hacktricks-training.md}}

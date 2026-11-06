# Fluxo de trabalho de Crypto CTF

{{#include ../../banners/hacktricks-training.md}}

## Checklist de triagem

1. Identifique o que você tem: codificação vs. criptografia vs. hash vs. assinatura vs. MAC.
2. Determine o que é controlado: texto simples/cifrado, IV/nonce, chave, oráculo (padding/erro/temporização), leak parcial.
3. Classifique: simétrica (AES/CTR/GCM), chave pública (RSA/ECC), hash/MAC (SHA/MD5/HMAC), clássica (Vigenere/XOR).
4. Aplique primeiro as verificações com maior probabilidade de sucesso: decodificar camadas, known-plaintext XOR, nonce reuse, mode misuse, comportamento do oráculo.
5. Recorra a métodos avançados somente quando necessário: reticulados (LLL/Coppersmith), SMT/Z3, side-channels.

## Recursos e utilitários online

São úteis quando a tarefa envolve identificação e remoção de camadas, ou quando você precisa confirmar rapidamente uma hipótese.

### Consultas de hashes

- Pesquise um hash do desafio quando ele for sabidamente sintético/público.
- CrackStation.<sup>[[1]](#references)</sup>
- MD5Decrypt.<sup>[[2]](#references)</sup>
- Busca em hashes.org.<sup>[[3]](#references)</sup>
- OnlineHashCrack.<sup>[[4]](#references)</sup>
- GPUHash.me.<sup>[[5]](#references)</sup>
- Hash Toolkit.<sup>[[6]](#references)</sup>

Não envie hashes reais de senhas nem material confidencial do desafio para serviços de consulta de terceiros. Prefira um ataque offline com wordlist/regras quando houver preocupações com divulgação, termos de serviço ou regras da competição.

### Ferramentas de identificação

- CyberChef (Magic, decodificação e conversão).<sup>[[7]](#references)</sup>
- dCode (ambiente de testes de cifras/codificações).<sup>[[8]](#references)</sup>
- Boxentriq (solucionadores de substituição).<sup>[[9]](#references)</sup>

### Plataformas de prática / referências

- CryptoHack (desafios práticos de criptografia).<sup>[[10]](#references)</sup>
- Cryptopals (armadilhas clássicas da criptografia moderna).<sup>[[11]](#references)</sup>

### Decodificação automatizada

- Ciphey.<sup>[[12]](#references)</sup>
- python-codext (testa várias bases/codificações).<sup>[[13]](#references)</sup>

Para código-fonte de linguagens esotéricas e estado de interpretadores personalizados, consulte [Crypto CTF Misc](../ctf-misc/).

## Codificações e cifras clássicas

### Técnica

Muitas tarefas de criptografia em CTFs usam transformações em camadas: codificação em base + substituição simples + compressão. O objetivo é identificar as camadas e removê-las com segurança.

### Codificações: teste várias bases

Se suspeitar de codificação em camadas (base64 → base32 → …), tente:

- CyberChef "Magic"
- `codext` (python-codext): `codext <string>`

Indícios comuns:

- Base64: `A-Za-z0-9+/=` (o padding `=` é comum)
- Base32: `A-Z2-7=` (geralmente com bastante padding `=`)
- Ascii85/Base85: pontuação densa; às vezes delimitada por `<~ ~>`

### Substituição / monoalfabética

- Solucionador de criptogramas do Boxentriq.<sup>[[9]](#references)</sup>
- quipqiup.<sup>[[14]](#references)</sup>

#### Recuperação por known-plaintext de nomes de arquivo Base32 substituídos

Quando um nome de arquivo ofuscado usa apenas `a-z2-7`, expande para cerca de `ceil(8 * byte_length / 5)` caracteres após a remoção de um sufixo fixo, e o mesmo texto simples produz a mesma saída em diferentes arquivos, teste **Base32 sem padding seguida de uma substituição fixa de símbolos**. Essas pistas, por si só, não são prova. Reúna nomes de arquivo previsíveis e seus textos cifrados, preserve maiúsculas e minúsculas, codifique cada texto simples em Base32 e alinhe os símbolos posição por posição. Cada símbolo repetido do texto simples deve corresponder ao mesmo símbolo cifrado, e o mapeamento inverso também deve ser único. Em um caso de ransomware, `ntuser.ini` e `NTUSER.DAT` forneceram esses pares; isso recuperou nomes de arquivo, **não o conteúdo dos arquivos nem as chaves de criptografia**.<sup>[[28]](#references)</sup>

```python
import base64
pairs = [("ntuser.ini", "zsub5mdlekr37dx4"), ("NTUSER.DAT", "4s5l5tul5kr6kv5t")]
forward, inverse = {}, {}
for name, ciphertext in pairs:
    b32 = base64.b32encode(name.encode("ascii")).decode().lower().rstrip("=")
    assert len(b32) == len(ciphertext)
    for p, c in zip(b32, ciphertext):
        assert forward.get(p, c) == c and inverse.get(c, p) == p
        forward[p], inverse[c] = c, p
target = "4s5l5tul5kr6kv5t"  # Remove the fixed suffix first
b32 = "".join(inverse[c] for c in target)
clear = base64.b32decode(b32.upper() + "=" * (-len(b32) % 8))
assert "".join(forward[c] for c in b32) == target
print(clear.decode("ascii"))
```

Se um alvo contiver símbolos não mapeados, obtenha mais pares conhecidos ou permute apenas os mapeamentos de símbolos Base32 não utilizados. Restaure o padding até atingir um limite de oito caracteres, rejeite Base32 inválido e nomes decodificados não imprimíveis; em seguida, recodifique os candidatos restantes e compare o **texto cifrado original inteiro**. Blocos de texto cifrado repetidos podem fornecer palpites adicionais: no caso acima, `3gpng2wv` foi mapeado de volta para Base32 `gaydambq`, que decodifica para cinco zeros ASCII. Um candidato imprimível, por si só, não é uma prova única.<sup>[[28]](#references)</sup>

### Caesar / ROT / Atbash

- Ferramenta automática de quebra de cifra Caesar da Nayuki.<sup>[[15]](#references)</sup>
- Ferramenta Atbash da Rumkin.<sup>[[16]](#references)</sup>

### Vigenère

- Ferramenta Vigenère do dCode.<sup>[[8]](#references)</sup>
- Solucionador Vigenère da Guballa.<sup>[[17]](#references)</sup>

### Cifra de Bacon

Geralmente aparece como grupos de 5 bits ou 5 letras:

```
00111 01101 01010 00000 ...
AABBB ABBAB ABABA AAAAA ...
```

### Morse

```
.... --- .-.. -.-. .- .-. .- -.-. --- .-.. .-
```

### Runes

Runes são frequentemente alfabetos de substituição; pesquise por "futhark cipher" e tente tabelas de mapeamento.

## Compressão em desafios

### Técnica

A compressão aparece constantemente como uma camada extra (zlib/deflate/gzip/xz/zstd), às vezes aninhada. Se a saída quase puder ser interpretada, mas parecer lixo, suspeite de compressão.

### Identificação rápida

- `file <blob>`
- Procure bytes mágicos:
  - gzip: `1f 8b`
  - zlib: geralmente `78 01`, `78 5e`, `78 9c` ou `78 da` (o segundo byte depende dos flags de compressão)
  - zip: `50 4b 03 04`
  - bzip2: `42 5a 68` (`BZh`)
  - xz: `fd 37 7a 58 5a 00`
  - zstd: `28 b5 2f fd`

### DEFLATE bruto

O CyberChef tem **Raw Deflate/Raw Inflate**, que costuma ser o caminho mais rápido quando o blob parece comprimido, mas `zlib` falha.

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

## Construções comuns de crypto em CTF

### Técnica

Elas aparecem com frequência porque são erros realistas de desenvolvedores ou bibliotecas comuns usadas incorretamente. O objetivo geralmente é reconhecê-las e aplicar um fluxo de trabalho conhecido de extração ou reconstrução.

### Fernet

Dica típica: duas strings Base64 (token + chave).

- Decodificador/anotações: decodificador Fernet da Asecuritysite.<sup>[[18]](#references)</sup>
- Em Python: `from cryptography.fernet import Fernet`

### Shamir Secret Sharing

Se você vir vários compartilhamentos e um limite `t` for mencionado, provavelmente é Shamir.

- Reconstrutor online (apenas para compartilhamentos de CTF não sensíveis).<sup>[[19]](#references)</sup>

### Formatos OpenSSL com salt

Às vezes, CTFs fornecem saídas de `openssl enc` (o cabeçalho geralmente começa com `Salted__`).

Ferramentas auxiliares para brute force:

- `bruteforce-salted-openssl`.<sup>[[20]](#references)</sup>
- `easy_BFopensslCTF`.<sup>[[21]](#references)</sup>

### Conjunto geral de ferramentas

- RsaCtfTool.<sup>[[22]](#references)</sup>
- featherduster.<sup>[[23]](#references)</sup>
- cryptovenom.<sup>[[24]](#references)</sup>

## Configuração local recomendada

Stack prático para CTF:

- Python com `pycryptodome` para primitivas simétricas e prototipagem rápida.<sup>[[25]](#references)</sup>
- SageMath para aritmética modular, CRT, reticulados e trabalho com RSA/ECC.<sup>[[26]](#references)</sup>
- Z3 para desafios baseados em restrições (quando o problema de crypto se reduz a restrições).<sup>[[27]](#references)</sup>

Pacotes Python sugeridos:

```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver
```



## References

- [1] [CrackStation](https://crackstation.net/)
- [2] [MD5Decrypt](https://md5decrypt.net/)
- [3] [busca de hashes.org](https://hashes.org/search.php)
- [4] [OnlineHashCrack](https://www.onlinehashcrack.com/)
- [5] [GPUHash.me](https://gpuhash.me/)
- [6] [Hash Toolkit](https://hashtoolkit.com/reverse-hash)
- [7] [GCHQ CyberChef](https://gchq.github.io/CyberChef/)
- [8] [ferramentas dCode](https://www.dcode.fr/tools-list)
- [9] [ferramentas de quebra de códigos do Boxentriq](https://www.boxentriq.com/code-breaking)
- [10] [CryptoHack](https://cryptohack.org/)
- [11] [Cryptopals](https://cryptopals.com/)
- [12] [Ciphey](https://github.com/Ciphey/Ciphey)
- [13] [python-codext](https://github.com/dhondta/python-codext)
- [14] [quipqiup](https://quipqiup.com/)
- [15] [Nayuki - Quebrador automático de cifras de César](https://www.nayuki.io/page/automatic-caesar-cipher-breaker-javascript)
- [16] [Rumkin - cifra Atbash](https://rumkin.com/tools/cipher/atbash/)
- [17] [resolvedor Vigenère do Guballa](https://www.guballa.de/vigenere-solver)
- [18] [Asecuritysite - decodificador Fernet](https://asecuritysite.com/encryption/ferdecode)
- [19] [reconstrutor de compartilhamento de segredo de Shamir](https://christian.gen.co/secrets/)
- [20] [bruteforce-salted-openssl](https://github.com/glv2/bruteforce-salted-openssl)
- [21] [easy_BFopensslCTF](https://github.com/carlospolop/easy_BFopensslCTF)
- [22] [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool)
- [23] [featherduster](https://github.com/nccgroup/featherduster)
- [24] [cryptovenom](https://github.com/lockedbyte/cryptovenom)
- [25] [documentação do PyCryptodome](https://pycryptodome.readthedocs.io/en/latest/)
- [26] [SageMath](https://www.sagemath.org/)
- [27] [Z3](https://github.com/Z3Prover/z3)
- [28] [Eye Research – Quebrando esquemas de criptografia do jeito mais fácil](https://labs.eye.security/breaking-encryption-schemes-the-lazy-way/)
{{#include ../../banners/hacktricks-training.md}}

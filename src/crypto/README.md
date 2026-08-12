# Criptografia

{{#include ../banners/hacktricks-training.md}}

Esta seção se concentra em criptografia prática para testes de segurança e CTFs: reconhecer padrões comuns, selecionar ferramentas adequadas e aplicar ataques conhecidos.

Para técnicas que ocultam dados dentro de arquivos, consulte a seção **Stego**.

## Como usar esta seção

Comece identificando a primitiva e seus parâmetros. Em seguida, determine o que o atacante controla ou observa, como uma oracle, um valor leaked ou a reutilização de um nonce, antes de selecionar um ataque.

### Fluxo de trabalho de CTF

{{#ref}}
ctf-workflow/README.md
{{#endref}}

### Criptografia simétrica

{{#ref}}
symmetric/README.md
{{#endref}}

### Hashes, MACs e KDFs

{{#ref}}
hashes/README.md
{{#endref}}

### Criptografia de chave pública

{{#ref}}
public-key/README.md
{{#endref}}

### TLS e certificados

{{#ref}}
tls-and-certificates/README.md
{{#endref}}

### Criptografia em malware

{{#ref}}
crypto-in-malware/README.md
{{#endref}}

### Diversos

{{#ref}}
ctf-misc/README.md
{{#endref}}

## Configuração rápida

Crie um ambiente Python isolado e instale os pacotes normalmente utilizados. A documentação do PyCryptodome recomenda instalar `pycryptodome` com `pip`; o SageMath fornece instruções de instalação separadas para cada plataforma compatível.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pycryptodome gmpy2 sympy pwntools
```
SageMath costuma ser útil para cálculos algébricos, de lattice, RSA e de curvas elípticas.<sup>[[2]](#references)</sup>

## References

- [1] [Documentação do PyCryptodome - Instalação](https://www.pycryptodome.org/src/installation)
- [2] [Documentação do SageMath - Guia de instalação](https://doc.sagemath.org/html/en/installation/)
{{#include ../banners/hacktricks-training.md}}

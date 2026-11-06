# Crypto CTF Misc

{{#include ../../banners/hacktricks-training.md}}

Esta seção reúne técnicas que aparecem em desafios de criptografia, mas não se encaixam perfeitamente nas outras categorias.

## Linguagens esotéricas

### Técnica

Use este fluxo de trabalho quando um desafio exigir a execução de um programa em uma linguagem esotérica e a decodificação de sua saída.

Se um desafio fornecer código que não parece pertencer a uma linguagem padrão:

- Identifique a linguagem pesquisando um token ou uma sequência de instruções distinta.
- Use um interpretador online ou uma imagem Docker.
- Se a saída for estranha, procure camadas de codificação ou compactação aplicadas após a execução.

Um índice útil de linguagens é a wiki Esolang.<sup>[[1]](#references)</sup> Para camadas comuns de codificação e compactação, use o [fluxo de trabalho de Crypto CTF](../ctf-workflow/). Se a pista for texto invisível, e não sintaxe executável, consulte [esteganografia de texto](../../stego/text/).

### Exfiltrando o estado pré-carregado do interpretador

Se um desafio aceitar código-fonte de uma linguagem esotérica e executá-lo em um **interpretador personalizado**, inspecione a memória inicial, a pilha e as instruções de saída antes de tratar o código-fonte como um enigma de decodificação. Quando o interpretador pré-carrega um segredo em uma pilha Befunge, um programa curto pode remover e imprimir os bytes existentes sem calculá-los. Isso exige controle sobre o código-fonte executado e um opcode de saída; não funciona em um interpretador normal com a pilha vazia. Em um desafio Befunge, a entrada abaixo emitia repetidamente caracteres de uma flag pré-carregada na pilha em ordem inversa.<sup>[[2]](#references)[[3]](#references)</sup>

```befunge
>,<
```

`>` inicia a execução para a direita, `,` remove e imprime um caractere, e `<` envia o ponteiro de instruções de volta para `,`. Verifique o comportamento do interpretador personalizado quando ocorre underflow e ao atingir o limite de instruções: a implementação citada para quando a pilha se esgota ou após 1.024 instruções. Se o segredo não estiver diretamente na pilha, inspecione outros estados inicializados e as instruções de saída/leitura disponíveis, em vez de presumir a semântica padrão do Befunge.<sup>[[3]](#references)[[4]](#references)</sup>



## References

- [1] [Esolang, wiki das linguagens de programação esotéricas](https://esolangs.org/wiki/Main_Page)
- [2] [Writeup original de WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/README.md)
- [3] [Código-fonte do interpretador de WolvCTF 2024 Befuddled1](https://github.com/C0d3-Bre4k3rs/WolvCTF2024-Writeups/blob/main/befuddled1/files/befunge.py)
- [4] [Referência da linguagem Befunge](https://esolangs.org/wiki/Befunge)
{{#include ../../banners/hacktricks-training.md}}

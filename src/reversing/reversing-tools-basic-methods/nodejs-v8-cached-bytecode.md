# Desofuscação estática de bytecode em cache do Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Os dados em cache do V8 são uma **representação com perdas e dependente da versão**, não código-fonte JavaScript nem um executável nativo convencional. Portanto, um fluxo de trabalho estático útil é: remover qualquer empacotamento externo, desmontar o cache com a build correspondente do V8, convertê-lo em um modelo de pseudocódigo intermediário e aplicar transformações que considerem as dependências sem executar a amostra. [View8](https://github.com/suleram/View8) e [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementam essa abordagem para payloads do Node.js protegidos por `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Obter e desmontar o cache

Primeiro, inspecione o preload/launcher em vez de presumir que todos os arquivos `.jsc` têm o mesmo wrapper. Por exemplo, um launcher como `node.exe -r preflight.js app.jsc` executa `preflight.js` antes do módulo principal; na família analisada, o preload removia uma camada Brotli. Após descompactar, identifique a geração exata do Node.js/V8 com base no runtime incluído. Um cache produzido por uma versão do V8 pode ser rejeitado ou decodificado incorretamente por outra; portanto, compile ou obtenha um `v8dasm` para a tag exata do V8 e aplique os patches necessários do View8 e de impressão de strings.<sup>[[1]](#references)[[2]](#references)</sup>

O fluxo de trabalho do toolkit, que não executa o código, é:<sup>[[2]](#references)</sup>

```bash
brotli -d app.jsc -o app.decompressed.jsc
/path/to/matching-v8dasm app.decompressed.jsc > app.jsc.disasm.txt
mkdir -p decompiled deobfuscated
python3 View8/view8.py --input_format disassembled \
  --inp app.jsc.disasm.txt --normalize \
  --out decompiled/app.dec.txt \
  --export_format decompiled serialized
python3 deobf_all.py --inp decompiled/app.dec.pkl \
  --out deobfuscated/app.deobf.txt \
  --export_format decompiled serialized
```

`--normalize` fornece identificadores estáveis às funções geradas entre execuções. A saída em texto serve para inspeção; o grafo de objetos serializado permite que passes independentes preservem as relações entre funções, declaradores, escopos e metadados. **Ele não é JavaScript reconstruído nem executável**.<sup>[[1]](#references)[[2]](#references)</sup>

### Fazer triagem de um cache sem compilar o V8

Para um cache bruto ou encapsulado em Brotli, `jscd` pode identificar o cabeçalho e enumerar constantes e funções sem carregar a amostra no Node.js. Use-o primeiro para verificar se as tabelas de versões são compatíveis com o arquivo e priorizar funções antes dos passes mais especializados de desofuscação do View8.<sup>[[4]](#references)</sup>

O hash da versão é uma pista de identificação, não uma prova de que um disassembler autônomo tenha os mesmos flags ou o mesmo snapshot somente leitura do produtor.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
jscd info app.jsc
jscd strings app.jsc > app.strings.txt
jscd functions app.jsc > app.functions.txt
jscd disasm app.jsc > app.jsc.disasm.txt
```

`jscd disasm` gera uma listagem compatível com View8, então o comando View8 acima pode usar essa saída em vez de `v8dasm` quando o cache for compatível. Inspecione as strings junto com a árvore de funções para localizar chamadas do decoder e prováveis pontos de entrada; não trate a saída aproximada de JavaScript do `jscd` como o código-fonte original. Se a ferramenta rejeitar a versão ou deixar placeholders de heap somente para leitura, use uma build correspondente do V8 ou forneça um mapa de nomes da mesma build, em vez de adivinhar nomes de propriedades.<sup>[[4]](#references)</sup>

Para um cache dentro de um aplicativo Electron, primeiro [extraia o ASAR e inspecione os pontos de entrada main e preload](../../network-services-pentesting/pentesting-web/electron-desktop-apps/). Os caches do Electron e do Node podem diferir no layout de snapshot e de compressão de ponteiros, mesmo quando as strings de versão do V8 coincidem.<sup>[[4]](#references)</sup>

### Leia o pseudocódigo do View8 como uma IR

Os nomes típicos são `func_<name>_0x<address>`, os argumentos são `a0...aN`, os registradores virtuais são `r0...rN` e `ACCU` é o acumulador do V8. `start` é o declarador raiz, enquanto `Scope[...]`, globais e dicionários modelam valores capturados ou compartilhados por funções aninhadas. Não interprete toda expressão como sintaxe JavaScript: por exemplo, `!r6 === "0"` representa a negação da comparação completa (`r6 !== "0"`) no View8, o que é importante ao reconstruir branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Desofuscação com reconhecimento de dependências

Aplique as transformações em uma ordem que exponha as entradas necessárias para a próxima etapa e repita a propagação até que a saída se estabilize. Uma ordem prática é:<sup>[[1]](#references)[[2]](#references)</sup>

1. Percorra a hierarquia de declaradores e propague valores de globais, registradores, dicionários e referências `Scope[...]`.
2. Recupere os argumentos do decoder de strings e substitua as chamadas criptografadas pelo texto simples.
3. Combine chunks de strings adjacentes; os nomes de propriedades e as strings de ordem do dispatcher resultantes liberam as etapas posteriores.
4. Desfaça o achatamento do fluxo de controle, incorpore proxies de chamadas e wrappers de operações atômicas, e resolva referências a funções armazenadas em dicionários.
5. Propague novamente, pois cada string, chave ou proxy resolvido pode revelar outra camada de indireção.
6. Reduza thunks de inicialização de execução única reconhecidos e remova helpers mortos somente depois que seus pontos de chamada forem resolvidos.

### Recupere arrays de strings RC4 com deslocamento como uma caixa-preta

Um layout comum do `javascript-obfuscator` armazena chunks RC4 codificados em Base64 em um único array. Wrappers do decoder fornecem um deslocamento numérico e uma chave curta, às vezes com os argumentos invertidos, e então somam ou subtraem constantes capturadas em escopos de closure. Quando o decoder raiz está muito ofuscado, recupere empiricamente o deslocamento desconhecido do índice do array, em vez de reconstruir a função inteira.<sup>[[1]](#references)</sup>

Para um array com `N` chunks e várias chamadas ao mesmo decoder:<sup>[[1]](#references)</sup>

```text
for each observed (numeric_argument, rc4_key):
    candidates = {}
    for shift in 0 .. N-1:
        index = apply_observed_sign(numeric_argument, shift)
        plaintext = RC4(Base64Decode(chunks[index]), rc4_key)
        if plaintext passes encoding/printability checks:
            candidates.add(shift)
root_shift = intersection(candidate_sets)
```

Não aceite um deslocamento com base em uma única descriptografia imprimível: o ciphertext incorreto pode parecer imprimível por acaso. Use pelo menos três observações distintas e aceite apenas um deslocamento único que produza texto plausível em todas elas. Em seguida, percorra o grafo de wrappers/declarers, acumulando cada adição ou subtração e registrando se o argumento numérico vem primeiro. Armazene esses metadados em cache por amostra, substitua as chamadas do decoder, concatene trechos de texto simples adjacentes e exporte strings separadamente para triagem.<sup>[[1]](#references)[[2]](#references)</sup>

### Preserve a semântica ao desfazer o flattening

Para loops de dispatcher controlados por strings como `3|2|1|0|4`, decodifique a string de ordem, mapeie cada comparação de estado para seu bloco, leve em conta a notação de condição negada do View8 e, em seguida, emita os blocos na ordem do dispatcher. Um `continue` aninhado pode representar um salto antecipado de volta ao dispatcher, em vez de um fluxo sequencial comum. Ao remover o loop, exclua esse `continue` e mova as instruções que originalmente vinham depois do `if` que o contém para um bloco `else` gerado; simplesmente excluir o dispatcher altera o comportamento.<sup>[[1]](#references)</sup>

### Incorporar proxies, operações e thunks lazy

Normalize helpers de encaminhamento como `return a0(a1, a2)` antes de substituir seus call sites por chamadas diretas. Trate wrappers para subtração, divisão, comparação, testes de pertinência ou invocação da mesma forma. Como a referência do helper pode estar armazenada atrás de uma chave de dicionário descriptografada ou de um valor de closure, execute a propagação de strings e estruturas antes e depois da incorporação.<sup>[[1]](#references)</sup>

Reconheça também closures que invocam uma função armazenada uma vez, limpam sua referência, armazenam o resultado em cache e retornam esse cache em chamadas posteriores. Reduzir esse thunk no local de inicialização expõe o dispatcher ou a função de capability subjacente, mas anote que a execução original era **one-shot e armazenada em cache**, em vez de modelar cada chamada como uma invocação nova.<sup>[[1]](#references)</sup>

## Observações de segurança e validação

- O carregamento de `pickle` em Python pode executar código. Carregue apenas arquivos `.pkl` gerados localmente pela execução confiável do View8; nunca trate um pickle fornecido pela amostra como dados.<sup>[[2]](#references)</sup>
- A ausência do corpo de uma função não prova que a fonte não continha essa função: o V8 pode serializar uma função lazy como metadados até que ela seja compilada na primeira chamada. Mantenha essas funções marcadas como não resolvidas durante a triagem estática.<sup>[[6]](#references)</sup>
- Passes orientados por padrões não são um decompiler geral de JavaScript. Preserve expressões não resolvidas e inspecione manualmente variantes ambíguas do dispatcher, em vez de forçar uma reescrita.<sup>[[1]](#references)[[2]](#references)</sup>
- Nomes de funções sugeridos com auxílio de LLM são dicas de navegação, não evidências. Processe as dependências começando pelas folhas, se for usá-los, mas verifique cada rótulo com base no corpo, nos argumentos, nas strings, no fluxo de dados, nas APIs e nos efeitos colaterais.<sup>[[1]](#references)[[2]](#references)</sup>



## References

- [1] [Quebrando o selo: desofuscação estática do bytecode V8 compilado do JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
- [4] [ejfkdev/jscd](https://github.com/ejfkdev/jscd)
- [5] [Cabeçalho V8 SerializedCodeData](https://chromium.googlesource.com/v8/v8/+/main/src/snapshot/code-serializer.h)
- [6] [Cache de código de vm.Script do Node.js](https://nodejs.org/api/vm.html#scriptcreatecacheddata)
{{#include ../../banners/hacktricks-training.md}}

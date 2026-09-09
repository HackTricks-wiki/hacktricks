# Desofuscação Estática de Bytecode em Cache do Node.js/V8

{{#include ../../banners/hacktricks-training.md}}

Os dados em cache do V8 são uma **representação dependente da versão e com perda**, não código-fonte JavaScript nem um executável nativo convencional. Portanto, um workflow estático útil é: remover qualquer empacotamento externo, desmontar o cache com a build correspondente do V8, elevá-lo a um modelo de pseudocódigo intermediário e aplicar transformações cientes de dependências sem executar o sample. [View8](https://github.com/suleram/View8) e [jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator) implementam essa abordagem para payloads do Node.js protegidos pelo `javascript-obfuscator`.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## Obter e desmontar o cache

Primeiro, inspecione o preload/launcher em vez de presumir que todo arquivo `.jsc` tenha o mesmo wrapper. Por exemplo, um launcher como `node.exe -r preflight.js app.jsc` executa `preflight.js` antes do módulo principal; na família analisada, o preload removia uma camada Brotli. Após o unpacking, identifique a geração exata do Node.js/V8 a partir do runtime incluído. Um cache produzido por uma versão do V8 pode ser rejeitado ou decodificado incorretamente por outra; portanto, compile ou obtenha um `v8dasm` para essa tag exata do V8 e aplique os patches necessários do View8 e de impressão de strings.<sup>[[1]](#references)[[2]](#references)</sup>

O workflow sem execução do toolkit é:<sup>[[2]](#references)</sup>
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
`--normalize` fornece identificadores estáveis às funções geradas entre diferentes execuções. A saída textual serve para inspeção; o grafo de objetos serializado permite que passes independentes preservem os relacionamentos entre funções, declaradores, escopos e metadados. Ele **não é JavaScript reconstruído nem executável**.<sup>[[1]](#references)[[2]](#references)</sup>

### Ler o pseudocódigo do View8 como uma IR

Os nomes típicos são `func_<name>_0x<address>`, os argumentos são `a0...aN`, os registradores virtuais são `r0...rN`, e `ACCU` é o acumulador do V8. `start` é o declarador raiz, enquanto `Scope[...]`, globais e dicionários representam valores capturados ou compartilhados por funções aninhadas. Não analise cada expressão como sintaxe JavaScript: por exemplo, `!r6 === "0"` do View8 representa a negação da comparação completa (`r6 !== "0"`), o que é importante ao reconstruir branches.<sup>[[1]](#references)[[3]](#references)</sup>

## Deobfuscation ciente de dependências

Aplique as transformações em uma ordem que exponha as entradas necessárias ao próximo pass e repita a propagação até que a saída se estabilize. Uma ordem prática é:<sup>[[1]](#references)[[2]](#references)</sup>

1. Percorra a hierarquia de declaradores e propague valores de globais, registradores, dicionários e referências `Scope[...]`.
2. Recupere os argumentos dos decoders de strings e substitua as chamadas criptografadas pelo texto claro.
3. Una chunks de strings adjacentes; os nomes de propriedades e as strings de ordem do dispatcher resultantes desbloqueiam os passes posteriores.
4. Desfaça o flattening do control flow, faça inline de call proxies e wrappers de operações atômicas e resolva referências a funções armazenadas em dicionários.
5. Propague novamente, pois cada string, chave ou proxy resolvido pode expor outra camada de indireção.
6. Colapse thunks de inicialização de execução única reconhecidos e remova helpers mortos somente depois que seus call sites forem resolvidos.

### Recupere arrays de strings RC4 deslocados como uma black box

Um layout comum do `javascript-obfuscator` armazena chunks RC4 codificados em Base64 em um único array. Wrappers de decoder fornecem um offset numérico e uma chave curta, às vezes com a ordem dos argumentos invertida, e depois adicionam ou subtraem constantes capturadas em escopos de closure. Quando o decoder raiz está fortemente obfuscado, recupere empiricamente o deslocamento desconhecido do índice do array em vez de reconstruir a função inteira.<sup>[[1]](#references)</sup>

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
Não aceite um shift a partir de uma única descriptografia imprimível: o ciphertext incorreto pode parecer imprimível por acaso. Use pelo menos três observações distintas e aceite apenas um shift único que produza texto plausível em todas elas. Em seguida, percorra o grafo de wrappers/declarers, acumulando cada adição ou subtração e registrando se o argumento numérico vem primeiro. Armazene esses metadados em cache por sample, substitua as chamadas do decoder, concatene chunks de plaintext adjacentes e exporte as strings separadamente para triage.<sup>[[1]](#references)[[2]](#references)</sup>

### Preserve a semântica ao desfazer o flattening

Para loops de dispatcher orientados por strings como `3|2|1|0|4`, decodifique a string de ordem, associe cada comparação de estado ao seu bloco, leve em conta a notação de condição negada do View8 e então emita os blocos na ordem do dispatcher. Um `continue` aninhado pode representar um salto antecipado de volta ao dispatcher, em vez de um fall-through comum. Ao remover o loop, exclua esse `continue` e mova as instruções que originalmente seguiam o `if` que o englobava para um branch `else` gerado; simplesmente excluir o dispatcher altera o comportamento.<sup>[[1]](#references)</sup>

### Faça inline de proxies, operações e thunks lazy

Normalize helpers de forwarding, como `return a0(a1, a2)`, antes de substituir seus call sites por chamadas diretas. Trate wrappers de subtração, divisão, comparação, testes de membership ou invocation de forma semelhante. Como a referência ao helper pode estar armazenada por trás de uma chave de dicionário descriptografada ou de um valor de closure, execute a propagação de strings e estruturas antes e depois do inlining.<sup>[[1]](#references)</sup>

Reconheça também closures que invocam uma função armazenada uma vez, limpam sua referência, armazenam o resultado em cache e retornam esse cache em chamadas posteriores. Colapsar esse thunk em um ponto de inicialização expõe o dispatcher ou a função de capability subjacente, mas anote que a execução original era **one-shot e armazenada em cache**, em vez de modelar cada chamada como uma nova invocation.<sup>[[1]](#references)</sup>

## Notas de segurança e validação

- O carregamento de `pickle` do Python pode executar código. Carregue apenas arquivos `.pkl` gerados localmente pela execução confiável do View8; nunca trate um pickle fornecido pelo sample como dados.<sup>[[2]](#references)</sup>
- Passes orientados por patterns não são um decompiler geral de JavaScript. Preserve expressões não resolvidas e inspecione manualmente variantes ambíguas de dispatchers, em vez de forçar uma reescrita.<sup>[[1]](#references)[[2]](#references)</sup>
- Nomes de funções auxiliados por LLM são apenas dicas de navegação, não evidências. Processe as dependências leaf-first se usá-los, mas verifique cada label em relação ao corpo, argumentos, strings, fluxo de dados, APIs e efeitos colaterais.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Quebrando o selo: desofuscação estática do bytecode V8 compilado do JSCeal](https://research.checkpoint.com/2026/breaking-the-seal-static-deobfuscation-of-jsceals-compiled-v8-bytecode)
- [2] [hasherezade/jsc_deobfuscator](https://github.com/hasherezade/jsc_deobfuscator)
- [3] [suleram/View8](https://github.com/suleram/View8)
{{#include ../../banners/hacktricks-training.md}}

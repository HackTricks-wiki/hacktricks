# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos básicos

- **Contratos inteligentes** são programas que são executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações descentralizadas (dApps)** são construídas sobre contratos inteligentes e contam com um front-end fácil de usar e um back-end transparente e auditável.
- **Tokens e moedas** se diferenciam pelo fato de as moedas servirem como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
  - **Tokens de utilidade** concedem acesso a serviços, e **tokens de segurança** representam a propriedade de ativos.
- **DeFi** significa finanças descentralizadas e oferece serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de exchanges descentralizadas e organizações autônomas descentralizadas.

## Mecanismos de consenso

Os mecanismos de consenso garantem a validação segura e acordada das transações na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores detenham uma determinada quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.<sup>[[1]](#references)</sup>

## Noções essenciais sobre Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. Elas são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes principais:

- **Transações com múltiplas assinaturas** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **entradas** (origem dos fundos), **saídas** (destino), **taxas** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Busca melhorar a escalabilidade do Bitcoin permitindo várias transações dentro de um canal e transmitindo à blockchain apenas o estado final.

## Preocupações com a privacidade do Bitcoin

Ataques à privacidade, como **Propriedade de Entradas Comuns** e **Detecção de Endereço de Troco de UTXO**, exploram padrões de transação. Estratégias como **mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Obtendo bitcoins anonimamente

Os métodos incluem transações em dinheiro, mineração e uso de mixers. **CoinJoin** combina várias transações para dificultar o rastreamento, enquanto **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos ataques à privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários costumam ser motivo de preocupação. Veja uma visão geral simplificada de alguns métodos comuns pelos quais atacantes podem comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Suposição de Propriedade de Entradas Comuns**

Em geral, é raro combinar entradas de usuários diferentes em uma única transação devido à complexidade envolvida. Por isso, **costuma-se presumir que dois endereços de entrada na mesma transação pertencem ao mesmo proprietário**.

## **Detecção de Endereço de Troco de UTXO**

Uma UTXO, ou **saída de transação não gasta**, precisa ser gasta por completo em uma transação. Se apenas uma parte dela for enviada para outro endereço, o restante vai para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo sua privacidade.

### Exemplo

Para reduzir esse risco, serviços de mistura ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em redes sociais e fóruns**

Às vezes, os usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Análise de grafo de transações**

As transações podem ser visualizadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Heurística de entrada desnecessária (heurística de troco ideal)**

Essa heurística se baseia na análise de transações com várias entradas e saídas para tentar adivinhar qual saída é o troco que retorna ao remetente.

### Exemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se adicionar mais entradas fizer com que o output de troco seja maior do que qualquer entrada individual, isso pode confundir a heurística.

## **Reutilização Forçada de Endereços**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, na esperança de que o destinatário as combine com outras entradas em transações futuras, vinculando assim os endereços entre si.

### Comportamento Correto da Wallet

As wallets devem evitar usar moedas recebidas em endereços já usados e vazios para impedir esse leak de privacidade.

## **Outras Técnicas de Análise de Blockchain**

- **Valores Exatos de Pagamento:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Números Redondos:** Um número redondo em uma transação sugere que se trata de um pagamento; o output com valor não redondo provavelmente é o troco.
- **Fingerprinting de Wallet:** Diferentes wallets têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de troco.
- **Correlações de Valor e Horário:** A divulgação dos horários ou valores das transações pode torná-las rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente válido se uma entidade operar muitos nós Bitcoin, ampliando sua capacidade de monitorar transações.

## Mais

Para obter uma lista abrangente de ataques e defesas relacionados à privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Anônimas de Bitcoin

## Maneiras de Obter Bitcoins Anonimamente

- **Transações em Dinheiro:** Obter bitcoin por meio de dinheiro em espécie.
- **Alternativas ao Dinheiro:** Comprar cartões-presente e trocá-los online por bitcoin.
- **Mineração:** A maneira mais privada de ganhar bitcoins é por meio da mineração, especialmente quando feita individualmente, pois os mining pools podem conhecer o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo:** Teoricamente, roubar bitcoin poderia ser outra maneira de obtê-lo anonimamente, embora isso seja ilegal e não recomendado.

## Serviços de Mixing

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e receber **outros bitcoins em troca**, dificultando o rastreamento do proprietário original. No entanto, isso exige confiar que o serviço não mantenha logs e realmente devolva os bitcoins. As opções alternativas de mixing incluem os cassinos de Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de diferentes usuários em uma só, complicando o processo para quem tenta associar entradas a outputs. Apesar de eficaz, transações com quantidades únicas de entradas e outputs ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart contracts do Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação comum, sem os outputs iguais característicos do CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade de entradas comuns usada por entidades de vigilância de transações.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transações como a acima poderiam ser PayJoin, aumentando a privacidade e permanecendo indistinguíveis das transações padrão de bitcoin.

**O uso de PayJoin poderia prejudicar significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca pela privacidade transacional.

# Práticas recomendadas para privacidade em criptomoedas

## **Técnicas de sincronização de carteiras**

Para manter a privacidade e a segurança, é crucial sincronizar as carteiras com a blockchain. Dois métodos se destacam:

- **Nó completo**: Ao baixar toda a blockchain, um nó completo garante o máximo de privacidade. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário tem interesse.
- **Filtragem de blocos no lado do cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem expor interesses específicos aos observadores da rede. Carteiras leves baixam esses filtros e buscam blocos completos somente quando há uma correspondência com os endereços do usuário.

## **Usando Tor para anonimato**

Como Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Evitando a reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço em cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para a privacidade das transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, frustrando ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem outputs de troco aumenta a privacidade ao dificultar os métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se não for possível evitar o troco, gerar vários outputs de troco ainda pode melhorar a privacidade.

# **Monero: um símbolo de anonimato**

Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: Gas e transações**

## **Entendendo Gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum e é precificado em **gwei**. Por exemplo, uma transação que custa 2,310,000 gwei (ou 0.00231 ETH) envolve um limite de gas e uma taxa base, além de uma taxa de prioridade para incentivar sua inclusão por um validador. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais, com o excedente sendo reembolsado.<sup>[[5]](#references)</sup>

## **Executando transações**

As transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de smart contract. Elas exigem uma taxa e precisam ser incluídas em um bloco. As informações essenciais de uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Vale notar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para quem deseja interagir com criptomoedas priorizando a privacidade e a segurança.

## Red Teaming de Web3 centrado em valor

- Faça o inventário dos componentes que movimentam valor (signers, oracles, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas MITRE AADAPT relevantes a fim de expor caminhos de escalonamento de privilégios.
- Ensaie cadeias de ataque com flash-loan/oracle/credenciais/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura de Web3

- A adulteração da supply chain das interfaces de carteiras pode alterar payloads EIP-712 logo antes da assinatura, obtendo assinaturas válidas para takeover de proxy baseado em delegatecall (por exemplo, sobrescrita de slot-0 de masterCopy do Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Modos comuns de falha em smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas sem assinatura, validação com estado, replay de ERC-1271 e drenagem de taxas via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Testes de mutação para encontrar pontos cegos em suítes de testes:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de ZK Proof / zkVM Guest

Quando um prover usa uma **zkVM** ou um circuito de proof específico da aplicação para atestar uma afirmação, o verificador só aprende que o **programa guest foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma proof que seja validada enquanto as **métricas públicas ou o invariante alegado são falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura dentro de proof guests

- Trate os bytes de witness/circuit privados como **entrada não confiável controlada por um atacante**, mesmo que estejam ocultos pela proof.
- Evite desserializá-los com helpers sem verificação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados fora de banda.
- Discriminantes de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

If um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` subsequente sobre esse valor se torna suspeito.

### Jump-table / UB counter bypass

Se Rust converter um `match` grande em uma **jump table**, um discriminante de enum inválido pode produzir **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo indexa além da primeira jump table e chega a código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que relatam métricas impossíveis, como menos gates, menos operações dispendiosas ou outros recursos limitados falsificados.

Lista de verificação:

- Procure enums controlados pelo atacante e desserializados a partir de entradas witness/privadas.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Trate a combinação de `unsafe` + desserialização sem verificações + despacho de opcode amplo como de alto risco.
- Faça engenharia reversa do binário gerado quando necessário; o layout da jump table pode ser mais importante do que o código-fonte.

### Restrições semânticas ausentes em interpretadores reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para conjuntos de instruções reversíveis/semelhantes à computação quântica, garanta que os operandos que precisam ser distintos sejam realmente restringidos para serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```

torna-se inseguro se o guest não rejeitar:

```text
op.q_control1 == op.q_control2 == op.q_target
```

Nesse caso, a transição se reduz a:

```text
q = q ^ (q & q) = 0
```

Isso cria uma **primitiva de reset determinística**, quebrando as suposições de reversibilidade e possibilitando cálculos não intencionais mais baratos. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam verificações funcionais enquanto contornam o modelo de custos que o verificador acredita estar sendo aplicado.

### Dados de advice sub-restritos do prover e aritmética modular

Os valores carregados de uma **pilha de advice/witness são controlados pelo prover**, mesmo quando descritos como quocientes, restos, inversos ou dicas pré-computados. Uma prova apenas estabelece que o witness satisfaz as restrições implementadas; ela não estabelece que o cálculo pretendido foi realizado se essas restrições omitirem uma verificação de tipo, intervalo ou forma canônica.<sup>[[13]](#references)</sup>

Para uma redução ou função auxiliar de divisão euclidiana, audite a relação inteira completa, e não apenas a subtração ou multiplicação final. Cada limb de `q` e `r` deve ser restringido à largura declarada, a reconstrução `x = q * m + r` deve ser válida na representação inteira pretendida, e o limite canônico `0 <= r < m` deve ser imposto. Valide um valor **antes** de passá-lo a uma instrução mais estreita `u32`/`u64`; uma operação de largura menor não prova retroativamente que o elemento original do campo ou o valor de múltiplos limbs tinha o tipo esperado.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

A falha `mod_12289` no Miden ilustra o padrão de exploit: o quociente era verificado como um valor de 64 bits em dois limbs, mas o resto fornecido por advice chegava a `u32overflowing_sub` sem validação equivalente. Um prover malicioso poderia coordenar valores inválidos de quociente e resto para que as constraints de subtração implementadas continuassem satisfeitas, enquanto o procedimento retornava um resto não matemático. Como esse resultado alimentava a verificação Falcon, a falha de soundness poderia ser escalada para forjar assinaturas de autorização, em vez de apenas produzir um resultado aritmético incorreto.<sup>[[13]](#references)</sup>

### Auditoria de VMs criptográficas com pilha implícita

Linguagens baseadas em pilha ocultam operandos; portanto, primeiro eleve as instruções para uma IR em que cada valor consumido e produzido na pilha seja uma expressão com proveniência. Em seguida, um pipeline de análise conservador pode:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construir o grafo de chamadas e inferir os efeitos na pilha de entrada e saída dos procedimentos.
2. Executar simbolicamente as instruções compatíveis e elevar o fluxo de controle para expressões SSA/estruturadas.
3. Propagar fatos abstratos como `Unknown`, `ProvenU32`, `Bool`, proveniência de valores e inicialização local até atingir um ponto fixo.
4. Sinalizar valores derivados de advice que alcancem aritmética tipada ou sinks não nulos sem um sanitizador em **todos** os caminhos de entrada.
5. Comparar as assinaturas declaradas e inferidas e verificar se cada saída preserva os valores da pilha pertencentes ao chamador.

Trate uma assinatura desconhecida ou uma construção não compatível como uma **lacuna de análise**, não como um resultado limpo. Chamadas dinâmicas, loops que não preservam a pilha e branches com efeitos diferentes na pilha podem impossibilitar um rastreamento seguro dos slots da pilha; um decompilador mais seguro rejeita ou marca esses casos, em vez de emitir pseudocódigo plausível, mas incorreto.<sup>[[10]](#references)[[13]](#references)</sup>

Nas junções do fluxo de controle, mantenha uma propriedade apenas quando ela for válida em todos os predecessores (por exemplo, `ProvenU32 join Unknown = Unknown`). Além disso, diferencie a convergência do ponto fixo de atingir um limite de iterações: somente uma sobreaproximação convergida e segura pode justificar tratar a ausência de um diagnóstico como evidência de que todas as execuções representadas satisfazem a propriedade.<sup>[[11]](#references)</sup>

### Use obrigações de prova para revelar pré-condições ocultas

Para conjuntos pequenos de instruções, traduza os procedimentos para um modelo executável de VM formal e prove tanto o resultado quanto a transformação completa da pilha. O teorema deve abranger terminação, entradas tipadas, o prefixo de saída esperado e a preservação da pilha do chamador que não foi alterada. Audite a declaração do teorema com o mesmo cuidado que a prova: o kernel pode validar uma prova de uma afirmação enfraquecida por acidente.<sup>[[12]](#references)[[13]](#references)</sup>

Hipóteses inesperadas são achados úteis. Na revisão do Miden, uma prova de rotação à direita de 64 bits exigiu `shift mod 32 != 0`, revelando um caso de falha para entradas grandes quando o deslocamento era múltiplo de 32; outra prova descobriu que `wrapping_mul` de 256 bits descartava valores da pilha pertencentes ao chamador. Adicione o caso de limite descoberto aos testes e, em seguida, corrija a implementação ou fortaleça deliberadamente a pré-condição pública, em vez de aceitar silenciosamente a hipótese adicional.<sup>[[12]](#references)[[13]](#references)</sup>

### O que testar em sistemas ZK

- Faça fuzzing de todos os parsers do guest com codificações malformadas de witness/entrada privada.
- Assegure a validação do intervalo do enum antes do despacho do opcode.
- Adicione verificações semânticas para aliasing de operandos e outras formas inválidas de instrução.
- Rastreie cada origem de advice/witness até cada sink de aritmética tipada e exija validação em todos os caminhos.<sup>[[11]](#references)[[13]](#references)</sup>
- Teste helpers aritméticos com limbs não canônicos, restos fora do intervalo e contagens de deslocamento nos limites.<sup>[[12]](#references)[[13]](#references)</sup>
- Assegure a altura da pilha e a preservação dos valores abaixo dos argumentos declarados do procedimento em cada retorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Compare os contadores informados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest tiver bugs.

## Autorização Dependente do Estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploração de DeFi/AMM

Se você está pesquisando a exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps amplificados por flash loans que cruzam limites), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados com múltiplos ativos que armazenam em cache saldos virtuais e podem ser envenenados quando `supply == 0`, consulte:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Prova de participação - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chave pública e chave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [O que são transações multisig? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transações | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e taxas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidade - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Superamos a prova de conhecimento zero do Google sobre criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curva elíptica contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório de prova de conceito da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arquitetura do decompilador MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Mecanismo de análise estática MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modelo MASM-to-Lean e provas de correção](https://github.com/trailofbits/masm-lean)
- [13] [Auditoria na era da IA (boa o suficiente)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}

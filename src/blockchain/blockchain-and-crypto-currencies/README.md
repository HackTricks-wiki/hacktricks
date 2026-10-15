# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

Este capítulo aborda conceitos de blockchain e segurança on-chain. Para um peer Bitcoin exposto, comece com [enumeração do serviço Bitcoin P2P](../../network-services-pentesting/8333-18333-38333-18444-pentesting-bitcoin.md); para um frontend de navegador, conexão de carteira ou backend off-chain, use [pentesting de DApp](../../pentesting-web/dapps-DecentralizedApplications.md). Para operações de privacidade de criptomoedas e suas limitações, consulte o [capítulo sobre privacidade de criptomoedas](../../privacy/cryptocurrency-privacy.md).

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que são executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações Descentralizadas (dApps)** são construídas sobre smart contracts e contam com um front-end intuitivo e um back-end transparente e auditável.
- **Tokens e Coins** diferem porque as coins servem como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
  - **Utility Tokens** dão acesso a serviços, e **Security Tokens** representam a propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas e oferece serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de exchange descentralizadas e organizações autônomas descentralizadas.

Para conhecer a terminologia de ordens spot, futuros, alavancagem e opções usada nos mercados de criptomoedas, consulte [Termos de Investimento](investment-terms.md).

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.<sup>[[1]](#references)</sup>

## Noções Essenciais sobre Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes Principais:

- **Transações Multisignature** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin ao permitir várias transações dentro de um canal, transmitindo à blockchain apenas o estado final.

## Questões de Privacidade do Bitcoin

Ataques à privacidade, como **Propriedade Comum de Inputs** e **Detecção de Endereço de Troco UTXO**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Como Obter Bitcoins Anonimamente

Os métodos incluem negociações em dinheiro, mineração e uso de mixers. **CoinJoin** mistura várias transações para dificultar o rastreamento, enquanto **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos Ataques à Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários costumam ser motivo de preocupação. Veja uma visão geral simplificada de alguns métodos comuns pelos quais atacantes podem comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Suposição de Propriedade Comum dos Inputs**

Em geral, é raro que inputs de usuários diferentes sejam combinados em uma única transação, devido à complexidade envolvida. Portanto, **costuma-se presumir que dois endereços de input na mesma transação pertencem ao mesmo proprietário**.

## **Detecção de Endereço de Troco UTXO**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante vai para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar esse risco, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Às vezes, os usuários compartilham seus endereços Bitcoin online, o que facilita **vincular o endereço ao seu proprietário**.

## **Análise do Grafo de Transações**

As transações podem ser visualizadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Heurística de Input Desnecessário (Heurística de Troco Ótimo)**

Essa heurística se baseia na análise de transações com vários inputs e outputs para tentar identificar qual output corresponde ao troco devolvido ao remetente.

### Exemplo

```bash
2 btc --> 4 btc
3 btc     1 btc
```

Se a adição de mais inputs fizer com que o troco seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Reutilização Forçada de Endereços**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, na esperança de que o destinatário os combine com outros inputs em transações futuras, vinculando assim os endereços.

### Comportamento Correto da Wallet

As wallets devem evitar usar moedas recebidas em endereços já usados e vazios para impedir esse leak de privacidade.

## **Outras Técnicas de Análise de Blockchain**

- **Valores de Pagamento Exatos:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Números Redondos:** Um número redondo em uma transação sugere que se trata de um pagamento, e que o output não redondo provavelmente é o troco.
- **Fingerprinting de Wallets:** Wallets diferentes têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de troco.
- **Correlações de Valores e Horários:** A divulgação dos horários ou valores das transações pode torná-las rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente verdadeiro se uma entidade operar muitos nós de Bitcoin, ampliando sua capacidade de monitorar transações.

## Mais

Para uma lista abrangente de ataques à privacidade e defesas, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Anônimas de Bitcoin

## Maneiras de Obter Bitcoins Anonimamente

- **Transações em Dinheiro:** Obter bitcoin usando dinheiro em espécie.
- **Alternativas ao Dinheiro:** Comprar cartões-presente e trocá-los por bitcoin online.
- **Mineração:** O método mais privado para ganhar bitcoins é a mineração, especialmente quando feita individualmente, pois os mining pools podem conhecer o endereço IP do minerador. [Informações sobre Mining Pools](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo:** Teoricamente, roubar bitcoin poderia ser outra forma de obtê-lo anonimamente, embora seja ilegal e não recomendado.

## Serviços de Mixing

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e receber **outros bitcoins em troca**, o que dificulta rastrear o proprietário original. No entanto, isso exige confiar que o serviço não manterá logs e realmente devolverá os bitcoins. As opções alternativas de mixing incluem casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de diferentes usuários em uma só, dificultando o processo de correspondência entre inputs e outputs. Apesar de sua eficácia, transações com valores exclusivos de inputs e outputs ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart contracts do Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, o **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação comum, sem os outputs iguais característicos do CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade comum dos inputs usada por entidades que monitoram transações.

```plaintext
2 btc --> 3 btc
5 btc     4 btc
```

Transações como a mencionada acima poderiam ser PayJoin, aumentando a privacidade e permanecendo indistinguíveis de transações padrão de bitcoin.

**O uso de PayJoin poderia atrapalhar significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca pela privacidade das transações.

# Melhores práticas para a privacidade em criptomoedas

## **Técnicas de sincronização de carteiras**

Para manter a privacidade e a segurança, é crucial sincronizar as carteiras com a blockchain. Dois métodos se destacam:

- **Nó completo**: Ao baixar toda a blockchain, um nó completo garante privacidade máxima. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário tem interesse.
- **Filtragem de blocos no lado do cliente**: Esse método consiste em criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem revelar interesses específicos aos observadores da rede. Carteiras leves baixam esses filtros e só obtêm os blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilização do Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar o Tor para mascarar seu endereço IP e aumentar a privacidade ao interagir com a rede.

## **Como evitar a reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço em cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. As carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para a privacidade das transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, frustrando ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem saídas de troco aumenta a privacidade ao dificultar os métodos de detecção de troco.
- **Múltiplas saídas de troco**: Se não for possível evitar o troco, gerar várias saídas de troco ainda pode melhorar a privacidade.

# **Monero: um farol de anonimato**

Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: gas e transações**

## **Entendendo o gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum e é cotado em **gwei**. Por exemplo, uma transação que custa 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, além de uma taxa de prioridade para incentivar os validadores a incluí-la. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais; o excedente é reembolsado.<sup>[[5]](#references)</sup>

## **Executando transações**

As transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuários ou de smart contracts. Elas exigem uma taxa e precisam ser incluídas em um bloco. As informações essenciais de uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Vale notar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para quem deseja usar criptomoedas priorizando a privacidade e a segurança.

## Red Teaming Web3 centrado em valor

- Faça o inventário dos componentes que controlam valor (signatários, oráculos, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas MITRE AADAPT relevantes a fim de revelar caminhos de escalonamento de privilégios.
- Simule cadeias de ataque de flash-loan/oracle/credenciais/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura Web3

- A adulteração da supply chain de interfaces de carteiras pode modificar payloads EIP-712 imediatamente antes da assinatura, coletando assinaturas válidas para takeover de proxies baseado em delegatecall (por exemplo, overwrite do slot-0 de Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Abstração de contas (ERC-4337)

- Modos comuns de falha em smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas sem assinatura, validação com estado, replay de ERC-1271 e drenagem de taxas por meio de revert após a validação.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Testagem de mutação para encontrar pontos cegos nos conjuntos de testes:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de provas ZK / guests de zkVM

Quando um prover usa uma **zkVM** ou um circuito de prova específico da aplicação para atestar uma afirmação, o verificador só fica sabendo que o **programa guest foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma prova que seja verificada mesmo que as **métricas públicas ou o invariante alegado sejam falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura dentro de guests de provas

- Trate os bytes de witness/circuito privados como **entrada não confiável controlada por um atacante**, mesmo que estejam ocultos pela prova.
- Evite desserializá-los com funções auxiliares sem validação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados fora de banda.
- Discriminantes de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:

```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
    rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```

Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` subsequente nesse valor se torna suspeito.

### Bypass de contador via jump table / UB

Se Rust compilar um `match` grande como uma **jump table**, um discriminante de enum inválido pode gerar **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo acessa uma posição além da primeira jump table e chega ao código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que relatam métricas impossíveis, como menos gates, menos operações custosas ou outros recursos limitados falsificados.

Lista de verificação para revisão:

- Procure enums controlados pelo atacante, desserializados de witness/entrada privada.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Considere `unsafe` + desserialização sem validação + despacho de opcode grande uma combinação de alto risco.
- Faça engenharia reversa do binário emitido quando necessário; o layout da jump table pode ser mais importante do que o código-fonte.

### Restrições semânticas ausentes em interpretadores reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para conjuntos de instruções reversíveis/semelhantes a quânticos, garanta que os operandos que precisam ser distintos sejam realmente restringidos a serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>

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

Isso cria uma **primitiva de reinicialização determinística**, quebrando as suposições de reversibilidade e permitindo computações não intencionais mais baratas. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam verificações funcionais enquanto contornam o modelo de custos que o verificador acredita estar sendo aplicado.

### Dicas do prover sub-restringidas e aritmética modular

Os valores carregados de uma **pilha de advice/witness** são controlados pelo prover, mesmo quando são descritos como quocientes, restos, inversos ou dicas pré-computados. Uma prova apenas estabelece que o witness satisfaz as restrições implementadas; ela não estabelece que a computação pretendida foi realizada se essas restrições omitirem uma verificação de tipo, intervalo ou forma canônica.<sup>[[13]](#references)</sup>

Para um helper de redução ou divisão euclidiana, audite a relação inteira completa, não apenas a subtração ou multiplicação final. Cada limb de `q` e `r` deve ser restringido à largura declarada, a reconstrução `x = q * m + r` deve ser válida na representação inteira pretendida, e o limite canônico `0 <= r < m` deve ser imposto. Valide um valor **antes** de passá-lo a uma instrução `u32`/`u64` mais estreita; uma operação de largura menor não prova retroativamente que o elemento original do campo ou o valor multi-limb tinha o tipo esperado.<sup>[[12]](#references)[[13]](#references)</sup>

```text
prover advice (q, r)
    -> limb/type assertions
    -> x = q * m + r
    -> 0 <= r < m
    -> consume q/r in narrow arithmetic
```

A falha `mod_12289` no Miden ilustra o padrão de exploração: o quociente era verificado como um valor de 64 bits dividido em dois limbs, mas o resto fornecido por advice chegava a `u32overflowing_sub` sem validação equivalente. Um prover malicioso poderia coordenar valores inválidos de quociente e resto para que as restrições de subtração implementadas continuassem satisfeitas, embora o procedimento retornasse um resto não matemático. Como esse resultado era usado na verificação do Falcon, a falha de solidez podia ser ampliada para gerar assinaturas de autorização forjadas, em vez de apenas produzir um resultado aritmético incorreto.<sup>[[13]](#references)</sup>

### Auditoria de VMs criptográficas com pilha implícita

Linguagens baseadas em pilha ocultam operandos. Portanto, primeiro converta as instruções em uma IR na qual cada valor consumido e produzido pela pilha seja uma expressão com proveniência. Em seguida, um pipeline de análise conservador pode:<sup>[[10]](#references)[[11]](#references)[[12]](#references)[[13]](#references)</sup>

1. Construir o grafo de chamadas e inferir os efeitos das procedures sobre a pilha de entrada e saída.
2. Executar simbolicamente as instruções compatíveis e converter o fluxo de controle em expressões SSA/estruturadas.
3. Propagar fatos abstratos como `Unknown`, `ProvenU32`, `Bool`, proveniência de valores e inicialização local até atingir um ponto fixo.
4. Sinalizar valores derivados de advice que chegam a operações aritméticas tipadas ou a sinks que exigem valor diferente de zero sem passar por um sanitizador em **todos** os caminhos de entrada.
5. Comparar as assinaturas declaradas e inferidas e verificar se cada saída preserva os valores da pilha pertencentes ao chamador.

Trate uma assinatura desconhecida ou uma construção não compatível como uma **lacuna de análise**, não como um resultado limpo. Chamadas dinâmicas, loops que não preservam a pilha e branches com efeitos diferentes sobre a pilha podem impossibilitar o rastreamento confiável de slots; um decompilador mais seguro rejeita ou sinaliza esses casos, em vez de gerar pseudocódigo plausível, mas incorreto.<sup>[[10]](#references)[[13]](#references)</sup>

Nos pontos de junção do fluxo de controle, mantenha uma propriedade apenas quando ela for válida em todos os predecessores (por exemplo, `ProvenU32 join Unknown = Unknown`). Além disso, diferencie a convergência do ponto fixo de atingir o limite de iterações: somente uma sobreaproximação convergida e sólida justifica tratar a ausência de um diagnóstico como evidência de que todas as execuções representadas satisfazem a propriedade.<sup>[[11]](#references)</sup>

### Use obrigações de prova para revelar precondições ocultas

Para conjuntos pequenos de instruções, converta procedures em um modelo executável de VM formal e prove tanto o resultado quanto a transformação completa da pilha. O teorema deve abranger a terminação, as entradas tipadas, o prefixo de saída esperado e a preservação da pilha do chamador que não foi alterada. Examine o enunciado do teorema com o mesmo cuidado que a prova: o kernel pode validar uma prova de uma afirmação enfraquecida por engano.<sup>[[12]](#references)[[13]](#references)</sup>

Hipóteses inesperadas são achados úteis. Na análise do Miden, uma prova de rotação à direita de 64 bits exigiu `shift mod 32 != 0`, revelando um caso de falha para entradas grandes quando o shift era múltiplo de 32; outra prova constatou que `wrapping_mul` de 256 bits descartava valores da pilha pertencentes ao chamador. Inclua o caso de limite descoberto nos testes e, em seguida, corrija a implementação ou fortaleça deliberadamente a precondição pública, em vez de aceitar silenciosamente a hipótese adicional.<sup>[[12]](#references)[[13]](#references)</sup>

### O que testar em sistemas ZK

- Faça fuzzing de todos os parsers do guest com codificações malformadas de witness/private input.
- Assegure a validação do intervalo do enum antes do dispatch do opcode.
- Adicione verificações semânticas para aliasing de operandos e outras formas inválidas de instrução.
- Rastreie cada origem de advice/witness até cada sink de aritmética tipada e exija validação em todos os caminhos.<sup>[[11]](#references)[[13]](#references)</sup>
- Teste helpers aritméticos com limbs não canônicos, restos fora do intervalo e valores de shift nos limites.<sup>[[12]](#references)[[13]](#references)</sup>
- Verifique a altura da pilha e a preservação dos valores abaixo dos argumentos declarados da procedure em cada retorno.<sup>[[10]](#references)[[12]](#references)[[13]](#references)</sup>
- Compare os contadores reportados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest tiver bugs.

## Autorização Dependente de Estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploração de DeFi/AMM

Se você está pesquisando a exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps que cruzam limites amplificados por flash loan), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados com múltiplos ativos que armazenam saldos virtuais em cache e podem ser envenenados quando `supply == 0`, consulte:

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
- [7] [Trail of Bits - Vencemos a prova de conhecimento zero do Google sobre criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curva elíptica contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório de prova de conceito da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
- [10] [Arquitetura do decompilador MASM](https://github.com/trailofbits/masm-decompiler/blob/main/ARCHITECTURE.md)
- [11] [Mecanismo de análise estática MASM](https://github.com/trailofbits/masm-lsp/tree/main/crates/masm-analysis)
- [12] [Modelo MASM-to-Lean e provas de correção](https://github.com/trailofbits/masm-lean)
- [13] [Auditoria na era da IA (boa o suficiente)](https://blog.trailofbits.com/2026/09/18/auditing-in-the-age-of-good-enough-ai/)
{{#include ../../banners/hacktricks-training.md}}

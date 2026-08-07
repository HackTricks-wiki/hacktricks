# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que são executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** são construídas sobre smart contracts, apresentando um front-end amigável e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se porque as coins funcionam como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** representam a propriedade de ativos.
- **DeFi** significa Decentralized Finance, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de Decentralized Exchange e Decentralized Autonomous Organizations.

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma determinada quantidade de tokens, reduzindo o consumo de energia em comparação com o PoW.<sup>[[1]](#references)</sup>

## Fundamentos do Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes Principais:

- **Multisignature Transactions** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos miners) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin, permitindo várias transações dentro de um canal e transmitindo apenas o estado final para a blockchain.

## Questões de Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Adquirindo Bitcoins Anonimamente

Os métodos incluem negociações em dinheiro, mineração e uso de mixers. O **CoinJoin** mistura várias transações para dificultar a rastreabilidade, enquanto o **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Ataques de Privacidade do Bitcoin

# Resumo dos Ataques de Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente motivo de preocupação. Veja uma visão simplificada de vários métodos comuns pelos quais attackers podem comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Geralmente, é raro que inputs de usuários diferentes sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação geralmente são considerados pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante será enviado para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Às vezes, os usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Análise do Grafo de Transações**

As transações podem ser visualizadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística baseia-se na análise de transações com vários inputs e outputs para tentar adivinhar qual output corresponde ao troco devolvido ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs fizer com que o output de troco seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Atacantes podem enviar pequenas quantidades para endereços usados anteriormente, esperando que o destinatário os combine com outros inputs em transações futuras, vinculando assim os endereços.

### Comportamento Correto da Wallet

As wallets devem evitar usar coins recebidas em endereços já usados e vazios, para evitar esse privacy leak.

## **Outras Técnicas de Análise de Blockchain**

- **Valores Exatos de Pagamento:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Números Redondos:** Um número redondo em uma transação sugere que se trata de um pagamento, sendo o output não redondo provavelmente o troco.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões exclusivos de criação de transações, permitindo que analistas identifiquem o software usado e potencialmente o endereço de troco.
- **Correlações de Valor e Tempo:** Divulgar horários ou valores de transações pode tornar as transações rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente verdadeiro quando uma entidade opera muitos nodes de Bitcoin, aumentando sua capacidade de monitorar transações.

## Mais

Para obter uma lista abrangente de ataques e defesas de privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Anônimas de Bitcoin

## Maneiras de Obter Bitcoins Anonimamente

- **Transações em Dinheiro:** Adquirir bitcoin usando dinheiro em espécie.
- **Alternativas ao Dinheiro:** Comprar gift cards e trocá-los online por bitcoin.
- **Mineração:** O método mais privado de obter bitcoins é por meio da mineração, especialmente quando realizada individualmente, pois mining pools podem conhecer o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo:** Teoricamente, roubar bitcoin poderia ser outro método de adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um mixing service, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, o que dificulta rastrear o proprietário original. No entanto, isso exige confiar que o serviço não manterá logs e realmente devolverá os bitcoins. Outras opções de mixing incluem cassinos de Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de usuários diferentes em uma só, complicando o processo para qualquer pessoa que tente associar inputs a outputs. Apesar de sua eficácia, transações com quantidades exclusivas de inputs e outputs ainda podem ser potencialmente rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obter mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um serviço semelhante no Ethereum, consulte [Tornado Cash](https://tornado.cash), que anonimiza transações usando fundos de mineradores.

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação comum, sem a característica distintiva de outputs iguais do CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade comum dos inputs usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima poderiam ser PayJoin, aprimorando a privacidade enquanto permanecem indistinguíveis de transações padrão de bitcoin.

**A utilização de PayJoin poderia interromper significativamente os métodos tradicionais de vigilância**, tornando-se um desenvolvimento promissor na busca por privacidade transacional.

# Melhores práticas para privacidade em criptomoedas

## **Técnicas de sincronização de carteiras**

Para manter a privacidade e a segurança, é crucial sincronizar as carteiras com a blockchain. Dois métodos se destacam:

- **Full node**: Ao baixar a blockchain inteira, um full node garante o máximo de privacidade. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário está interessado.
- **Filtragem de blocos no lado do cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem expor interesses específicos aos observadores da rede. Carteiras leves baixam esses filtros e só obtêm blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilização do Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar o Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção da reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço em cada transação. A reutilização de endereços pode comprometer a privacidade ao vincular transações à mesma entidade. As carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para privacidade transacional**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, impedindo ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem outputs de troco aumenta a privacidade ao interromper os métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se evitar o troco não for viável, gerar múltiplos outputs de troco ainda pode melhorar a privacidade.

# **Monero: um farol do anonimato**

Monero atende à necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão de privacidade.

# **Ethereum: gas e transações**

## **Entendendo o gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum, precificado em **gwei**. Por exemplo, uma transação que custa 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, com uma gorjeta para incentivar os mineradores. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais, sendo o excedente reembolsado.<sup>[[5]](#references)</sup>

## **Execução de transações**

As transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de smart contract. Elas exigem uma taxa e devem ser mineradas. As informações essenciais em uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Vale destacar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para qualquer pessoa que queira interagir com criptomoedas priorizando privacidade e segurança.

## Red Teaming de Web3 centrado em valor

- Faça um inventário dos componentes que controlam valor (signers, oracles, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas relevantes do MITRE AADAPT a fim de expor caminhos de escalada de privilégios.
- Simule cadeias de ataque de flash-loan/oracle/credential/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura de Web3

- A adulteração da supply chain das interfaces de carteira pode modificar payloads EIP-712 imediatamente antes da assinatura, coletando assinaturas válidas para tomadas de controle de proxies baseadas em delegatecall (por exemplo, sobrescrita do slot-0 de `masterCopy` do Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Os modos comuns de falha de smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas não assinados, validação stateful, replay de ERC-1271 e drenagem de taxas por meio de revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Mutation testing para encontrar pontos cegos nas test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de provas ZK / zkVM Guest

Quando um prover usa uma **zkVM** ou um circuito de prova específico da aplicação para atestar uma afirmação, o verificador aprende apenas que o **guest program foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma prova que seja validada enquanto as **métricas públicas ou o invariante declarado são falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura dentro de proof guests

- Trate bytes de witness/circuito privado como **entrada não confiável controlada pelo atacante**, mesmo que estejam ocultos pela prova.
- Evite desserializá-los com helpers não verificados, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados out-of-band.
- Discriminantes de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` subsequente sobre esse valor se torna suspeito.

### Bypass de contadores usando jump table / UB

Se o Rust converter um `match` grande em uma **jump table**, um discriminante de enum inválido poderá produzir **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo indexa além da primeira jump table e chega ao código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar proofs que relatam métricas impossíveis, como menos gates, menos operações dispendiosas ou outros recursos limitados falsificados.

Checklist de revisão:

- Procure enums controlados pelo atacante e desserializados a partir de witness/private input.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Considere `unsafe` + desserialização sem verificações + dispatch de opcode grande uma combinação de alto risco.
- Faça reverse engineering do binário emitido quando necessário; o layout da jump table pode ser mais importante que o código-fonte.

### Restrições semânticas ausentes em interpreters reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a proof deve impor.

Para conjuntos de instruções reversíveis/semelhantes a quantum, certifique-se de que os operandos que precisam ser distintos estejam realmente restritos a serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>
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
Isso cria um **primitivo de reset determinístico**, quebrando as premissas de reversibilidade e permitindo computações não intencionais mais baratas. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam verificações funcionais enquanto contornam o modelo de custos que o verificador acredita estar sendo aplicado.

### O que testar em sistemas ZK

- Fazer fuzz em todos os parsers guest com codificações de witness/private-input malformadas.
- Garantir a validação do intervalo de enums antes do opcode dispatch.
- Adicionar verificações semânticas para aliasing de operandos e outras formas de instrução inválidas.
- Comparar os contadores reportados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **declaração errada** se o programa guest tiver um bug.

## Exploração de DeFi/AMM

Se você estiver pesquisando exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps com crossing de limiar amplificado por flash loan), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados com múltiplos ativos que armazenam saldos virtuais em cache e podem ser envenenados quando `supply == 0`, consulte:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## Referências

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Public Key & Private Key Explained - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [What are multi-signature transactions? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transactions | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas and fees | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacy - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations (patched version)](https://arxiv.org/abs/2603.28846v2)
- [9] [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}

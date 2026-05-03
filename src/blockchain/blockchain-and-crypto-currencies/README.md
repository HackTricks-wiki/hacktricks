# Blockchain and Crypto-Currencies

{{#include ../../banners/hacktricks-training.md}}

## Basic Concepts

- **Smart Contracts** são definidos como programas que executam em uma blockchain quando certas condições são atendidas, automatizando execuções de acordos sem intermediários.
- **Decentralized Applications (dApps)** são construídas sobre smart contracts, apresentando um front-end amigável e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se em que coins servem como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** indicam propriedade de ativos.
- **DeFi** significa Decentralized Finance, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se a Decentralized Exchange Platforms e Decentralized Autonomous Organizations, respectivamente.

## Consensus Mechanisms

Consensus mechanisms garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificação de transações.
- **Proof of Stake (PoS)** exige que validadores detenham uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.

## Bitcoin Essentials

### Transactions

As transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por meio de assinaturas digitais, garantindo que apenas o proprietário da private key possa iniciar transferências.

#### Key Components:

- **Multisignature Transactions** exigem múltiplas assinaturas para autorizar uma transação.
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos miners) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um channel, publicando apenas o estado final na blockchain.

## Bitcoin Privacy Concerns

Ataques de privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao obscurecer os links de transação entre usuários.

## Acquiring Bitcoins Anonymously

Os métodos incluem trocas em dinheiro, mining e uso de mixers. **CoinJoin** mistura múltiplas transações para complicar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações regulares para maior privacidade.

# Bitcoin Privacy Atacks

# Summary of Bitcoin Privacy Attacks

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente موضوع de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais attackers podem comprometer a privacidade do Bitcoin.

## **Common Input Ownership Assumption**

Em geral, é raro que inputs de usuários diferentes sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação são frequentemente assumidos como pertencentes ao mesmo owner**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser gasto integralmente em uma transação. Se apenas uma parte dele for enviada para outro address, o restante vai para um novo change address. Observadores podem assumir que esse novo address pertence ao sender, comprometendo a privacidade.

### Example

Para mitigar isso, serviços de mixing ou o uso de múltiplos addresses podem ajudar a obscurecer a ownership.

## **Social Networks & Forums Exposure**

Às vezes, usuários compartilham seus Bitcoin addresses online, tornando **fácil vincular o address ao seu owner**.

## **Transaction Graph Analysis**

As transações podem ser visualizadas como graphs, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heuristic é baseada na análise de transações com múltiplos inputs e outputs para adivinhar qual output é o change retornando ao sender.

### Example
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs faz o change output ficar maior do que qualquer input individual, isso pode confundir a heuristic.

## **Forced Address Reuse**

Attacker podem enviar pequenas quantias para addresses já usados anteriormente, esperando que o recipient combine isso com outros inputs em transações futuras, vinculando assim addresses entre si.

### Correct Wallet Behavior

Wallets should avoid using coins recebidas em addresses vazios já usados para evitar esse privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transações sem change provavelmente são entre dois addresses pertencentes ao mesmo user.
- **Round Numbers:** Um número redondo em uma transação sugere que é um payment, e o output não redondo provavelmente é o change.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões únicos de criação de transactions, permitindo que analysts identifiquem o software usado e, potencialmente, o change address.
- **Amount & Timing Correlations:** Divulgar os horários ou amounts das transactions pode torná-las rastreáveis.

## **Traffic Analysis**

Ao monitorar o network traffic, attackers podem potencialmente vincular transactions ou blocks a IP addresses, comprometendo a privacy do user. Isso é especialmente verdadeiro se uma entidade opera muitos Bitcoin nodes, aumentando sua capacidade de monitorar transactions.

## More

Para uma lista abrangente de privacy attacks e defenses, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin por cash.
- **Cash Alternatives**: Comprar gift cards e trocá-los online por bitcoin.
- **Mining**: O método mais private para ganhar bitcoins é por mining, especialmente quando feito sozinho, porque mining pools podem saber o IP address do miner. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo anonymousamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um mixing service, um user pode **enviar bitcoins** e receber **different bitcoins em retorno**, o que dificulta rastrear o original owner. Ainda assim, isso exige confiar no serviço para não manter logs e realmente devolver os bitcoins. Alternativas de mixing incluem Bitcoin casinos.

## CoinJoin

**CoinJoin** combina múltiplas transactions de diferentes users em uma só, complicando o processo para qualquer pessoa tentando casar inputs com outputs. Apesar de sua effectiveness, transactions com tamanhos únicos de input e output ainda podem potencialmente ser rastreadas.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais information, visite [CoinJoin](https://coinjoin.io/en). Para um service similar no Ethereum, confira [Tornado Cash](https://tornado.cash), que anonymizes transactions com funds de miners.

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transaction entre duas parties (por exemplo, um customer e um merchant) como uma transaction regular, sem os outputs iguais característicos do CoinJoin. Isso a torna extremamente difícil de detectar e pode invalidar a common-input-ownership heuristic usada por entidades de surveillance de transactions.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima podem ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis de transações padrão de bitcoin.

**A utilização de PayJoin poderia interromper significativamente os métodos tradicionais de surveillance**, tornando-se um desenvolvimento promissor na busca por privacidade transacional.

# Melhores Práticas para Privacidade em Cryptocurrencies

## **Técnicas de Sincronização de Wallet**

Para manter privacidade e segurança, sincronizar wallets com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar toda a blockchain, um full node garante a máxima privacidade. Todas as transações já realizadas são armazenadas localmente, tornando impossível para adversários identificar quais transações ou addresses interessam ao usuário.
- **Client-side block filtering**: Este método envolve criar filters para cada block na blockchain, permitindo que wallets identifiquem transações relevantes sem expor interesses específicos a observadores da rede. Wallets leves baixam esses filters, obtendo full blocks apenas quando uma correspondência com os addresses do usuário é encontrada.

## **Utilizando Tor para Anonymity**

Como o Bitcoin opera em uma peer-to-peer network, é recomendado usar Tor para mascarar seu IP address, aumentando a privacidade ao interagir com a rede.

## **Prevenindo Reutilização de Address**

Para proteger a privacidade, é vital usar um novo address para cada transação. Reutilizar addresses pode comprometer a privacidade ao vincular transações à mesma entidade. Wallets modernas desencorajam a reutilização de addresses por meio de seu design.

## **Estratégias para Privacy de Transaction**

- **Multiple transactions**: Dividir um pagamento em várias transactions pode obscurecer o valor da transaction, frustrando ataques de privacy.
- **Change avoidance**: Optar por transactions que não exijam change outputs melhora a privacidade ao dificultar métodos de detecção de change.
- **Multiple change outputs**: Se evitar change não for viável, gerar múltiplos change outputs ainda pode melhorar a privacidade.

# **Monero: Um Farol de Anonymity**

Monero atende à necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão de privacy.

# **Ethereum: Gas e Transactions**

## **Entendendo Gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum, precificado em **gwei**. Por exemplo, uma transaction custando 2,310,000 gwei (ou 0.00231 ETH) envolve um gas limit e uma base fee, com uma tip para incentivar miners. Usuários podem definir uma max fee para garantir que não paguem demais, com o excedente reembolsado.

## **Executando Transactions**

Transactions no Ethereum envolvem um sender e um recipient, que podem ser addresses de user ou smart contract. Elas exigem uma fee e precisam ser mined. Informações essenciais em uma transaction incluem o recipient, a signature do sender, value, optional data, gas limit e fees. Notavelmente, o address do sender é deduzido a partir da signature, eliminando a necessidade de incluí-lo nos dados da transaction.

Essas práticas e mecanismos são fundamentais para qualquer pessoa que queira se envolver com cryptocurrencies enquanto prioriza privacidade e segurança.

## Value-Centric Web3 Red Teaming

- Inventory value-bearing components (signers, oracles, bridges, automation) to understand who can move funds and how.
- Map each component to relevant MITRE AADAPT tactics to expose privilege escalation paths.
- Rehearse flash-loan/oracle/credential/cross-chain attack chains to validate impact and document exploitable preconditions.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- Supply-chain tampering of wallet UIs can mutate EIP-712 payloads right before signing, harvesting valid signatures for delegatecall-based proxy takeovers (e.g., slot-0 overwrite of Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Common smart-account failure modes include bypassing `EntryPoint` access control, unsigned gas fields, stateful validation, ERC-1271 replay, and fee-drain via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## ZK Proof / zkVM Guest Integrity

Quando um prover usa um **zkVM** ou um proof circuit específico da aplicação para atestar uma claim, o verifier está apenas aprendendo que o **guest program foi executado conforme escrito**. Se o guest contiver **unsafe deserialization**, **undefined behavior** ou **missing semantic constraints**, um prover malicioso pode gerar uma proof que verifica enquanto as **public metrics ou a claimed invariant são falsas**.

### Unsafe deserialization dentro de proof guests

- Trate private witness/circuit bytes como **untrusted attacker input** mesmo que estejam ocultos pela proof.
- Evite desserializá-los com helpers sem validação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados fora de banda.
- Enum discriminants, relative pointers, lengths e indexes carregados de dados serializados não confiáveis devem ser validados antes de influenciar o control flow ou o memory access.

Practical audit pattern:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminant fora do intervalo**, todo `match` downstream sobre esse valor se torna suspeito.

### Bypass de jump-table / UB counter

Se Rust reduzir um `match` grande para uma **jump table**, um discriminant inválido do enum pode produzir **fluxo de controle indefinido**. Um padrão perigoso é:

1. Um `match` atualiza **counters/constraints críticos de segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminant fora do intervalo indexa além da primeira jump table e cai em código associado à segunda.

Resultado: a operação continua executando, mas o caminho de contabilização é ignorado. Em um zkVM isso pode forjar provas que reportam métricas impossíveis, como menos gates, menos operações caras ou outros recursos limitados falsificados.

Checklist de revisão:

- Procure por enums controlados pelo atacante, desserializados de witness/private input.
- Inspecione `match` repetidos sobre o mesmo opcode/campo kind.
- Trate `unsafe` + desserialização sem verificação + dispatch grande de opcode como uma combinação de alto risco.
- Reverse engineer o binário gerado quando necessário; o layout da jump table pode importar mais que o source.

### Constraints semânticas ausentes em interpreters reversíveis/especializados

Não valide apenas a segurança de memória; valide também as **regras semânticas** que a prova deve impor.

Para instruction sets reversíveis/quânticos, garanta que operands que precisam ser distintos estejam de fato constrained para serem distintos. Uma operação do tipo Toffoli/CCX implementada como:
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
torna-se inseguro se o guest não rejeitar:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Nesse caso, a transição colapsa em:
```text
q = q ^ (q & q) = 0
```
Isso cria um **deterministic reset primitive**, quebrando as suposições de reversibilidade e permitindo computações não pretendidas mais baratas. Em proof systems que atestam uso de recursos, isso pode permitir que attackers satisfaçam verificações funcionais enquanto contornam o cost model que o verifier acredita estar sendo aplicado.

### O que testar em ZK systems

- Faça fuzz de todos os guest parsers com codificações malformed de witness/private-input.
- Assegure validação de range de enum antes do opcode dispatch.
- Adicione semantic checks para operand aliasing e outras formas inválidas de instrução.
- Compare os counters reported/public com uma implementação de referência independente.
- Lembre-se de que um proof válido ainda pode provar a **wrong statement** se o guest program estiver bugado.

## DeFi/AMM Exploitation

Se você estiver pesquisando exploitation prática de DEXes e AMMs (Uniswap v4 hooks, abuso de rounding/precision, flash-loan amplified threshold-crossing swaps), veja:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para multi-asset weighted pools que armazenam virtual balances em cache e podem ser poisoned quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [Trail of Bits - We beat Google's zero-knowledge proof of quantum cryptanalysis](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [Google patched paper version](https://arxiv.org/abs/2603.28846v2)
- [Trail of Bits proof-of-concept repository](https://github.com/trailofbits/quantum-zk-proof-poc)

{{#include ../../banners/hacktricks-training.md}}

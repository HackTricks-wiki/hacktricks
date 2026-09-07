# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Contratos Inteligentes** são definidos como programas que executam em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações Descentralizadas (dApps)** são baseadas em contratos inteligentes, apresentando um front-end fácil de usar e um back-end transparente e auditável.
- **Tokens e Coins** diferenciam-se porque coins funcionam como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** representam a propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a Plataformas de Exchange Descentralizadas e Organizações Autônomas Descentralizadas.

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma determinada quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.<sup>[[1]](#references)</sup>

## Fundamentos do Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por meio de assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes Principais:

- **Transações Multisignature** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos miners) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin, permitindo várias transações dentro de um canal e transmitindo apenas o estado final para a blockchain.

## Problemas de Privacidade do Bitcoin

Ataques de privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Adquirindo Bitcoins Anonimamente

Os métodos incluem negociações em dinheiro, mineração e uso de mixers. **CoinJoin** mistura várias transações para dificultar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos Ataques de Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente motivos de preocupação. Veja uma visão geral simplificada de vários métodos comuns pelos quais attackers podem comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Geralmente, é raro que inputs de usuários diferentes sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação são frequentemente considerados como pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante irá para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Às vezes, os usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Análise de Grafos de Transações**

As transações podem ser visualizadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heuristic baseia-se na análise de transações com vários inputs e outputs para tentar determinar qual output corresponde ao troco que retorna ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs fizer com que o output do troco seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, esperando que o destinatário os combine com outros inputs em transações futuras, vinculando assim os endereços.

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

## Formas de Obter Bitcoins Anonimamente

- **Transações em Dinheiro:** Adquirir bitcoin usando dinheiro.
- **Alternativas ao Dinheiro:** Comprar gift cards e trocá-los online por bitcoin.
- **Mining:** O método mais privado para obter bitcoins é por meio de mining, especialmente quando feito individualmente, pois mining pools podem conhecer o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Roubo:** Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um mixing service, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, dificultando o rastreamento do proprietário original. No entanto, isso exige confiar que o serviço não manterá logs e realmente devolverá os bitcoins. Outras opções de mixing incluem casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiplas transações de usuários diferentes em uma só, complicando o processo para qualquer pessoa que tente associar inputs a outputs. Apesar de sua eficácia, transações com quantidades exclusivas de inputs e outputs ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obter mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart contract de Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação comum, sem os outputs iguais característicos do CoinJoin. Isso torna a detecção extremamente difícil e pode invalidar a heurística de propriedade comum dos inputs usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima poderiam ser PayJoin, aprimorando a privacidade enquanto permanecem indistinguíveis de transações bitcoin padrão.

**A utilização de PayJoin poderia interromper significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca por privacidade transacional.

# Melhores práticas para privacidade em criptomoedas

## **Técnicas de sincronização de wallets**

Para manter a privacidade e a segurança, sincronizar as wallets com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar toda a blockchain, um full node garante máxima privacidade. Todas as transações já realizadas são armazenadas localmente, tornando impossível para adversários identificar em quais transações ou endereços o usuário está interessado.
- **Filtragem de blocos no lado do cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as wallets identifiquem transações relevantes sem expor interesses específicos aos observadores da rede. Wallets leves baixam esses filtros e só obtêm blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilização do Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para ocultar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção da reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço em cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Wallets modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para privacidade transacional**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, frustrando ataques contra a privacidade.
- **Evitar troco**: Optar por transações que não exigem outputs de troco aumenta a privacidade ao interromper métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se evitar o troco não for viável, gerar múltiplos outputs de troco ainda pode melhorar a privacidade.

# **Monero: Um farol do anonimato**

Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: Gas e transações**

## **Entendendo o Gas**

Gas mede o esforço computacional necessário para executar operações na Ethereum, sendo precificado em **gwei**. Por exemplo, uma transação que custa 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, com uma taxa de prioridade para incentivar a inclusão pelo validador. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais, com o excedente sendo reembolsado.<sup>[[5]](#references)</sup>

## **Execução de transações**

As transações na Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuários ou de smart contracts. Elas exigem uma taxa e devem ser incluídas em um bloco. As informações essenciais em uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. É importante observar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para qualquer pessoa que queira interagir com criptomoedas priorizando privacidade e segurança.

## Red Teaming de Web3 centrado em valor

- Faça um inventário dos componentes que mantêm valor (signers, oracles, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas relevantes do MITRE AADAPT a fim de expor caminhos de privilege escalation.
- Simule cadeias de ataque envolvendo flash loans/oracles/credenciais/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura de Web3

- A adulteração da supply chain de UIs de wallets pode modificar payloads EIP-712 imediatamente antes da assinatura, coletando assinaturas válidas para takeovers de proxies baseados em delegatecall (por exemplo, sobrescrita do slot-0 de `masterCopy` do Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Modos comuns de falha de smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas sem assinatura, validação stateful, replay de ERC-1271 e drenagem de taxas por meio de revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Testes de mutação para encontrar pontos cegos em test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de ZK Proof / zkVM Guest

Quando um prover usa um **zkVM** ou um circuito de proof específico da aplicação para atestar uma afirmação, o verificador apenas aprende que o **guest program foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma proof que seja validada enquanto as **métricas públicas ou o invariant declarado são falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura dentro de proof guests

- Trate bytes de private witness/circuit como **untrusted attacker input**, mesmo que estejam ocultos pela proof.
- Evite desserializá-los com helpers sem verificação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados out-of-band.
- Discriminants de enums, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` posterior sobre esse valor se torna suspeito.

### Bypass de contadores por jump table / UB

Se o Rust transformar um `match` grande em uma **jump table**, um discriminante de enum inválido poderá produzir **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos de segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo indexa além da primeira jump table e salta para um trecho de código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar proofs que relatam métricas impossíveis, como menos gates, menos operações caras ou outros recursos limitados falsificados.

Checklist de revisão:

- Procure enums controlados pelo atacante e desserializados a partir de witness/private input.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Considere `unsafe` + desserialização sem verificações + dispatch de opcode grande uma combinação de alto risco.
- Faça reverse engineering do binário emitido quando necessário; o layout da jump table pode ser mais importante do que o código-fonte.

### Restrições semânticas ausentes em interpreters reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a proof deve impor.

Para instruction sets reversíveis/semelhantes a quantum, certifique-se de que os operandos que precisam ser distintos estejam realmente restritos a serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>
```rust
let v = cond & self.qubit(op.q_control1) & self.qubit(op.q_control2);
*self.qubit_mut(op.q_target) ^= v;
```
torna-se inseguro se o convidado não rejeitar:
```text
op.q_control1 == op.q_control2 == op.q_target
```
Nesse caso, a transição se reduz a:
```text
q = q ^ (q & q) = 0
```
Isso cria uma **primitiva de reset determinística**, quebrando as suposições de reversibilidade e permitindo computações não intencionais mais baratas. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que attackers satisfaçam verificações funcionais enquanto contornam o modelo de custo que o verifier acredita estar sendo aplicado.

### O que testar em sistemas ZK

- Faça fuzzing de todos os parsers do guest com codificações malformadas de witness/private-input.
- Garanta a validação do intervalo de enums antes do dispatch do opcode.
- Adicione verificações semânticas para aliasing de operandos e outras formas inválidas de instruções.
- Compare os contadores reportados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest tiver bugs.

## Autorização dependente do estado

{{#ref}}
state-divergence-default-value-authorization-bypasses.md
{{#endref}}

## Exploração de DeFi/AMM

Se você estiver pesquisando exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps de crossing de limiar amplificados por flash-loan), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que armazenam virtual balances em cache e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chave pública e chave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [O que são transações multi-signature? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transações | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e taxas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidade - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Vencemos a prova zero-knowledge quântica de cryptanalysis do Google](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curvas elípticas contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório proof-of-concept da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}

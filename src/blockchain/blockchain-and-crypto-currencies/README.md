# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que são executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** são construídas sobre smart contracts, apresentando um front-end fácil de usar e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se porque as coins servem como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** representam a propriedade de ativos.
- **DeFi** significa Decentralized Finance, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a plataformas de Decentralized Exchange e a Decentralized Autonomous Organizations.

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para a verificação de transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma determinada quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.<sup>[[1]](#references)</sup>

## Fundamentos do Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por meio de assinaturas digitais, garantindo que apenas o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes Principais:

- **Multisignature Transactions** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos miners) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin, permitindo várias transações dentro de um canal e transmitindo apenas o estado final para a blockchain.

## Problemas de Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre as transações dos usuários.

## Adquirindo Bitcoins Anonimamente

Os métodos incluem negociações em dinheiro, mineração e uso de mixers. **CoinJoin** mistura várias transações para dificultar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos Ataques à Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários frequentemente são motivo de preocupação. Veja a seguir uma visão simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Common Input Ownership Assumption**

Geralmente, é raro que inputs de usuários diferentes sejam combinados em uma única transação devido à complexidade envolvida. Portanto, **dois endereços de input na mesma transação geralmente são considerados pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante será enviado para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para reduzir esse risco, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Social Networks & Forums Exposure**

Às vezes, os usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Transaction Graph Analysis**

As transações podem ser visualizadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística baseia-se na análise de transações com vários inputs e outputs para tentar identificar qual output corresponde ao troco que retorna ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs fizer com que o output do troco seja maior que qualquer input individual, isso poderá confundir a heurística.

## **Forced Address Reuse**

Os atacantes podem enviar pequenas quantias para endereços usados anteriormente, esperando que o destinatário os combine com outros inputs em transações futuras, associando assim os endereços.

### Comportamento correto da carteira

As carteiras devem evitar usar coins recebidos em endereços já usados e vazios, para prevenir este privacy leak.

## **Other Blockchain Analysis Techniques**

- **Quantias exatas de pagamento:** Transações sem troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Números redondos:** Um número redondo em uma transação sugere que se trata de um pagamento, sendo o output não redondo provavelmente o troco.
- **Fingerprinting de carteiras:** Diferentes carteiras têm padrões exclusivos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de troco.
- **Correlações de quantia e tempo:** A divulgação dos horários ou das quantias das transações pode torná-las rastreáveis.

## **Traffic Analysis**

Ao monitorar o tráfego de rede, os atacantes podem potencialmente associar transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente verdadeiro quando uma entidade opera muitos nodes de Bitcoin, aumentando sua capacidade de monitorar transações.

## More

Para obter uma lista abrangente de ataques e defesas de privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Transações em dinheiro:** Adquirir bitcoin usando dinheiro.
- **Alternativas ao dinheiro:** Comprar gift cards e trocá-los online por bitcoin.
- **Mining:** O método mais privado de obter bitcoins é por meio de mining, especialmente quando feito individualmente, pois mining pools podem conhecer o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft:** Teoricamente, roubar bitcoin poderia ser outro método de adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um mixing service, um usuário pode **send bitcoins** e receber **different bitcoins in return**, o que dificulta rastrear o proprietário original. No entanto, isso exige confiar que o serviço não manterá logs e realmente devolverá os bitcoins. Opções alternativas de mixing incluem casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de diferentes usuários em uma só, complicando o processo para qualquer pessoa que tente associar inputs a outputs. Apesar de sua eficácia, transações com quantidades exclusivas de inputs e outputs ainda podem ser potencialmente rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obter mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart-contracts do Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação normal, sem a característica distinta de outputs iguais do CoinJoin. Isso torna a detecção extremamente difícil e poderia invalidar a heurística de propriedade comum dos inputs usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a anterior poderiam ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis de transações bitcoin padrão.

**A utilização de PayJoin poderia interromper significativamente os métodos tradicionais de vigilância**, tornando-a um desenvolvimento promissor na busca por privacidade transacional.

# **Melhores práticas para privacidade em criptomoedas**

## **Técnicas de sincronização de wallets**

Para manter a privacidade e a segurança, é crucial sincronizar as wallets com a blockchain. Dois métodos se destacam:

- **Full node**: Ao baixar a blockchain inteira, um full node garante a máxima privacidade. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário está interessado.
- **Client-side block filtering**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as wallets identifiquem transações relevantes sem expor interesses específicos aos observadores da rede. Lightweight wallets baixam esses filtros e só obtêm blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilização do Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar o endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção da reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço em cada transação. A reutilização de endereços pode comprometer a privacidade ao vincular transações à mesma entidade. As wallets modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para privacidade transacional**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, frustrando ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem outputs de troco aumenta a privacidade ao dificultar os métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se não for possível evitar o troco, gerar múltiplos outputs de troco ainda pode melhorar a privacidade.

# **Monero: um farol do anonimato**

Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: Gas e transações**

## **Entendendo o Gas**

Gas mede o esforço computacional necessário para executar operações na Ethereum, sendo precificado em **gwei**. Por exemplo, uma transação que custa 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, com uma taxa de prioridade para incentivar a inclusão pelo validador. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais, com o excedente sendo reembolsado.<sup>[[5]](#references)</sup>

## **Execução de transações**

As transações na Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuários ou de smart contracts. Elas exigem uma taxa e devem ser incluídas em um bloco. As informações essenciais em uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. É importante observar que o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para qualquer pessoa que queira interagir com criptomoedas priorizando privacidade e segurança.

## Red Teaming de Web3 centrado em valor

- Faça um inventário dos componentes que movimentam valor (signers, oracles, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas relevantes do MITRE AADAPT a fim de expor caminhos de privilege escalation.
- Simule cadeias de ataque envolvendo flash loans/oracles/credenciais/cross-chain para validar o impacto e documentar as pré-condições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura da Web3

- A adulteração da supply chain das interfaces de wallet pode modificar payloads EIP-712 imediatamente antes da assinatura, coletando assinaturas válidas para takeover de proxies baseados em delegatecall (por exemplo, sobrescrita do slot-0 de `masterCopy` da Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Modos comuns de falha em smart accounts incluem bypass do controle de acesso do `EntryPoint`, campos de gas não assinados, validação stateful, replay de ERC-1271 e drenagem de taxas por meio de revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de smart contracts

- Mutation testing para encontrar pontos cegos nas test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de provas ZK / guest de zkVM

Quando um prover usa uma **zkVM** ou um circuito de prova específico da aplicação para atestar uma afirmação, o verifier aprende apenas que o **guest program foi executado conforme escrito**. Se o guest contiver **desserialização insegura**, **comportamento indefinido** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma prova que seja validada enquanto as **métricas públicas ou o invariant declarado forem falsos**.<sup>[[7]](#references)</sup>

### Desserialização insegura dentro de proof guests

- Trate bytes de private witness/circuit como **untrusted attacker input**, mesmo que estejam ocultos pela prova.
- Evite desserializá-los com helpers sem verificação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados out-of-band.
- Discriminants de enums, relative pointers, lengths e indexes carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminant fora do intervalo**, todo `match` downstream sobre esse valor se torna suspeito.

### Bypass de contadores usando jump table / UB

Se o Rust reduzir um `match` grande a uma **jump table**, um discriminant de enum inválido poderá produzir **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminant fora do intervalo indexa além da primeira jump table e chega ao código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que relatam métricas impossíveis, como menos gates, menos operações caras ou outros recursos limitados falsificados.

Checklist de revisão:

- Procure enums controlados pelo atacante e desserializados a partir de witness/private input.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Trate `unsafe` + desserialização sem verificações + dispatch de opcode grande como uma combinação de alto risco.
- Faça engenharia reversa do binário gerado quando necessário; o layout da jump table pode ser mais importante que o código-fonte.

### Restrições semânticas ausentes em interpreters reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para instruction sets reversíveis/semelhantes aos quânticos, garanta que os operandos que devem ser distintos estejam realmente restritos a serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>
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
Isso cria um **primitivo de reset determinístico**, quebrando as suposições de reversibilidade e permitindo computações não intencionais mais baratas. Em proof systems que atestam o uso de recursos, isso pode permitir que attackers satisfaçam verificações funcionais enquanto contornam o modelo de custo que o verifier acredita estar sendo aplicado.

### O que testar em sistemas ZK

- Fazer fuzz em todos os parsers do guest com encodings de witness/private-input malformados.
- Garantir a validação do intervalo de enums antes do dispatch do opcode.
- Adicionar verificações semânticas para aliasing de operandos e outras formas de instruções inválidas.
- Comparar contadores reportados/públicos com uma implementação de referência independente.
- Lembrar que uma proof válida ainda pode provar a **declaração errada** se o programa do guest tiver bugs.

## Exploração de DeFi/AMM

Se você estiver pesquisando exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps de crossing de threshold amplificados por flash loans), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que armazenam saldos virtuais em cache e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chave Pública e Chave Privada Explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [O que são transações multiassinatura? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transações | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e taxas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidade - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Superamos a proof de zero-knowledge do Google sobre criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curvas elípticas contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório de proof-of-concept da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}

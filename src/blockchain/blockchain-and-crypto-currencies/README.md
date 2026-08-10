# Blockchain e Criptomoedas

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que são executados em uma blockchain quando determinadas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Aplicações Descentralizadas (dApps)** são desenvolvidas com base em smart contracts, apresentando um front-end fácil de usar e um back-end transparente e auditável.
- **Tokens e Coins** diferenciam-se porque as coins funcionam como dinheiro digital, enquanto os tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, enquanto **Security Tokens** representam a propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a Plataformas de Exchange Descentralizadas e Organizações Autônomas Descentralizadas.

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificar transações.
- **Proof of Stake (PoS)** exige que os validadores mantenham uma determinada quantidade de tokens, reduzindo o consumo de energia em comparação com o PoW.<sup>[[1]](#references)</sup>

## Fundamentos do Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por meio de assinaturas digitais, garantindo que apenas o proprietário da chave privada possa iniciar transferências.<sup>[[2]](#references)</sup>

#### Componentes principais:

- **Transações Multisignature** exigem várias assinaturas para autorizar uma transação.<sup>[[3]](#references)</sup>
- As transações consistem em **inputs** (fonte dos fundos), **outputs** (destino), **fees** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin, permitindo várias transações dentro de um canal e transmitindo à blockchain apenas o estado final.

## Preocupações com a Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao ocultar os vínculos entre transações de diferentes usuários.

## Obtendo Bitcoins Anonimamente

Os métodos incluem negociações em dinheiro, mineração e uso de mixers. O **CoinJoin** mistura várias transações para dificultar a rastreabilidade, enquanto o **PayJoin** disfarça CoinJoins como transações comuns para aumentar a privacidade.

# Resumo dos Ataques à Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente motivo de preocupação. Veja a seguir uma visão geral simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade do Bitcoin.<sup>[[6]](#references)</sup>

## **Suposição de Propriedade de Entradas Comuns**

Geralmente, é raro que inputs de usuários diferentes sejam combinados em uma única transação devido à complexidade envolvida. Portanto, **considera-se frequentemente que dois endereços de input na mesma transação pertencem ao mesmo proprietário**.

## **Detecção de Endereço de Troco de UTXO**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte dele for enviada para outro endereço, o restante será encaminhado para um novo endereço de troco. Observadores podem presumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para reduzir esse risco, serviços de mixing ou o uso de vários endereços podem ajudar a ocultar a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Às vezes, os usuários compartilham seus endereços de Bitcoin online, tornando **fácil associar o endereço ao seu proprietário**.

## **Análise de Grafos de Transações**

As transações podem ser visualizadas como grafos, revelando possíveis conexões entre usuários com base no fluxo de fundos.

## **Heurística de Input Desnecessário (Heurística de Troco Ideal)**

Essa heurística baseia-se na análise de transações com vários inputs e outputs para tentar determinar qual output corresponde ao troco retornado ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs fizer com que o change output seja maior que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Atacantes podem enviar pequenas quantias para endereços usados anteriormente, esperando que o destinatário os combine com outros inputs em transações futuras, vinculando assim os endereços.

### Comportamento Correto da Wallet

As wallets devem evitar usar coins recebidos em endereços já usados e vazios para prevenir esse privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transações sem change provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Round Numbers:** Um número redondo em uma transação sugere que ela é um pagamento, sendo que o output não redondo provavelmente é o change.
- **Wallet Fingerprinting:** Diferentes wallets possuem padrões exclusivos de criação de transações, permitindo que analistas identifiquem o software usado e potencialmente o change address.
- **Amount & Timing Correlations:** A divulgação dos horários ou valores das transações pode tornar as transações rastreáveis.

## **Traffic Analysis**

Ao monitorar o tráfego de rede, os atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade dos usuários. Isso é especialmente verdadeiro quando uma entidade opera muitos nós de Bitcoin, aumentando sua capacidade de monitorar transações.

## More

Para obter uma lista abrangente de ataques e defesas de privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin usando dinheiro em espécie.
- **Cash Alternatives**: Comprar gift cards e trocá-los online por bitcoin.
- **Mining**: O método mais privado para obter bitcoins é por meio de mining, especialmente quando realizado individualmente, pois os mining pools podem saber o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um mixing service, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, o que dificulta rastrear o proprietário original. No entanto, isso exige confiar que o serviço não manterá logs e realmente devolverá os bitcoins. Opções alternativas de mixing incluem casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina várias transações de usuários diferentes em uma só, complicando o processo para qualquer pessoa que tente associar inputs a outputs. Apesar de sua eficácia, transações com quantidades exclusivas de inputs e outputs ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para obter mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um mixer de smart-contract do Ethereum que separa depósitos de saques posteriores, consulte [Tornado Cash](https://tornado.cash).

## PayJoin

Uma variante do CoinJoin, o **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação normal, sem a característica distinta de outputs iguais do CoinJoin. Isso torna sua detecção extremamente difícil e pode invalidar a heurística de common-input-ownership usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima poderiam ser PayJoin, aprimorando a privacidade e permanecendo indistinguíveis de transações bitcoin padrão.

**A utilização de PayJoin poderia interromper significativamente os métodos tradicionais de vigilância**, tornando-a uma evolução promissora na busca pela privacidade transacional.

# Boas práticas de privacidade em criptomoedas

## **Técnicas de sincronização de Wallets**

Para manter a privacidade e a segurança, sincronizar as wallets com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar a blockchain inteira, um full node garante privacidade máxima. Todas as transações já realizadas são armazenadas localmente, impossibilitando que adversários identifiquem em quais transações ou endereços o usuário está interessado.
- **Client-side block filtering**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que as wallets identifiquem transações relevantes sem expor interesses específicos aos observadores da rede. Lightweight wallets baixam esses filtros e só buscam blocos completos quando encontram uma correspondência com os endereços do usuário.

## **Utilizando Tor para anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Evitando a reutilização de endereços**

Para proteger a privacidade, é essencial usar um novo endereço em cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Wallets modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para privacidade transacional**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode ocultar o valor da transação, impedindo ataques à privacidade.
- **Evitar troco**: Optar por transações que não exigem outputs de troco aumenta a privacidade ao interromper os métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se evitar o troco não for viável, gerar múltiplos outputs de troco ainda pode melhorar a privacidade.

# **Monero: Um farol do anonimato**

Monero foi projetado para priorizar a privacidade das transações.

# **Ethereum: Gas e transações**

## **Entendendo Gas**

Gas mede o esforço computacional necessário para executar operações na Ethereum, com preço definido em **gwei**. Por exemplo, uma transação que custa 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, com uma taxa de prioridade para incentivar a inclusão pelo validador. Os usuários podem definir uma taxa máxima para garantir que não paguem a mais, com o excedente sendo reembolsado.<sup>[[5]](#references)</sup>

## **Executando transações**

As transações na Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de smart contract. Elas exigem uma taxa e devem ser incluídas em um bloco. As informações essenciais de uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, o limite de gas e as taxas. Notavelmente, o endereço do remetente é deduzido da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.<sup>[[4]](#references)</sup>

Essas práticas e mecanismos são fundamentais para qualquer pessoa que queira interagir com criptomoedas priorizando privacidade e segurança.

## Red Teaming de Web3 centrado em valor

- Faça um inventário dos componentes que custodiam valor (signers, oracles, bridges, automação) para entender quem pode movimentar fundos e como.
- Mapeie cada componente para as táticas relevantes do MITRE AADAPT a fim de expor caminhos de privilege escalation.
- Reproduza cadeias de ataque envolvendo flash-loan/oracle/credenciais/cross-chain para validar o impacto e documentar as precondições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do fluxo de assinatura da Web3

- A adulteração da supply chain das interfaces de wallet pode modificar payloads EIP-712 imediatamente antes da assinatura, coletando assinaturas válidas para takeovers de proxies baseados em delegatecall (por exemplo, sobrescrita do slot-0 de masterCopy do Safe).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Modos comuns de falha de smart accounts incluem contornar o controle de acesso de `EntryPoint`, campos de gas não assinados, validação stateful, replay de ERC-1271 e drenagem de taxas por meio de revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Segurança de Smart Contracts

- Mutation testing para encontrar pontos cegos nas test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Integridade de ZK Proof / zkVM Guest

Quando um prover usa uma **zkVM** ou um circuito de proof específico da aplicação para atestar uma afirmação, o verifier aprende apenas que o **guest program foi executado conforme escrito**. Se o guest contiver **unsafe deserialization**, **undefined behavior** ou **restrições semânticas ausentes**, um prover malicioso poderá gerar uma proof que é validada enquanto as **métricas públicas ou o invariante declarado são falsos**.<sup>[[7]](#references)</sup>

### Unsafe deserialization dentro de proof guests

- Trate bytes privados de witness/circuit como **untrusted attacker input**, mesmo que estejam ocultos pela proof.
- Evite desserializá-los com helpers sem verificação, como `rkyv::access_unchecked`, a menos que os bytes já tenham sido validados out-of-band.
- Discriminants de enum, ponteiros relativos, comprimentos e índices carregados de dados serializados não confiáveis devem ser validados antes de influenciarem o fluxo de controle ou o acesso à memória.

Padrão prático de auditoria:
```rust
let private_circuit_bytes = sp1_zkvm::io::read_vec();
let ops = unsafe {
rkyv::access_unchecked::<rkyv::Archived<Vec<Op>>>(&private_circuit_bytes)
};
```
Se um campo como `op.kind` for um enum e um atacante puder injetar um **discriminante fora do intervalo**, todo `match` subsequente sobre esse valor se torna suspeito.

### Jump-table / bypass de contadores por UB

Se o Rust transformar um `match` grande em uma **jump table**, um discriminante de enum inválido poderá produzir **fluxo de controle indefinido**. Um padrão perigoso é:<sup>[[7]](#references)[[9]](#references)</sup>

1. Um `match` atualiza **contadores/restrições críticos para a segurança**.
2. Um segundo `match` executa a **semântica real da instrução**.
3. Um discriminante fora do intervalo indexa além da primeira jump table e chega ao código associado à segunda.

Resultado: a operação ainda é executada, mas o caminho de contabilização é ignorado. Em uma zkVM, isso pode forjar provas que reportam métricas impossíveis, como menos gates, menos operações dispendiosas ou outros recursos limitados falsificados.

Checklist de revisão:

- Procure enums controlados pelo atacante e desserializados a partir de witness/private input.
- Inspecione instruções `match` repetidas sobre o mesmo campo de opcode/kind.
- Considere `unsafe` + desserialização sem verificações + dispatch de opcode grande uma combinação de alto risco.
- Faça engenharia reversa do binário gerado quando necessário; o layout da jump table pode ser mais importante que o código-fonte.

### Restrições semânticas ausentes em interpretadores reversíveis/especializados

Não valide apenas a segurança da memória; valide também as **regras semânticas** que a prova deve impor.

Para conjuntos de instruções reversíveis/semelhantes aos quânticos, garanta que os operandos que devem ser distintos estejam realmente restritos para serem distintos. Uma operação semelhante a Toffoli/CCX implementada como:<sup>[[7]](#references)[[8]](#references)</sup>
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
Isso cria uma **primitiva de reset determinística**, quebrando as suposições de reversibilidade e permitindo computações não pretendidas mais baratas. Em sistemas de prova que atestam o uso de recursos, isso pode permitir que atacantes satisfaçam verificações funcionais enquanto contornam o modelo de custo que o verificador acredita estar sendo aplicado.

### O que testar em sistemas ZK

- Fazer fuzzing de todos os parsers guest com codificações de witness/private-input malformadas.
- Garantir a validação do intervalo de enum antes do opcode dispatch.
- Adicionar verificações semânticas para operand aliasing e outras formas de instruções inválidas.
- Comparar os contadores reportados/públicos com uma implementação de referência independente.
- Lembre-se de que uma prova válida ainda pode provar a **afirmação errada** se o programa guest tiver bugs.

## Exploração de DeFi/AMM

Se você estiver pesquisando a exploração prática de DEXes e AMMs (hooks do Uniswap v4, abuso de arredondamento/precisão, swaps de crossing de limiar amplificados por flash loan), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multiativos que armazenam em cache saldos virtuais e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

## References

- [1] [Proof of stake - Wikipedia](https://en.wikipedia.org/wiki/Proof_of_stake)
- [2] [Chave pública e chave privada explicadas - Mycryptopedia](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [3] [O que são transações multisig? - Bitcoin Stack Exchange](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [4] [Transações | ethereum.org](https://ethereum.org/en/developers/docs/transactions/)
- [5] [Gas e taxas | ethereum.org](https://ethereum.org/en/developers/docs/gas/)
- [6] [Privacidade - Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)
- [7] [Trail of Bits - Superamos a prova de conhecimento zero do Google sobre criptoanálise quântica](https://blog.trailofbits.com/2026/04/17/we-beat-googles-zero-knowledge-proof-of-quantum-cryptanalysis/)
- [8] [Protegendo criptomoedas de curva elíptica contra vulnerabilidades quânticas: estimativas de recursos e mitigações (versão corrigida)](https://arxiv.org/abs/2603.28846v2)
- [9] [Repositório proof-of-concept da Trail of Bits](https://github.com/trailofbits/quantum-zk-proof-poc)
{{#include ../../banners/hacktricks-training.md}}

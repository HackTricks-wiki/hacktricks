# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que executam em uma blockchain quando certas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** são construídas sobre smart contracts, com um front-end amigável ao usuário e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se no sentido em que coins funcionam como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** significam propriedade de ativos.
- **DeFi** significa finanças descentralizadas, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a Plataformas de Exchange Descentralizadas e Organizações Autônomas Descentralizadas.

## Mecanismos de Consenso

Mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificação de transações.
- **Proof of Stake (PoS)** exige que validadores mantenham uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.

## Conceitos Essenciais do Bitcoin

### Transações

As transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.

#### Componentes-chave:

- **Multisignature Transactions** requerem múltiplas assinaturas para autorizar uma transação.
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos miners) e **scripts** (regras da transação).

### Lightning Network

Visa melhorar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um canal, apenas transmitindo o estado final para a blockchain.

## Preocupações de Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao obscurecer ligações de transações entre usuários.

## Aquisição de Bitcoins Anonimamente

Métodos incluem trocas em dinheiro, mineração e uso de mixers. **CoinJoin** mistura múltiplas transações para complicar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações normais para maior privacidade.

# Ataques de Privacidade do Bitcoin

# Resumo dos Ataques de Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente motivo de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade no Bitcoin.

## **Common Input Ownership Assumption**

Geralmente é raro que inputs de diferentes usuários sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação costumam ser assumidos como pertencentes ao mesmo dono**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte for enviada para outro endereço, o restante vai para um novo endereço de change. Observadores podem assumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mixing ou o uso de múltiplos endereços podem ajudar a obscurecer a propriedade.

## **Social Networks & Forums Exposure**

Usuários às vezes compartilham seus endereços de Bitcoin online, tornando **fácil vincular o endereço ao seu proprietário**.

## **Transaction Graph Analysis**

Transações podem ser visualizadas como grafos, revelando conexões potenciais entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística baseia-se em analisar transações com múltiplos inputs e outputs para adivinhar qual output é o change que retorna ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
If adding more inputs makes the change output larger than any single input, it can confuse the heuristic.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Comportamento Correto da Carteira

Carteiras should avoid using coins received on already used, empty addresses to prevent this privacy leak.

## **Outras Técnicas de Análise de Blockchain**

- **Exact Payment Amounts:** Transações sem troco são provavelmente entre dois endereços pertencentes ao mesmo usuário.
- **Round Numbers:** Um número arredondado em uma transação sugere que é um pagamento, com a saída não arredondada provavelmente sendo o troco.
- **Wallet Fingerprinting:** Diferentes carteiras têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e potencialmente o endereço de troco.
- **Amount & Timing Correlations:** Divulgar horários ou valores de transações pode torná-las rastreáveis.

## **Análise de Tráfego**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade do usuário. Isso é especialmente verdadeiro se uma entidade operar muitos nós Bitcoin, aumentando sua capacidade de monitorar transações.

## Mais

Para uma lista abrangente de ataques de privacidade e defesas, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Bitcoin Anônimas

## Maneiras de Obter Bitcoins Anonimamente

- **Cash Transactions**: Adquirir bitcoin com dinheiro.
- **Cash Alternatives**: Comprar cartões-presente e trocá-los online por bitcoin.
- **Mining**: O método mais privado para ganhar bitcoins é através da mineração, especialmente quando feito sozinho, pois pools de mineração podem conhecer o IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Serviços de Mixagem

Ao usar um mixing service, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, o que dificulta rastrear o proprietário original. Ainda assim, isso requer confiar no serviço para não manter registros e para realmente devolver os bitcoins. Opções alternativas de mixagem incluem cassinos Bitcoin.

## CoinJoin

CoinJoin mescla múltiplas transações de diferentes usuários em uma única, complicando o processo para quem tenta casar inputs com outputs. Apesar de sua eficácia, transações com tamanhos únicos de inputs e outputs ainda podem potencialmente ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um serviço similar no Ethereum, confira [Tornado Cash](https://tornado.cash), que anonimiza transações com fundos de miners.

## PayJoin

Uma variante do CoinJoin, PayJoin (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação regular, sem as saídas iguais características do CoinJoin. Isso a torna extremamente difícil de detectar e pode invalidar a common-input-ownership heuristic usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima podem ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis de transações bitcoin padrão.

**A utilização do PayJoin poderia perturbar significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca pela privacidade nas transações.

# Melhores Práticas para Privacidade em Criptomoedas

## **Wallet Synchronization Techniques**

Para manter a privacidade e a segurança, sincronizar wallets com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar toda a blockchain, um full node garante máxima privacidade. Todas as transações já realizadas são armazenadas localmente, tornando impossível para adversários identificarem quais transações ou endereços interessam ao usuário.
- **Client-side block filtering**: Esse método envolve criar filtros para cada bloco na blockchain, permitindo que wallets identifiquem transações relevantes sem expor interesses específicos a observadores da rede. Lightweight wallets baixam esses filtros, buscando blocos completos apenas quando há uma correspondência com os endereços do usuário.

## **Utilizing Tor for Anonymity**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Preventing Address Reuse**

Para proteger a privacidade, é vital usar um novo endereço para cada transação. Reutilizar endereços pode comprometer a privacidade ao ligar transações à mesma entidade. Wallets modernas desencorajam o reuso de endereços pelo seu design.

## **Strategies for Transaction Privacy**

- **Multiple transactions**: Dividir um pagamento em várias transações pode obscurecer o valor da transação, frustrando ataques à privacidade.
- **Change avoidance**: Optar por transações que não requerem change outputs aumenta a privacidade ao interromper métodos de detecção de change.
- **Multiple change outputs**: Se evitar change não for viável, gerar múltiplos change outputs ainda pode melhorar a privacidade.

# **Monero: A Beacon of Anonymity**

Monero atende à necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão de privacidade.

# **Ethereum: Gas and Transactions**

## **Understanding Gas**

Gas mede o esforço computacional necessário para executar operações na Ethereum, precificado em **gwei**. Por exemplo, uma transação que custa 2,310,000 gwei (ou 0.00231 ETH) envolve um gas limit e uma base fee, com uma tip para incentivar os miners. Usuários podem definir uma max fee para garantir que não paguem em excesso, com o excedente sendo reembolsado.

## **Executing Transactions**

Transações na Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de smart contract. Elas exigem uma fee e devem ser mineradas. As informações essenciais em uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, gas limit e fees. Notavelmente, o endereço do remetente é deduzido a partir da assinatura, eliminando a necessidade de incluí‑lo nos dados da transação.

Essas práticas e mecanismos são fundamentais para quem pretende lidar com criptomoedas dando prioridade à privacidade e à segurança.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## References

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## DeFi/AMM Exploitation

If you are researching practical exploitation of DEXes and AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), check:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}

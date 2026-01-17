# Blockchain e Cripto-Moedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que são executados em uma blockchain quando certas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** constroem-se sobre smart contracts, com uma interface front-end amigável ao usuário e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se onde coins servem como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** sinalizam propriedade de ativos.
- **DeFi** significa Decentralized Finance, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Mecanismos de Consenso

Mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para a verificação de transações.
- **Proof of Stake (PoS)** exige que validadores mantenham uma certa quantidade de tokens, reduzindo o consumo de energia em comparação ao PoW.

## Noções Essenciais sobre Bitcoin

### Transações

Transações de Bitcoin envolvem a transferência de fundos entre endereços. Transações são validadas por assinaturas digitais, garantindo que apenas o proprietário da chave privada possa iniciar transferências.

#### Componentes Principais:

- **Multisignature Transactions** requerem múltiplas assinaturas para autorizar uma transação.
- Transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagos aos miners) e **scripts** (regras da transação).

### Lightning Network

Objetiva melhorar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um canal, transmitindo à blockchain apenas o estado final.

## Preocupações de Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao obscuring (ofuscar) os vínculos de transação entre usuários.

## Adquirindo Bitcoins Anonimamente

Métodos incluem trocas em dinheiro, mining e uso de mixers. **CoinJoin** mistura múltiplas transações para complicar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações normais para maior privacidade.

# Ataques de Privacidade do Bitcoin

# Resumo dos Ataques de Privacidade ao Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários frequentemente são motivos de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade no Bitcoin.

## **Common Input Ownership Assumption**

Geralmente é raro que inputs de diferentes usuários sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação são frequentemente assumidos como pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser totalmente gasto em uma transação. Se apenas uma parte dele é enviada para outro endereço, o restante vai para um novo endereço de change. Observadores podem assumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mixing ou o uso de múltiplos endereços podem ajudar a obscurecer a propriedade.

## **Exposição em Redes Sociais & Fóruns**

Usuários às vezes compartilham seus endereços Bitcoin online, tornando **fácil ligar o endereço ao seu proprietário**.

## **Análise do Grafo de Transações**

Transações podem ser visualizadas como grafos, revelando potenciais conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística baseia-se na análise de transações com múltiplos inputs e outputs para adivinhar qual output é o change retornando ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs fizer com que a saída de change seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Attackers may send small amounts to previously used addresses, hoping the recipient combines these with other inputs in future transactions, thereby linking addresses together.

### Correct Wallet Behavior

As carteiras devem evitar usar moedas recebidas em endereços já usados e vazios para prevenir esse privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transações sem change provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Round Numbers:** Um número arredondado em uma transação sugere que se trata de um pagamento, com a saída não arredondada provavelmente sendo o change.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de change.
- **Amount & Timing Correlations:** Divulgar horários ou valores de transações pode torná-las rastreáveis.

## **Traffic Analysis**

Monitorando o tráfego de rede, attackers can potentially link transactions or blocks to IP addresses, comprometendo a privacidade do usuário. Isso é especialmente verdade se uma entidade operar muitos nós Bitcoin, aumentando sua capacidade de monitorar transações.

## More

Para uma lista completa de ataques e defesas de privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Acquiring bitcoin through cash.
- **Cash Alternatives**: Purchasing gift cards and exchanging them online for bitcoin.
- **Mining**: The most private method to earn bitcoins is through mining, especially when done alone because mining pools may know the miner's IP address. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Theoretically, stealing bitcoin could be another method to acquire it anonymously, although it's illegal and not recommended.

## Mixing Services

Ao usar um mixing service, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, o que dificulta traçar o dono original. Ainda assim, isso requer confiar no serviço para que não mantenha logs e para que realmente retorne os bitcoins. Alternativas de mixing incluem casinos de Bitcoin.

## CoinJoin

**CoinJoin** combina múltiplas transações de diferentes usuários em uma só, complicando o processo para quem tenta casar inputs com outputs. Apesar de sua efetividade, transações com tamanhos únicos de inputs e outputs ainda podem ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um serviço similar no Ethereum, confira [Tornado Cash](https://tornado.cash), que anonimiza transações com fundos de miners.

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação normal, sem as saídas iguais características do CoinJoin. Isso a torna extremamente difícil de detectar e pode invalidar a heurística common-input-ownership usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima podem ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis de transações bitcoin padrão.

**A utilização do PayJoin pode desestabilizar significativamente métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca pela privacidade nas transações.

# Melhores Práticas para Privacidade em Criptomoedas

## **Técnicas de Sincronização de Carteiras**

Para manter privacidade e segurança, sincronizar carteiras com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar a blockchain completa, um full node garante privacidade máxima. Todas as transações já realizadas são armazenadas localmente, tornando impossível para adversários identificar quais transações ou endereços interessam ao usuário.
- **Client-side block filtering**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que carteiras identifiquem transações relevantes sem expor interesses específicos a observadores da rede. Carteiras leves baixam esses filtros, buscando blocos completos apenas quando há uma correspondência com os endereços do usuário.

## **Utilizar Tor para Anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção da Reutilização de Endereços**

Para proteger a privacidade, é vital usar um endereço novo para cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Carteiras modernas desestimulam a reutilização de endereços pelo design.

## **Estratégias para Privacidade de Transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode obscurecer o valor, frustrando ataques à privacidade.
- **Evitar outputs de troco**: Optar por transações que não exigem outputs de troco aumenta a privacidade ao dificultar métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se evitar troco não for viável, gerar múltiplos outputs de troco ainda pode melhorar a privacidade.

# **Monero: um Farol de Anonimato**

Monero atende à necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão para privacidade.

# **Ethereum: Gas e Transações**

## **Entendendo o Gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum, cotado em **gwei**. Por exemplo, uma transação custando 2.310.000 gwei (ou 0,00231 ETH) envolve um limite de gas e uma taxa base, com uma gorjeta para incentivar mineradores. Usuários podem definir uma taxa máxima para garantir que não paguem em excesso, com o excedente reembolsado.

## **Executando Transações**

Transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de smart contract. Elas exigem uma taxa e devem ser mineradas. Informações essenciais em uma transação incluem o destinatário, assinatura do remetente, valor, dados opcionais, limite de gas e taxas. Notavelmente, o endereço do remetente é deduzido a partir da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.

Essas práticas e mecanismos são fundamentais para quem deseja lidar com criptomoedas priorizando privacidade e segurança.

## Red Teaming Web3 Centrado em Valor

- Inventariar componentes portadores de valor (signers, oracles, bridges, automation) para entender quem pode mover fundos e como.
- Mapear cada componente às táticas relevantes do MITRE AADAPT para expor caminhos de escalada de privilégios.
- Ensaie cadeias de ataque flash-loan/oracle/credential/cross-chain para validar impacto e documentar pré-condições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Comprometimento do Fluxo de Assinatura Web3

- Manipulação da supply-chain da UI de carteiras pode alterar payloads EIP-712 imediatamente antes da assinatura, colhendo assinaturas válidas para takeovers de proxy baseados em delegatecall (por exemplo, overwrite de slot-0 do Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Segurança de Smart Contracts

- Mutation testing para encontrar pontos cegos nas suítes de teste:

{{#ref}}
../smart-contract-security/mutation-testing-with-slither.md
{{#endref}}

## Referências

- [https://en.wikipedia.org/wiki/Proof_of_stake](https://en.wikipedia.org/wiki/Proof_of_stake)
- [https://www.mycryptopedia.com/public-key-private-key-explained/](https://www.mycryptopedia.com/public-key-private-key-explained/)
- [https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions](https://bitcoin.stackexchange.com/questions/3718/what-are-multi-signature-transactions)
- [https://ethereum.org/en/developers/docs/transactions/](https://ethereum.org/en/developers/docs/transactions/)
- [https://ethereum.org/en/developers/docs/gas/](https://ethereum.org/en/developers/docs/gas/)
- [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy#Forced_address_reuse)

## Exploração DeFi/AMM

Se você está pesquisando exploração prática de DEXes e AMMs (Uniswap v4 hooks, abuso de arredondamento/precisão, swaps de cruzamento de limiar amplificados por flash‑loan), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-ativo que cacheiam saldos virtuais e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}

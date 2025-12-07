# Blockchain e Cripto-Moedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que executam em uma blockchain quando certas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** se baseiam em smart contracts, apresentando uma interface front-end amigável ao usuário e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se onde coins servem como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** sinalizam propriedade de ativos.
- **DeFi** significa Decentralized Finance, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a Decentralized Exchange Platforms e Decentralized Autonomous Organizations.

## Mecanismos de Consenso

Mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para a verificação de transações.
- **Proof of Stake (PoS)** exige que validadores possuam uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.

## Bitcoin Essentials

### Transactions

Transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas através de assinaturas digitais, garantindo que apenas o proprietário da chave privada possa iniciar transferências.

#### Componentes Principais:

- **Multisignature Transactions** exigem múltiplas assinaturas para autorizar uma transação.
- As transações consistem de **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos miners) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um canal, transmitindo para a blockchain apenas o estado final.

## Preocupações de Privacidade do Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** aumentam o anonimato ao obscurecer ligações de transações entre usuários.

## Aquisição Anônima de Bitcoins

Métodos incluem trocas em dinheiro, mining e uso de mixers. **CoinJoin** mistura múltiplas transações para complicar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações comuns para maior privacidade.

# Ataques de Privacidade do Bitcoin

# Sumário dos Ataques de Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários frequentemente são motivo de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade do Bitcoin.

## **Common Input Ownership Assumption**

É geralmente raro que inputs de diferentes usuários sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação são frequentemente assumidos como pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser gasto integralmente em uma transação. Se apenas uma parte dele é enviada para outro endereço, o restante vai para um novo change address. Observadores podem assumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mixing ou o uso de múltiplos endereços podem ajudar a obscurecer a propriedade.

## **Social Networks & Forums Exposure**

Usuários às vezes compartilham seus endereços de Bitcoin online, tornando **fácil vincular o endereço ao seu proprietário**.

## **Transaction Graph Analysis**

Transações podem ser visualizadas como grafos, revelando potenciais conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística é baseada na análise de transações com múltiplos inputs e outputs para adivinhar qual output é o change que retorna ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais entradas fizer com que a saída de troco seja maior do que qualquer entrada individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Atacantes podem enviar pequenas quantias para endereços já usados anteriormente, esperando que o destinatário combine essas quantias com outras entradas em transações futuras, ligando assim os endereços entre si.

### Correct Wallet Behavior

As carteiras devem evitar usar moedas recebidas em endereços já usados e vazios para impedir esse leak de privacidade.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transações sem saída de troco provavelmente ocorrem entre dois endereços pertencentes ao mesmo usuário.
- **Round Numbers:** Um número arredondado em uma transação sugere que é um pagamento, com a saída não arredondada provavelmente sendo o troco.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e potencialmente o endereço de troco.
- **Amount & Timing Correlations:** Divulgar horários ou valores de transações pode tornar as transações rastreáveis.

## **Traffic Analysis**

Ao monitorar o tráfego de rede, atacantes podem potencialmente relacionar transações ou blocos a endereços IP, comprometendo a privacidade do usuário. Isso é especialmente verdadeiro se uma entidade opera muitos nós Bitcoin, aumentando sua capacidade de monitorar transações.

## More

For a comprehensive list of privacy attacks and defenses, visit [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Anônimas de Bitcoin

## Formas de Obter Bitcoins Anonimamente

- **Cash Transactions**: Adquirir bitcoin com dinheiro.
- **Cash Alternatives**: Comprar cartões-presente e trocá-los online por bitcoin.
- **Mining**: O método mais privado para ganhar bitcoins é por meio da mineração, especialmente quando realizada individualmente, porque mining pools podem conhecer o IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, o que torna difícil rastrear o proprietário original. Ainda assim, isso requer confiança de que o serviço não manterá logs e que realmente devolverá os bitcoins. Opções alternativas de mixing incluem cassinos Bitcoin.

## CoinJoin

**CoinJoin** combina múltiplas transações de diferentes usuários em uma só, complicando o processo para quem tenta casar entradas com saídas. Apesar de sua eficácia, transações com tamanhos únicos de entrada e saída ainda podem ser potencialmente rastreadas.

Transações de exemplo que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

For more information, visit [CoinJoin](https://coinjoin.io/en). For a similar service on Ethereum, check out [Tornado Cash](https://tornado.cash), which anonymizes transactions with funds from miners.

## PayJoin

A variant of CoinJoin, **PayJoin** (or P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação regular, sem as saídas iguais distintivas características do CoinJoin. Isso torna extremamente difícil de detectar e pode invalidar a heurística common-input-ownership usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transactions like the above could be PayJoin, enhancing privacy while remaining indistinguishable from standard bitcoin transactions.

**A utilização de PayJoin poderia afetar significativamente os métodos tradicionais de vigilância**, tornando-se um avanço promissor na busca por privacidade transacional.

# Melhores Práticas para Privacidade em Criptomoedas

## **Técnicas de Sincronização de Wallets**

Para manter a privacidade e a segurança, sincronizar wallets com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar toda a blockchain, um full node garante privacidade máxima. Todas as transações já realizadas são armazenadas localmente, tornando impossível para adversários identificar quais transações ou endereços interessam ao usuário.
- **Client-side block filtering**: Este método envolve criar filtros para cada bloco na blockchain, permitindo que wallets identifiquem transações relevantes sem expor interesses específicos a observadores da rede. Wallets leves baixam esses filtros, buscando blocos completos apenas quando há correspondência com os endereços do usuário.

## **Utilizando Tor para Anonimato**

Considerando que Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, melhorando a privacidade ao interagir com a rede.

## **Prevenção de Reutilização de Endereços**

Para proteger a privacidade, é vital usar um novo endereço para cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Wallets modernas desencorajam a reutilização de endereços por design.

## **Estratégias para Privacidade de Transações**

- **Multiple transactions**: Dividir um pagamento em várias transações pode obscurecer o valor da transação, frustrando ataques à privacidade.
- **Change avoidance**: Optar por transações que não exigem change outputs aumenta a privacidade ao dificultar métodos de detecção de change.
- **Multiple change outputs**: Se evitar change não for viável, gerar múltiplos change outputs ainda pode melhorar a privacidade.

# **Monero: Um Farol de Anonimato**

Monero responde à necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão para privacidade.

# **Ethereum: Gas e Transações**

## **Entendendo o Gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum, precificado em **gwei**. Por exemplo, uma transação que custa 2,310,000 gwei (ou 0.00231 ETH) envolve um gas limit e uma base fee, com um tip para incentivar miners. Usuários podem definir um max fee para garantir que não paguem demais, com o excedente reembolsado.

## **Executando Transações**

Transações no Ethereum envolvem um sender e um recipient, que podem ser endereços de usuário ou smart contract. Elas exigem uma fee e precisam ser mined. Informações essenciais em uma transação incluem o recipient, a assinatura do sender, o value, dados opcionais, gas limit e fees. Notavelmente, o endereço do sender é deduzido a partir da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.

Essas práticas e mecanismos são fundamentais para quem deseja usar criptomoedas priorizando privacidade e segurança.

## Smart Contract Security

- Mutation testing to find blind spots in test suites:

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

Se você está pesquisando exploração prática de DEXes e AMMs (Uniswap v4 hooks, rounding/precision abuse, flash‑loan amplified threshold‑crossing swaps), consulte:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-asset que cacheiam virtual balances e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}

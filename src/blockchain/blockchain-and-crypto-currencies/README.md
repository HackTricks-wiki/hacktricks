# Blockchain e Cripto-Moedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que executam em uma blockchain quando certas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** são construídas sobre smart contracts, apresentando um front-end amigável ao usuário e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se: coins servem como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** sinalizam posse de ativos.
- **DeFi** significa Finanças Descentralizadas, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se, respectivamente, a Plataformas de Exchange Descentralizadas e Organizações Autônomas Descentralizadas.

## Mecanismos de Consenso

Os mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificação de transações.
- **Proof of Stake (PoS)** exige que validadores mantenham uma certa quantidade de tokens, reduzindo o consumo de energia em comparação com PoW.

## Noções Essenciais do Bitcoin

### Transações

Transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas através de assinaturas digitais, garantindo que apenas o proprietário da chave privada possa iniciar transferências.

#### Componentes-chave:

- **Multisignature Transactions** requerem múltiplas assinaturas para autorizar uma transação.
- Transações consistem em **inputs** (fonte dos fundos), **outputs** (destino), **fees** (pagas aos miners) e **scripts** (regras da transação).

### Lightning Network

Tem como objetivo melhorar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um canal, apenas transmitindo o estado final para a blockchain.

## Preocupações com a Privacidade no Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transação. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao obscurecer ligações de transações entre usuários.

## Como Adquirir Bitcoins Anonimamente

Métodos incluem trocas em dinheiro, mineração e uso de mixers. **CoinJoin** mistura múltiplas transações para complicar o rastreamento, enquanto **PayJoin** disfarça CoinJoins como transações regulares para maior privacidade.

# Ataques de Privacidade do Bitcoin

# Resumo dos Ataques de Privacidade do Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários frequentemente são motivos de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade no Bitcoin.

## **Common Input Ownership Assumption**

Geralmente é raro que inputs de diferentes usuários sejam combinados em uma única transação devido à complexidade envolvida. Assim, **duas addresses de input na mesma transação são frequentemente assumidas como pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser gasto integralmente em uma transação. Se apenas uma parte dele é enviada para outro endereço, o restante vai para um novo endereço de mudança (change address). Observadores podem assumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mixagem ou o uso de múltiplos endereços podem ajudar a obscurecer a propriedade.

## **Social Networks & Forums Exposure**

Usuários às vezes compartilham seus endereços Bitcoin online, tornando **fácil vincular o endereço ao seu proprietário**.

## **Transaction Graph Analysis**

Transações podem ser visualizadas como grafos, revelando potenciais conexões entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística baseia-se na análise de transações com múltiplos inputs e outputs para adivinhar qual output é a mudança retornando ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs fizer com que a saída de troco seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Os atacantes podem enviar pequenas quantias para endereços previamente usados, na esperança de que o destinatário combine esses valores com outros inputs em transações futuras, vinculando assim os endereços entre si.

### Correct Wallet Behavior

As wallets devem evitar usar moedas recebidas em endereços já usados e vazios para prevenir esse privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transações sem change são provavelmente entre dois endereços pertencentes ao mesmo usuário.
- **Round Numbers:** Um número redondo em uma transação sugere que é um pagamento, com a saída não redonda provavelmente sendo o troco.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de change.
- **Amount & Timing Correlations:** Divulgar horários ou valores de transações pode tornar transações rastreáveis.

## **Traffic Analysis**

Ao monitorar o tráfego de rede, atacantes podem potencialmente vincular transações ou blocos a endereços IP, comprometendo a privacidade do usuário. Isso é especialmente verdadeiro se uma entidade operar muitos nós Bitcoin, aumentando sua capacidade de monitorar transações.

## More

Para uma lista abrangente de ataques e defesas de privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin em dinheiro.
- **Cash Alternatives**: Comprar gift cards e trocá-los online por bitcoin.
- **Mining**: O método mais privado para ganhar bitcoins é através da mineração, especialmente quando feita sozinho, pois pools de mineração podem conhecer o IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um serviço de mixagem, um usuário pode **enviar bitcoins** e receber **bitcoins diferentes em troca**, o que dificulta rastrear o proprietário original. Ainda assim, isso exige confiança no serviço para que não mantenha logs e para que realmente devolva os bitcoins. Opções alternativas de mixagem incluem cassinos de Bitcoin.

## CoinJoin

**CoinJoin** mescla múltiplas transações de diferentes usuários em uma só, complicando o processo para quem tenta relacionar inputs com outputs. Apesar de sua efetividade, transações com tamanhos únicos de input e output ainda podem ser potencialmente rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um serviço similar no Ethereum, confira [Tornado Cash](https://tornado.cash), que anonimiza transações com fundos de miners.

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação normal, sem as saídas iguais características do CoinJoin. Isso a torna extremamente difícil de detectar e pode invalidar a heurística de common-input-ownership usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima podem ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis de transações bitcoin padrão.

**A utilização do PayJoin poderia atrapalhar significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca pela privacidade nas transações.

# Melhores Práticas para Privacidade em Criptomoedas

## **Técnicas de Sincronização de Carteiras**

Para manter a privacidade e a segurança, sincronizar carteiras com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar a blockchain inteira, um full node assegura privacidade máxima. Todas as transações já realizadas são armazenadas localmente, tornando impossível para adversários identificar em quais transações ou endereços o usuário está interessado.
- **Client-side block filtering**: Este método envolve criar filtros para cada bloco da blockchain, permitindo que as carteiras identifiquem transações relevantes sem expor interesses específicos a observadores da rede. Carteiras leves baixam esses filtros, buscando os blocos completos apenas quando há uma correspondência com os endereços do usuário.

## **Utilizando Tor para Anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar o Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção de Reutilização de Endereços**

Para proteger a privacidade, é vital usar um novo endereço para cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Carteiras modernas desencorajam a reutilização de endereços por meio do seu design.

## **Estratégias para Privacidade de Transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode obscurecer o valor transferido, frustrando ataques à privacidade.
- **Evitar outputs de troco**: Optar por transações que não exigem outputs de troco melhora a privacidade, dificultando métodos de detecção de change.
- **Múltiplos outputs de troco**: Se evitar troco não for viável, gerar múltiplos outputs de troco ainda pode aprimorar a privacidade.

# **Monero: Um Farol de Anonimato**

Monero atende à necessidade de anonimato absoluto em transações digitais, estabelecendo um padrão elevado para privacidade.

# **Ethereum: Gas e Transações**

## **Entendendo o Gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum, precificado em **gwei**. Por exemplo, uma transação custando 2,310,000 gwei (ou 0.00231 ETH) envolve um gas limit e uma base fee, com uma tip para incentivar os miners. Usuários podem definir uma max fee para garantir que não paguem demais, com o excedente sendo reembolsado.

## **Executando Transações**

Transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de contrato inteligente. Elas exigem uma taxa e devem ser mineradas. Informações essenciais em uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, gas limit e taxas. Notavelmente, o endereço do remetente é deduzido a partir da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.

Essas práticas e mecanismos são fundamentais para quem pretende interagir com criptomoedas priorizando privacidade e segurança.

## Value-Centric Web3 Red Teaming

- Inventariar componentes que carregam valor (signers, oracles, bridges, automation) para entender quem pode mover fundos e como.
- Mapear cada componente para táticas MITRE AADAPT relevantes para expor caminhos de escalonamento de privilégios.
- Ensaiar cadeias de ataque flash-loan/oracle/credential/cross-chain para validar impacto e documentar pré-condições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Web3 Signing Workflow Compromise

- O comprometimento da cadeia de suprimentos das UI de wallet pode mutar payloads EIP-712 imediatamente antes da assinatura, colhendo assinaturas válidas para takeover de proxy baseado em delegatecall (ex.: sobrescrever slot-0 do Safe masterCopy).

{{#ref}}
web3-signing-workflow-compromise-safe-delegatecall-proxy-takeover.md
{{#endref}}

## Account Abstraction (ERC-4337)

- Modos comuns de falha de smart-account incluem burlar o controle de acesso de `EntryPoint`, campos de gas não assinados, validação stateful, replay ERC-1271, e drenagem de taxas via revert-after-validation.

{{#ref}}
erc-4337-smart-account-security-pitfalls.md
{{#endref}}

## Smart Contract Security

- Mutation testing para encontrar pontos cegos em suítes de teste:

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

## DeFi/AMM Exploitation

Se você está pesquisando exploração prática de DEXes e AMMs (Uniswap v4 hooks, abuso de rounding/precision, swaps amplificados por flash‑loan que ultrapassam thresholds), veja:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-ativo que cacheiam saldos virtuais e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}

# Blockchain e Criptomoedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que são executados em uma blockchain quando certas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** são construídas sobre Smart Contracts, apresentando uma interface front-end amigável ao usuário e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se onde coins servem como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** representam propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se a Plataformas de Exchange Descentralizadas e Organizações Autônomas Descentralizadas, respectivamente.

## Mecanismos de Consenso

Mecanismos de consenso asseguram validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** depende de poder computacional para verificação de transações.
- **Proof of Stake (PoS)** exige que validadores possuam uma certa quantidade de tokens, reduzindo o consumo de energia comparado ao PoW.

## Essenciais do Bitcoin

### Transações

Transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por assinaturas digitais, garantindo que apenas o proprietário da chave privada possa iniciar transferências.

#### Componentes Principais:

- **Multisignature Transactions** requerem múltiplas assinaturas para autorizar uma transação.
- Transações consistem de **inputs** (fonte dos fundos), **outputs** (destino), **fees** (pagos aos miners), e **scripts** (regras da transação).

### Lightning Network

Visa aumentar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um canal, transmitindo para a blockchain apenas o estado final.

## Preocupações com Privacidade no Bitcoin

Ataques à privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao obscurecer os vínculos das transações entre usuários.

## Aquisição Anônima de Bitcoins

Métodos incluem trocas em dinheiro, mineração e uso de mixers. **CoinJoin** mistura múltiplas transações para complicar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações regulares para aumentar a privacidade.

# Ataques de Privacidade do Bitcoin

# Resumo dos Ataques de Privacidade no Bitcoin

No mundo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente motivo de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade no Bitcoin.

## **Common Input Ownership Assumption**

Geralmente é raro que inputs de diferentes usuários sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de input na mesma transação são frequentemente assumidos como pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Um UTXO, ou **Unspent Transaction Output**, deve ser gasto totalmente em uma transação. Se apenas parte dele for enviada para outro endereço, o restante vai para um novo change address. Observadores podem assumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mistura (mixing) ou o uso de múltiplos endereços podem ajudar a obscurecer a propriedade.

## **Social Networks & Forums Exposure**

Usuários às vezes compartilham seus endereços de Bitcoin online, tornando **fácil vincular o endereço ao seu proprietário**.

## **Transaction Graph Analysis**

Transações podem ser visualizadas como grafos, revelando conexões potenciais entre usuários com base no fluxo de fundos.

## **Unnecessary Input Heuristic (Optimal Change Heuristic)**

Essa heurística baseia-se na análise de transações com múltiplos inputs e outputs para adivinhar qual output é o troco retornando ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs faz com que a saída de troco seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Atacantes podem enviar pequenas quantias para endereços previamente usados, na esperança de que o destinatário combine essas quantias com outras entradas em transações futuras, ligando assim os endereços.

### Comportamento Correto da Wallet

Wallets devem evitar usar moedas recebidas em endereços vazios já usados para prevenir esse leak de privacidade.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transações sem troco são provavelmente entre dois endereços pertencentes ao mesmo usuário.
- **Round Numbers:** Um número arredondado em uma transação sugere que é um pagamento, sendo a saída não arredondada provavelmente o troco.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e potencialmente o endereço de troco.
- **Amount & Timing Correlations:** Divulgar horários ou quantias de transação pode tornar as transações rastreáveis.

## **Traffic Analysis**

Ao monitorar o tráfego de rede, atacantes podem potencialmente ligar transações ou blocos a endereços IP, comprometendo a privacidade do usuário. Isso é especialmente verdadeiro se uma entidade opera muitos Bitcoin nodes, aumentando sua capacidade de monitorar transações.

## More

Para uma lista abrangente de ataques e defesas de privacidade, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Anonymous Bitcoin Transactions

## Ways to Get Bitcoins Anonymously

- **Cash Transactions**: Adquirir bitcoin em dinheiro.
- **Cash Alternatives**: Comprar cartões-presente e trocá-los online por bitcoin.
- **Mining**: O método mais privado para ganhar bitcoins é através da mineração, especialmente quando feito sozinho, pois mining pools podem conhecer o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, roubar bitcoin poderia ser outro método de adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um mixing service, um usuário pode enviar bitcoins e receber bitcoins diferentes em troca, o que dificulta traçar o proprietário original. Ainda assim, isso exige confiar que o serviço não mantenha logs e que realmente devolva os bitcoins. Opções alternativas de mixing incluem cassinos de Bitcoin.

## CoinJoin

CoinJoin combina múltiplas transações de diferentes usuários em uma só, complicando o processo para quem tenta casar inputs com outputs. Apesar de sua eficácia, transações com tamanhos de input e output únicos ainda podem, potencialmente, ser rastreadas.

Exemplos de transações que podem ter usado CoinJoin incluem `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um serviço similar no Ethereum, confira [Tornado Cash](https://tornado.cash), que anonimiza transações com fundos de miners.

## PayJoin

Uma variante do CoinJoin, PayJoin (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação regular, sem as saídas iguais características do CoinJoin. Isso a torna extremamente difícil de detectar e pode invalidar a common-input-ownership heuristic usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima podem ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis de transações bitcoin padrão.

**A utilização do PayJoin poderia perturbar significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca por privacidade transacional.

# Melhores Práticas para Privacidade em Criptomoedas

## **Técnicas de Sincronização de Carteiras**

Para manter privacidade e segurança, sincronizar carteiras com a blockchain é crucial. Dois métodos se destacam:

- **Full node**: Ao baixar a blockchain inteira, um nó completo garante privacidade máxima. Todas as transações já feitas são armazenadas localmente, tornando impossível para adversários identificar em quais transações ou endereços o usuário tem interesse.
- **Client-side block filtering**: Esse método envolve criar filtros para cada bloco na blockchain, permitindo que carteiras identifiquem transações relevantes sem expor interesses específicos a observadores da rede. Carteiras leves baixam esses filtros, buscando os blocos completos apenas quando há uma correspondência com os endereços do usuário.

## **Utilizar Tor para Anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção da Reutilização de Endereços**

Para proteger a privacidade, é vital usar um novo endereço para cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Carteiras modernas desencorajam a reutilização de endereços por meio de seu design.

## **Estratégias para Privacidade de Transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode obscurecer o valor, frustrando ataques à privacidade.
- **Evitar outputs de troco**: Optar por transações que não requerem outputs de troco melhora a privacidade, dificultando métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se evitar troco não for viável, gerar múltiplos outputs de troco ainda pode melhorar a privacidade.

# **Monero: Um Farol de Anonimato**

Monero atende à necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão de privacidade.

# **Ethereum: Gas e Transações**

## **Entendendo o Gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum, cotado em **gwei**. Por exemplo, uma transação que custa 2,310,000 gwei (ou 0,00231 ETH) envolve um gas limit e uma base fee, com uma tip para incentivar os miners. Usuários podem definir um max fee para garantir que não paguem a mais, com o excedente reembolsado.

## **Executando Transações**

Transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou de smart contracts. Elas requerem uma fee e devem ser mineradas. Informações essenciais em uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, gas limit e fees. Notavelmente, o endereço do remetente é deduzido a partir da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.

Essas práticas e mecanismos são fundamentais para qualquer pessoa que queira interagir com criptomoedas priorizando privacidade e segurança.

## Value-Centric Web3 Red Teaming

- Inventariar componentes que detêm valor (signers, oracles, bridges, automation) para entender quem pode mover fundos e como.
- Mapear cada componente para táticas MITRE AADAPT relevantes para expor caminhos de escalonamento de privilégio.
- Ensaie cadeias de ataque flash-loan/oracle/credential/cross-chain para validar impacto e documentar pré-condições exploráveis.

{{#ref}}
value-centric-web3-red-teaming.md
{{#endref}}

## Segurança de Smart Contracts

- Testes de mutação para encontrar pontos cegos nas suítes de teste:

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

Se você está pesquisando exploração prática de DEXes e AMMs (Uniswap v4 hooks, abuso de arredondamento/precisão, swaps que atravessam limites amplificados por flash‑loan), confira:

{{#ref}}
defi-amm-hook-precision.md
{{#endref}}

Para pools ponderados multi-ativos que fazem cache de saldos virtuais e podem ser envenenados quando `supply == 0`, estude:

{{#ref}}
defi-amm-virtual-balance-cache-exploitation.md
{{#endref}}

{{#include ../../banners/hacktricks-training.md}}

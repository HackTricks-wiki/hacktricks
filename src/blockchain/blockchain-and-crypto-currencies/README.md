# Blockchain e Cripto-moedas

{{#include ../../banners/hacktricks-training.md}}

## Conceitos Básicos

- **Smart Contracts** são definidos como programas que são executados em uma blockchain quando certas condições são atendidas, automatizando a execução de acordos sem intermediários.
- **Decentralized Applications (dApps)** são construídas sobre smart contracts, apresentando um front-end amigável ao usuário e um back-end transparente e auditável.
- **Tokens & Coins** diferenciam-se: coins servem como dinheiro digital, enquanto tokens representam valor ou propriedade em contextos específicos.
- **Utility Tokens** concedem acesso a serviços, e **Security Tokens** indicam propriedade de ativos.
- **DeFi** significa Finanças Descentralizadas, oferecendo serviços financeiros sem autoridades centrais.
- **DEX** e **DAOs** referem-se a Plataformas de Exchange Descentralizadas e Organizações Autônomas Descentralizadas, respectivamente.

## Mecanismos de Consenso

Mecanismos de consenso garantem validações de transações seguras e acordadas na blockchain:

- **Proof of Work (PoW)** baseia-se em poder computacional para verificação de transações.
- **Proof of Stake (PoS)** exige que validadores detenham uma certa quantidade de tokens, reduzindo o consumo de energia comparado ao PoW.

## Conceitos Essenciais do Bitcoin

### Transações

Transações de Bitcoin envolvem a transferência de fundos entre endereços. As transações são validadas por assinaturas digitais, garantindo que somente o proprietário da chave privada possa iniciar transferências.

#### Componentes Principais:

- **Multisignature Transactions** requerem múltiplas assinaturas para autorizar uma transação.
- As transações consistem em **inputs** (origem dos fundos), **outputs** (destino), **fees** (pagas aos mineradores) e **scripts** (regras da transação).

### Lightning Network

Visa melhorar a escalabilidade do Bitcoin permitindo múltiplas transações dentro de um canal, transmitindo à blockchain apenas o estado final.

## Preocupações de Privacidade no Bitcoin

Ataques de privacidade, como **Common Input Ownership** e **UTXO Change Address Detection**, exploram padrões de transações. Estratégias como **Mixers** e **CoinJoin** melhoram o anonimato ao obscurecer os vínculos de transações entre usuários.

## Adquirir Bitcoins Anonimamente

Métodos incluem troca em dinheiro, mineração e uso de mixers. **CoinJoin** mistura múltiplas transações para complicar a rastreabilidade, enquanto **PayJoin** disfarça CoinJoins como transações regulares para maior privacidade.

# Ataques de Privacidade no Bitcoin

# Resumo dos Ataques de Privacidade no Bitcoin

No universo do Bitcoin, a privacidade das transações e o anonimato dos usuários são frequentemente motivo de preocupação. Aqui está uma visão simplificada de vários métodos comuns pelos quais atacantes podem comprometer a privacidade no Bitcoin.

## **Common Input Ownership Assumption**

Geralmente é raro que inputs de diferentes usuários sejam combinados em uma única transação devido à complexidade envolvida. Assim, **dois endereços de entrada na mesma transação são frequentemente assumidos como pertencentes ao mesmo proprietário**.

## **UTXO Change Address Detection**

Uma UTXO, ou **Saída de Transação Não Gasta**, deve ser totalmente gasta em uma transação. Se apenas uma parte for enviada para outro endereço, o restante vai para um novo endereço de troco. Observadores podem assumir que esse novo endereço pertence ao remetente, comprometendo a privacidade.

### Exemplo

Para mitigar isso, serviços de mixagem ou o uso de múltiplos endereços podem ajudar a obscurecer a propriedade.

## **Exposição em Redes Sociais e Fóruns**

Usuários às vezes compartilham seus endereços Bitcoin online, tornando **fácil vincular o endereço ao seu proprietário**.

## **Análise de Grafo de Transações**

Transações podem ser visualizadas como grafos, revelando conexões potenciais entre usuários com base no fluxo de fundos.

## **Heurística de Entrada Desnecessária (Heurística de Troco Ótimo)**

Essa heurística baseia-se em analisar transações com múltiplas entradas e saídas para adivinhar qual saída é o troco que retorna ao remetente.

### Exemplo
```bash
2 btc --> 4 btc
3 btc     1 btc
```
Se adicionar mais inputs fizer com que a saída de change seja maior do que qualquer input individual, isso pode confundir a heurística.

## **Forced Address Reuse**

Atacantes podem enviar pequenas quantias para endereços já usados, esperando que o destinatário combine essas quantias com outros inputs em transações futuras, ligando os endereços entre si.

### Comportamento correto da wallet

As carteiras devem evitar usar moedas recebidas em endereços já usados e vazios para prevenir este privacy leak.

## **Other Blockchain Analysis Techniques**

- **Exact Payment Amounts:** Transações sem change provavelmente são entre dois endereços pertencentes ao mesmo usuário.
- **Round Numbers:** Um número arredondado em uma transação sugere que é um pagamento, com a saída não arredondada provavelmente sendo o change.
- **Wallet Fingerprinting:** Diferentes wallets têm padrões únicos de criação de transações, permitindo que analistas identifiquem o software usado e, potencialmente, o endereço de change.
- **Amount & Timing Correlations:** Divulgar os horários ou valores das transações pode torná-las rastreáveis.

## **Traffic Analysis**

Ao monitorar o tráfego de rede, atacantes podem potencialmente ligar transações ou blocos a endereços IP, comprometendo a privacidade do usuário. Isso é especialmente verdadeiro se uma entidade opera muitos nós Bitcoin, aumentando sua capacidade de monitorar transações.

## Mais

Para uma lista abrangente de ataques à privacidade e defesas, visite [Bitcoin Privacy on Bitcoin Wiki](https://en.bitcoin.it/wiki/Privacy).

# Transações Bitcoin Anônimas

## Formas de Obter Bitcoins de Forma Anônima

- **Cash Transactions**: Adquirir bitcoin em dinheiro.
- **Cash Alternatives**: Comprar gift cards e trocá-los online por bitcoin.
- **Mining**: O método mais privado para ganhar bitcoins é através de mining, especialmente quando feito sozinho, porque mining pools podem conhecer o endereço IP do minerador. [Mining Pools Information](https://en.bitcoin.it/wiki/Pooled_mining)
- **Theft**: Teoricamente, roubar bitcoin poderia ser outro método para adquiri-lo anonimamente, embora seja ilegal e não recomendado.

## Mixing Services

Ao usar um serviço de mixing, um usuário pode **enviar bitcoins** e **receber bitcoins diferentes em retorno**, o que dificulta rastrear o proprietário original. Porém, isso requer confiar que o serviço não mantenha logs e que de fato devolva os bitcoins. Opções alternativas de mixing incluem cassinos Bitcoin.

## CoinJoin

CoinJoin mescla múltiplas transações de diferentes usuários em uma só, complicando o processo para quem tenta casar inputs com outputs. Apesar da sua eficácia, transações com tamanhos únicos de inputs e outputs ainda podem ser rastreadas.

Example transactions that may have used CoinJoin include `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` and `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

Para mais informações, visite [CoinJoin](https://coinjoin.io/en). Para um serviço similar no Ethereum, veja [Tornado Cash](https://tornado.cash), que anonimiza transações com fundos de mineradores.

## PayJoin

Uma variante do CoinJoin, **PayJoin** (ou P2EP), disfarça a transação entre duas partes (por exemplo, um cliente e um comerciante) como uma transação normal, sem as saídas iguais distintivas características do CoinJoin. Isso a torna extremamente difícil de detectar e pode invalidar a heurística de common-input-ownership usada por entidades de vigilância de transações.
```plaintext
2 btc --> 3 btc
5 btc     4 btc
```
Transações como a acima podem ser PayJoin, aumentando a privacidade enquanto permanecem indistinguíveis de transações padrão do bitcoin.

**O uso do PayJoin poderia perturbar significativamente os métodos tradicionais de vigilância**, tornando-o um desenvolvimento promissor na busca pela privacidade transacional.

# Melhores Práticas de Privacidade em Criptomoedas

## **Técnicas de Sincronização de Carteiras**

Para manter privacidade e segurança, sincronizar carteiras com a blockchain é crucial. Dois métodos se destacam:

- **Nó completo**: Ao baixar a blockchain inteira, um nó completo garante privacidade máxima. Todas as transações já realizadas são armazenadas localmente, tornando impossível para adversários identificar quais transações ou endereços interessam ao usuário.
- **Filtragem de blocos no lado do cliente**: Esse método envolve criar filtros para cada bloco da blockchain, permitindo que carteiras identifiquem transações relevantes sem expor interesses específicos aos observadores da rede. Carteiras leves baixam esses filtros, buscando blocos completos apenas quando há uma correspondência com os endereços do usuário.

## **Usando Tor para Anonimato**

Como o Bitcoin opera em uma rede peer-to-peer, recomenda-se usar Tor para mascarar seu endereço IP, aumentando a privacidade ao interagir com a rede.

## **Prevenção da Reutilização de Endereços**

Para proteger a privacidade, é vital usar um endereço novo para cada transação. Reutilizar endereços pode comprometer a privacidade ao vincular transações à mesma entidade. Carteiras modernas desencorajam a reutilização de endereços por design.

## **Estratégias para Privacidade de Transações**

- **Múltiplas transações**: Dividir um pagamento em várias transações pode obscurecer o valor da transação, frustrando ataques de privacidade.
- **Evitar outputs de troco**: Optar por transações que não exigem outputs de troco aumenta a privacidade ao atrapalhar métodos de detecção de troco.
- **Múltiplos outputs de troco**: Se evitar troco não for viável, gerar múltiplos outputs de troco ainda pode melhorar a privacidade.

# **Monero: Um Farol de Anonimato**

Monero atende à necessidade de anonimato absoluto em transações digitais, estabelecendo um alto padrão para privacidade.

# **Ethereum: Gas e Transações**

## **Entendendo o Gas**

Gas mede o esforço computacional necessário para executar operações no Ethereum, precificado em **gwei**. Por exemplo, uma transação custando 2,310,000 gwei (ou 0.00231 ETH) envolve um gas limit e uma base fee, com uma tip para incentivar os miners. Usuários podem definir um max fee para garantir que não paguem em excesso, com o excedente sendo reembolsado.

## **Executando Transações**

Transações no Ethereum envolvem um remetente e um destinatário, que podem ser endereços de usuário ou smart contract. Elas exigem uma taxa e devem ser mineradas. Informações essenciais em uma transação incluem o destinatário, a assinatura do remetente, o valor, dados opcionais, gas limit e taxas. Notavelmente, o endereço do remetente é deduzido a partir da assinatura, eliminando a necessidade de incluí-lo nos dados da transação.

Essas práticas e mecanismos são fundamentais para qualquer pessoa que deseje interagir com criptomoedas priorizando privacidade e segurança.

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

{{#include ../../banners/hacktricks-training.md}}

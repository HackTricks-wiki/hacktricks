<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>


# Terminologia Básica

* **Contrato inteligente**: Contratos inteligentes são simplesmente **programas armazenados em um blockchain que são executados quando condições predeterminadas são atendidas**. Eles geralmente são usados para automatizar a **execução** de um **acordo** para que todos os participantes possam ter certeza imediata do resultado, sem envolvimento ou perda de tempo de qualquer intermediário. (De [aqui](https://www.ibm.com/topics/smart-contracts)).
  * Basicamente, um contrato inteligente é um **pedaço de código** que será executado quando as pessoas acessarem e aceitarem o contrato. Contratos inteligentes **rodam em blockchains** (então os resultados são armazenados de forma imutável) e podem ser lidos pelas pessoas antes de aceitá-los.
* **dApps**: **Aplicativos descentralizados** são implementados em cima de **contratos inteligentes**. Eles geralmente têm uma interface onde o usuário pode interagir com o aplicativo, o **back-end** é público (para que possa ser auditado) e é implementado como um **contrato inteligente**. Às vezes, é necessário o uso de um banco de dados, o blockchain Ethereum aloca um determinado armazenamento para cada conta.
* **Tokens e moedas**: Uma **moeda** é uma criptomoeda que age como **dinheiro digital** e um **token** é algo que **representa** algum **valor**, mas não é uma moeda.
  * **Tokens de utilidade**: Esses tokens permitem que o usuário **acessa determinado serviço posteriormente** (é algo que tem algum valor em um ambiente específico).
  * **Tokens de segurança**: Eles representam a **propriedade** ou algum ativo.
* **DeFi**: **Finanças Descentralizadas**.
* **DEX: Plataformas de troca descentralizadas**.
* **DAOs**: **Organizações Autônomas Descentralizadas**.

# Mecanismos de Consenso

Para que uma transação em blockchain seja reconhecida, ela deve ser **anexada** ao **blockchain**. Validadores (mineradores) realizam essa anexação; na maioria dos protocolos, eles **recebem uma recompensa** por fazê-lo. Para que o blockchain permaneça seguro, ele deve ter um mecanismo para **impedir que um usuário ou grupo mal-intencionado assuma a maioria da validação**.

O Proof of Work, outro mecanismo de consenso comumente usado, usa uma validação de habilidade computacional para verificar transações, exigindo que um potencial atacante adquira uma grande fração do poder computacional da rede de validadores.

## Prova de Trabalho (PoW)

Isso usa uma **validação de habilidade computacional** para verificar transações, exigindo que um potencial atacante adquira uma grande fração do poder computacional da rede de validadores.\
Os **mineradores** vão **selecionar várias transações** e, em seguida, começar a **calcular a Prova de Trabalho**. O **minerador com os maiores recursos computacionais** é mais provável que **termine mais cedo** a Prova de Trabalho e obtenha as taxas de todas as transações.

## Prova de Participação (PoS)

PoS realiza isso exigindo que os validadores tenham alguma quantidade de tokens de blockchain, exigindo que **potenciais atacantes adquiram uma grande fração dos tokens** no blockchain para montar um ataque.\
Nesse tipo de consenso, quanto mais tokens um minerador tiver, mais provavelmente será que o minerador será solicitado a criar o próximo bloco.\
Comparado com PoW, isso reduziu muito o consumo de energia que os mineradores estão gastando.

# Bitcoin

## Transações

Uma **transação** simples é um **movimento de dinheiro** de um endereço para outro.\
Um **endereço** em bitcoin é o hash da **chave pública**, portanto, alguém para fazer uma transação de um endereço precisa saber a chave privada associada a essa chave pública (o endereço).\
Então, quando uma **transação** é realizada, ela é **assinada** com a chave privada do endereço para mostrar que a transação é **legítima**.

A primeira parte da produção de uma assinatura digital no Bitcoin pode ser representada matematicamente da seguinte maneira:\
_**Sig**_ = _**Fsig**_(_**Fhash**_(_**m**_),_**dA**_)

Onde:

* \_d\_A é a chave privada de assinatura
* _m_ é a **transação**
* F
## Detecção de Endereço de Troco UTXO

**UTXO** significa **Unspent Transaction Outputs** (Saídas de Transações Não Gastas). Em uma transação que usa a saída de uma transação anterior como entrada, **toda a saída precisa ser gasta** (para evitar ataques de gasto duplo). Portanto, se a intenção era **enviar** apenas **parte** do dinheiro dessa saída para um endereço e **manter** a **outra parte**, **2 saídas diferentes** aparecerão: a **pretendida** e um **novo endereço de troco aleatório** onde o restante do dinheiro será salvo.

Assim, um observador pode assumir que **o novo endereço de troco gerado pertence ao proprietário do UTXO**.

## Redes Sociais e Fóruns

Algumas pessoas fornecem dados sobre seus endereços de bitcoin em diferentes sites na Internet. **Isso torna bastante fácil identificar o proprietário de um endereço**.

## Gráficos de Transações

Ao representar as transações em gráficos, é possível saber com certa probabilidade para onde foi o dinheiro de uma conta. Portanto, é possível saber algo sobre **usuários** que estão **relacionados** na blockchain.

## **Heurística de entrada desnecessária**

Também chamada de "heurística de troco ótimo". Considere esta transação de bitcoin. Ela tem duas entradas no valor de 2 BTC e 3 BTC e duas saídas no valor de 4 BTC e 1 BTC.
```
2 btc --> 4 btc
3 btc     1 btc
```
Supondo que uma das saídas é o troco e a outra saída é o pagamento. Existem duas interpretações: a saída de pagamento é ou a saída de 4 BTC ou a saída de 1 BTC. Mas se a saída de 1 BTC for o valor do pagamento, então a entrada de 3 BTC é desnecessária, já que a carteira poderia ter gasto apenas a entrada de 2 BTC e pago taxas de mineração mais baixas por isso. Isso é uma indicação de que a saída real de pagamento é de 4 BTC e que 1 BTC é a saída de troco.

Isso é um problema para transações que possuem mais de uma entrada. Uma maneira de corrigir essa falha é adicionar mais entradas até que a saída de troco seja maior do que qualquer entrada, por exemplo:
```
2 btc --> 4 btc
3 btc     6 btc
5 btc
```
## Reutilização forçada de endereço

A **reutilização forçada de endereço** ou **reutilização incentivada de endereço** ocorre quando um adversário paga uma pequena quantia de bitcoin para endereços que já foram usados na blockchain. O adversário espera que os usuários ou seus softwares de carteira **usem os pagamentos como entradas para uma transação maior que revelará outros endereços por meio da heurística de propriedade comum de entrada**. Esses pagamentos podem ser entendidos como uma forma de coagir o proprietário do endereço a reutilizar o endereço involuntariamente.

Às vezes, esse ataque é incorretamente chamado de **ataque de poeira**.

O comportamento correto das carteiras é não gastar moedas que foram depositadas em endereços vazios já usados.

## Outras análises de blockchain

* **Quantias exatas de pagamento**: Para evitar transações com troco, o pagamento precisa ser igual ao UTXO (o que é altamente improvável). Portanto, uma **transação sem endereço de troco provavelmente é uma transferência entre 2 endereços do mesmo usuário**.
* **Números redondos**: Em uma transação, se uma das saídas for um "**número redondo**", é altamente provável que seja um **pagamento a um humano que colocou aquele preço "redondo"**, então a outra parte deve ser o troco.
* **Identificação de carteira**: Um analista cuidadoso às vezes pode deduzir qual software criou uma determinada transação, porque os **diferentes softwares de carteira nem sempre criam transações exatamente da mesma maneira**. A identificação de carteira pode ser usada para detectar saídas de troco porque uma saída de troco é aquela gasta com a mesma identificação de carteira.
* **Correlações de quantidade e tempo**: Se a pessoa que realizou a transação **divulgar** o **tempo** e/ou **quantidade** da transação, pode ser facilmente **descoberto**.

## Análise de tráfego

Algumas organizações **monitorando seu tráfego** podem ver você se comunicando na rede bitcoin.\
Se o adversário vir uma transação ou bloco **saindo do seu nó que não entrou anteriormente**, então ele pode saber com quase certeza que **a transação foi feita por você ou o bloco foi minerado por você**. Como as conexões de internet estão envolvidas, o adversário poderá **vincular o endereço IP às informações de bitcoin descobertas**.

Um atacante que não consegue monitorar todo o tráfego da Internet, mas que tem **muitos nós de Bitcoin** para ficar **mais próximo** das fontes, pode ser capaz de saber o endereço IP que está anunciando transações ou blocos.\
Além disso, algumas carteiras periodicamente retransmitem suas transações não confirmadas para que elas tenham mais chances de se propagar amplamente pela rede e serem mineradas.

## Outros ataques para encontrar informações sobre o proprietário dos endereços

Para mais ataques, leia [https://en.bitcoin.it/wiki/Privacy](https://en.bitcoin.it/wiki/Privacy)

# Bitcoins Anônimos

## Obtendo Bitcoins anonimamente

* **Negociações em dinheiro:** Compre bitcoin usando dinheiro.
* **Substituto de dinheiro:** Compre cartões-presente ou similares e troque-os por bitcoin online.
* **Mineração:** A mineração é a maneira mais anônima de obter bitcoin. Isso se aplica à mineração solo, já que as [piscinas de mineração](https://en.bitcoin.it/wiki/Pooled\_mining) geralmente conhecem o endereço IP do minerador.
* **Roubo:** Em teoria, outra maneira de obter bitcoin anônimo é roubá-los.

## Misturadores

Um usuário **enviaria bitcoins para um serviço de mistura** e o serviço **enviaria bitcoins diferentes de volta para o usuário**, menos uma taxa. Em teoria, um adversário observando a blockchain seria **incapaz de vincular** as transações de entrada e saída.

No entanto, o usuário precisa confiar no serviço de mistura para devolver o bitcoin e também para não estar salvando logs sobre as relações entre o dinheiro recebido e enviado.\
Alguns outros serviços também podem ser usados como misturadores, como cassinos Bitcoin onde você pode enviar bitcoins e recuperá-los mais tarde.

## CoinJoin

**CoinJoin** irá **misturar várias transações de diferentes usuários em apenas uma** para tornar mais **difícil** para um observador descobrir **qual entrada está relacionada a qual saída**.\
Isso oferece um novo nível de privacidade, no entanto, **algumas** **transações** em que algumas quantias de entrada e saída estão correlacionadas ou são muito diferentes do restante das entradas e saídas **ainda podem ser correlacionadas** pelo observador externo.

Exemplos de IDs de transações (provavelmente) CoinJoin na blockchain do bitcoin são `402d3e1df685d1fdf82f36b220079c1bf44db227df2d676625ebcbee3f6cb22a` e `85378815f6ee170aa8c26694ee2df42b99cff7fa9357f073c1192fff1f540238`.

[**https://coinjoin.io/en**](https://coinjoin.io/en)\
**Semelhante ao CoinJoin, mas melhor e para Ethereum você tem** [**Tornado Cash**](https://tornado.cash) **(o dinheiro é dado pelos mineradores, então ele aparece apenas em sua carteira).**

## PayJoin

O tipo de CoinJoin discutido na seção anterior pode ser facilmente identificado como tal verificando as múltiplas saídas com o mesmo valor.

PayJoin (também chamado de pay-to-end-point ou P2EP) é um tipo especial de CoinJoin entre duas partes em que uma parte paga a outra. A transação então **não tem as múltiplas saídas distintas** com o mesmo valor, e portanto não é visível como um CoinJoin de saída igual. Considere esta transação:
```
2 btc --> 3 btc
5 btc     4 btc
```
Isso pode ser interpretado como uma simples transação pagando para algum lugar com troco sobrando (ignore por enquanto a questão de qual saída é pagamento e qual é troco). Outra maneira de interpretar essa transação é que a entrada de 2 BTC é de propriedade de um comerciante e 5 BTC é de propriedade de seu cliente, e que essa transação envolve o cliente pagando 1 BTC ao comerciante. Não há como saber qual dessas duas interpretações está correta. O resultado é uma transação de coinjoin que quebra a heurística comum de propriedade de entrada e melhora a privacidade, mas também é **indetectável e indistinguível de qualquer transação regular de bitcoin**.

Se as transações PayJoin se tornassem moderadamente usadas, isso faria com que a **heurística comum de propriedade de entrada fosse completamente falha na prática**. Como elas são indetectáveis, nem mesmo saberíamos se elas estão sendo usadas hoje. Como as empresas de vigilância de transações dependem principalmente dessa heurística, a partir de 2019 há grande entusiasmo em torno da ideia do PayJoin.

# Boas práticas de privacidade do Bitcoin

## Sincronização de carteira

As carteiras de Bitcoin devem obter informações sobre seu saldo e histórico de alguma forma. A partir do final de 2018, as soluções práticas e privadas mais existentes são usar uma **carteira de nó completo** (que é maximamente privada) e **filtragem de bloco do lado do cliente** (que é muito boa).

* **Nó completo:** Os nós completos baixam todo o blockchain, que contém todas as transações on-chain que já ocorreram no Bitcoin. Portanto, um adversário que observa a conexão à internet do usuário não poderá aprender quais transações ou endereços o usuário está interessado.
* **Filtragem de bloco do lado do cliente:** A filtragem de bloco do lado do cliente funciona criando **filtros** que contêm todos os **endereços** para cada transação em um bloco. Os filtros podem testar se um **elemento está no conjunto**; falsos positivos são possíveis, mas não falsos negativos. Uma carteira leve **baixaria** todos os filtros para cada **bloco** no **blockchain** e verificaria correspondências com seus **próprios** **endereços**. Blocos que contêm correspondências seriam baixados na íntegra da rede peer-to-peer, e esses blocos seriam usados para obter o histórico e o saldo atual da carteira.

## Tor

A rede Bitcoin usa uma rede peer-to-peer, o que significa que outros pares podem aprender seu endereço IP. É por isso que é recomendável **conectar-se através do Tor sempre que você quiser interagir com a rede Bitcoin**.

## Evitando a reutilização de endereços

**Endereços usados mais de uma vez são muito prejudiciais à privacidade, porque isso vincula mais transações de blockchain com a prova de que foram criadas pela mesma entidade**. A maneira mais privada e segura de usar o Bitcoin é enviar um **novo endereço para cada pessoa que lhe paga**. Depois que as moedas recebidas forem gastas, o endereço nunca deve ser usado novamente. Além disso, um novo endereço Bitcoin deve ser exigido ao enviar Bitcoin. Todas as boas carteiras de Bitcoin têm uma interface do usuário que desencoraja a reutilização de endereços.

## Múltiplas transações

**Pagar** alguém com **mais de uma transação on-chain** pode reduzir muito o poder de ataques de privacidade baseados em quantidades, como correlação de quantidades e números redondos. Por exemplo, se o usuário quiser pagar 5 BTC a alguém e não quiser que o valor de 5 BTC seja facilmente pesquisado, ele pode enviar duas transações para o valor de 2 BTC e 3 BTC, que juntas somam 5 BTC.

## Evitando troco

A evitação de troco é onde as entradas e saídas da transação são cuidadosamente escolhidas para não exigir nenhuma saída de troco. **Não ter uma saída de troco é excelente para a privacidade**, pois quebra as heurísticas de detecção de troco.

## Múltiplas saídas de troco

Se a evitação de troco não for uma opção, então **criar mais de uma saída de troco pode melhorar a privacidade**. Isso também quebra as heurísticas de detecção de troco, que geralmente assumem que há apenas uma saída de troco. Como esse método usa mais espaço de bloco do que o usual, a evitação de troco é preferível.

# Monero

Quando o Monero foi desenvolvido, a grande necessidade de **anonimato completo** foi o que ele procurou resolver e, em grande parte, preencheu esse vazio.

# Ethereum

## Gás

Gás refere-se à unidade que mede a **quantidade** de **esforço computacional** necessária para executar operações específicas na rede Ethereum. Gás refere-se à **taxa** necessária para conduzir com sucesso uma **transação** na Ethereum.

Os preços do gás são denominados em **gwei**, que é uma denominação de ETH - cada gwei é igual a **0,000000001 ETH** (10-9 ETH). Por exemplo, em vez de dizer que seu gás custa 0,000000001 ether, você pode dizer que seu gás custa 1 gwei. A palavra 'gwei' em si significa 'giga-wei', e é igual a **1.000.000.000 wei**. Wei em si é a **menor unidade de ETH**.

Para calcular o gás que uma transação vai custar, leia este exemplo:

Digamos que Jordan tenha que pagar a Taylor 1 ETH. Na transação, o limite de gás é de 21.000 unidades e a taxa básica é de 100 gwei. Jordan inclui uma gorjeta de 10 gwei.

Usando a fórmula acima, podemos calcular isso como `21.000 * (100 + 10) = 2.310.000 gwei` ou 0,00231 ETH.

Quando Jordan envia o dinheiro, 1,00231 ETH serão deduzidos da conta de Jordan. Taylor será creditado com 1,0000 ETH. O minerador recebe a gorjeta de 0,00021 ETH. A taxa básica de 0,0021 ETH é queimada.

Além disso, Jordan também pode definir uma taxa máxima (`maxFeePerGas`) para a transação. A diferença entre a taxa máxima e a taxa real é reembolsada a Jordan, ou seja, `reembolso = taxa máxima - (taxa básica + taxa de prioridade)`. Jordan pode definir um valor máximo a pagar pela transação para ser executada e

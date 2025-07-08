# Termos de Investimento

{{#include /banners/hacktricks-training.md}}

## Spot

Esta é a maneira mais básica de fazer algumas negociações. Você pode **indicar a quantidade do ativo e o preço** que deseja comprar ou vender, e sempre que esse preço for alcançado, a operação é realizada.

Normalmente, você também pode usar o **preço de mercado atual** para realizar a transação o mais rápido possível ao preço atual.

**Stop Loss - Limit**: Você também pode indicar a quantidade e o preço dos ativos para comprar ou vender, enquanto também indica um preço mais baixo para comprar ou vender caso seja alcançado (para parar perdas).

## Futuros

Um futuro é um contrato onde 2 partes chegam a um acordo para **adquirir algo no futuro a um preço fixo**. Por exemplo, vender 1 bitcoin em 6 meses a 70.000$.

Obviamente, se em 6 meses o valor do bitcoin for 80.000$, a parte vendedora perde dinheiro e a parte compradora ganha. Se em 6 meses o valor do bitcoin for 60.000$, o oposto acontece.

No entanto, isso é interessante, por exemplo, para negócios que estão gerando um produto e precisam ter a segurança de que poderão vendê-lo a um preço que cubra os custos. Ou negócios que desejam garantir preços fixos no futuro para algo, mesmo que mais altos.

Embora nas exchanges isso seja geralmente usado para tentar obter lucro.

* Observe que uma "posição longa" significa que alguém está apostando que um preço vai aumentar.
* Enquanto uma "posição curta" significa que alguém está apostando que um preço vai cair.

### Hedging Com Futuros <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Se um gestor de fundos tem medo de que algumas ações vão cair, ele pode assumir uma posição curta sobre alguns ativos, como bitcoins ou contratos futuros do S\&P 500. Isso seria semelhante a comprar ou ter alguns ativos e criar um contrato para vender esses ativos em um momento futuro a um preço maior.

Caso o preço caia, o gestor do fundo ganhará benefícios porque venderá os ativos a um preço maior. Se o preço dos ativos subir, o gestor não ganhará esse benefício, mas ainda manterá seus ativos.

### Futuros Perpétuos

**Estes são "futuros" que durarão indefinidamente** (sem uma data de contrato final). É muito comum encontrá-los, por exemplo, em exchanges de criptomoedas, onde você pode entrar e sair de futuros com base no preço das criptos.

Observe que, nesses casos, os benefícios e perdas podem ser em tempo real; se o preço aumentar 1%, você ganha 1%; se o preço diminuir 1%, você perderá.

### Futuros com Alavancagem

**Alavancagem** permite que você controle uma posição maior no mercado com uma quantia menor de dinheiro. Basicamente, permite que você "apostar" muito mais dinheiro do que você tem, arriscando apenas o dinheiro que você realmente possui.

Por exemplo, se você abrir uma posição futura no BTC/USDT com 100$ a uma alavancagem de 50x, isso significa que se o preço aumentar 1%, você estaria ganhando 1x50 = 50% do seu investimento inicial (50$). E, portanto, você terá 150$.\
No entanto, se o preço diminuir 1%, você perderá 50% de seus fundos (59$ neste caso). E se o preço diminuir 2%, você perderá toda a sua aposta (2x50 = 100%).

Portanto, a alavancagem permite controlar a quantidade de dinheiro que você aposta, aumentando os ganhos e as perdas.

## Diferenças entre Futuros e Opções

A principal diferença entre futuros e opções é que o contrato é opcional para o comprador: ele pode decidir executá-lo ou não (geralmente ele só o fará se se beneficiar disso). O vendedor deve vender se o comprador quiser usar a opção.\
No entanto, o comprador pagará uma taxa ao vendedor para abrir a opção (então o vendedor, que aparentemente está assumindo mais risco, começa a ganhar algum dinheiro).

### 1. **Obrigação vs. Direito:**

* **Futuros:** Quando você compra ou vende um contrato futuro, está entrando em um **acordo vinculativo** para comprar ou vender um ativo a um preço específico em uma data futura. Tanto o comprador quanto o vendedor estão **obrigados** a cumprir o contrato na expiração (a menos que o contrato seja encerrado antes disso).
* **Opções:** Com opções, você tem o **direito, mas não a obrigação**, de comprar (no caso de uma **opção de compra**) ou vender (no caso de uma **opção de venda**) um ativo a um preço específico antes ou em uma certa data de expiração. O **comprador** tem a opção de executar, enquanto o **vendedor** é obrigado a cumprir a negociação se o comprador decidir exercer a opção.

### 2. **Risco:**

* **Futuros:** Tanto o comprador quanto o vendedor assumem **risco ilimitado** porque estão obrigados a completar o contrato. O risco é a diferença entre o preço acordado e o preço de mercado na data de expiração.
* **Opções:** O risco do comprador é limitado ao **prêmio** pago para adquirir a opção. Se o mercado não se mover a favor do detentor da opção, ele pode simplesmente deixar a opção expirar. No entanto, o **vendedor** (escritor) da opção tem risco ilimitado se o mercado se mover significativamente contra ele.

### 3. **Custo:**

* **Futuros:** Não há custo inicial além da margem necessária para manter a posição, já que o comprador e o vendedor estão ambos obrigados a completar a negociação.
* **Opções:** O comprador deve pagar um **prêmio de opção** antecipadamente pelo direito de exercer a opção. Este prêmio é essencialmente o custo da opção.

### 4. **Potencial de Lucro:**

* **Futuros:** O lucro ou a perda é baseado na diferença entre o preço de mercado na expiração e o preço acordado no contrato.
* **Opções:** O comprador lucra quando o mercado se move favoravelmente além do preço de exercício, mais do que o prêmio pago. O vendedor lucra mantendo o prêmio se a opção não for exercida.

{{#include /banners/hacktricks-training.md}}

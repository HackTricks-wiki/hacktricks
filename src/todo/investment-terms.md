# Termos de Investimento

{{#include ../banners/hacktricks-training.md}}

## Spot

Esta é a forma mais básica de fazer trading. Você pode **indicar a quantidade do ativo e o preço** pelo qual deseja comprar ou vender e, sempre que esse preço for atingido, a operação será realizada.

Normalmente, você também pode usar o **preço atual de mercado** para realizar a transação o mais rapidamente possível pelo preço atual.

**Stop Loss - Limit**: Você também pode indicar a quantidade e o preço dos ativos a comprar ou vender, além de indicar um preço inferior para comprar ou vender caso ele seja atingido (para interromper perdas).

## Futuros

Um futuro é um contrato no qual 2 partes concordam em **adquirir algo no futuro a um preço fixo**. Por exemplo, vender 1 bitcoin em 6 meses por 70.000$.

Obviamente, se após 6 meses o valor do bitcoin for 80.000$, o vendedor perderá dinheiro e o comprador ganhará. Se, em 6 meses, o valor do bitcoin for 60.000$, o oposto acontecerá.

No entanto, isso é interessante, por exemplo, para empresas que estão gerando um produto e precisam ter a segurança de que conseguirão vendê-lo por um preço que cubra os custos. Também é útil para empresas que desejam garantir preços fixos no futuro para algo, mesmo que sejam mais altos.

Embora, nas exchanges, isso geralmente seja usado para tentar obter lucro.

* Observe que uma "posição comprada" significa que alguém está apostando que o preço vai aumentar
* Enquanto uma "posição vendida" significa que alguém está apostando que o preço vai cair

### Hedging com Futuros <a href="#mntl-sc-block_7-0" id="mntl-sc-block_7-0"></a>

Se um gestor de fundo teme que algumas ações vão cair, ele pode assumir uma posição vendida em alguns ativos, como bitcoins ou contratos futuros do S\&P 500. Isso seria semelhante a comprar ou possuir alguns ativos e criar um contrato para vendê-los em um momento futuro por um preço maior.

Caso o preço caia, o gestor do fundo obterá lucro porque venderá os ativos por um preço maior. Se o preço dos ativos subir, o gestor não obterá esse lucro, mas ainda manterá seus ativos.

### Futuros Perpétuos

**Estes são "futuros" que durarão indefinidamente** (sem uma data de término do contrato). É muito comum encontrá-los, por exemplo, em exchanges de criptomoedas, onde você pode entrar e sair de futuros com base no preço das criptomoedas.

Observe que, nesses casos, os ganhos e as perdas podem ocorrer em tempo real: se o preço aumentar 1%, você ganha 1%; se o preço diminuir 1%, você perderá esse valor.

### Futuros com Alavancagem

A **alavancagem** permite controlar uma posição maior no mercado com uma quantia menor de dinheiro. Basicamente, ela permite que você "aposte" muito mais dinheiro do que possui, arriscando apenas o dinheiro que realmente tem.

Por exemplo, se você abrir uma posição futura em BTC/USDT com 100$ e uma alavancagem de 50x, isso significa que, se o preço aumentar 1%, você ganhará 1x50 = 50% do seu investimento inicial (50$). E, portanto, terá 150$.\
No entanto, se o preço diminuir 1%, você perderá 50% dos seus fundos (59$ neste caso). E, se o preço diminuir 2%, perderá toda a sua aposta (2x50 = 100%).

Portanto, a alavancagem permite controlar a quantia de dinheiro apostada, aumentando os ganhos e as perdas.

## Diferenças entre Futuros e Opções

A principal diferença entre futuros e opções é que o contrato é opcional para o comprador: ele pode decidir executá-lo ou não (normalmente, só o fará se obtiver algum benefício). O vendedor deve vender se o comprador quiser usar a opção.\
No entanto, o comprador pagará alguma taxa ao vendedor pela abertura da opção (assim, o vendedor, que aparentemente está assumindo mais riscos, começa a ganhar algum dinheiro).

### 1. **Obrigação vs. Direito:**

* **Futuros:** Quando você compra ou vende um contrato futuro, está entrando em um **acordo vinculativo** para comprar ou vender um ativo a um preço específico em uma data futura. Tanto o comprador quanto o vendedor são **obrigados** a cumprir o contrato no vencimento (a menos que o contrato seja encerrado antes disso).
* **Opções:** Com opções, você tem o **direito, mas não a obrigação**, de comprar (no caso de uma **opção de compra**) ou vender (no caso de uma **opção de venda**) um ativo a um preço específico antes ou em uma determinada data de vencimento. O **comprador** tem a opção de executar, enquanto o **vendedor** é obrigado a cumprir a negociação se o comprador decidir exercer a opção.

### 2. **Risco:**

* **Futuros:** Tanto o comprador quanto o vendedor assumem **risco ilimitado**, pois são obrigados a concluir o contrato. O risco é a diferença entre o preço acordado e o preço de mercado na data de vencimento.
* **Opções:** O risco do comprador é limitado ao **prêmio** pago pela compra da opção. Se o mercado não se mover a favor do titular da opção, ele pode simplesmente deixar a opção expirar. No entanto, o **vendedor** (lançador) da opção tem risco ilimitado se o mercado se mover significativamente contra ele.

### 3. **Custo:**

* **Futuros:** Não há custo inicial além da margem necessária para manter a posição, pois tanto o comprador quanto o vendedor são obrigados a concluir a negociação.
* **Opções:** O comprador deve pagar antecipadamente um **prêmio da opção** pelo direito de exercer a opção. Esse prêmio é essencialmente o custo da opção.

### 4. **Potencial de Lucro:**

* **Futuros:** O lucro ou a perda baseia-se na diferença entre o preço de mercado no vencimento e o preço acordado no contrato.
* **Opções:** O comprador lucra quando o mercado se move favoravelmente além do preço de exercício por uma quantia superior ao prêmio pago. O vendedor lucra ao ficar com o prêmio se a opção não for exercida.

{{#include ../banners/hacktricks-training.md}}

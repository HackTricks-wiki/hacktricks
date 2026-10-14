# Termos de investimento

{{#include ../../banners/hacktricks-training.md}}

## À vista

A negociação à vista troca um ativo por sua entrega imediata. Uma ordem limitada especifica a quantidade e o preço limite; ela é executada somente quando o mercado consegue atender a esse preço ou a um preço melhor. Já uma ordem a mercado busca execução imediata aos melhores preços disponíveis naquele momento e pode sofrer slippage.<sup>[[4]](#references)</sup>

Uma ordem stop-limit tem um preço de stop que ativa uma ordem limitada. Ela pode restringir o preço de execução, mas não garante a execução se o mercado ultrapassar o limite.<sup>[[4]](#references)</sup>

## Futuros

Um contrato futuro é um acordo padronizado para comprar ou vender uma commodity ou instrumento financeiro especificado em uma data futura. Por exemplo, duas partes poderiam acordar o preço de US$ 70.000 por um bitcoin, com liquidação em seis meses.<sup>[[1]](#references)</sup>

Se o preço de liquidação for US$ 80.000, a posição comprada terá lucro e a posição vendida terá prejuízo em relação ao preço contratual de US$ 70.000. Se for US$ 60.000, ocorre o inverso. Os contratos futuros negociados em bolsa são ajustados a mercado e normalmente encerrados ou rolados antes do vencimento; portanto, este é um exemplo simplificado.<sup>[[2]](#references)</sup>

Produtores e consumidores usam futuros para proteger-se contra o risco de preço; outros participantes os usam para buscar lucro ou fornecer liquidez.<sup>[[1]](#references)</sup>

- Uma **posição comprada** geralmente lucra quando o preço do contrato sobe.
- Uma **posição vendida** geralmente lucra quando o preço do contrato cai.<sup>[[2]](#references)</sup>

### Proteção com futuros

Se um gestor de fundos espera que uma carteira caia, ele pode vender a descoberto um contrato futuro de índice de ações suficientemente correlacionado. Os ganhos com a proteção vendida podem compensar parte das perdas da carteira; o risco de base significa que essa compensação raramente é exata. Um futuro de bitcoin protegeria a exposição ao bitcoin, não automaticamente uma carteira de ações.

Se o mercado protegido cair, a posição vendida em futuros pode gerar ganhos enquanto os ativos mantidos perdem valor. Se o mercado subir, os ativos podem se valorizar enquanto a proteção gera perdas. A proteção reduz riscos específicos, em vez de criar lucro garantido.<sup>[[1]](#references)</sup>

### Futuros perpétuos

Contratos perpétuos são derivativos sem data de vencimento fixa. Plataformas de criptoativos costumam usar pagamentos periódicos de funding para ajudar a manter seu preço próximo ao preço à vista do ativo subjacente; as condições variam de acordo com a plataforma.<sup>[[3]](#references)</sup>

O lucro e o prejuízo variam conforme o preço de marcação se movimenta. Uma variação de preço de 1% produz aproximadamente uma variação de 1% no valor nocional da posição, antes de taxas e funding, mas a alavancagem pode fazer com que isso represente uma porcentagem muito maior da garantia depositada.

### Futuros com alavancagem

A **alavancagem** permite que um trader controle uma posição nocional maior com um depósito de margem menor. As perdas nem sempre se limitam à margem inicial: liquidação, gaps, taxas e regras da plataforma podem gerar perdas adicionais.<sup>[[3]](#references)</sup>

Por exemplo, US$ 100 de margem com alavancagem de 50x controlam uma posição de US$ 5.000. Desconsiderando taxas, funding e mecanismos de liquidação, uma variação favorável de 1% gera um ganho de US$ 50 (50% da margem inicial), enquanto uma variação desfavorável de 1% gera uma perda de US$ 50. Uma variação desfavorável de 2% corresponde a US$ 100, embora uma plataforma normalmente liquide a posição antes que toda a margem seja consumida.

A alavancagem amplia tanto os ganhos quanto as perdas e possibilita a liquidação após uma variação desfavorável relativamente pequena.

## Diferenças entre futuros e opções

O comprador de uma opção recebe o direito, mas não a obrigação, de exercê-la conforme as condições do contrato. O lançador da opção tem a obrigação correspondente caso o comprador a exerça. O comprador paga ao lançador um prêmio por esse direito.<sup>[[4]](#references)</sup>

### 1. **Obrigação vs. direito:**

* **Futuros:** Ao comprar ou vender um contrato futuro, você assume um **acordo vinculativo** para comprar ou vender um ativo a um preço específico em uma data futura. Tanto o comprador quanto o vendedor são **obrigados** a cumprir o contrato no vencimento (a menos que o contrato seja encerrado antes disso).
* **Opções:** Com opções, você tem o **direito, mas não a obrigação**, de comprar (no caso de uma **opção de compra**) ou vender (no caso de uma **opção de venda**) um ativo a um preço específico antes ou em determinada data de vencimento. O **comprador** pode optar por executar a operação, enquanto o **vendedor** é obrigado a cumpri-la se o comprador decidir exercer a opção.

### 2. **Risco:**

* **Futuros:** Ambos os lados podem sofrer perdas substanciais. Se a perda é matematicamente ilimitada depende da posição e do ativo subjacente: uma posição vendida pode ter perda teórica ilimitada, enquanto uma posição comprada não pode perder mais do que o valor nocional se o ativo subjacente não puder cair abaixo de zero.
* **Opções:** Um comprador que não lança outra opção geralmente arrisca o prêmio pago. O lançador de uma opção de compra descoberta pode enfrentar perdas teoricamente ilimitadas; outras estratégias de lançamento de opções têm diferentes perfis de risco, limitados ou ilimitados.

### 3. **Custo:**

* **Futuros:** Não há custo inicial além da margem necessária para manter a posição, pois tanto o comprador quanto o vendedor são obrigados a concluir a operação.
* **Opções:** O comprador deve pagar antecipadamente um **prêmio da opção** pelo direito de exercê-la. Esse prêmio é, essencialmente, o custo da opção.

### 4. **Potencial de lucro:**

* **Futuros:** O lucro ou prejuízo baseia-se na diferença entre o preço de mercado no vencimento e o preço acordado no contrato.
* **Opções:** O comprador lucra quando o mercado se move favoravelmente para além do preço de exercício por um valor superior ao prêmio pago. O vendedor lucra ao ficar com o prêmio se a opção não for exercida.

## References

- [1] [CFTC - O propósito econômico dos mercados de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Fundamentos do mercado de futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Entenda os riscos da negociação de moedas virtuais](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossário da CFTC - Opção, prêmio e exercício](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../../banners/hacktricks-training.md}}

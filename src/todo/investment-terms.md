# Termos de Investimento

{{#include ../banners/hacktricks-training.md}}

## À vista

A negociação à vista troca um ativo por entrega imediata. Uma ordem limitada especifica a quantidade e o preço-limite; ela é executada somente quando o mercado pode atender a esse preço ou a um preço melhor. Já uma ordem a mercado busca execução imediata aos melhores preços disponíveis e pode sofrer slippage.<sup>[[4]](#references)</sup>

Uma ordem stop-limit tem um preço de stop que ativa uma ordem limitada. Ela pode restringir o preço de execução, mas não garante a execução se o mercado ultrapassar o limite.<sup>[[4]](#references)</sup>

## Futuros

Um contrato futuro é um acordo padronizado para comprar ou vender uma commodity ou instrumento financeiro especificado em uma data futura. Por exemplo, duas partes poderiam concordar com um preço de US$ 70.000 por um bitcoin, com liquidação em seis meses.<sup>[[1]](#references)</sup>

Se o preço de liquidação for US$ 80.000, a posição comprada ganha e a posição vendida perde em relação ao preço contratual de US$ 70.000. Se for US$ 60.000, a direção se inverte. Os contratos futuros efetivamente negociados em exchanges são ajustados ao mercado e geralmente encerrados ou rolados antes do vencimento, portanto, esta é uma ilustração simplificada.<sup>[[2]](#references)</sup>

Produtores e consumidores usam futuros para proteger-se contra o risco de preço; outros participantes os usam para buscar lucro ou fornecer liquidez.<sup>[[1]](#references)</sup>

- Uma **posição comprada** geralmente lucra quando o preço do contrato sobe.
- Uma **posição vendida** geralmente lucra quando o preço do contrato cai.<sup>[[2]](#references)</sup>

### Hedge com Futuros

Se um gestor de fundo espera que uma carteira caia, ele pode assumir uma posição vendida em um contrato futuro de índice de ações suficientemente correlacionado. Os ganhos do hedge vendido podem compensar parte das perdas da carteira; o risco de base significa que essa compensação raramente é exata. Um futuro de bitcoin protegeria uma exposição a bitcoin, não automaticamente uma carteira de ações.

Se o mercado protegido cair, a posição vendida em futuros poderá ganhar enquanto os ativos mantidos perderão valor. Se ele subir, os ativos mantidos poderão ganhar enquanto o hedge perderá. O hedge reduz um risco específico, em vez de criar um lucro garantido.<sup>[[1]](#references)</sup>

### Futuros Perpétuos

Contratos perpétuos são derivativos sem uma data de vencimento fixa. Plataformas de criptoativos normalmente usam pagamentos periódicos de funding para ajudar a manter seu preço próximo do preço à vista do ativo subjacente; os termos variam conforme a plataforma.<sup>[[3]](#references)</sup>

O lucro e a perda mudam conforme o preço de marcação se movimenta. Uma variação de preço de 1% produz aproximadamente uma variação de 1% no valor nocional da posição antes de taxas e funding, mas a alavancagem pode transformar isso em uma porcentagem muito maior da garantia depositada.

### Futuros com Alavancagem

**Alavancagem** permite que um trader controle uma posição nocional maior com um depósito de margem menor. As perdas nem sempre se limitam à margem inicial: liquidação, gaps, taxas e regras da plataforma podem produzir perdas adicionais.<sup>[[3]](#references)</sup>

Por exemplo, uma margem de US$ 100 com alavancagem de 50x controla uma posição de US$ 5.000. Ignorando taxas, funding e mecanismos de liquidação, uma variação favorável de 1% produz um ganho de US$ 50 (50% da margem inicial), enquanto uma variação adversa de 1% produz uma perda de US$ 50. Uma variação adversa de 2% corresponde a US$ 100, embora uma plataforma normalmente liquide a posição antes que toda a margem seja consumida.

A alavancagem amplia tanto os ganhos quanto as perdas e possibilita a liquidação após uma variação adversa relativamente pequena.

## Diferenças entre Futuros e Opções

O comprador de uma opção recebe um direito, não uma obrigação, de exercer nos termos do contrato. O lançador da opção tem a obrigação correspondente caso o comprador exerça a opção. O comprador paga ao lançador um prêmio por esse direito.<sup>[[4]](#references)</sup>

### 1. **Obrigação vs. Direito:**

* **Futuros:** Quando você compra ou vende um contrato futuro, está firmando um **acordo vinculante** para comprar ou vender um ativo a um preço específico em uma data futura. Tanto o comprador quanto o vendedor são **obrigados** a cumprir o contrato no vencimento (a menos que o contrato seja encerrado antes disso).
* **Opções:** Com opções, você tem o **direito, mas não a obrigação**, de comprar (no caso de uma **opção de compra**) ou vender (no caso de uma **opção de venda**) um ativo a um preço específico antes ou em determinada data de vencimento. O **comprador** tem a opção de executar, enquanto o **vendedor** é obrigado a cumprir a negociação se o comprador decidir exercer a opção.

### 2. **Risco:**

* **Futuros:** Ambos os lados podem sofrer perdas substanciais. O fato de a perda ser matematicamente ilimitada depende da posição e do ativo subjacente: uma posição vendida pode ter uma perda teórica ilimitada, enquanto uma posição comprada não pode perder mais do que o valor nocional se o ativo subjacente não puder cair abaixo de zero.
* **Opções:** Um comprador que não lança outra opção geralmente arrisca o prêmio pago. Um lançador de uma opção de compra descoberta pode enfrentar uma perda teoricamente ilimitada; outras estratégias de lançamento de opções têm diferentes perfis de risco limitado ou ilimitado.

### 3. **Custo:**

* **Futuros:** Não há custo inicial além da margem exigida para manter a posição, pois o comprador e o vendedor são obrigados a concluir a negociação.
* **Opções:** O comprador deve pagar antecipadamente um **prêmio da opção** pelo direito de exercer a opção. Esse prêmio é essencialmente o custo da opção.

### 4. **Potencial de Lucro:**

* **Futuros:** O lucro ou a perda baseia-se na diferença entre o preço de mercado no vencimento e o preço acordado no contrato.
* **Opções:** O comprador lucra quando o mercado se movimenta favoravelmente para além do preço de exercício em um valor superior ao prêmio pago. O vendedor lucra mantendo o prêmio se a opção não for exercida.

## References

- [1] [CFTC - A finalidade econômica dos mercados futuros](https://www.cftc.gov/LearnAndProtect/EducationCenter/economicpurpose)
- [2] [CFTC - Noções básicas do mercado futuro](https://www.cftc.gov/LearnAndProtect/EducationCenter/FuturesMarketBasics/index2.htm)
- [3] [CFTC - Entenda os riscos da negociação de moedas virtuais](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/understand_risks_of_virtual_currency.html)
- [4] [Glossário da CFTC - Opção, prêmio e exercício](https://www.cftc.gov/LearnAndProtect/AdvisoriesAndArticles/CFTCGlossary/index.htm)
{{#include ../banners/hacktricks-training.md}}

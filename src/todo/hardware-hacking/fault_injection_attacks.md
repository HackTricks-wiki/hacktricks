# Ataques de Injeção de Falhas

{{#include ../../banners/hacktricks-training.md}}

A injeção de falhas — frequentemente chamada de **glitching** no contexto de segurança de hardware — perturba deliberadamente um dispositivo enquanto ele está em operação, fazendo com que execute um cálculo incorreto. Uma falha útil pode ignorar uma instrução, corromper dados, contornar uma verificação de segurança ou produzir uma saída criptográfica defeituosa da qual informações secretas podem ser derivadas.<sup>[[1]](#references)</sup>

As técnicas comuns manipulam a tensão de alimentação ou o clock, injetam interferência eletromagnética ou utilizam estimulação óptica ou a laser.<sup>[[1]](#references)</sup> Sua precisão e invasividade variam, mas testes bem-sucedidos geralmente exigem um gatilho reproduzível e varreduras sistemáticas de tempo, duração do pulso e intensidade. Comece com uma baseline estável, registre separadamente resets e saídas malformadas e altere um parâmetro por vez.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Método de Injeção de Falhas sem Gatilho e Não Invasivo Baseado em Interferência Eletromagnética Intencional](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [ChipWhisperer Documentation - Visão Geral e Comparação do Hardware de Captura](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}

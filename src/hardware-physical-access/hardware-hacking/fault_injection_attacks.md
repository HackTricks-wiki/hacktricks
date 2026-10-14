# Fault Injection Attacks

{{#include ../../banners/hacktricks-training.md}}

A injeção de falhas — muitas vezes chamada de **glitching** em trabalhos de segurança de hardware — perturba deliberadamente um dispositivo enquanto ele está em funcionamento, fazendo com que execute um cálculo incorreto. Uma falha útil pode ignorar uma instrução, corromper dados, contornar uma verificação de segurança ou produzir uma saída criptográfica defeituosa da qual seja possível derivar informações secretas.<sup>[[1]](#references)</sup>

As técnicas comuns manipulam a tensão de alimentação ou o clock, injetam interferência eletromagnética ou usam estimulação óptica ou a laser.<sup>[[1]](#references)</sup> Elas diferem em precisão e invasividade, mas testes bem-sucedidos geralmente exigem um gatilho repetível e varreduras sistemáticas de temporização, largura de pulso e intensidade. Comece com uma referência estável, registre separadamente as reinicializações e as saídas malformadas, e altere um parâmetro de cada vez.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Método não invasivo de injeção de falhas sem gatilho baseado em interferência eletromagnética intencional](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentação do ChipWhisperer - Visão geral e comparação do hardware de captura](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}

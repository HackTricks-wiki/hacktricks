# Ataques de Fault Injection

{{#include ../../banners/hacktricks-training.md}}

Fault injection perturba deliberadamente um dispositivo enquanto ele está operando, fazendo com que execute um cálculo incorreto. Uma falha útil pode ignorar uma instrução, corromper dados, contornar uma verificação de segurança ou produzir uma saída criptográfica defeituosa da qual informações secretas podem ser derivadas.<sup>[[1]](#references)</sup>

As técnicas comuns manipulam a tensão de alimentação ou o clock, injetam interferência eletromagnética ou usam estimulação óptica ou a laser.<sup>[[1]](#references)</sup> Sua precisão e invasividade variam, mas testes bem-sucedidos geralmente exigem um gatilho repetível e varreduras sistemáticas de temporização, largura de pulso e intensidade. Comece com uma linha de base estável, registre separadamente os resets e as saídas malformadas e altere um parâmetro por vez.<sup>[[2]](#references)</sup>

## References

- [1] [Hayashi et al. - Método de Fault Injection não invasivo e sem gatilho baseado em interferência eletromagnética intencional](https://csrc.nist.gov/csrc/media/events/non-invasive-attack-testing-workshop/documents/04_hayashi.pdf)
- [2] [Documentação do ChipWhisperer - Visão geral e comparação do hardware de captura](https://chipwhisperer.readthedocs.io/en/latest/Capture/overview.html)
{{#include ../../banners/hacktricks-training.md}}

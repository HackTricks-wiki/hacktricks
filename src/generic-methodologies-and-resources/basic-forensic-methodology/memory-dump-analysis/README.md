# Análise de dump de memória

{{#include ../../../banners/hacktricks-training.md}}

## Início

Comece **procurando** por **malware** dentro do pcap. Use as **ferramentas** mencionadas em [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility é o principal framework open-source para análise de dumps de memória**. Essa ferramenta Python analisa dumps de fontes externas ou VMs VMware, identificando dados como processos e senhas com base no perfil do sistema operacional do dump. Ela é extensível por meio de plugins, tornando-a altamente versátil para investigações forenses.

[**Encontre aqui uma cheatsheet**](volatility-cheatsheet.md)

## Relatório de crash de mini dump

Quando o dump é pequeno (apenas alguns KB, talvez alguns MB), provavelmente é um relatório de crash de mini dump, e não um dump de memória.

![Volatility - Relatório de crash de mini dump: Quando o dump é pequeno (apenas alguns KB, talvez alguns MB), provavelmente é um relatório de crash de mini dump, e não um dump de memória](<../../../images/image (532).png>)

Se você tiver o Visual Studio instalado, poderá abrir esse arquivo e obter algumas informações básicas, como nome do processo, arquitetura, informações da exceção e módulos em execução:

![Volatility - Relatório de crash de mini dump: Se você tiver o Visual Studio instalado, poderá abrir esse arquivo e obter algumas informações básicas, como nome do processo, arquitetura, informações da exceção e...](<../../../images/image (263).png>)

Você também pode carregar a exceção e visualizar as instruções decompiladas

![Volatility - Relatório de crash de mini dump: Você também pode carregar a exceção e visualizar as instruções decompiladas](<../../../images/image (142).png>)

![Volatility - Relatório de crash de mini dump: Você também pode carregar a exceção e visualizar as instruções decompiladas](<../../../images/image (610).png>)

De qualquer forma, o Visual Studio não é a melhor ferramenta para realizar uma análise aprofundada do dump.

Você deve **abri-lo** usando o **IDA** ou o **Radare** para inspecioná-lo **detalhadamente**.

{{#include ../../../banners/hacktricks-training.md}}

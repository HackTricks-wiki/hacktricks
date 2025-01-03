# Análise de despejo de memória

{{#include ../../../banners/hacktricks-training.md}}

## Início

Comece **procurando** por **malware** dentro do pcap. Use as **ferramentas** mencionadas em [**Análise de Malware**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

**Volatility é o principal framework de código aberto para análise de despejo de memória**. Esta ferramenta Python analisa despejos de fontes externas ou VMs VMware, identificando dados como processos e senhas com base no perfil do SO do despejo. É extensível com plugins, tornando-a altamente versátil para investigações forenses.

**[Encontre aqui um cheatsheet](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)**

## Relatório de falha de mini despejo

Quando o despejo é pequeno (apenas alguns KB, talvez alguns MB), então provavelmente é um relatório de falha de mini despejo e não um despejo de memória.

![](<../../../images/image (216).png>)

Se você tiver o Visual Studio instalado, pode abrir este arquivo e vincular algumas informações básicas, como nome do processo, arquitetura, informações de exceção e módulos sendo executados:

![](<../../../images/image (217).png>)

Você também pode carregar a exceção e ver as instruções decompiladas

![](<../../../images/image (219).png>)

![](<../../../images/image (218) (1).png>)

De qualquer forma, o Visual Studio não é a melhor ferramenta para realizar uma análise da profundidade do despejo.

Você deve **abri-lo** usando **IDA** ou **Radare** para inspecioná-lo em **profundidade**.

​

{{#include ../../../banners/hacktricks-training.md}}

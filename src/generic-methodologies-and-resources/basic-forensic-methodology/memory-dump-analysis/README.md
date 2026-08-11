# Análise de dump de memória

{{#include ../../../banners/hacktricks-training.md}}

## Início

Comece **procurando** por **malware** dentro do pcap. Use as **ferramentas** mencionadas em [**Malware Analysis**](../malware-analysis.md).

## [Volatility](volatility-cheatsheet.md)

**Volatility é um framework open-source para análise de dumps de memória**. Essa ferramenta Python analisa dumps de fontes externas ou VMs do VMware, identificando dados como processos e senhas com base no perfil do sistema operacional do dump. Ela é extensível com plugins, o que a torna altamente versátil para investigações forenses.<sup>[[1]](#references)[[2]](#references)</sup>

[**Encontre aqui uma cheatsheet**](volatility-cheatsheet.md)

## Relatório de crash de mini dump

Quando o dump é pequeno (apenas alguns KB, talvez alguns MB), ele pode ser um relatório de crash de mini dump em vez de um dump de memória completo.<sup>[[3]](#references)</sup>

![Volatility - Relatório de crash de mini dump: um arquivo de dump pequeno identificado como um relatório de crash Mini DuMP](<../../../images/image (532).png>)

Se você tiver o Visual Studio instalado, poderá abrir esse arquivo para visualizar informações básicas, como o nome do processo, a arquitetura, os detalhes da exceção e os módulos carregados:<sup>[[4]](#references)</sup>

![Volatility - Relatório de crash de mini dump: se você tiver o Visual Studio instalado, poderá abrir esse arquivo e obter algumas informações básicas, como nome do processo, arquitetura, informações da exceção e...](<../../../images/image (263).png>)

Você também pode inspecionar a exceção e visualizar o disassembly do módulo.<sup>[[4]](#references)</sup>

![Painel de ações do Visual Studio para minidump, com opções para depurar nativamente e definir caminhos de símbolos](<../../../images/image (142).png>)

![Disassembly do Visual Studio com instruções da exceção do minidump](<../../../images/image (610).png>)

De qualquer forma, o Visual Studio não é a melhor ferramenta para realizar uma análise aprofundada do dump.

Você deve **abri-lo** usando o **IDA** ou o **Radare** para inspecioná-lo em **profundidade**.

## References

- [1] [Volatility Framework](https://github.com/volatilityfoundation/volatility)
- [2] [Uso do Volatility](https://github.com/volatilityfoundation/volatility/wiki/volatility-usage)
- [3] [Arquivos Minidump](https://learn.microsoft.com/en-us/windows/win32/debug/minidump-files)
- [4] [Usar arquivos de dump no depurador do Visual Studio](https://learn.microsoft.com/en-us/visualstudio/debugger/using-dump-files?view=visualstudio)
{{#include ../../../banners/hacktricks-training.md}}

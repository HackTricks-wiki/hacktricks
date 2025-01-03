{{#include ../../banners/hacktricks-training.md}}

# Linha de Base

Uma linha de base consiste em tirar uma instantânea de certas partes de um sistema para **compará-la com um status futuro para destacar mudanças**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do sistema de arquivos para poder descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, processos em execução, serviços em execução e qualquer outra coisa que não deveria mudar muito, ou de forma alguma.

## Monitoramento de Integridade de Arquivos

O Monitoramento de Integridade de Arquivos (FIM) é uma técnica de segurança crítica que protege ambientes de TI e dados ao rastrear mudanças em arquivos. Envolve duas etapas principais:

1. **Comparação de Linha de Base:** Estabelecer uma linha de base usando atributos de arquivo ou somas de verificação criptográficas (como MD5 ou SHA-2) para comparações futuras a fim de detectar modificações.
2. **Notificação de Mudança em Tempo Real:** Receber alertas instantâneos quando arquivos são acessados ou alterados, tipicamente através de extensões do kernel do SO.

## Ferramentas

- [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
- [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

## Referências

- [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)

{{#include ../../banners/hacktricks-training.md}}

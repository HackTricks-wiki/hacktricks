# Baseline

Uma linha de base consiste em tirar uma foto de certas partes de um sistema para **compará-la com um status futuro para destacar mudanças**.

Por exemplo, você pode calcular e armazenar o hash de cada arquivo do sistema de arquivos para poder descobrir quais arquivos foram modificados.\
Isso também pode ser feito com as contas de usuário criadas, processos em execução, serviços em execução e qualquer outra coisa que não deva mudar muito, ou nada.

## Monitoramento de Integridade de Arquivos

O monitoramento de integridade de arquivos é uma das técnicas mais poderosas usadas para proteger infraestruturas de TI e dados empresariais contra uma ampla variedade de ameaças conhecidas e desconhecidas.\
O objetivo é gerar uma **linha de base de todos os arquivos** que você deseja monitorar e, em seguida, **verificar periodicamente** esses arquivos em busca de possíveis **alterações** (no conteúdo, atributo, metadados, etc.).

1\. **Comparação de linha de base**, em que um ou mais atributos de arquivo serão capturados ou calculados e armazenados como uma linha de base que pode ser comparada no futuro. Isso pode ser tão simples quanto a hora e a data do arquivo, no entanto, como esses dados podem ser facilmente falsificados, uma abordagem mais confiável é geralmente usada. Isso pode incluir avaliar periodicamente o checksum criptográfico para um arquivo monitorado (por exemplo, usando o algoritmo de hash MD5 ou SHA-2) e, em seguida, comparar o resultado com o checksum calculado anteriormente.

2\. **Notificação de alteração em tempo real**, que é tipicamente implementada dentro ou como uma extensão do kernel do sistema operacional que sinalizará quando um arquivo for acessado ou modificado.

## Ferramentas

* [https://github.com/topics/file-integrity-monitoring](https://github.com/topics/file-integrity-monitoring)
* [https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software](https://www.solarwinds.com/security-event-manager/use-cases/file-integrity-monitoring-software)

# Referências

* [https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it](https://cybersecurity.att.com/blogs/security-essentials/what-is-file-integrity-monitoring-and-why-you-need-it)


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

- Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)

- **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

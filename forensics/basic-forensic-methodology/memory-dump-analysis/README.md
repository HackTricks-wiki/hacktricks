# Análise de despejo de memória

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) é o evento de segurança cibernética mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e segurança cibernética em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Começar

Comece **procurando** por **malware** dentro do pcap. Use as **ferramentas** mencionadas em [**Análise de Malware**](../malware-analysis.md).

## [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md)

O principal framework de código aberto para análise de despejo de memória é o [Volatility](../../../generic-methodologies-and-resources/basic-forensic-methodology/memory-dump-analysis/volatility-cheatsheet.md). O Volatility é um script Python para análise de despejos de memória que foram coletados com uma ferramenta externa (ou uma imagem de memória VMware coletada pausando a VM). Portanto, dado o arquivo de despejo de memória e o "perfil" relevante (o SO do qual o despejo foi coletado), o Volatility pode começar a identificar as estruturas nos dados: processos em execução, senhas, etc. Ele também é extensível usando plugins para extrair vários tipos de artefatos.\
De: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

## Relatório de falha de despejo mínimo

Quando o despejo é pequeno (apenas alguns KB, talvez alguns MB), então provavelmente é um relatório de falha de despejo mínimo e não um despejo de memória.

![](<../../../.gitbook/assets/image (216).png>)

Se você tiver o Visual Studio instalado, poderá abrir este arquivo e vincular algumas informações básicas como nome do processo, arquitetura, informações de exceção e módulos em execução:

![](<../../../.gitbook/assets/image (217).png>)

Você também pode carregar a exceção e ver as instruções descompiladas

![](<../../../.gitbook/assets/image (219).png>)

![](<../../../.gitbook/assets/image (218) (1).png>)

De qualquer forma, o Visual Studio não é a melhor ferramenta para realizar uma análise da profundidade do despejo.

Você deve abri-lo usando o IDA ou o Radare para inspecioná-lo em profundidade.

# Checklist - Escalada de Privilégios no Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga** me no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).​

</details>

<figure><img src="../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando seus clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se a lenda do hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

### **Melhor ferramenta para procurar vetores de escalada de privilégios locais no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do Sistema](privilege-escalation/#system-information)

* [ ] Obtenha informações do **SO**
* [ ] Verifique o [**PATH**](privilege-escalation/#path), alguma **pasta gravável**?
* [ ] Verifique as [**variáveis de ambiente**](privilege-escalation/#env-info), algum detalhe sensível?
* [ ] Procure por [**exploits do kernel**](privilege-escalation/#kernel-exploits) **usando scripts** (DirtyCow?)
* [ ] **Verifique** se a [**versão do sudo é vulnerável**](privilege-escalation/#sudo-version)
* [ ] [**Dmesg** falha na verificação de assinatura](privilege-escalation/#dmesg-signature-verification-failed)
* [ ] Mais enumeração do sistema ([data, estatísticas do sistema, informações da CPU, impressoras](privilege-escalation/#more-system-enumeration))
* [ ] [Enumerar mais defesas](privilege-escalation/#enumerate-possible-defenses)

### [Drives](privilege-escalation/#drives)

* [ ] Liste as unidades **montadas**
* [ ] Alguma unidade **desmontada**?
* [ ] Alguma credencial em fstab?

### [**Software Instalado**](privilege-escalation/#installed-software)

* [ ] Verifique se há **software útil** instalado
* [ ] Verifique se há **software vulnerável** instalado

### [Processos](privilege-escalation/#processes)

* [ ] Existe algum software desconhecido em execução?
* [ ] Existe algum software em execução com **privilégios maiores do que deveria**?
* [ ] Procure por **exploits de processos em execução** (especialmente a versão em execução).
* [ ] Você pode **modificar o binário** de algum processo em execução?
* [ ] **Monitore os processos** e verifique se algum processo interessante está sendo executado com frequência.
* [ ] Você pode **ler** alguma **memória de processo** interessante (onde senhas podem estar salvas)?

### [Tarefas Agendadas/Cron?](privilege-escalation/#scheduled-jobs)

* [ ] O [**PATH** ](privilege-escalation/#cron-path)está sendo modificado por algum cron e você pode **escrever** nele?
* [ ] Algum [**curinga** ](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection)em um cron job?
* [ ] Algum **script modificável** está sendo **executado** ou está dentro de uma **pasta modificável**?
* [ ] Você detectou que algum **script** pode estar sendo [**executado** com muita **frequência**](privilege-escalation/#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Serviços](privilege-escalation/#services)

* [ ] Algum arquivo **.service gravável**?
* [ ] Algum **binário gravável** executado por um **serviço**?
* [ ] Alguma **pasta gravável no PATH do systemd**?
### [Timers](privilege-escalation/#timers)

* [ ] Existe algum **timer gravável**?

### [Sockets](privilege-escalation/#sockets)

* [ ] Existe algum arquivo **.socket gravável**?
* [ ] É possível **comunicar-se com algum socket**?
* [ ] Existem **sockets HTTP** com informações interessantes?

### [D-Bus](privilege-escalation/#d-bus)

* [ ] É possível **comunicar-se com algum D-Bus**?

### [Rede](privilege-escalation/#network)

* [ ] Enumere a rede para saber onde você está
* [ ] Existem **portas abertas** que você não conseguia acessar antes de obter um shell na máquina?
* [ ] É possível **capturar tráfego** usando `tcpdump`?

### [Usuários](privilege-escalation/#users)

* [ ] Enumeração de usuários/grupos genéricos
* [ ] Você possui um **UID muito grande**? A máquina está **vulnerável**?
* [ ] É possível [**elevar privilégios graças a um grupo**](privilege-escalation/interesting-groups-linux-pe/) ao qual você pertence?
* [ ] Dados da **Área de Transferência**?
* [ ] Política de Senhas?
* [ ] Tente **usar** todas as **senhas conhecidas** que você descobriu anteriormente para fazer login **com cada** usuário possível. Tente fazer login também sem uma senha.

### [PATH Gravável](privilege-escalation/#writable-path-abuses)

* [ ] Se você tiver **privilégios de gravação em alguma pasta no PATH**, poderá elevar privilégios

### [Comandos SUDO e SUID](privilege-escalation/#sudo-and-suid)

* [ ] É possível executar **qualquer comando com sudo**? É possível usá-lo para LER, ESCREVER ou EXECUTAR qualquer coisa como root? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Existe algum **binário SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
* [ ] Os comandos [**sudo** são **limitados** por **caminho**? É possível **burlar** as restrições](privilege-escalation/#sudo-execution-bypassing-paths)?
* [ ] [**Binário Sudo/SUID sem caminho indicado**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
* [ ] [**Binário SUID especificando caminho**](privilege-escalation/#suid-binary-with-command-path)? Bypass
* [ ] [**Vulnerabilidade LD\_PRELOAD**](privilege-escalation/#ld\_preload)
* [ ] [**Ausência de biblioteca .so em binário SUID**](privilege-escalation/#suid-binary-so-injection) de uma pasta gravável?
* [ ] [**Tokens SUDO disponíveis**](privilege-escalation/#reusing-sudo-tokens)? É possível [**criar um token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
* [ ] É possível [**ler ou modificar arquivos sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
* [ ] É possível [**modificar /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
* [ ] Comando [**OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacidades](privilege-escalation/#capabilities)

* [ ] Algum binário possui alguma **capacidade inesperada**?

### [ACLs](privilege-escalation/#acls)

* [ ] Algum arquivo possui alguma **ACL inesperada**?

### [Sessões de Shell Abertas](privilege-escalation/#open-shell-sessions)

* [ ] **screen**
* [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

* [ ] **Debian** [**OpenSSL PRNG Previsível - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
* [ ] [**Valores de configuração SSH interessantes**](privilege-escalation/#ssh-interesting-configuration-values)

### [Arquivos Interessantes](privilege-escalation/#interesting-files)

* [ ] Arquivos de **perfil** - Ler dados sensíveis? Escrever para privilégios elevados?
* [ ] Arquivos **passwd/shadow** - Ler dados sensíveis? Escrever para privilégios elevados?
* [ ] Verifique pastas comumente interessantes para dados sensíveis
* [ ] **Localização/Estrutura de arquivos estranha**, você pode ter acesso ou alterar arquivos executáveis
* [ ] **Modificado** nos últimos minutos
* [ ] Arquivos de banco de dados **Sqlite**
* [ ] Arquivos **ocultos**
* [ ] **Scripts/Binários no PATH**
* [ ] Arquivos **web** (senhas?)
* [ ] **Backups**?
* [ ] **Arquivos conhecidos que contêm senhas**: Use **Linpeas** e **LaZagne**
* [ ] **Busca genérica**

### [Arquivos Graváveis](privilege-escalation/#writable-files)

* [ ] **Modificar biblioteca Python** para executar comandos arbitrários?
* [ ] É possível **modificar arquivos de log**? Exploração do **Logtotten**
* [ ] É possível **modificar /etc/sysconfig/network-scripts/**? Exploração do Centos/Redhat
* [ ] É possível [**escrever em arquivos ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [Outros truques](privilege-escalation/#other-tricks)

* [ ] É possível [**abusar do NFS para elevar privilégios**](privilege-escalation/#nfs-privilege-escalation)?
* [ ] É necessário [**escapar de um shell restritivo**](privilege-escalation/#escaping-from-restricted-shells)?

<figure><img src="../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando os clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se uma lenda hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) e comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do Telegram**](https://t.me/peass) ou **siga-me no Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

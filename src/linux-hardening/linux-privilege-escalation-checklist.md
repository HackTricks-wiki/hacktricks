# Checklist - Escalação de Privilégios no Linux

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de escalonamento de privilégios locais no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do Sistema](privilege-escalation/#system-information)

- [ ] Obter **informações do SO**
- [ ] Verificar o [**PATH**](privilege-escalation/#path), alguma **pasta gravável**?
- [ ] Verificar [**variáveis de ambiente**](privilege-escalation/#env-info), algum detalhe sensível?
- [ ] Procurar por [**explorações de kernel**](privilege-escalation/#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] **Verificar** se a [**versão do sudo** é vulnerável](privilege-escalation/#sudo-version)
- [ ] [**Verificação de assinatura do Dmesg** falhou](privilege-escalation/#dmesg-signature-verification-failed)
- [ ] Mais enumeração do sistema ([data, estatísticas do sistema, informações da CPU, impressoras](privilege-escalation/#more-system-enumeration))
- [ ] [**Enumerar mais defesas**](privilege-escalation/#enumerate-possible-defenses)

### [Unidades](privilege-escalation/#drives)

- [ ] **Listar unidades** montadas
- [ ] **Alguma unidade não montada?**
- [ ] **Algumas credenciais no fstab?**

### [**Software Instalado**](privilege-escalation/#installed-software)

- [ ] **Verificar por** [**software útil**](privilege-escalation/#useful-software) **instalado**
- [ ] **Verificar por** [**software vulnerável**](privilege-escalation/#vulnerable-software-installed) **instalado**

### [Processos](privilege-escalation/#processes)

- [ ] Algum **software desconhecido em execução**?
- [ ] Algum software em execução com **mais privilégios do que deveria ter**?
- [ ] Procurar por **explorações de processos em execução** (especialmente a versão em execução).
- [ ] Você pode **modificar o binário** de algum processo em execução?
- [ ] **Monitorar processos** e verificar se algum processo interessante está sendo executado com frequência.
- [ ] Você pode **ler** alguma **memória de processo** interessante (onde senhas poderiam estar salvas)?

### [Tarefas Agendadas/Cron?](privilege-escalation/#scheduled-jobs)

- [ ] O [**PATH**](privilege-escalation/#cron-path) está sendo modificado por algum cron e você pode **escrever** nele?
- [ ] Algum [**caractere curinga**](privilege-escalation/#cron-using-a-script-with-a-wildcard-wildcard-injection) em uma tarefa cron?
- [ ] Algum [**script modificável**](privilege-escalation/#cron-script-overwriting-and-symlink) está sendo **executado** ou está dentro de uma **pasta modificável**?
- [ ] Você detectou que algum **script** poderia estar ou está sendo [**executado** muito **frequentemente**](privilege-escalation/#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Serviços](privilege-escalation/#services)

- [ ] Algum arquivo **.service** **gravável**?
- [ ] Algum **binário gravável** executado por um **serviço**?
- [ ] Alguma **pasta gravável no PATH do systemd**?

### [Tempos](privilege-escalation/#timers)

- [ ] Algum **temporizador gravável**?

### [Sockets](privilege-escalation/#sockets)

- [ ] Algum arquivo **.socket** **gravável**?
- [ ] Você pode **se comunicar com algum socket**?
- [ ] **Sockets HTTP** com informações interessantes?

### [D-Bus](privilege-escalation/#d-bus)

- [ ] Você pode **se comunicar com algum D-Bus**?

### [Rede](privilege-escalation/#network)

- [ ] Enumerar a rede para saber onde você está
- [ ] **Portas abertas que você não conseguiu acessar antes** de obter um shell dentro da máquina?
- [ ] Você pode **capturar tráfego** usando `tcpdump`?

### [Usuários](privilege-escalation/#users)

- [ ] Enumeração de usuários/grupos **genéricos**
- [ ] Você tem um **UID muito grande**? A **máquina** é **vulnerável**?
- [ ] Você pode [**escalar privilégios graças a um grupo**](privilege-escalation/interesting-groups-linux-pe/) ao qual pertence?
- [ ] Dados da **Área de Transferência**?
- [ ] Política de Senhas?
- [ ] Tente **usar** cada **senha conhecida** que você descobriu anteriormente para fazer login **com cada** possível **usuário**. Tente fazer login também sem uma senha.

### [PATH Gravável](privilege-escalation/#writable-path-abuses)

- [ ] Se você tiver **privilégios de escrita sobre alguma pasta no PATH**, pode ser capaz de escalar privilégios

### [Comandos SUDO e SUID](privilege-escalation/#sudo-and-suid)

- [ ] Você pode executar **qualquer comando com sudo**? Você pode usá-lo para LER, ESCREVER ou EXECUTAR algo como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Algum **binário SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Os [**comandos sudo** são **limitados** por **path**? você pode **contornar** as restrições](privilege-escalation/#sudo-execution-bypassing-paths)?
- [ ] [**Binário Sudo/SUID sem path indicado**](privilege-escalation/#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binário SUID especificando path**](privilege-escalation/#suid-binary-with-command-path)? Contornar
- [ ] [**Vuln LD_PRELOAD**](privilege-escalation/#ld_preload)
- [ ] [**Falta de biblioteca .so em binário SUID**](privilege-escalation/#suid-binary-so-injection) de uma pasta gravável?
- [ ] [**Tokens SUDO disponíveis**](privilege-escalation/#reusing-sudo-tokens)? [**Você pode criar um token SUDO**](privilege-escalation/#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Você pode [**ler ou modificar arquivos sudoers**](privilege-escalation/#etc-sudoers-etc-sudoers-d)?
- [ ] Você pode [**modificar /etc/ld.so.conf.d/**](privilege-escalation/#etc-ld-so-conf-d)?
- [ ] Comando [**OpenBSD DOAS**](privilege-escalation/#doas)

### [Capacidades](privilege-escalation/#capabilities)

- [ ] Algum binário tem alguma **capacidade inesperada**?

### [ACLs](privilege-escalation/#acls)

- [ ] Algum arquivo tem alguma **ACL inesperada**?

### [Sessões de Shell Abertas](privilege-escalation/#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/#ssh)

- [ ] **Debian** [**OpenSSL PRNG Previsível - CVE-2008-0166**](privilege-escalation/#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores de configuração interessantes do SSH**](privilege-escalation/#ssh-interesting-configuration-values)

### [Arquivos Interessantes](privilege-escalation/#interesting-files)

- [ ] **Arquivos de perfil** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Arquivos passwd/shadow** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Verificar pastas comumente interessantes** por dados sensíveis
- [ ] **Localização Estranha/Arquivos de Propriedade,** você pode ter acesso ou alterar arquivos executáveis
- [ ] **Modificado** nos últimos minutos
- [ ] **Arquivos de DB Sqlite**
- [ ] **Arquivos Ocultos**
- [ ] **Scripts/Binários no PATH**
- [ ] **Arquivos Web** (senhas?)
- [ ] **Backups**?
- [ ] **Arquivos conhecidos que contêm senhas**: Use **Linpeas** e **LaZagne**
- [ ] **Busca genérica**

### [**Arquivos Graváveis**](privilege-escalation/#writable-files)

- [ ] **Modificar biblioteca python** para executar comandos arbitrários?
- [ ] Você pode **modificar arquivos de log**? Exploit **Logtotten**
- [ ] Você pode **modificar /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Você pode [**escrever em arquivos ini, int.d, systemd ou rc.d**](privilege-escalation/#init-init-d-systemd-and-rc-d)?

### [**Outras truques**](privilege-escalation/#other-tricks)

- [ ] Você pode [**abusar do NFS para escalar privilégios**](privilege-escalation/#nfs-privilege-escalation)?
- [ ] Você precisa [**escapar de um shell restritivo**](privilege-escalation/#escaping-from-restricted-shells)?

{{#include ../banners/hacktricks-training.md}}

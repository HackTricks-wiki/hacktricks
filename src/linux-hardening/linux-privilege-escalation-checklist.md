# Checklist - Elevação de Privilégios no Linux

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores de elevação de privilégio local no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do Sistema](privilege-escalation/index.html#system-information)

- [ ] Obter **informações do OS**
- [ ] Verificar o [**PATH**](privilege-escalation/index.html#path), existe alguma **pasta gravável**?
- [ ] Verificar [**variáveis de env**](privilege-escalation/index.html#env-info), há algum detalhe sensível?
- [ ] Procurar por [**explorações de kernel**](privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] **Verificar** se a [**versão do sudo** é vulnerável](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Mais enumeração do sistema ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerar mais defesas](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Listar** drives montados
- [ ] **Algum drive não montado?**
- [ ] **Alguma credencial em fstab?**

### [**Software Instalado**](privilege-escalation/index.html#installed-software)

- [ ] **Verificar** se há [**software útil**](privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Verificar** se há [**software vulnerável**](privilege-escalation/index.html#vulnerable-software-installed) **instalado**

### [Processos](privilege-escalation/index.html#processes)

- [ ] Algum **software desconhecido em execução**?
- [ ] Algum software em execução com **mais privilégios do que deveria**?
- [ ] Procurar por **explorações de processos em execução** (especialmente a versão em execução).
- [ ] Você pode **modificar o binário** de algum processo em execução?
- [ ] **Monitorar processos** e verificar se algum processo interessante é executado frequentemente.
- [ ] Você pode **ler** alguma **memória de processo** interessante (onde senhas podem estar salvas)?

### [Tarefas Agendadas/Cron?](privilege-escalation/index.html#scheduled-jobs)

- [ ] O [**PATH** ](privilege-escalation/index.html#cron-path) está sendo modificado por algum cron e você pode **escrever** nele?
- [ ] Algum [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) em um job cron?
- [ ] Algum [**script modificável** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) está sendo **executado** ou está dentro de uma **pasta modificável**?
- [ ] Você detectou que algum **script** pode estar sendo [**executado** com muita **frequência**](privilege-escalation/index.html#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Serviços](privilege-escalation/index.html#services)

- [ ] Algum arquivo **.service gravável**?
- [ ] Algum **binário gravável** executado por um **service**?
- [ ] Alguma **pasta gravável no systemd PATH**?
- [ ] Algum **systemd unit drop-in gravável** em `/etc/systemd/system/<unit>.d/*.conf` que pode sobrescrever `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Algum **timer gravável**?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Algum arquivo **.socket gravável**?
- [ ] Você consegue **comunicar com algum socket**?
- [ ] **HTTP sockets** com informação interessante?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Você consegue **comunicar com algum D-Bus**?

### [Rede](privilege-escalation/index.html#network)

- [ ] Enumerar a rede para saber onde você está
- [ ] **Portas abertas que você não conseguia acessar antes** de obter um shell na máquina?
- [ ] Você pode **capturar tráfego** usando `tcpdump`?

### [Usuários](privilege-escalation/index.html#users)

- [ ] Enumeração genérica de usuários/grupos
- [ ] Você tem um **UID muito grande**? A **máquina** é **vulnerável**?
- [ ] Você pode [**escalar privilégios graças a um grupo**](privilege-escalation/interesting-groups-linux-pe/index.html) do qual faz parte?
- [ ] **Dados da área de transferência**?
- [ ] Política de senhas?
- [ ] Tente **usar** todas as **senhas conhecidas** que você descobriu anteriormente para logar **com cada** possível **usuário**. Tente também logar sem senha.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Se você tem **permissão de escrita sobre alguma pasta no PATH** pode ser possível escalar privilégios

### [SUDO e SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Você consegue executar **algum comando com sudo**? Pode usá-lo para LER, ESCREVER ou EXECUTAR algo como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` permite `sudoedit`, verifique **injeção de argumento no sudoedit** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar arquivos arbitrários em versões vulneráveis (`sudo -V` < 1.9.12p2). Exemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Existe algum **binário SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Os [**comandos sudo são limitados por path? você pode **burlar** as restrições](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Comando Sudo/SUID sem path indicado**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binário SUID especificando path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Falta de .so library em binário SUID**](privilege-escalation/index.html#suid-binary-so-injection) vindo de uma pasta gravável?
- [ ] [**Tokens SUDO disponíveis**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Você consegue criar um token SUDO**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Você pode [**ler ou modificar arquivos sudoers**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Você pode [**modificar /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] [**OpenBSD DOAS**](privilege-escalation/index.html#doas) command

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Algum binário possui alguma **capability inesperada**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Algum arquivo possui alguma **ACL inesperada**?

### [Sessões Shell Abertas](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores de configuração SSH interessantes**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Arquivos Interessantes](privilege-escalation/index.html#interesting-files)

- [ ] **Arquivos de profile** - Ler dados sensíveis? Escrever para privesc?
- [ ] **passwd/shadow** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Verificar pastas comumente interessantes** por dados sensíveis
- [ ] **Arquivos em locais estranhos/possuídos,** você pode ter acesso ou alterar arquivos executáveis
- [ ] **Modificados** nos últimos minutos
- [ ] **Arquivos Sqlite DB**
- [ ] **Arquivos ocultos**
- [ ] **Script/Binários no PATH**
- [ ] **Arquivos web** (senhas?)
- [ ] **Backups**?
- [ ] **Arquivos conhecidos que contêm senhas**: Use **Linpeas** e **LaZagne**
- [ ] **Busca genérica**

### [**Arquivos Graváveis**](privilege-escalation/index.html#writable-files)

- [ ] **Modificar biblioteca python** para executar comandos arbitrários?
- [ ] Você pode **modificar arquivos de log**? exploit Logtotten
- [ ] Você pode **modificar /etc/sysconfig/network-scripts/**? exploit Centos/Redhat
- [ ] Você pode [**escrever em ini, init.d, systemd ou rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Outros truques**](privilege-escalation/index.html#other-tricks)

- [ ] Você pode [**abusar do NFS para escalar privilégios**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Precisa [**escapar de um shell restrito**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}

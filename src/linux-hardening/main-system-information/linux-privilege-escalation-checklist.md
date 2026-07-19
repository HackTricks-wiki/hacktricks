# Checklist - Escalação de Privilégios no Linux

{{#include ../../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores locais de escalação de privilégios no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do Sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obter **informações do SO**
- [ ] Verificar o [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), há alguma **pasta gravável**?
- [ ] Verificar [**variáveis de ambiente**](../linux-basics/linux-privilege-escalation/index.html#env-info), há algum detalhe sensível?
- [ ] Procurar [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] **Verificar** se a [**versão do sudo** é vulnerável](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Falha na verificação da assinatura do Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Revisar [**configurações incorretas de kernel module e carregamento de módulos**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, imposição de assinaturas e `modules_disabled`.
- [ ] Verificar [**caminhos de abuso de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) se o caminho do helper puder ser modificado ou acionado.
- [ ] Verificar [**caminhos graváveis em /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), incluindo arquivos `.ko*` graváveis e metadados `modules.*`.
- [ ] Mais enumeração do sistema ([data, estatísticas do sistema, informações da CPU, impressoras](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerar mais defesas](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unidades](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Listar** unidades montadas
- [ ] **Existe alguma unidade não montada?**
- [ ] **Há alguma credencial no fstab?**

### [**Software instalado**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Verificar se há**[ **software útil**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Verificar se há** [**software vulnerável**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instalado**

### [Processos](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Há algum **software desconhecido em execução**?
- [ ] Há algum software em execução com **mais privilégios do que deveria**?
- [ ] Procurar **exploits de processos em execução** (especialmente da versão em execução).
- [ ] Você pode **modificar o binary** de algum processo em execução?
- [ ] **Monitorar processos** e verificar se algum processo interessante está sendo executado com frequência.
- [ ] Você pode **ler** alguma **memória de processo** interessante (onde as senhas poderiam estar salvas)?

### [Tarefas agendadas/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] O [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)está sendo modificado por algum cron e você pode **escrever** nele?
- [ ] Há algum [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)em uma tarefa cron?
- [ ] Algum [**script modificável** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)está sendo **executado** ou está dentro de uma **pasta modificável**?
- [ ] Você detectou que algum **script** poderia estar ou está sendo [**executado** com muita **frequência**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Existe algum arquivo **.service gravável**?
- [ ] Existe algum **binary gravável** executado por um **service**?
- [ ] Existe alguma **pasta gravável no PATH do systemd**?
- [ ] Existe algum **drop-in de unit do systemd gravável** em `/etc/systemd/system/<unit>.d/*.conf` que possa substituir `ExecStart`/`User`?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Existe algum **timer gravável**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Existe algum arquivo **.socket gravável**?
- [ ] Você pode **se comunicar com algum socket**?
- [ ] Existem **sockets HTTP** com informações interessantes?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Você pode **se comunicar com algum D-Bus**?

### [Rede](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerar a rede para saber onde você está
- [ ] Existem **portas abertas às quais você não conseguia acessar antes** de obter um shell dentro da máquina?
- [ ] Você pode **sniffar o tráfego** usando `tcpdump`?

### [Usuários](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeração** genérica de usuários/grupos
- [ ] Você tem um **UID muito grande**? A **máquina** é **vulnerável**?
- [ ] Você pode [**escalar privilégios graças a um grupo**](../user-information/interesting-groups-linux-pe/index.html) ao qual pertence?
- [ ] Dados da **clipboard**?
- [ ] Política de senhas?
- [ ] Tentar **usar** todas as **senhas conhecidas** que você descobriu anteriormente para fazer login **com cada** **usuário** possível. Tentar fazer login também sem uma senha.

### [PATH gravável](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se você tiver **permissões de escrita sobre alguma pasta no PATH**, poderá conseguir escalar privilégios

### [Comandos SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Você pode executar **algum comando com sudo**? Pode usá-lo para LER, ESCREVER ou EXECUTAR qualquer coisa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` permitir `sudoedit`, verificar **injeção de argumentos do sudoedit** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar arquivos arbitrários em versões vulneráveis (`sudo -V` < 1.9.12p2). Exemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Existe algum **binary SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Os comandos [**sudo** são **limitados** pelo **path**? Você pode **bypassar as restrições**](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binary Sudo/SUID sem path indicado**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binary SUID especificando um path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vuln de LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ausência de biblioteca .so no binary SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) a partir de uma pasta gravável?
- [ ] [**RPATH/RUNPATH SUID ou path de biblioteca gravável**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens disponíveis**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Você pode criar um SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Você pode [**ler ou modificar arquivos sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Você pode [**modificar /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Comando [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Algum binary possui alguma **capability inesperada**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Algum arquivo possui alguma **ACL inesperada**?

### [Sessões de shell abertas](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores de configuração interessantes do SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Arquivos interessantes](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Arquivos de perfil** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Arquivos passwd/shadow** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Verificar pastas normalmente interessantes** em busca de dados sensíveis
- [ ] **Arquivos em locais estranhos/de propriedade de alguém,** aos quais você pode ter acesso ou cujos arquivos executáveis pode alterar
- [ ] **Modificados** nos últimos minutos
- [ ] **Arquivos de DB Sqlite**
- [ ] **Arquivos ocultos**
- [ ] **Scripts/Binaries no PATH**
- [ ] **Arquivos web** (senhas?)
- [ ] **Backups**?
- [ ] **Arquivos conhecidos que contêm senhas**: usar **Linpeas** e **LaZagne**
- [ ] **Busca genérica**

### [**Arquivos graváveis**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modificar biblioteca Python** para executar comandos arbitrários?
- [ ] Você pode **modificar arquivos de log**? Exploit **Logtotten**
- [ ] Você pode **modificar /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Você pode [**escrever em arquivos ini, int.d, systemd ou rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Outros truques**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Você pode [**abusar do NFS para escalar privilégios**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Você precisa [**escapar de um shell restritivo**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referências

- [Aviso do Sudo: edição arbitrária de arquivos pelo sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Documentação do Oracle Linux: configuração de drop-in do systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}

# Lista de verificação de Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

# Lista de verificação - Linux Privilege Escalation



### **Melhor tool para procurar vetores locais de Linux privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obter **informações do SO**
- [ ] Verificar o [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), alguma **pasta gravável**?
- [ ] Verificar [**variáveis de ambiente**](../linux-basics/linux-privilege-escalation/index.html#env-info), algum detalhe sensível?
- [ ] Procurar por [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] **Verificar** se a [**versão do sudo** é vulnerável](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Falha na verificação da assinatura do Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Revisar [**configurações incorretas de kernel module e carregamento de modules**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, enforcement de assinatura e `modules_disabled`.
- [ ] Verificar [**caminhos de abuso de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) se o caminho do helper puder ser modificado ou acionado.
- [ ] Verificar [**caminhos graváveis em /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), incluindo arquivos `.ko*` graváveis e metadados `modules.*`.
- [ ] Mais enumeração do sistema ([data, estatísticas do sistema, informações da CPU, impressoras](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerar mais defesas](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Listar** drives montados
- [ ] **Algum drive não montado?**
- [ ] **Alguma credencial no fstab?**

### [**Software instalado**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Verificar se há**[ **software útil**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Verificar se há** [**software vulnerável**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instalado**

### [Processes](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Há algum **software desconhecido em execução**?
- [ ] Há algum software em execução com **mais privilégios do que deveria ter**?
- [ ] Procurar por **exploits de processes em execução** (especialmente a versão em execução).
- [ ] É possível **modificar o binary** de algum process em execução?
- [ ] **Monitorar processes** e verificar se algum process interessante está sendo executado frequentemente.
- [ ] É possível **ler** a **memória de algum process** interessante (onde passwords poderiam estar salvas)?

### [Scheduled/Cron jobs?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] O [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)está sendo modificado por algum cron e você pode **escrever** nele?
- [ ] Há algum [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)em um cron job?
- [ ] Algum [**script modificável** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)está sendo **executado** ou está dentro de uma **pasta modificável**?
- [ ] Você detectou que algum **script** poderia estar ou está sendo [**executado** com muita **frequência**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Services](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Existe algum arquivo **.service gravável**?
- [ ] Existe algum **binary gravável** executado por um **service**?
- [ ] Existe alguma **pasta gravável no PATH do systemd**?
- [ ] Existe algum **systemd unit drop-in gravável** em `/etc/systemd/system/<unit>.d/*.conf` que possa sobrescrever `ExecStart`/`User`?

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Existe algum **timer gravável**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Existe algum arquivo **.socket gravável**?
- [ ] É possível **comunicar-se com algum socket**?
- [ ] Há **sockets HTTP** com informações interessantes?

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] É possível **comunicar-se com algum D-Bus**?

### [Network](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerar a network para saber onde você está
- [ ] Existem **ports abertos aos quais você não conseguia acessar antes** de obter um shell dentro da máquina?
- [ ] É possível **sniffar traffic** usando `tcpdump`?

### [Users](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeração** genérica de users/groups
- [ ] Você tem um **UID muito grande**? A **máquina** é **vulnerável**?
- [ ] É possível [**escalar privilégios graças a um group**](../user-information/interesting-groups-linux-pe/index.html) ao qual você pertence?
- [ ] Dados da **clipboard**?
- [ ] Password Policy?
- [ ] Tentar **usar** cada **password conhecida** que você descobriu anteriormente para fazer login **com cada** **user** possível. Tentar fazer login também sem uma password.

### [Writable PATH](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se você tiver **privilégios de escrita sobre alguma pasta no PATH**, poderá conseguir escalar privilégios

### [Comandos SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] É possível executar **algum comando com sudo**? É possível usá-lo para LER, ESCREVER ou EXECUTAR qualquer coisa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` permitir `sudoedit`, verificar **sudoedit argument injection** (CVE-2023-22809) por meio de `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar arquivos arbitrários em versões vulneráveis (`sudo -V` < 1.9.12p2). Exemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Existe algum **binary SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Os comandos [**sudo** são **limitados** pelo **path**? É possível **bypassar** as restrições](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binary Sudo/SUID sem path indicado**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binary SUID especificando um path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vuln de LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ausência de library .so no binary SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) em uma pasta gravável?
- [ ] [**SUID RPATH/RUNPATH ou library path gravável**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens disponíveis**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**É possível criar um SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] É possível [**ler ou modificar arquivos sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] É possível [**modificar /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
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
- [ ] [**Valores interessantes da configuração do SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Arquivos interessantes](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Arquivos de Profile** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Arquivos passwd/shadow** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Verificar pastas normalmente interessantes** em busca de dados sensíveis
- [ ] **Arquivos em locais estranhos/de propriedade incomum,** aos quais você pode ter acesso ou cujos arquivos executáveis pode alterar
- [ ] **Modificados** nos últimos minutos
- [ ] **Arquivos de DB SQLite**
- [ ] **Arquivos ocultos**
- [ ] **Scripts/Binaries no PATH**
- [ ] **Arquivos web** (passwords?)
- [ ] **Backups**?
- [ ] **Arquivos conhecidos que contêm passwords**: usar **Linpeas** e **LaZagne**
- [ ] **Busca genérica**

### [**Arquivos graváveis**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modificar library Python** para executar comandos arbitrários?
- [ ] É possível **modificar arquivos de log**? Exploit **Logtotten**
- [ ] É possível **modificar /etc/sysconfig/network-scripts/**? Exploit de Centos/Redhat
- [ ] É possível [**escrever em arquivos ini, int.d, systemd ou rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Outros tricks**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] É possível [**abusar do NFS para escalar privilégios**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] É necessário [**escapar de um shell restritivo**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referências

- [Advisory do Sudo: edição arbitrária de arquivos com sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Documentação do Oracle Linux: configuração de systemd drop-in](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../../banners/hacktricks-training.md}}

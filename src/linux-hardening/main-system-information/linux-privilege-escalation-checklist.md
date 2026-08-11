# Checklist de Escalação de Privilégios no Linux

# Checklist - Escalação de Privilégios no Linux



### **Melhor ferramenta para procurar vetores de escalação de privilégios locais no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do Sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obter **informações do SO**
- [ ] Verificar o [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path), existe alguma **pasta gravável**?
- [ ] Verificar [**variáveis de ambiente**](../linux-basics/linux-privilege-escalation/index.html#env-info), há algum detalhe sensível?
- [ ] Procurar [**kernel exploits**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] Antes de executar um kernel PoC, verificar seus **pré-requisitos reais**, não apenas `uname -r`: arquitetura, opções/módulos `CONFIG_*` necessários, criação de namespaces e mitigações ativas. Por exemplo, testar a disponibilidade de user/network namespaces com `unshare -Urn true`; exploits modernos de netfilter podem exigir `CONFIG_USER_NS`, user namespaces não privilegiados e `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Verificar** se a [**versão do sudo** é vulnerável](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] [**Falha na verificação da assinatura do Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Revisar [**configurações incorretas de módulos do kernel e carregamento de módulos**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, imposição de assinaturas e `modules_disabled`.
- [ ] Verificar [**caminhos de abuso de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) se o caminho do helper puder ser modificado ou acionado.
- [ ] Verificar [**caminhos graváveis em /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), incluindo arquivos `.ko*` graváveis e metadados `modules.*`.
- [ ] Mais enumeração do sistema ([data, estatísticas do sistema, informações da CPU, impressoras](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerar mais defesas](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] Listar drives **montados**
- [ ] Existe algum **drive não montado**?
- [ ] Existem **creds no fstab**?

### [**Software Instalado**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Verificar se há**[ **software útil**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Verificar se há** [**software vulnerável**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instalado**
- [ ] No Debian/Ubuntu, verificar se o **needrestart interpreter scanning** está instalado/habilitado: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Builds vulneráveis atravessavam o limite de privilégios reutilizando `PYTHONPATH`/`RUBYLIB` controlados pelo atacante, fazendo race condition em `/proc/<pid>/exe` ou examinando caminhos Perl controlados pelo atacante quando o APT ou `unattended-upgrades` invocava o needrestart como root.<sup>[[4]](#references)</sup>

### [Processos](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Há algum **software desconhecido em execução**?
- [ ] Há algum software sendo executado com **mais privilégios do que deveria**?
- [ ] Procurar **exploits de processos em execução** (especialmente da versão em execução).
- [ ] Você pode **modificar o binário** de algum processo em execução?
- [ ] **Monitorar os processos** e verificar se algum processo interessante está sendo executado frequentemente.
- [ ] Você pode **ler** a **memória de algum processo** interessante (onde senhas podem estar armazenadas)?

### [Tarefas agendadas/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] O [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)está sendo modificado por algum cron e você pode **escrever** nele?
- [ ] Há algum [**wildcard** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)em um cron job?
- [ ] Algum [**script modificável** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)está sendo **executado** ou está dentro de uma **pasta modificável**?
- [ ] Você detectou que algum **script** pode estar ou está sendo [**executado** com muita **frequência**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Serviços](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Existe algum arquivo **.service gravável**?
- [ ] Existe algum **binário gravável** executado por um **serviço**?
- [ ] Existe algum **helper, arquivo de configuração ou de ambiente gravável referenciado por uma unit root** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Inspecione a unit mesclada com `systemctl cat <unit>` e revise o [abuso de arquivos de service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Existe alguma **pasta gravável no PATH do systemd**?
- [ ] Existe algum **drop-in de unit do systemd gravável** em `/etc/systemd/system/<unit>.d/*.conf` que possa sobrescrever `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Existe algum **timer gravável**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Existe algum arquivo **.socket gravável**?
- [ ] Você pode **se comunicar com algum socket**?
- [ ] Existem **sockets HTTP** com informações interessantes?
- [ ] Você pode acessar uma [**API de container-runtime ou node-agent**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), como `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ou um endpoint do kubelet? Teste a API HTTP/gRPC bruta mesmo quando a CLI usual estiver ausente.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Você pode **se comunicar com algum D-Bus**?

### [Rede](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumerar a rede para saber onde você está
- [ ] Existem **portas abertas que você não conseguia acessar antes** de obter um shell dentro da máquina?
- [ ] Você pode **sniffar o tráfego** usando `tcpdump`?

### [Usuários](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] **Enumeração** genérica de usuários/grupos
- [ ] Você tem um **UID muito grande**? A **máquina** é **vulnerável**?
- [ ] Você pode [**escalar privilégios graças a um grupo**](../user-information/interesting-groups-linux-pe/index.html) ao qual pertence?
- [ ] Dados da **clipboard**?
- [ ] Política de senhas?
- [ ] Tentar **usar** cada **senha conhecida** que você descobriu anteriormente para fazer login **com cada** usuário possível. Tentar fazer login também sem senha.

### [PATH Gravável](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se você tiver **privilégios de escrita sobre alguma pasta no PATH**, poderá conseguir escalar privilégios

### [Comandos SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Você pode executar **algum comando com sudo**? Pode usá-lo para LER, ESCREVER ou EXECUTAR qualquer coisa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` permitir `sudoedit`, verificar **injeção de argumentos do sudoedit** (CVE-2023-22809) por meio de `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar arquivos arbitrários em versões vulneráveis (`sudo -V` < 1.9.12p2). Exemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Existe algum **binário SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Os comandos [**sudo** são **limitados** pelo **path**? Você pode **bypassar** as restrições](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Binário Sudo/SUID sem path indicado**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binário SUID especificando path**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**Vuln de LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ausência de biblioteca .so no binário SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) a partir de uma pasta gravável?
- [ ] [**SUID RPATH/RUNPATH ou caminho de biblioteca gravável**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] [**SUDO tokens disponíveis**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Você pode criar um SUDO token**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Você pode [**ler ou modificar arquivos sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Você pode [**modificar /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Comando [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Algum binário possui alguma **capability inesperada**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Algum arquivo possui alguma **ACL inesperada**?

### [Sessões de Shell abertas](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores interessantes de configuração do SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Arquivos Interessantes](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Arquivos de perfil** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Arquivos passwd/shadow** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Verificar pastas geralmente interessantes** em busca de dados sensíveis
- [ ] **Arquivos em locais/proprietários incomuns**, aos quais você pode ter acesso ou cujos arquivos executáveis pode alterar
- [ ] **Modificados** nos últimos minutos
- [ ] **Arquivos de DB SQLite**
- [ ] **Arquivos ocultos**
- [ ] **Scripts/Binários no PATH**
- [ ] **Arquivos web** (senhas?)
- [ ] **Backups**?
- [ ] **Arquivos conhecidos que contêm senhas**: usar **Linpeas** e **LaZagne**
- [ ] **Busca genérica**

### [**Arquivos Graváveis**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] **Modificar biblioteca Python** para executar comandos arbitrários?
- [ ] Você pode **modificar arquivos de log**? Exploit **Logtotten**
- [ ] Você pode **modificar /etc/sysconfig/network-scripts/**? Exploit de Centos/Redhat
- [ ] Você pode [**escrever em arquivos ini, int.d, systemd ou rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Outros truques**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Você pode [**abusar do NFS para escalar privilégios**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Você precisa [**escapar de um shell restritivo**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Aviso do Sudo: edição arbitrária de arquivos pelo sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentação do Oracle Linux: configuração de drop-in do systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: requisitos e pesquisa do exploit do CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Aviso de segurança da Qualys: LPEs no needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}

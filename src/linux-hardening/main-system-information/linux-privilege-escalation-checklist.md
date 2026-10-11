# Checklist de Escalada de Privilégios no Linux

{{#include ../../banners/hacktricks-training.md}}

# Checklist - Escalada de Privilégios no Linux



### **Melhor ferramenta para procurar vetores de escalada de privilégios locais no Linux:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [Informações do sistema](../linux-basics/linux-privilege-escalation/index.html#system-information)

- [ ] Obtenha informações do **SO**
- [ ] Verifique o [**PATH**](../linux-basics/linux-privilege-escalation/index.html#path). Há alguma **pasta gravável**?
- [ ] Verifique as [**variáveis de ambiente**](../linux-basics/linux-privilege-escalation/index.html#env-info). Há algum dado confidencial?
- [ ] Procure [**exploits de kernel**](../linux-basics/linux-privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] Antes de executar um PoC de kernel, verifique os **pré-requisitos reais**, não apenas `uname -r`: arquitetura, opções/módulos `CONFIG_*` necessários, criação de namespaces e mitigações ativas. Por exemplo, teste a disponibilidade de namespaces de usuário/rede com `unshare -Urn true`; exploits modernos de netfilter podem exigir `CONFIG_USER_NS`, namespaces de usuário sem privilégios e `CONFIG_NF_TABLES`.<sup>[[3]](#references)</sup>
- [ ] **Verifique** se a [**versão do sudo** é vulnerável](../linux-basics/linux-privilege-escalation/index.html#sudo-version)
- [ ] Falha na verificação de assinatura do [**Dmesg**](../linux-basics/linux-privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Revise [**configurações incorretas de módulos do kernel e do carregamento de módulos**](kernel-modules-and-modprobe.md#kernel-module-and-module-loading-misconfigurations): `insmod`, `modinfo`, `lsmod`, `dmesg`, aplicação de assinaturas e `modules_disabled`.
- [ ] Verifique [**caminhos de abuso de kernel.modprobe / modprobe_path**](kernel-modules-and-modprobe.md#kernelmodprobe--modprobe_path-abuse-checks) caso o caminho do helper possa ser modificado ou acionado.
- [ ] Verifique [**caminhos graváveis em /lib/modules**](kernel-modules-and-modprobe.md#writable-libmodules-review), incluindo arquivos `.ko*` graváveis e metadados `modules.*`.
- [ ] Mais enumeração do sistema ([data, estatísticas do sistema, informações da CPU, impressoras](../linux-basics/linux-privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumere mais defesas](../linux-basics/linux-privilege-escalation/index.html#enumerate-possible-defenses)

### [Unidades](../linux-basics/linux-privilege-escalation/index.html#drives)

- [ ] **Liste as unidades montadas**
- [ ] Há alguma **unidade desmontada**?
- [ ] Há alguma credencial no fstab?

### [**Software instalado**](../linux-basics/linux-privilege-escalation/index.html#installed-software)

- [ ] **Verifique se há** [**software útil**](../linux-basics/linux-privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Verifique se há** [**software vulnerável**](../linux-basics/linux-privilege-escalation/index.html#vulnerable-software-installed) **instalado**
- [ ] No Debian/Ubuntu, verifique se o **escaneamento de interpretadores do needrestart** está instalado/ativado: `dpkg-query -W needrestart 2>/dev/null; grep -R interpscan /etc/needrestart 2>/dev/null`. Versões vulneráveis atravessavam a fronteira de privilégios reutilizando `PYTHONPATH`/`RUBYLIB` controlados pelo atacante, explorando uma condição de corrida em `/proc/<pid>/exe` ou escaneando caminhos Perl controlados pelo atacante quando o APT ou o `unattended-upgrades` executava o needrestart como root.<sup>[[4]](#references)</sup>

### [Processos](../linux-basics/linux-privilege-escalation/index.html#processes)

- [ ] Há algum **software desconhecido em execução**?
- [ ] Há algum software em execução com **mais privilégios do que deveria**?
- [ ] Procure **exploits para os processos em execução** (especialmente para a versão em execução).
- [ ] Você consegue **modificar o binário** de algum processo em execução?
- [ ] **Monitore os processos** e verifique se algum processo interessante é executado com frequência.
- [ ] Você consegue **ler** a **memória de algum processo** interessante (onde senhas podem estar salvas)?

### [Tarefas agendadas/Cron?](../linux-basics/linux-privilege-escalation/index.html#scheduled-jobs)

- [ ] O [**PATH** ](../linux-basics/linux-privilege-escalation/index.html#cron-path)está sendo modificado por algum cron, e você consegue **escrever** nele?
- [ ] Há algum [**curinga** ](../linux-basics/linux-privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection)em uma tarefa cron?
- [ ] Algum [**script modificável** ](../linux-basics/linux-privilege-escalation/index.html#cron-script-overwriting-and-symlink)está sendo **executado** ou está dentro de uma **pasta modificável**?
- [ ] Você detectou algum **script** que poderia estar ou está sendo [**executado** com muita **frequência**](../linux-basics/linux-privilege-escalation/index.html#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Serviços](../linux-basics/linux-privilege-escalation/index.html#services)

- [ ] Há algum arquivo **.service gravável**?
- [ ] Há algum **binário gravável** executado por um **serviço**?
- [ ] Há algum **helper, arquivo de configuração ou de ambiente gravável referenciado por uma unit do root** (`ExecStartPre=`, `ExecStartPost=`, `EnvironmentFile=`)? Inspecione a unit mesclada com `systemctl cat <unit>` e revise o [abuso de arquivos service/socket](../interesting-files-permissions/write-to-root.md).
- [ ] Um fluxo de trabalho privilegiado sob demanda executa um helper em um diretório gravável por um usuário com menos privilégios? Verifique o helper e o diretório pai para encontrar [execução pelo root de caminhos modificáveis pelo usuário](../interesting-files-permissions/write-to-root.md#root-executing-user-writable-scriptsbinaries); helpers de curta duração podem aparecer somente enquanto o fluxo de trabalho está em execução.
- [ ] Há alguma **pasta gravável no PATH do systemd**?
- [ ] Há algum **drop-in de unit do systemd gravável** em `/etc/systemd/system/<unit>.d/*.conf` que possa substituir `ExecStart`/`User`?<sup>[[2]](#references)</sup>

### [Timers](../linux-basics/linux-privilege-escalation/index.html#timers)

- [ ] Há algum **timer gravável**?

### [Sockets](../linux-basics/linux-privilege-escalation/index.html#sockets)

- [ ] Há algum arquivo **.socket gravável**?
- [ ] Você consegue **se comunicar com algum socket**?
- [ ] Há **sockets HTTP** com informações interessantes?
- [ ] Você consegue acessar uma [**API de runtime de container ou de agente de nó**](../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md), como `docker.sock`, `containerd.sock`, `crio.sock`, `podman.sock`, `buildkitd.sock` ou um endpoint do kubelet? Teste a API HTTP/gRPC diretamente, mesmo que a CLI usual não esteja disponível.

### [D-Bus](../linux-basics/linux-privilege-escalation/index.html#d-bus)

- [ ] Você consegue **se comunicar com algum D-Bus**?

### [Rede](../linux-basics/linux-privilege-escalation/index.html#network)

- [ ] Enumere a rede para descobrir onde você está
- [ ] Há **portas abertas que você não conseguia acessar antes** de obter um shell na máquina?
- [ ] Você consegue **capturar tráfego** usando `tcpdump`?

### [Usuários](../linux-basics/linux-privilege-escalation/index.html#users)

- [ ] Enumeração genérica de usuários/grupos
- [ ] Você tem um **UID muito alto**? A **máquina** é **vulnerável**?
- [ ] Você consegue [**escalar privilégios graças a um grupo**](../user-information/interesting-groups-linux-pe/index.html) ao qual pertence?
- [ ] Há dados na **área de transferência**?
- [ ] Política de senhas?
- [ ] Tente **usar** cada **senha conhecida** que descobriu anteriormente para fazer login com **cada usuário** possível. Tente também fazer login sem senha.

### [PATH gravável](../linux-basics/linux-privilege-escalation/index.html#writable-path-abuses)

- [ ] Se você tiver **permissões de escrita em alguma pasta do PATH**, poderá conseguir escalar privilégios

### [Comandos SUDO e SUID](../linux-basics/linux-privilege-escalation/index.html#sudo-and-suid)

- [ ] Você consegue executar **algum comando com sudo**? Consegue usá-lo para LER, ESCREVER ou EXECUTAR qualquer coisa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` permitir `sudoedit`, verifique a **injeção de argumentos do sudoedit** (CVE-2023-22809) por meio de `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar arquivos arbitrários em versões vulneráveis (`sudo -V` < 1.9.12p2). Exemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`.<sup>[[1]](#references)</sup>
- [ ] Há algum **binário SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Os comandos [**sudo** são **limitados** por **caminho**? É possível **contornar** as restrições](../linux-basics/linux-privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Comando sudo/binário SUID sem caminho indicado**](../linux-basics/linux-privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**Binário SUID especificando o caminho**](../linux-basics/linux-privilege-escalation/index.html#suid-binary-with-command-path)? Contorne as restrições
- [ ] [**Vulnerabilidade de LD_PRELOAD**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#ld_preload-ld_library_path-and-suid)
- [ ] [**Ausência de biblioteca .so em binário SUID**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#missing-shared-object-injection) em uma pasta gravável?
- [ ] [**RPATH/RUNPATH de SUID ou caminho de biblioteca gravável**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#rpath-and-runpath)?
- [ ] Há [**tokens SUDO disponíveis**](../linux-basics/linux-privilege-escalation/index.html#reusing-sudo-tokens)? [**Você consegue criar um token SUDO**](../linux-basics/linux-privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Você consegue [**ler ou modificar arquivos sudoers**](../linux-basics/linux-privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Você consegue [**modificar /etc/ld.so.conf.d/**](../interesting-files-permissions/suid-shared-library-and-linker-abuse.md#linker-configuration)?
- [ ] Comando [**OpenBSD DOAS**](../linux-basics/linux-privilege-escalation/index.html#doas)

### [Capabilities](../linux-basics/linux-privilege-escalation/index.html#capabilities)

- [ ] Algum binário tem uma **capability inesperada**?

### [ACLs](../linux-basics/linux-privilege-escalation/index.html#acls)

- [ ] Algum arquivo tem uma **ACL inesperada**?

### [Sessões de shell abertas](../linux-basics/linux-privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](../linux-basics/linux-privilege-escalation/index.html#ssh)

- [ ] [**PRNG previsível do OpenSSL no Debian - CVE-2008-0166**](../linux-basics/linux-privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**Valores de configuração interessantes do SSH**](../linux-basics/linux-privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Arquivos interessantes](../linux-basics/linux-privilege-escalation/index.html#interesting-files)

- [ ] **Arquivos de perfil** - Há dados confidenciais para ler? É possível escrever neles para escalar privilégios?
- [ ] **Arquivos passwd/shadow** - Há dados confidenciais para ler? É possível escrever neles para escalar privilégios?
- [ ] **Verifique pastas comumente interessantes** em busca de dados confidenciais
- [ ] **Arquivos em locais/pertencentes a usuários estranhos**; você pode ter acesso a arquivos executáveis ou alterá-los
- [ ] Arquivos **modificados** nos últimos minutos
- [ ] **Arquivos DB do Sqlite**
- [ ] **Arquivos ocultos**
- [ ] **Scripts/binários no PATH**
- [ ] **Arquivos web** (senhas?)
- [ ] **Backups**?
- [ ] **Arquivos conhecidos que contêm senhas**: use **Linpeas** e **LaZagne**
- [ ] **Busca genérica**

### [**Arquivos graváveis**](../linux-basics/linux-privilege-escalation/index.html#writable-files)

- [ ] É possível **modificar uma biblioteca Python** para executar comandos arbitrários?
- [ ] Você consegue **modificar arquivos de log**? Exploit **Logtotten**
- [ ] Você consegue **modificar /etc/sysconfig/network-scripts/**? Exploit para Centos/Redhat
- [ ] Você consegue [**escrever em arquivos ini, int.d, systemd ou rc.d**](../linux-basics/linux-privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Outros truques**](../linux-basics/linux-privilege-escalation/index.html#other-tricks)

- [ ] Você consegue [**abusar do NFS para escalar privilégios**](../linux-basics/linux-privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Você precisa [**escapar de um shell restrito**](../linux-basics/linux-privilege-escalation/index.html#escaping-from-restricted-shells)?



## References

- [1] [Aviso do Sudo: edição arbitrária de arquivos com sudoedit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [2] [Documentação do Oracle Linux: configuração de drop-ins do systemd](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
- [3] [Notselwyn: requisitos e pesquisa do exploit CVE-2024-1086](https://github.com/Notselwyn/CVE-2024-1086)
- [4] [Aviso de segurança da Qualys: LPEs no needrestart](https://www.qualys.com/2024/11/19/needrestart/needrestart.txt)
{{#include ../../banners/hacktricks-training.md}}

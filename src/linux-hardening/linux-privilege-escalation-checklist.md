# Checklist - Linux Privilege Escalation

{{#include ../banners/hacktricks-training.md}}

### **Melhor ferramenta para procurar vetores locais de Linux privilege escalation:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

### [System Information](privilege-escalation/index.html#system-information)

- [ ] Obter **informações do OS**
- [ ] Verificar o [**PATH**](privilege-escalation/index.html#path), existe alguma **pasta gravável**?
- [ ] Verificar [**env variables**](privilege-escalation/index.html#env-info), algum detalhe sensível?
- [ ] Procurar por [**kernel exploits**](privilege-escalation/index.html#kernel-exploits) **usando scripts** (DirtyCow?)
- [ ] **Verificar** se a [**sudo version** is vulnerable](privilege-escalation/index.html#sudo-version)
- [ ] [**Dmesg** signature verification failed](privilege-escalation/index.html#dmesg-signature-verification-failed)
- [ ] Mais enumeração do sistema ([date, system stats, cpu info, printers](privilege-escalation/index.html#more-system-enumeration))
- [ ] [Enumerate more defenses](privilege-escalation/index.html#enumerate-possible-defenses)

### [Drives](privilege-escalation/index.html#drives)

- [ ] **Listar** drives montados
- [ ] Alguma unidade não montada?
- [ ] Alguma credencial em fstab?

### [**Installed Software**](privilege-escalation/index.html#installed-software)

- [ ] **Verificar se há**[ **useful software**](privilege-escalation/index.html#useful-software) **instalado**
- [ ] **Verificar se há** [**vulnerable software**](privilege-escalation/index.html#vulnerable-software-installed) **instalado**

### [Processes](privilege-escalation/index.html#processes)

- [ ] Há algum **software desconhecido em execução**?
- [ ] Algum software está em execução com **mais privilégios do que deveria**?
- [ ] Procurar por **exploits de processos em execução** (especialmente a versão em execução).
- [ ] Consegue **modificar o binário** de algum processo em execução?
- [ ] **Monitorar processos** e verificar se algum processo interessante está sendo executado frequentemente.
- [ ] Consegue **ler** alguma **memória de processo** interessante (onde senhas podem estar armazenadas)?

### [Scheduled/Cron jobs?](privilege-escalation/index.html#scheduled-jobs)

- [ ] O [**PATH** ](privilege-escalation/index.html#cron-path) está sendo modificado por algum cron e você pode **escrever** nele?
- [ ] Algum [**wildcard** ](privilege-escalation/index.html#cron-using-a-script-with-a-wildcard-wildcard-injection) em um cron job?
- [ ] Algum [**modifiable script** ](privilege-escalation/index.html#cron-script-overwriting-and-symlink) está sendo **executado** ou está dentro de uma **pasta modificável**?
- [ ] Você detectou que algum **script** poderia estar sendo [**executed** very **frequently**](privilege-escalation/index.html#frequent-cron-jobs)? (a cada 1, 2 ou 5 minutos)

### [Services](privilege-escalation/index.html#services)

- [ ] Algum arquivo **.service** gravável?
- [ ] Algum **binário gravável** executado por um **serviço**?
- [ ] Alguma **pasta gravável no PATH do systemd**?
- [ ] Algum **drop-in de unidade systemd gravável** em `/etc/systemd/system/<unit>.d/*.conf` que possa sobrescrever `ExecStart`/`User`?

### [Timers](privilege-escalation/index.html#timers)

- [ ] Algum **timer** gravável?

### [Sockets](privilege-escalation/index.html#sockets)

- [ ] Algum arquivo **.socket** gravável?
- [ ] Consegue **comunicar com algum socket**?
- [ ] **HTTP sockets** com informações interessantes?

### [D-Bus](privilege-escalation/index.html#d-bus)

- [ ] Consegue **comunicar-se com algum D-Bus**?

### [Network](privilege-escalation/index.html#network)

- [ ] Enumerar a rede para saber onde você está
- [ ] Portas abertas que você não conseguia acessar antes de obter um shell na máquina?
- [ ] Consegue **sniff traffic** usando `tcpdump`?

### [Users](privilege-escalation/index.html#users)

- [ ] Enumeração genérica de usuários/grupos
- [ ] Você tem um **UID muito grande**? A **máquina** é **vulnerável**?
- [ ] Consegue [**escalate privileges thanks to a group**](privilege-escalation/interesting-groups-linux-pe/index.html) do qual você faz parte?
- [ ] Dados da **Clipboard**?
- [ ] Política de senhas?
- [ ] Tente **usar** cada **senha conhecida** que você descobriu anteriormente para fazer login **com cada** possível **usuário**. Tente também fazer login sem senha.

### [Writable PATH](privilege-escalation/index.html#writable-path-abuses)

- [ ] Se você tem **privilégios de escrita sobre alguma pasta no PATH** você pode ser capaz de escalar privilégios

### [SUDO and SUID commands](privilege-escalation/index.html#sudo-and-suid)

- [ ] Consegue executar **qualquer comando com sudo**? Consegue usá-lo para LER, ESCREVER ou EXECUTAR qualquer coisa como root? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Se `sudo -l` permite `sudoedit`, verifique por **sudoedit argument injection** (CVE-2023-22809) via `SUDO_EDITOR`/`VISUAL`/`EDITOR` para editar arquivos arbitrários em versões vulneráveis (`sudo -V` < 1.9.12p2). Exemplo: `SUDO_EDITOR="vim -- /etc/sudoers" sudoedit /etc/hosts`
- [ ] Existe algum **binário SUID explorável**? ([**GTFOBins**](https://gtfobins.github.io))
- [ ] Are [**sudo** commands **limited** by **path**? can you **bypass** the restrictions](privilege-escalation/index.html#sudo-execution-bypassing-paths)?
- [ ] [**Sudo/SUID binary without path indicated**](privilege-escalation/index.html#sudo-command-suid-binary-without-command-path)?
- [ ] [**SUID binary specifying path**](privilege-escalation/index.html#suid-binary-with-command-path)? Bypass
- [ ] [**LD_PRELOAD vuln**](privilege-escalation/index.html#ld_preload)
- [ ] [**Lack of .so library in SUID binary**](privilege-escalation/index.html#suid-binary-so-injection) a partir de uma pasta gravável?
- [ ] [**SUDO tokens available**](privilege-escalation/index.html#reusing-sudo-tokens)? [**Can you create a SUDO token**](privilege-escalation/index.html#var-run-sudo-ts-less-than-username-greater-than)?
- [ ] Consegue [**read or modify sudoers files**](privilege-escalation/index.html#etc-sudoers-etc-sudoers-d)?
- [ ] Consegue [**modify /etc/ld.so.conf.d/**](privilege-escalation/index.html#etc-ld-so-conf-d)?
- [ ] Comando [**OpenBSD DOAS**](privilege-escalation/index.html#doas)

### [Capabilities](privilege-escalation/index.html#capabilities)

- [ ] Algum binário possui alguma **capability inesperada**?

### [ACLs](privilege-escalation/index.html#acls)

- [ ] Algum arquivo possui alguma **ACL inesperada**?

### [Open Shell sessions](privilege-escalation/index.html#open-shell-sessions)

- [ ] **screen**
- [ ] **tmux**

### [SSH](privilege-escalation/index.html#ssh)

- [ ] **Debian** [**OpenSSL Predictable PRNG - CVE-2008-0166**](privilege-escalation/index.html#debian-openssl-predictable-prng-cve-2008-0166)
- [ ] [**SSH Interesting configuration values**](privilege-escalation/index.html#ssh-interesting-configuration-values)

### [Interesting Files](privilege-escalation/index.html#interesting-files)

- [ ] **Profile files** - Ler dados sensíveis? Escrever para privesc?
- [ ] **passwd/shadow files** - Ler dados sensíveis? Escrever para privesc?
- [ ] **Check commonly interesting folders** para dados sensíveis
- [ ] **Weird Location/Owned files,** você pode ter acesso ou alterar arquivos executáveis
- [ ] **Modified** in last mins
- [ ] **Sqlite DB files**
- [ ] **Hidden files**
- [ ] **Script/Binaries in PATH**
- [ ] **Web files** (passwords?)
- [ ] **Backups**?
- [ ] **Known files that contains passwords**: Use **Linpeas** and **LaZagne**
- [ ] **Generic search**

### [**Writable Files**](privilege-escalation/index.html#writable-files)

- [ ] **Modificar biblioteca python** para executar comandos arbitrários?
- [ ] Consegue **modificar arquivos de log**? Exploit **Logtotten**
- [ ] Consegue **modificar /etc/sysconfig/network-scripts/**? Exploit Centos/Redhat
- [ ] Consegue [**write in ini, int.d, systemd or rc.d files**](privilege-escalation/index.html#init-init-d-systemd-and-rc-d)?

### [**Other tricks**](privilege-escalation/index.html#other-tricks)

- [ ] Consegue [**abuse NFS to escalate privileges**](privilege-escalation/index.html#nfs-privilege-escalation)?
- [ ] Precisa [**escape from a restrictive shell**](privilege-escalation/index.html#escaping-from-restricted-shells)?



## Referências

- [Sudo advisory: sudoedit arbitrary file edit](https://www.sudo.ws/security/advisories/sudoedit_any/)
- [Oracle Linux docs: systemd drop-in configuration](https://docs.oracle.com/en/operating-systems/oracle-linux/8/systemd/ModifyingsystemdConfigurationFiles.html)
{{#include ../banners/hacktricks-training.md}}

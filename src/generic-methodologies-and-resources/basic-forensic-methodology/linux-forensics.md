# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Coleta Inicial de Informações

### Informações Básicas

Antes de mais nada, é recomendado ter algum **USB** com **bons binários e bibliotecas conhecidos** nele (você pode simplesmente pegar o ubuntu e copiar as pastas _/bin_, _/sbin_, _/lib,_ e _/lib64_), depois monte o USB e modifique as variáveis de ambiente para usar esses binários:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Uma vez que você tenha configurado o sistema para usar binários bons e conhecidos, você pode começar a **extrair algumas informações básicas**:
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### Informações suspeitas

Ao obter as informações básicas, você deve verificar coisas estranhas como:

- **Processos root** normalmente rodam com PIDs baixos, então se você encontrar um processo root com um PID alto, pode suspeitar
- Verifique os **logins registrados** de usuários sem shell dentro de `/etc/passwd`
- Verifique por **hashes de senha** dentro de `/etc/shadow` para usuários sem shell

### Memory Dump

Para obter a memória do sistema em execução, é recomendado usar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilá-lo**, você precisa usar o **mesmo kernel** que a máquina vítima está usando.

> [!TIP]
> Lembre-se de que você **não pode instalar LiME nem qualquer outra coisa** na máquina vítima, pois isso fará várias alterações nela

Então, se você tiver uma versão idêntica do Ubuntu, pode usar `apt-get install lime-forensics-dkms`\
Em outros casos, você precisa baixar [**LiME**](https://github.com/504ensicsLabs/LiME) do github e compilá-lo com os headers corretos do kernel. Para **obter os headers exatos do kernel** da máquina vítima, você pode simplesmente **copiar o diretório** `/lib/modules/<kernel version>` para a sua máquina e então **compilar** LiME usando-os:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME suporta 3 **formats**:

- Raw (every segment concatenated together)
- Padded (same as raw, but with zeroes in right bits)
- Lime (recommended format with metadata

LiME também pode ser usado para **enviar o dump via network** em vez de armazená-lo no sistema usando algo como: `path=tcp:4444`

### Disk Imaging

#### Shutting down

Antes de tudo, você precisará **desligar o sistema**. Isso nem sempre é uma opção, pois às vezes o sistema será um production server que a empresa não pode se dar ao luxo de desligar.\
Existem **2 maneiras** de desligar o sistema, um desligamento **normal** e um desligamento de **"plug the plug"**. O primeiro permitirá que os **processos** terminem como de costume e que o **filesystem** seja **synchronized**, mas também permitirá que o possível **malware** **destrua evidências**. A abordagem de "pull the plug" pode causar **alguma perda de informação** (não muita informação será perdida, pois já tiramos uma imagem da memory) e o **malware não terá oportunidade** de fazer nada a respeito. Portanto, se você **suspeitar** que pode haver um **malware**, basta executar o **`sync`** **command** no sistema e puxar o plug.

#### Taking an image of the disk

É importante notar que **antes de conectar seu computador a qualquer coisa relacionada ao caso**, você precisa ter certeza de que ele será **montado apenas para leitura** para evitar modificar qualquer informação.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-análise de imagem de disco

Criando uma imagem de disco sem mais dados.
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## Buscar por Malware conhecido

### Arquivos do Sistema Modificados

Linux oferece ferramentas para garantir a integridade dos componentes do sistema, cruciais para identificar arquivos potencialmente problemáticos.

- **Sistemas baseados em RedHat**: Use `rpm -Va` para uma verificação abrangente.
- **Sistemas baseados em Debian**: `dpkg --verify` para verificação inicial, seguido por `debsums | grep -v "OK$"` (depois de instalar `debsums` com `apt-get install debsums`) para identificar quaisquer problemas.

### Detectores de Malware/Rootkit

Leia a seguinte página para aprender sobre ferramentas que podem ser úteis para encontrar malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Buscar programas instalados

Para pesquisar de forma eficaz programas instalados em sistemas Debian e RedHat, considere aproveitar logs e bancos de dados do sistema junto com verificações manuais em diretórios comuns.

- Para Debian, inspecione _**`/var/lib/dpkg/status`**_ e _**`/var/log/dpkg.log`**_ para obter detalhes sobre instalações de pacotes, usando `grep` para filtrar informações específicas.
- Usuários de RedHat podem consultar o banco de dados RPM com `rpm -qa --root=/mntpath/var/lib/rpm` para listar os pacotes instalados.

Para descobrir software instalado manualmente ou fora desses gerenciadores de pacotes, explore diretórios como _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ e _**`/sbin`**_. Combine listagens de diretórios com comandos específicos do sistema para identificar executáveis não associados a pacotes conhecidos, melhorando sua busca por todos os programas instalados.
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## Recuperar Binaries Em Execução Excluídos

Imagine um processo que foi executado a partir de /tmp/exec e depois excluído. É possível extraí-lo
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Inspecionar locais de Autostart

### Tarefas Agendadas
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### Caça: abuso de Cron/Anacron via 0anacron e stubs suspeitos
Atacantes frequentemente editam o stub 0anacron presente em cada diretório /etc/cron.*/ para garantir execução periódica.
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: rollback de endurecimento do SSH e shells de backdoor
Alterações em sshd_config e shells de contas de sistema são comuns no pós-exploitation para preservar o acesso.
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons typically use api.dropboxapi.com or content.dropboxapi.com over HTTPS with Authorization: Bearer tokens.
- Hunt in proxy/Zeek/NetFlow for unexpected Dropbox egress from servers.
- Cloudflare Tunnel (`cloudflared`) provides backup C2 over outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Serviços

Caminhos onde um malware pode ser instalado como um serviço:

- **/etc/inittab**: Chama scripts de inicialização como rc.sysinit, direcionando para scripts de startup adicionais.
- **/etc/rc.d/** e **/etc/rc.boot/**: Contêm scripts para startup de serviços, sendo o último encontrado em versões mais antigas do Linux.
- **/etc/init.d/**: Usado em certas versões do Linux, como Debian, para armazenar scripts de startup.
- Os serviços também podem ser ativados via **/etc/inetd.conf** ou **/etc/xinetd/**, dependendo da variante do Linux.
- **/etc/systemd/system**: Um diretório para scripts do gerenciador de sistema e serviços.
- **/etc/systemd/system/multi-user.target.wants/**: Contém links para serviços que devem ser iniciados em um runlevel multi-user.
- **/usr/local/etc/rc.d/**: Para serviços customizados ou de terceiros.
- **\~/.config/autostart/**: Para aplicações de inicialização automática específicas do usuário, que podem ser um esconderijo para malware direcionado ao usuário.
- **/lib/systemd/system/**: Arquivos unit padrão de escopo do sistema fornecidos por pacotes instalados.

#### Hunt: systemd timers and transient units

A persistência no Systemd não se limita a arquivos `.service`. Investigue units `.timer`, units no nível de usuário e **transient units** criadas em tempo de execução.
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Transient units are easy to miss because `/run/systemd/transient/` is **non-persistent**. If you are collecting a live image, grab it before shutdown.

### Kernel Modules

Linux kernel modules, often utilized by malware as rootkit components, are loaded at system boot. The directories and files critical for these modules include:

- **/lib/modules/$(uname -r)**: Contém módulos para a versão atual do kernel.
- **/etc/modprobe.d**: Contém arquivos de configuração para controlar o carregamento de módulos.
- **/etc/modprobe** and **/etc/modprobe.conf**: Arquivos para configurações globais de módulos.

### Other Autostart Locations

Linux employs various files for automatically executing programs upon user login, potentially harboring malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: Executed for any user login.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: Arquivos específicos do usuário que são executados ao fazer login.
- **/etc/rc.local**: Executa após todos os serviços do sistema terem iniciado, marcando o fim da transição para um ambiente multiusuário.

## Examine Logs

Linux systems track user activities and system events through various log files. These logs are pivotal for identifying unauthorized access, malware infections, and other security incidents. Key log files include:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): Capturam mensagens e atividades de todo o sistema.
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): Registram tentativas de autenticação, logins bem-sucedidos e falhos.
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: Contém mensagens de inicialização do sistema.
- **/var/log/maillog** or **/var/log/mail.log**: Registra atividades do servidor de e-mail, útil para rastrear serviços relacionados a e-mail.
- **/var/log/kern.log**: Armazena mensagens do kernel, incluindo erros e avisos.
- **/var/log/dmesg**: Contém mensagens de drivers de dispositivos.
- **/var/log/faillog**: Registra tentativas de login falhas, ajudando em investigações de violação de segurança.
- **/var/log/cron**: Registra execuções de cron job.
- **/var/log/daemon.log**: Acompanha atividades de serviços em segundo plano.
- **/var/log/btmp**: Documenta tentativas de login falhas.
- **/var/log/httpd/**: Contém logs de erro e acesso do Apache HTTPD.
- **/var/log/mysqld.log** or **/var/log/mysql.log**: Registra atividades do banco de dados MySQL.
- **/var/log/xferlog**: Registra transferências de arquivos FTP.
- **/var/log/**: Sempre verifique aqui por logs inesperados.

> [!TIP]
> Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.

### Journald triage (`journalctl`)

On modern Linux hosts, the **systemd journal** is usually the highest-value source for **service execution**, **auth events**, **package operations**, and **kernel/user-space messages**. During live response, try to preserve both the **persistent** journal (`/var/log/journal/`) and the **runtime** journal (`/run/log/journal/`) because short-lived attacker activity may only exist in the latter.
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
Campos úteis do journal para triagem incluem `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` e `MESSAGE`. Se o journald foi configurado sem armazenamento persistente, espere encontrar apenas dados recentes em `/run/log/journal/`.

### Triagem do framework de auditoria (`auditd`)

Se o `auditd` estiver habilitado, prefira-o sempre que você precisar de **atribuição de processo** para alterações em arquivos, execução de comandos, atividade de login ou instalação de pacotes.
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
Quando as regras foram implantadas com chaves, faça pivot a partir delas em vez de fazer grep nos logs brutos:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux mantém um histórico de comandos para cada usuário**, armazenado em:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Além disso, o comando `last -Faiwx` fornece uma lista de logins de usuários. Verifique se há logins desconhecidos ou inesperados.

Verifique arquivos que podem conceder rprivileges extras:

- Revise `/etc/sudoers` para privilégios de usuário não previstos que possam ter sido concedidos.
- Revise `/etc/sudoers.d/` para privilégios de usuário não previstos que possam ter sido concedidos.
- Examine `/etc/groups` para identificar quaisquer associações de grupo ou permissões incomuns.
- Examine `/etc/passwd` para identificar quaisquer associações de grupo ou permissões incomuns.

Alguns apps também geram seus próprios logs:

- **SSH**: Examine _\~/.ssh/authorized_keys_ e _\~/.ssh/known_hosts_ para conexões remotas não autorizadas.
- **Gnome Desktop**: Veja _\~/.recently-used.xbel_ para arquivos acessados recentemente via aplicações Gnome.
- **Firefox/Chrome**: Verifique o histórico e os downloads do navegador em _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ para atividades suspeitas.
- **VIM**: Revise _\~/.viminfo_ para detalhes de uso, como caminhos de arquivos acessados e histórico de busca.
- **Open Office**: Verifique o acesso recente a documentos que possa indicar arquivos comprometidos.
- **FTP/SFTP**: Revise os logs em _\~/.ftp_history_ ou _\~/.sftp_history_ para transferências de arquivos que possam ser não autorizadas.
- **MySQL**: Investigue _\~/.mysql_history_ para consultas MySQL executadas, potencialmente revelando atividades de banco de dados não autorizadas.
- **Less**: Analise _\~/.lesshst_ para histórico de uso, incluindo arquivos visualizados e comandos executados.
- **Git**: Examine _\~/.gitconfig_ e _.git/logs_ do projeto para alterações nos repositórios.

### Logs de USB

[**usbrip**](https://github.com/snovvcrash/usbrip) é um pequeno software escrito em Python 3 puro que analisa arquivos de log do Linux (`/var/log/syslog*` ou `/var/log/messages*` dependendo da distro) para construir tabelas de histórico de eventos USB.

É interessante **saber todos os USBs que foram usados** e será mais útil se você tiver uma lista autorizada de USBs para encontrar "violation events" (o uso de USBs que não estejam dentro dessa lista).

### Instalação
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Exemplos
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Mais exemplos e informações dentro do github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Revisar Contas de Usuário e Atividades de Logon

Examine os _**/etc/passwd**_, _**/etc/shadow**_ e os **logs de segurança** em busca de nomes incomuns ou contas criadas e/ou usadas em proximidade com eventos conhecidos não autorizados. Além disso, verifique possíveis ataques de brute-force em sudo.\
Além disso, verifique arquivos como _**/etc/sudoers**_ e _**/etc/groups**_ em busca de privilégios inesperados concedidos a usuários.\
Por fim, procure contas sem **senhas** ou com senhas **fáceis de adivinhar**.

## Examinar o Sistema de Arquivos

### Analisando Estruturas do Sistema de Arquivos em Investigação de Malware

Ao investigar incidentes de malware, a estrutura do sistema de arquivos é uma fonte crucial de informação, revelando tanto a sequência de eventos quanto o conteúdo do malware. No entanto, autores de malware estão desenvolvendo técnicas para dificultar essa análise, como modificar timestamps de arquivos ou evitar o sistema de arquivos para armazenamento de dados.

Para combater esses métodos anti-forenses, é essencial:

- **Realizar uma análise completa de timeline** usando ferramentas como **Autopsy** para visualizar timelines de eventos ou o `mactime` do **Sleuth Kit** para dados detalhados de timeline.
- **Investigar scripts inesperados** no $PATH do sistema, que podem incluir scripts shell ou PHP usados por atacantes.
- **Examinar `/dev` em busca de arquivos atípicos**, já que tradicionalmente contém arquivos especiais, mas pode abrigar arquivos relacionados a malware.
- **Procurar arquivos ou diretórios ocultos** com nomes como ".. " (dois pontos ponto espaço) ou "..^G" (dois pontos ponto control-G), que podem ocultar conteúdo malicioso.
- **Identificar arquivos setuid root** usando o comando: `find / -user root -perm -04000 -print` Isso encontra arquivos com permissões elevadas, que podem ser abusadas por atacantes.
- **Revisar timestamps de exclusão** nas tabelas inode para detectar exclusões massivas de arquivos, possivelmente indicando a presença de rootkits ou trojans.
- **Inspecionar inodes consecutivos** em busca de arquivos maliciosos próximos após identificar um, pois eles podem ter sido colocados juntos.
- **Verificar diretórios binários comuns** (_/bin_, _/sbin_) em busca de arquivos modificados recentemente, já que eles podem ter sido alterados por malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Note que um **attacker** pode **modificar** o **time** para fazer **files appear** **legitimate**, mas ele **cannot** modificar o **inode**. Se você encontrar que um **file** indica que foi criado e modificado no **same time** que o restante dos files na mesma pasta, mas o **inode** está **unexpectedly bigger**, então os **timestamps of that file were modified**.

### Inode-focused quick triage

Se você suspeita de anti-forensics, execute estas verificações focadas em inode cedo:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Quando um inode suspeito está em uma imagem/dispositivo de filesystem EXT, inspecione os metadados do inode diretamente:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Campos úteis:
- **Links**: se `0`, nenhuma entrada de diretório referencia atualmente o inode.
- **dtime**: timestamp de exclusão definido quando o inode foi desvinculado.
- **ctime/mtime**: ajuda a correlacionar mudanças de metadados/conteúdo com a linha do tempo do incidente.

### Capabilities, xattrs, and rootkits de userland baseados em preload

A persistência moderna no Linux muitas vezes evita binários `setuid` óbvios e, em vez disso, abusa de **file capabilities**, **extended attributes** e do dynamic loader.
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
Preste atenção especial a bibliotecas referenciadas de paths **writable** como `/tmp`, `/dev/shm`, `/var/tmp`, ou locais estranhos em `/usr/local/lib`. Também verifique binaries com capabilities fora da propriedade normal de packages e correlacione-os com os resultados de verificação de packages (`rpm -Va`, `dpkg --verify`, `debsums`).

## Compare files of different filesystem versions

### Filesystem Version Comparison Summary

Para comparar versões de filesystem e identificar mudanças, usamos comandos simplificados de `git diff`:

- **Para encontrar novos arquivos**, compare dois diretórios:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **Para conteúdo modificado**, liste as alterações ignorando linhas específicas:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **Para detectar arquivos excluídos**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) ajudam a restringir para mudanças específicas como arquivos adicionados (`A`), deletados (`D`) ou modificados (`M`).
- `A`: Arquivos adicionados
- `C`: Arquivos copiados
- `D`: Arquivos deletados
- `M`: Arquivos modificados
- `R`: Arquivos renomeados
- `T`: Mudanças de tipo (ex.: arquivo para symlink)
- `U`: Arquivos não mesclados
- `X`: Arquivos desconhecidos
- `B`: Arquivos quebrados

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}

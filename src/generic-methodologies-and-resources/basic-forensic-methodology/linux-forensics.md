# Forensics do Linux

{{#include ../../banners/hacktricks-training.md}}

## Coleta Inicial de Informações

### Informações Básicas

Antes de tudo, é recomendado ter algum **USB** com **binários e bibliotecas confiáveis** (você pode simplesmente obter o ubuntu e copiar as pastas _/bin_, _/sbin_, _/lib,_ e _/lib64_), depois montar o USB e modificar as variáveis de ambiente para usar esses binários:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
Depois de configurar o sistema para usar binários bons e conhecidos, você pode começar a **extrair algumas informações básicas**:
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

Ao obter as informações básicas, você deve verificar coisas estranhas, como:

- **Processos root** geralmente são executados com PIDs baixos; portanto, se você encontrar um processo root com um PID alto, pode suspeitar
- Verifique os **logins registrados** de usuários sem um shell dentro de `/etc/passwd`
- Verifique os **hashes de senha** dentro de `/etc/shadow` para usuários sem um shell

### Memory Dump

Para obter a memória do sistema em execução, recomenda-se usar [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilá-lo**, você precisa usar o **mesmo kernel** que a máquina vítima está usando.

> [!TIP]
> Lembre-se de que você **não pode instalar o LiME nem qualquer outra coisa** na máquina vítima, pois isso fará várias alterações nela

Portanto, se você tiver uma versão idêntica do Ubuntu, poderá usar `apt-get install lime-forensics-dkms`\
Em outros casos, você precisa baixar o [**LiME**](https://github.com/504ensicsLabs/LiME) do GitHub e compilá-lo com os headers corretos do kernel. Para **obter os headers exatos do kernel** da máquina vítima, basta **copiar o diretório** `/lib/modules/<kernel version>` para a sua máquina e, em seguida, **compilar** o LiME usando-os:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME suporta 3 **formatos**:

- Raw (cada segmento concatenado)
- Padded (igual ao raw, mas com zeros nos bits corretos)
- Lime (formato recomendado com metadados

LiME também pode ser usado para **enviar o dump pela rede** em vez de armazená-lo no sistema usando algo como: `path=tcp:4444`

### Imagem do disco

#### Desligamento

Antes de tudo, será necessário **desligar o sistema**. Isso nem sempre é uma opção, pois às vezes o sistema será um servidor de produção que a empresa não pode se dar ao luxo de desligar.\
Há **2 maneiras** de desligar o sistema: um **desligamento normal** e um **desligamento "puxando o plugue"**. O primeiro permitirá que os **processos sejam encerrados normalmente** e que o **filesystem** seja **sincronizado**, mas também permitirá que o possível **malware** **destrua evidências**. A abordagem de "puxar o plugue" pode causar **alguma perda de informações** (não muitas informações serão perdidas, pois já obtivemos uma imagem da memória) e o **malware não terá nenhuma oportunidade** de fazer algo a respeito. Portanto, se você **suspeitar** que pode haver um **malware**, basta executar o **comando** **`sync`** no sistema e puxar o plugue.

#### Criando uma imagem do disco

É importante observar que, **antes de conectar o computador a qualquer coisa relacionada ao caso**, você precisa ter certeza de que ele será **montado como somente leitura** para evitar modificar qualquer informação.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-análise da imagem de disco

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
## Procurar por Malware conhecido

### Arquivos do sistema modificados

O Linux oferece ferramentas para garantir a integridade dos componentes do sistema, algo crucial para identificar arquivos potencialmente problemáticos.<sup>[[1]](#references)</sup>

- **Sistemas baseados em RedHat**: use `rpm -Va` para uma verificação abrangente.
- **Sistemas baseados em Debian**: use `dpkg --verify` para a verificação inicial, seguido de `debsums | grep -v "OK$"` (após instalar `debsums` com `apt-get install debsums`) para identificar quaisquer problemas.

### Detectores de Malware/Rootkit

Leia a página a seguir para conhecer ferramentas que podem ser úteis para encontrar malware:


{{#ref}}
malware-analysis.md
{{#endref}}

## Procurar por programas instalados

Para procurar efetivamente por programas instalados em sistemas Debian e RedHat, considere utilizar logs e bancos de dados do sistema juntamente com verificações manuais em diretórios comuns.<sup>[[1]](#references)</sup>

- No Debian, examine _**`/var/lib/dpkg/status`**_ e _**`/var/log/dpkg.log`**_ para obter detalhes sobre as instalações de pacotes, usando `grep` para filtrar informações específicas.
- Usuários do RedHat podem consultar o banco de dados RPM com `rpm -qa --root=/mntpath/var/lib/rpm` para listar os pacotes instalados.

Para descobrir softwares instalados manualmente ou fora desses gerenciadores de pacotes, explore diretórios como _**`/usr/local`**_, _**`/opt`**_, _**`/usr/sbin`**_, _**`/usr/bin`**_, _**`/bin`**_ e _**`/sbin`**_. Combine listagens de diretórios com comandos específicos do sistema para identificar executáveis não associados a pacotes conhecidos, aprimorando sua busca por todos os programas instalados.
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
## Recuperar Binários em Execução Excluídos

Imagine um processo que foi executado a partir de /tmp/exec e depois excluído. É possível extraí-lo.
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Triagem de Syscall Trace com SQLite e FTS5

Quando um processo ainda está em execução ou pode ser executado novamente em um lab, **`strace`** pode fornecer um trace comportamental rápido sem exigir kernel modules ou telemetria completa de EDR. Para traces grandes, evite ler o log bruto diretamente ou colá-lo em um LLM: armazene-o em um banco de dados **SQLite** e consulte apenas o subconjunto mínimo necessário.<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> Anexar o `strace` altera o timing do processo e pode afetar race conditions ou outros bugs frágeis. Prefira reproduzir o problema em uma cópia/lab system quando possível.

### Captura

Para um processo novo:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
Para um processo em execução:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Opções úteis:

- `-ff`: seguir forks/threads e manter saídas por processo
- `-ttt`: timestamps de epoch para facilitar a correlação da timeline
- `-yy`: resolver descritores de arquivo para caminhos/sockets correspondentes, quando possível
- `-s 4096`: evitar que argumentos longos de caminho e buffer sejam truncados

### Normalizar

Um esquema prático consiste em uma linha por syscall e uma linha por argumento:
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
Isso evita tentar transformar linhas heterogêneas de syscall em uma única tabela ampla e mantém os joins previsíveis durante a triagem.

### Indexe argumentos ricos em texto com FTS5

A busca ingênua por caminhos com `LIKE "%...%"` torna-se muito lenta em traces grandes. Crie um índice FTS5 para o texto dos argumentos e pesquise nele:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
Exemplo: recuperar a atividade de arquivos em `/tmp` sem verificar cada linha:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### Investigações de alto sinal

- **PATH hijacking / fake sudo**: procure por gravações e atividades de `chmod`/`rename` em `~/.local/bin/`, depois correlacione com `execve` posteriores de nomes com aparência privilegiada, como `sudo`.
- **TOCTOU em arquivos temporários**: acompanhe o mesmo caminho `/tmp/...` através de `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink` e `execve` para identificar lacunas entre verificação e uso.
- **Causa raiz de crash**: correlacione o `mmap` de um arquivo com gravações ou truncamento do mesmo inode/caminho por outro processo, depois inspecione a sequência de sinal/saída em busca de `SIGBUS`.
- **Recuperação do destino de rede**: filtre `connect`, `sendto`, `sendmsg`, `recvfrom` e argumentos relacionados a sockets para extrair IPs e portas dos peers.

### Análise de traces assistida por LLM

Se quiser que um LLM auxilie, disponibilize um handle SQLite **somente leitura** e forneça o schema completo. Permita que ele emita SQL bruto em vez de encapsular o banco de dados atrás de funções auxiliares restritas. Isso geralmente funciona melhor para `JOINs`, correlação temporal e consultas FTS.

Regras práticas:

- Mantenha o banco de dados somente leitura, por exemplo, com `sqlite3 'file:trace.db?mode=ro'`.
- Forneça ao modelo exemplos de consultas válidas com `JOIN` e `FTS5 MATCH`.
- **Não** cole logs brutos de `strace` de vários GB no prompt.
- Faça perguntas focadas, como:
- "Liste os arquivos persistentes gravados por este programa."
- "Ele criou ou substituiu executáveis em diretórios do PATH controlados pelo usuário?"
- "Explique por que este trace termina em SIGBUS."

## Inspecionar locais de Autostart

### Tarefas agendadas
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
#### Hunt: abuso de Cron/Anacron via 0anacron e stubs suspeitos
Atacantes frequentemente editam o stub 0anacron presente em cada diretório /etc/cron.*/ para garantir a execução periódica.<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: reversão do hardening do SSH e backdoor shells
Alterações em sshd_config e nos shells de contas do sistema são comuns após a post-exploitation para preservar o acesso.<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: marcadores de C2 na Cloud (Dropbox/Cloudflare Tunnel)
- Os beacons da API do Dropbox normalmente usam api.dropboxapi.com ou content.dropboxapi.com via HTTPS com tokens Authorization: Bearer.
- Procure no proxy/Zeek/NetFlow por egress inesperado do Dropbox a partir de servidores.
- O Cloudflare Tunnel (`cloudflared`) fornece um C2 de backup por meio de 443 de saída.<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Serviços

Caminhos onde um malware pode ser instalado como um serviço:

- **/etc/inittab**: Chama scripts de inicialização como rc.sysinit, direcionando posteriormente para scripts de inicialização.
- **/etc/rc.d/** e **/etc/rc.boot/**: Contêm scripts para a inicialização de serviços; o segundo é encontrado em versões mais antigas do Linux.
- **/etc/init.d/**: Usado em determinadas versões do Linux, como o Debian, para armazenar scripts de inicialização.
- Os serviços também podem ser ativados por meio de **/etc/inetd.conf** ou **/etc/xinetd/**, dependendo da variante do Linux.
- **/etc/systemd/system**: Um diretório para scripts do gerenciador do sistema e de serviços.
- **/etc/systemd/system/multi-user.target.wants/**: Contém links para serviços que devem ser iniciados em um runlevel multiusuário.
- **/usr/local/etc/rc.d/**: Para serviços personalizados ou de terceiros.
- **\~/.config/autostart/**: Para aplicações de inicialização automática específicas do usuário, podendo ser um local de ocultação para malware direcionado a usuários.
- **/lib/systemd/system/**: Arquivos de unidades padrão de todo o sistema fornecidos pelos pacotes instalados.

#### Hunt: timers e transient units do systemd

A persistência do systemd não se limita aos arquivos `.service`. Investigue unidades `.timer`, unidades em nível de usuário e **transient units** criadas em tempo de execução.
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
Unidades transitórias são fáceis de não perceber porque `/run/systemd/transient/` é **não persistente**. Se você estiver coletando uma imagem live, copie-a antes do desligamento.

### Módulos do Kernel

Os módulos do kernel Linux, frequentemente utilizados por malware como componentes de rootkit, são carregados na inicialização do sistema. Os diretórios e arquivos críticos para esses módulos incluem:

- **/lib/modules/$(uname -r)**: Contém os módulos da versão do kernel em execução.
- **/etc/modprobe.d**: Contém arquivos de configuração para controlar o carregamento dos módulos.
- **/etc/modprobe** e **/etc/modprobe.conf**: Arquivos para configurações globais dos módulos.

### Outros locais de autostart

O Linux utiliza vários arquivos para executar programas automaticamente após o login do usuário, que podem conter malware:

- **/etc/profile.d/**\*, **/etc/profile** e **/etc/bash.bashrc**: Executados no login de qualquer usuário.
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile** e **~/.config/autostart**: Arquivos específicos do usuário executados durante o login.
- **/etc/rc.local**: Executado após a inicialização de todos os serviços do sistema, marcando o fim da transição para um ambiente multiusuário.

## Examinar logs

Os sistemas Linux registram atividades dos usuários e eventos do sistema por meio de vários arquivos de log. Esses logs são essenciais para identificar acessos não autorizados, infecções por malware e outros incidentes de segurança.<sup>[[2]](#references)</sup> Os principais arquivos de log incluem:

- **/var/log/syslog** (Debian) ou **/var/log/messages** (RedHat): Capturam mensagens e atividades de todo o sistema.
- **/var/log/auth.log** (Debian) ou **/var/log/secure** (RedHat): Registram tentativas de autenticação e logins bem-sucedidos e malsucedidos.
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` para filtrar eventos de autenticação relevantes.
- **/var/log/boot.log**: Contém mensagens de inicialização do sistema.
- **/var/log/maillog** ou **/var/log/mail.log**: Registram atividades do servidor de e-mail, sendo úteis para rastrear serviços relacionados a e-mail.
- **/var/log/kern.log**: Armazena mensagens do kernel, incluindo erros e avisos.
- **/var/log/dmesg**: Contém mensagens dos drivers de dispositivos.
- **/var/log/faillog**: Registra tentativas de login malsucedidas, auxiliando nas investigações de violações de segurança.
- **/var/log/cron**: Registra a execução de tarefas do cron.
- **/var/log/daemon.log**: Rastreia atividades de serviços em segundo plano.
- **/var/log/btmp**: Documenta tentativas de login malsucedidas.
- **/var/log/httpd/**: Contém logs de erro e acesso do Apache HTTPD.
- **/var/log/mysqld.log** ou **/var/log/mysql.log**: Registra atividades do banco de dados MySQL.
- **/var/log/xferlog**: Registra transferências de arquivos via FTP.
- **/var/log/**: Sempre verifique se há logs inesperados aqui.

> [!TIP]
> Os logs do sistema Linux e os subsistemas de auditoria podem ser desativados ou excluídos durante uma intrusão ou incidente de malware. Como os logs dos sistemas Linux geralmente contêm algumas das informações mais úteis sobre atividades maliciosas, os invasores os excluem rotineiramente. Portanto, ao examinar os arquivos de log disponíveis, é importante procurar lacunas ou entradas fora de ordem que possam indicar exclusão ou adulteração.

### Triagem do Journald (`journalctl`)

Em hosts Linux modernos, o **systemd journal** geralmente é a fonte de maior valor para **execução de serviços**, **eventos de autenticação**, **operações de pacotes** e **mensagens do kernel e do espaço de usuário**. Durante a resposta em tempo real, tente preservar tanto o journal **persistente** (`/var/log/journal/`) quanto o journal de **runtime** (`/run/log/journal/`), pois atividades de invasores de curta duração podem existir apenas neste último.<sup>[[5]](#references)</sup>
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
Campos úteis do journal para triagem incluem `_SYSTEMD_UNIT`, `_EXE`, `_COMM`, `_CMDLINE`, `_UID`, `_GID`, `_PID`, `_BOOT_ID` e `MESSAGE`. Se o journald tiver sido configurado sem armazenamento persistente, espere encontrar apenas dados recentes em `/run/log/journal/`.

### Triagem do framework de auditoria (`auditd`)

Se o `auditd` estiver habilitado, prefira-o sempre que precisar atribuir processos a alterações de arquivos, execução de comandos, atividades de login ou instalação de pacotes.<sup>[[6]](#references)</sup>
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
Quando as regras foram implantadas com chaves, faça pivot a partir delas em vez de pesquisar nos logs brutos:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**O Linux mantém um histórico de comandos para cada usuário**, armazenado em:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

Além disso, o comando `last -Faiwx` fornece uma lista de logins de usuários. Verifique-a em busca de logins desconhecidos ou inesperados.

Verifique os arquivos que podem conceder privilégios adicionais:

- Revise `/etc/sudoers` em busca de privilégios de usuário inesperados que possam ter sido concedidos.
- Revise `/etc/sudoers.d/` em busca de privilégios de usuário inesperados que possam ter sido concedidos.
- Examine `/etc/groups` para identificar associações de grupo ou permissões incomuns.
- Examine `/etc/passwd` para identificar associações de grupo ou permissões incomuns.

Alguns aplicativos também geram seus próprios logs:

- **SSH**: Examine _\~/.ssh/authorized_keys_ e _\~/.ssh/known_hosts_ em busca de conexões remotas não autorizadas.
- **Gnome Desktop**: Verifique _\~/.recently-used.xbel_ em busca de arquivos acessados recentemente por meio de aplicativos Gnome.
- **Firefox/Chrome**: Verifique o histórico e os downloads do navegador em _\~/.mozilla/firefox_ ou _\~/.config/google-chrome_ em busca de atividades suspeitas.
- **VIM**: Revise _\~/.viminfo_ em busca de detalhes de uso, como caminhos de arquivos acessados e histórico de pesquisas.
- **Open Office**: Verifique o acesso recente a documentos que possa indicar arquivos comprometidos.
- **FTP/SFTP**: Revise os logs em _\~/.ftp_history_ ou _\~/.sftp_history_ em busca de transferências de arquivos que possam não ter sido autorizadas.
- **MySQL**: Investigue _\~/.mysql_history_ em busca de queries MySQL executadas, que podem revelar atividades não autorizadas no banco de dados.
- **Less**: Analise _\~/.lesshst_ em busca do histórico de uso, incluindo arquivos visualizados e comandos executados.
- **Git**: Examine _\~/.gitconfig_ e _.git/logs_ do projeto em busca de alterações nos repositórios.

### Logs de USB

[**usbrip**](https://github.com/snovvcrash/usbrip) é um pequeno software escrito inteiramente em Python 3 que analisa arquivos de log do Linux (`/var/log/syslog*` ou `/var/log/messages*`, dependendo da distribuição) para criar tabelas do histórico de eventos de USB.

É interessante **saber quais USBs foram utilizados** e será ainda mais útil se você tiver uma lista autorizada de USBs para encontrar "eventos de violação" (o uso de USBs que não estão nessa lista).

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
Mais exemplos e informações no github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Revisar Contas de Usuário e Atividades de Logon

Examine _**/etc/passwd**_, _**/etc/shadow**_ e os **security logs** em busca de nomes incomuns ou contas criadas e/ou usadas próximas a eventos não autorizados conhecidos. Além disso, verifique possíveis ataques de brute-force contra o sudo.\
Além disso, verifique arquivos como _**/etc/sudoers**_ e _**/etc/groups**_ em busca de privilégios inesperados concedidos a usuários.\
Por fim, procure contas **sem senhas** ou com senhas **fáceis de adivinhar**.<sup>[[1]](#references)</sup>

## Examinar o Sistema de Arquivos

### Analisando Estruturas do Sistema de Arquivos em uma Investigação de Malware

Ao investigar incidentes de malware, a estrutura do sistema de arquivos é uma fonte crucial de informações, revelando tanto a sequência de eventos quanto o conteúdo do malware. No entanto, os autores de malware estão desenvolvendo técnicas para dificultar essa análise, como modificar timestamps de arquivos ou evitar o sistema de arquivos para armazenar dados.<sup>[[1]](#references)</sup>

Para combater esses métodos anti-forensics, é essencial:

- **Realizar uma análise completa da timeline** usando ferramentas como **Autopsy** para visualizar timelines de eventos ou o `mactime` do **Sleuth Kit** para obter dados detalhados da timeline.
- **Investigar scripts inesperados** no $PATH do sistema, que podem incluir scripts shell ou PHP usados por attackers.
- **Examinar `/dev` em busca de arquivos atípicos**, pois tradicionalmente ele contém arquivos especiais, mas também pode abrigar arquivos relacionados a malware.
- **Procurar arquivos ou diretórios ocultos** com nomes como ".. " (dot dot space) ou "..^G" (dot dot control-G), que podem ocultar conteúdo malicioso.
- **Identificar arquivos setuid root** usando o comando: `find / -user root -perm -04000 -print` Isso encontra arquivos com permissões elevadas, que podem ser abusadas por attackers.
- **Revisar timestamps de exclusão** nas tabelas de inode para identificar exclusões em massa de arquivos, possivelmente indicando a presença de rootkits ou trojans.
- **Inspecionar inodes consecutivos** em busca de arquivos maliciosos próximos após identificar um deles, pois eles podem ter sido colocados juntos.
- **Verificar diretórios comuns de binários** (_/bin_, _/sbin_) em busca de arquivos modificados recentemente, pois eles podem ter sido alterados por malware.
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> Observe que um **attacker** pode **modificar** o **time** para fazer com que os **files pareçam** **legitimate**, mas ele **não pode** modificar o **inode**. Se você descobrir que um **file** indica que foi criado e modificado no **mesmo time** que o restante dos files na mesma pasta, mas o **inode** é **inesperadamente maior**, então os **timestamps** desse file foram modificados.

### Triagem rápida focada em inode

Se você suspeitar de anti-forensics, execute estas verificações focadas em inode no início:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
Quando um inode suspeito estiver em uma imagem/dispositivo de sistema de arquivos EXT, inspecione diretamente os metadados do inode:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Campos úteis:
- **Links**: se `0`, nenhuma entrada de diretório referencia atualmente o inode.
- **dtime**: timestamp de exclusão definido quando o inode foi desvinculado.
- **ctime/mtime**: ajudam a correlacionar alterações de metadados/conteúdo com a linha do tempo do incidente.

### Capabilities, xattrs e rootkits userland baseados em preload

A persistência moderna no Linux geralmente evita binários `setuid` óbvios e, em vez disso, abusa de **capabilities de arquivo**, **atributos estendidos** e do carregador dinâmico.
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
Preste atenção especial às bibliotecas referenciadas a partir de caminhos **writable** como `/tmp`, `/dev/shm`, `/var/tmp` ou locais incomuns em `/usr/local/lib`. Verifique também binários com capabilities fora da propriedade normal de pacotes e correlacione-os com os resultados da verificação de pacotes (`rpm -Va`, `dpkg --verify`, `debsums`).

## Comparar arquivos de diferentes versões do sistema de arquivos

### Resumo da comparação de versões do sistema de arquivos

Para comparar versões do sistema de arquivos e identificar alterações, usamos comandos simplificados do `git diff`:<sup>[[3]](#references)</sup>

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
- **Opções de filtro** (`--diff-filter`) ajudam a restringir as alterações específicas, como arquivos adicionados (`A`), excluídos (`D`) ou modificados (`M`).
- `A`: Arquivos adicionados
- `C`: Arquivos copiados
- `D`: Arquivos excluídos
- `M`: Arquivos modificados
- `R`: Arquivos renomeados
- `T`: Alterações de tipo (por exemplo, de arquivo para symlink)
- `U`: Arquivos não mesclados
- `X`: Arquivos desconhecidos
- `B`: Arquivos corrompidos

## Referências

- [1] [Guia de campo de Malware Forensics para sistemas Linux: Guias de Forense Digital – Capítulo 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Explicação dos logs do Linux](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [Documentação do git diff – opção --diff-filter](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – Patching for persistence: como o malware Linux DripDropper se move pela cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Análise forense de Journals do Linux](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - Auditoria do sistema](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Diga olá ao Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [Extensão FTS5 do SQLite](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}

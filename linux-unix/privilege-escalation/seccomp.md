# Informação Básica

**Seccomp** ou Modo de Computação Segura, em resumo, é um recurso do kernel Linux que pode atuar como um **filtro de chamadas do sistema**.\
Seccomp tem 2 modos.

**seccomp** (abreviação de **modo de computação segura**) é uma facilidade de segurança de computador no **kernel Linux**. seccomp permite que um processo faça uma transição unidirecional para um estado "seguro" onde **ele não pode fazer nenhuma chamada do sistema, exceto** `exit()`, `sigreturn()`, `read()` e `write()` para descritores de arquivo **já abertos**. Se ele tentar fazer qualquer outra chamada do sistema, o **kernel** irá **encerrar** o **processo** com SIGKILL ou SIGSYS. Nesse sentido, ele não virtualiza os recursos do sistema, mas isola completamente o processo deles.

O modo seccomp é **habilitado via a chamada do sistema `prctl(2)`** usando o argumento `PR_SET_SECCOMP`, ou (desde o kernel Linux 3.17) via a chamada do sistema `seccomp(2)`. O modo seccomp costumava ser habilitado escrevendo em um arquivo, `/proc/self/seccomp`, mas esse método foi removido em favor do `prctl()`. Em algumas versões do kernel, o seccomp desativa a instrução x86 `RDTSC`, que retorna o número de ciclos do processador decorridos desde a inicialização, usada para temporização de alta precisão.

**seccomp-bpf** é uma extensão do seccomp que permite **filtrar chamadas do sistema usando uma política configurável** implementada usando regras do Berkeley Packet Filter. É usado pelo OpenSSH e vsftpd, bem como pelos navegadores da web Google Chrome/Chromium no Chrome OS e Linux. (Nesse sentido, o seccomp-bpf alcança funcionalidade semelhante, mas com mais flexibilidade e desempenho mais alto, ao systrace mais antigo - que parece não ser mais suportado para Linux.)

## **Modo Original/Estrito**

Neste modo, o **Seccomp permite apenas as chamadas do sistema** `exit()`, `sigreturn()`, `read()` e `write()` para descritores de arquivo já abertos. Se qualquer outra chamada do sistema for feita, o processo é morto usando SIGKILL

{% code title="seccomp_strict.c" %}
```c
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
## Seccomp-bpf

Este modo permite **filtrar chamadas de sistema usando uma política configurável** implementada usando regras do Berkeley Packet Filter.

{% code title="seccomp_bpf.c" %}
```c
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
{% endcode %}

# Seccomp no Docker

O **Seccomp-bpf** é suportado pelo **Docker** para restringir as **syscalls** dos contêineres, diminuindo efetivamente a área de superfície. Você pode encontrar as **syscalls bloqueadas** por **padrão** em [https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/) e o **perfil seccomp padrão** pode ser encontrado aqui [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json).\
Você pode executar um contêiner docker com uma **política seccomp diferente** com:
```bash
docker run --rm \
             -it \
             --security-opt seccomp=/path/to/seccomp/profile.json \
             hello-world
```
Se você quiser, por exemplo, **proibir** um contêiner de executar algum **syscall** como `uname`, você pode baixar o perfil padrão em [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) e simplesmente **remover a string `uname` da lista**.\
Se você quiser ter certeza de que **algum binário não funcione dentro de um contêiner docker**, você pode usar o strace para listar as syscalls que o binário está usando e, em seguida, proibi-las.\
No exemplo a seguir, as **syscalls** de `uname` são descobertas:
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
Se você está usando o **Docker apenas para lançar um aplicativo**, você pode **fazer um perfil dele com o `strace`** e **permitir apenas as chamadas de sistema** que ele precisa.
{% endhint %}

## Desativando no Docker

Inicie um contêiner com a flag: **`--security-opt seccomp=unconfined`**.

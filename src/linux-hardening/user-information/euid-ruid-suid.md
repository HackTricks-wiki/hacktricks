# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variáveis de Identificação do Usuário

- **`ruid`**: O **ID de usuário real** denota o usuário que iniciou o processo.
- **`euid`**: Conhecido como **ID de usuário efetivo**, representa a identidade do usuário utilizada pelo sistema para determinar os privilégios do processo. Geralmente, `euid` é igual a `ruid`, exceto em casos como a execução de um binário SetUID, em que `euid` assume a identidade do proprietário do arquivo, concedendo assim permissões operacionais específicas.
- **`suid`**: Esse **ID de usuário salvo** é fundamental quando um processo com altos privilégios (normalmente executado como root) precisa renunciar temporariamente aos seus privilégios para realizar determinadas tarefas, podendo posteriormente recuperar seu status elevado inicial.

#### Observação importante

Um processo que não esteja sendo executado como root só pode modificar seu `euid` para corresponder ao `ruid`, `euid` ou `suid` atual.

### Entendendo as funções set\*uid

- **`setuid`**: Ao contrário do que se pode supor inicialmente, `setuid` modifica principalmente o `euid`, e não o `ruid`. Especificamente, para processos privilegiados, ele alinha `ruid`, `euid` e `suid` ao usuário especificado, geralmente root, efetivamente consolidando esses IDs devido à substituição pelo `suid`. Informações detalhadas podem ser encontradas na [setuid man page](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** e **`setresuid`**: Essas funções permitem o ajuste detalhado de `ruid`, `euid` e `suid`. No entanto, seus recursos dependem do nível de privilégio do processo. Para processos que não são root, as modificações estão restritas aos valores atuais de `ruid`, `euid` e `suid`. Em contraste, processos root ou aqueles com a capacidade `CAP_SETUID` podem atribuir valores arbitrários a esses IDs. Mais informações podem ser obtidas na [setresuid man page](https://man7.org/linux/man-pages/man2/setresuid.2.html) e na [setreuid man page](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Essas funcionalidades não foram projetadas como um mecanismo de segurança, mas para facilitar o fluxo operacional pretendido, como quando um programa adota a identidade de outro usuário alterando seu ID de usuário efetivo.

Vale destacar que, embora `setuid` possa ser uma opção comum para elevar privilégios a root (pois alinha todos os IDs a root), diferenciar essas funções é fundamental para entender e manipular o comportamento dos IDs de usuário em diferentes cenários.

### Mecanismos de Execução de Programas no Linux

#### **System Call `execve`**

- **Funcionalidade**: `execve` inicia um programa, determinado pelo primeiro argumento. Ele recebe dois argumentos de array, `argv` para os argumentos e `envp` para o ambiente.
- **Comportamento**: Ele mantém o espaço de memória do chamador, mas atualiza os segmentos de stack, heap e dados. O código do programa é substituído pelo novo programa.
- **Preservação dos IDs de Usuário**:
- `ruid`, `euid` e os IDs de grupos suplementares permanecem inalterados.
- `euid` pode sofrer alterações específicas se o novo programa tiver o bit SetUID definido.
- `suid` é atualizado a partir de `euid` após a execução.
- **Documentação**: Informações detalhadas podem ser encontradas na [``execve` man page](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### **Função `system`**

- **Funcionalidade**: Diferentemente de `execve`, `system` cria um processo filho usando `fork` e executa um comando dentro desse processo filho usando `execl`.
- **Execução de Comandos**: Executa o comando por meio de `sh` com `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.
- **Comportamento**: Como `execl` é uma forma de `execve`, ele funciona de maneira semelhante, mas no contexto de um novo processo filho.
- **Documentação**: Mais informações podem ser obtidas na [`system` man page](https://man7.org/linux/man-pages/man3/system.3.html).

#### **Comportamento de `bash` e `sh` com SUID**

- **`bash`**:
- Possui uma opção `-p` que influencia como `euid` e `ruid` são tratados.
- Sem `-p`, `bash` define `euid` como `ruid` se eles forem inicialmente diferentes.
- Com `-p`, o `euid` inicial é preservado.
- Mais detalhes podem ser encontrados na [`bash` man page](https://linux.die.net/man/1/bash).
- **`sh`**:
- Não possui um mecanismo semelhante a `-p` em `bash`.
- O comportamento relacionado aos IDs de usuário não é mencionado explicitamente, exceto na opção `-i`, que enfatiza a preservação da igualdade entre `euid` e `ruid`.
- Informações adicionais estão disponíveis na [`sh` man page](https://man7.org/linux/man-pages/man1/sh.1p.html).

Esses mecanismos, distintos em sua operação, oferecem uma variedade versátil de opções para executar e alternar entre programas, com nuances específicas na forma como os IDs de usuário são gerenciados e preservados.

### Testando o Comportamento dos IDs de Usuário durante Execuções

Exemplos retirados de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail, consulte-o para obter mais informações<sup>[[1]](#references)</sup>

#### Caso 1: Usando `setuid` com `system`

**Objetivo**: Entender o efeito de `setuid` em combinação com `system` e `bash` como `sh`.

**Código C**:
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
**Compilação e Permissões:**
```bash
oxdf@hacky$ gcc a.c -o /mnt/nfsshare/a;
oxdf@hacky$ chmod 4755 /mnt/nfsshare/a
```

```bash
bash-4.2$ $ ./a
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

- `ruid` e `euid` começam como 99 (nobody) e 1000 (frank), respectivamente.
- `setuid` alinha ambos para 1000.
- `system` executa `/bin/bash -c id` devido ao symlink de sh para bash.
- `bash`, sem `-p`, ajusta `euid` para corresponder a `ruid`, resultando em ambos como 99 (nobody).

#### Caso 2: Usando setreuid com system

**Código C**:
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
**Compilação e Permissões:**
```bash
oxdf@hacky$ gcc b.c -o /mnt/nfsshare/b; chmod 4755 /mnt/nfsshare/b
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

- `setreuid` define ruid e euid como 1000.
- `system` invoca o bash, que mantém os IDs de usuário devido à igualdade entre eles, operando efetivamente como frank.

#### Caso 3: Usando setuid com execve

Objetivo: Explorar a interação entre setuid e execve.
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/usr/bin/id", NULL, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./c
uid=99(nobody) gid=99(nobody) euid=1000(frank) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

- `ruid` permanece 99, mas `euid` é definido como 1000, de acordo com o efeito de setuid.

**Exemplo de código C 2 (Chamando o Bash):**
```bash
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
setuid(1000);
execve("/bin/bash", NULL, NULL);
return 0;
}
```
**Execução e Resultado:**
```bash
bash-4.2$ $ ./d
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

- Embora `euid` seja definido como 1000 por `setuid`, o `bash` redefine `euid` para `ruid` (99) devido à ausência de `-p`.

**Exemplo de código C 3 (Usando bash -p):**
```bash
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
**Execução e Resultado:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=100
```
## Referências

- [1] [SetUID Rabbit Hole - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - página man do setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - página man do setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - página man do setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - página man do execve](https://man7.org/linux/man-pages/man2/execve.2.html)

{{#include ../../banners/hacktricks-training.md}}

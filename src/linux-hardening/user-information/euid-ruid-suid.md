# euid, ruid, suid

{{#include ../../banners/hacktricks-training.md}}

### Variáveis de Identificação do Usuário

- **`ruid`**: O **ID de usuário real** denota o usuário que iniciou o processo.<sup>[[1]](#references)</sup>
- **`euid`**: Conhecido como **ID de usuário efetivo**, representa a identidade do usuário utilizada pelo sistema para determinar os privilégios do processo. Geralmente, `euid` é igual a `ruid`, exceto em casos como a execução de um binário SetUID (quando a transição set-user-ID é respeitada), em que `euid` assume a identidade do proprietário do arquivo, concedendo permissões operacionais específicas.<sup>[[1]](#references)[[5]](#references)</sup>
- **`suid`**: Este **ID de usuário salvo** é essencial quando um processo com privilégios elevados (normalmente executado como root) precisa abrir mão temporariamente de seus privilégios para executar determinadas tarefas e, posteriormente, recuperar seu status elevado inicial.<sup>[[1]](#references)</sup>

#### Observação Importante

Um processo sem privilégios só pode modificar seu `euid` para corresponder ao `ruid`, `euid` ou `suid` atual.<sup>[[3]](#references)</sup>

### Entendendo as Funções set\*uid

- **`setuid`**: Ao contrário do que se pode supor inicialmente, `setuid` define o `euid` do processo chamador. Para um processo privilegiado, ela também define `ruid` e `suid` como o usuário especificado; depois que todos os IDs são definidos como root, o processo não pode recuperar uma identidade anterior usando `setuid`. Informações detalhadas podem ser encontradas na [página man de setuid](https://man7.org/linux/man-pages/man2/setuid.2.html).<sup>[[2]](#references)</sup>
- **`setreuid`** e **`setresuid`**: `setreuid` altera `ruid` e `euid`, enquanto `setresuid` altera os três IDs. Para um processo sem privilégios, `setresuid` restringe cada destino ao `ruid`, `euid` ou `suid` atual; `setreuid` restringe `euid` a esses valores e `ruid` ao `ruid` ou `euid` atual. Um processo com `CAP_SETUID` pode atribuir valores arbitrários aos IDs suportados por cada chamada. Mais informações podem ser obtidas na [página man de setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html) e na [página man de setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html).<sup>[[3]](#references)[[4]](#references)</sup>

Essas funcionalidades não foram projetadas como um mecanismo de segurança, mas para facilitar o fluxo operacional pretendido, como quando um programa adota a identidade de outro usuário alterando seu ID de usuário efetivo.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

É importante observar que uma chamada privilegiada a `setuid` pode atribuir os três IDs, enquanto `setreuid` e `setresuid` oferecem controles diferentes; diferenciar essas funções é essencial para entender as transições de IDs de usuário.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)</sup>

### Mecanismos de Execução de Programas no Linux

#### Chamada de Sistema **`execve`**

- **Funcionalidade**: `execve` inicia um programa, determinado pelo primeiro argumento. Ela recebe dois argumentos de array, `argv` para os argumentos e `envp` para o ambiente.<sup>[[5]](#references)</sup>
- **Comportamento**: Mantém o espaço de memória do chamador, mas atualiza as áreas de stack, heap e dados. O código do programa é substituído pelo novo programa.<sup>[[5]](#references)</sup>
- **Preservação dos IDs de Usuário**:
- `ruid` e os IDs de grupos suplementares permanecem inalterados.<sup>[[5]](#references)</sup>
- `euid` normalmente não é alterado, mas pode mudar se o novo programa tiver o bit SetUID definido.<sup>[[5]](#references)</sup>
- `suid` é atualizado a partir de `euid` após a execução.<sup>[[5]](#references)</sup>
- **Documentação**: Informações detalhadas podem ser encontradas na [página man de `execve`](https://man7.org/linux/man-pages/man2/execve.2.html).<sup>[[5]](#references)</sup>

#### Função **`system`**

- **Funcionalidade**: Diferentemente de `execve`, `system` se comporta como se criasse um processo filho usando `fork` e executasse o comando dentro desse processo filho usando `execl`.<sup>[[6]](#references)</sup>
- **Execução de Comandos**: Executa o comando por meio de `sh` com `execl("/bin/sh", "sh", "-c", command, (char *) NULL);`.<sup>[[6]](#references)</sup>
- **Comportamento**: Como `execl` é uma chamada da família `exec`, ela opera de forma semelhante a `execve`, mas no contexto de um novo processo filho.<sup>[[1]](#references)[[5]](#references)[[6]](#references)</sup>
- **Documentação**: Mais informações podem ser obtidas na [página man de `system`](https://man7.org/linux/man-pages/man3/system.3.html).<sup>[[6]](#references)</sup>

#### **Comportamento de `bash` e `sh` com SUID**

- **`bash`**:
- Possui uma opção `-p` que influencia a forma como `euid` e `ruid` são tratados.<sup>[[7]](#references)</sup>
- Sem `-p`, `bash` define `euid` como `ruid` se eles forem inicialmente diferentes.<sup>[[7]](#references)</sup>
- Com `-p`, o `euid` inicial é preservado.<sup>[[7]](#references)</sup>
- Mais detalhes podem ser encontrados na [página man de `bash`](https://linux.die.net/man/1/bash).<sup>[[7]](#references)</sup>
- **`sh`**:
- O `sh` POSIX não define uma opção de preservação de privilégios no estilo do `-p` do Bash.<sup>[[8]](#references)</sup>
- Sua lista de opções POSIX inclui `-i`, que seleciona o modo interativo e pode ser rejeitada quando os IDs real e efetivo forem diferentes.<sup>[[8]](#references)</sup>
- Informações adicionais estão disponíveis na [página man de `sh`](https://man7.org/linux/man-pages/man1/sh.1p.html).<sup>[[8]](#references)</sup>

Esses mecanismos, distintos em sua operação, oferecem uma ampla variedade de opções para executar e alternar entre programas, com nuances específicas na forma como os IDs de usuário são gerenciados e preservados.

### Testando os Comportamentos dos IDs de Usuário nas Execuções

Exemplos obtidos de https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail; consulte essa referência para obter mais informações.<sup>[[1]](#references)</sup>

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
- Neste contexto sem privilégios, `setuid(1000)` mantém `ruid` em 99 e `euid` em 1000.<sup>[[1]](#references)</sup>
- `system` executa `/bin/bash -c id` devido ao symlink de sh para bash.
- `bash`, sem `-p`, ajusta `euid` para corresponder a `ruid`, fazendo com que ambos sejam 99 (nobody).<sup>[[1]](#references)</sup>

#### Caso 2: Usando setreuid com system

**Código C:**
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
**Execução e resultado:**
```bash
bash-4.2$ $ ./b
uid=1000(frank) gid=99(nobody) groups=99(nobody) context=system_u:system_r:unconfined_service_t:s0
```
**Análise:**

- `setreuid` define ruid e euid como 1000.
- `system` invoca o bash, que mantém os IDs de usuário devido à igualdade entre eles, operando efetivamente como frank.<sup>[[1]](#references)</sup>

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

- `ruid` permanece 99, mas `euid` é definido como 1000, de acordo com o efeito de `setuid`.<sup>[[1]](#references)</sup>

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

- Embora `euid` seja definido como 1000 por `setuid`, `bash` redefine euid para `ruid` (99) devido à ausência de `-p`.<sup>[[1]](#references)</sup>

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
**Execução e resultado:**
```bash
bash-4.2$ $ ./e
bash-4.2$ $ id
uid=99(nobody) gid=99(nobody) euid=1000(frank)
```
## References

- [1] [SetUID Toca do Coelho - 0xdf](https://0xdf.gitlab.io/2022/05/31/setuid-rabbithole.html#testing-on-jail)
- [2] [man7.org - página de manual do setuid](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [3] [man7.org - página de manual do setresuid](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [4] [man7.org - página de manual do setreuid](https://man7.org/linux/man-pages/man2/setreuid.2.html)
- [5] [man7.org - página de manual do execve](https://man7.org/linux/man-pages/man2/execve.2.html)
- [6] [man7.org - página de manual do system](https://man7.org/linux/man-pages/man3/system.3.html)
- [7] [man7.org - página de manual do bash](https://man7.org/linux/man-pages/man1/bash.1.html)
- [8] [man7.org - página de manual do POSIX sh](https://man7.org/linux/man-pages/man1/sh.1p.html)
{{#include ../../banners/hacktricks-training.md}}

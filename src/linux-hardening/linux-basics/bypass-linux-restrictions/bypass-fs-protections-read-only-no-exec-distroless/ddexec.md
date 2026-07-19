# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contexto

No Linux, para executar um programa, ele precisa existir como um arquivo e ser acessível de alguma forma por meio da hierarquia do sistema de arquivos (é assim que `execve()` funciona). Esse arquivo pode estar armazenado em disco ou na memória RAM (tmpfs, memfd), mas é necessário um filepath. Isso tornou muito fácil controlar o que é executado em um sistema Linux, detectar threats e as ferramentas do attacker ou impedi-los de tentar executar qualquer coisa própria (_e. g._ não permitir que usuários sem privilégios coloquem arquivos executáveis em qualquer lugar).

Mas esta técnica veio para mudar tudo isso. Se você não pode iniciar o processo que deseja... **então hijack um que já exista**.

Esta técnica permite **bypassar técnicas comuns de proteção, como read-only, noexec, file-name whitelisting, hash whitelisting...**

## Dependências

O script final depende das seguintes tools para funcionar; elas precisam estar acessíveis no sistema que você está atacando (por padrão, você encontrará todas elas em praticamente qualquer lugar):
```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```
## A técnica

Se você consegue modificar arbitrariamente a memória de um processo, pode assumir o controle dele. Isso pode ser usado para sequestrar um processo já existente e substituí-lo por outro programa. Podemos fazer isso usando a syscall `ptrace()` (que exige a capacidade de executar syscalls ou que o `gdb` esteja disponível no sistema) ou, de forma mais interessante, escrevendo em `/proc/$pid/mem`.

O arquivo `/proc/$pid/mem` é um mapeamento individual de todo o espaço de endereçamento de um processo (_por exemplo_, de `0x0000000000000000` a `0x7ffffffffffff000` em x86-64). Isso significa que ler ou escrever nesse arquivo no offset `x` equivale a ler ou modificar o conteúdo no endereço virtual `x`.

Agora, temos quatro problemas básicos para enfrentar:

- Em geral, somente o root e o proprietário do arquivo podem modificá-lo.
- ASLR.
- Se tentarmos ler ou escrever em um endereço que não esteja mapeado no espaço de endereçamento do programa, obteremos um erro de I/O.

Esses problemas têm soluções que, embora não sejam perfeitas, são eficazes:

- A maioria dos interpretadores de shell permite a criação de file descriptors que serão herdados pelos processos filhos. Podemos criar um fd apontando para o arquivo `mem` do shell com permissões de escrita... assim, os processos filhos que usarem esse fd poderão modificar a memória do shell.
- ASLR nem sequer é um problema: podemos verificar o arquivo `maps` do shell ou qualquer outro arquivo do procfs para obter informações sobre o espaço de endereçamento do processo.
- Portanto, precisamos executar `lseek()` sobre o arquivo. A partir do shell, isso não pode ser feito sem usar o famoso `dd`.

### Em mais detalhes

As etapas são relativamente fáceis e não exigem nenhum tipo de conhecimento especializado para serem compreendidas:

- Analisar o binário que queremos executar e o loader para descobrir quais mapeamentos eles precisam. Em seguida, criar um "shell"code que execute, em termos gerais, as mesmas etapas que o kernel executa a cada chamada a `execve()`:
- Criar esses mapeamentos.
- Ler os binários para dentro deles.
- Configurar as permissões.
- Por fim, inicializar a stack com os argumentos do programa e inserir o auxiliary vector (necessário para o loader).
- Saltar para o loader e deixá-lo fazer o restante (carregar as libraries necessárias para o programa).
- Obter, a partir do arquivo `syscall`, o endereço para o qual o processo retornará após a syscall que está executando.
- Sobrescrever esse local, que será executável, com nosso shellcode (por meio de `mem`, podemos modificar páginas sem permissão de escrita).
- Passar o programa que queremos executar para o stdin do processo (será `read()` pelo referido "shell"code).
- Nesse ponto, cabe ao loader carregar as libraries necessárias para o nosso programa e saltar para ele.

**Confira a tool em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Há várias alternativas ao `dd`; uma delas, `tail`, é atualmente o programa padrão usado para executar `lseek()` através do arquivo `mem` (que era o único propósito de usar `dd`). Essas alternativas são:
```bash
tail
hexdump
cmp
xxd
```
Ao definir a variável `SEEKER`, você pode alterar o seeker usado, _por exemplo_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se você encontrar outro `seeker` válido que não esteja implementado no script, ainda poderá usá-lo definindo a variável `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloqueiem isto, EDRs.

## Referências

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}

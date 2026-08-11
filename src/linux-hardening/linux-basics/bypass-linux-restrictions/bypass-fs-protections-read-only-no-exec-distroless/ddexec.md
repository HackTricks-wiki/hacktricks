# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contexto

No Linux, para executar um programa, ele precisa existir como um arquivo e ser acessível de alguma forma por meio da hierarquia do sistema de arquivos (é assim que `execve()` funciona). Esse arquivo pode estar armazenado no disco ou na RAM (tmpfs, memfd), mas é necessário ter um filepath. Isso tornou muito fácil controlar o que é executado em um sistema Linux, facilitando a detecção de threats e das ferramentas dos attackers, ou impedindo completamente que eles tentem executar qualquer coisa própria (_por exemplo_, não permitir que usuários sem privilégios coloquem arquivos executáveis em nenhum local).

Mas essa técnica veio para mudar tudo isso. Se você não consegue iniciar o processo que deseja... **então você sequestra um que já existe**.

Essa técnica permite **contornar técnicas comuns de proteção, como read-only, noexec, file-name whitelisting e hash whitelisting**.<sup>[[1]](#references)</sup>

## Dependências

O script final depende das seguintes ferramentas para funcionar; elas precisam estar acessíveis no sistema que você está atacando (por padrão, você encontrará todas elas em praticamente qualquer lugar):
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

Se você consegue modificar arbitrariamente a memória de um processo, então pode assumir o controle dele. Isso pode ser usado para sequestrar um processo já existente e substituí-lo por outro programa. Podemos fazer isso usando a syscall `ptrace()` (que exige a capacidade de executar syscalls ou que o gdb esteja disponível no sistema) ou, de forma mais interessante, escrevendo em `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

O arquivo `/proc/$pid/mem` é um mapeamento individual de todo o espaço de endereçamento de um processo (_por exemplo_, de `0x0000000000000000` a `0x7ffffffffffff000` em x86-64). Isso significa que ler ou escrever nesse arquivo em um offset `x` equivale a ler ou modificar o conteúdo no endereço virtual `x`.

Agora, temos quatro problemas básicos a enfrentar:

- Em geral, apenas o root e o proprietário do arquivo podem modificá-lo.
- ASLR.
- Se tentarmos ler ou escrever em um endereço não mapeado no espaço de endereçamento do programa, obteremos um erro de I/O.

Esses problemas têm soluções que, embora não sejam perfeitas, são boas:

- A maioria dos interpretadores de shell permite a criação de file descriptors que serão herdados pelos processos filhos. Podemos criar um fd apontando para o arquivo `mem` do shell com permissões de escrita... assim, os processos filhos que usarem esse fd poderão modificar a memória do shell.
- ASLR nem sequer é um problema; podemos verificar o arquivo `maps` do shell ou qualquer outro arquivo do procfs para obter informações sobre o espaço de endereçamento do processo.
- Portanto, precisamos executar `lseek()` sobre o arquivo. A partir do shell, isso não pode ser feito sem usar o infame `dd`.

### Em mais detalhes

As etapas são relativamente fáceis e não exigem nenhum tipo de experiência para serem compreendidas:<sup>[[1]](#references)</sup>

- Analise o binário que queremos executar e o loader para descobrir de quais mappings eles precisam. Em seguida, crie um "shell"code que realizará, em termos gerais, as mesmas etapas que o kernel executa a cada chamada a `execve()`:
- Crie os mappings mencionados.
- Leia os binários neles.
- Configure as permissões.
- Por fim, inicialize a stack com os argumentos do programa e coloque o auxiliary vector (necessário para o loader).
- Salte para o loader e deixe que ele faça o restante (carregar as libraries necessárias para o programa).
- Obtenha, do arquivo `syscall`, o endereço para o qual o processo retornará após a syscall que está executando.
- Sobrescreva esse local, que será executável, com nosso shellcode (por meio de `mem`, podemos modificar páginas sem permissão de escrita).
- Passe o programa que queremos executar para o stdin do processo (será `read()` pelo referido "shell"code).
- Nesse ponto, cabe ao loader carregar as libraries necessárias para o nosso programa e saltar para ele.

**Confira a ferramenta em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Existem várias alternativas ao `dd`; uma delas, `tail`, é atualmente o programa padrão usado para executar `lseek()` através do arquivo `mem` (que era o único motivo para usar `dd`). Essas alternativas são:<sup>[[1]](#references)</sup>
```bash
tail
hexdump
cmp
xxd
```
Definindo a variável `SEEKER`, você pode alterar o seeker usado, _por exemplo_:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Caso encontre outro seeker válido que não esteja implementado no script, ainda poderá utilizá-lo definindo a variável `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloqueiem isto, EDRs.

## References

- [1] [DDexec: Uma técnica para executar arquivos binários filelessly e furtivamente no Linux](https://github.com/arget13/DDexec)
{{#include ../../../../banners/hacktricks-training.md}}

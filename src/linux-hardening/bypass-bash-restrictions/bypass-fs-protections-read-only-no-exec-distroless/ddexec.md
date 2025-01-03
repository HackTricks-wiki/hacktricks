# DDexec / EverythingExec

{{#include ../../../banners/hacktricks-training.md}}

## Contexto

No Linux, para executar um programa, ele deve existir como um arquivo, deve ser acessível de alguma forma através da hierarquia do sistema de arquivos (é assim que `execve()` funciona). Este arquivo pode residir no disco ou na RAM (tmpfs, memfd), mas você precisa de um caminho de arquivo. Isso facilitou muito o controle sobre o que é executado em um sistema Linux, tornando fácil detectar ameaças e ferramentas de atacantes ou impedir que eles tentem executar qualquer coisa deles (_e. g._ não permitindo que usuários não privilegiados coloquem arquivos executáveis em qualquer lugar).

Mas esta técnica está aqui para mudar tudo isso. Se você não pode iniciar o processo que deseja... **então você sequestra um já existente**.

Esta técnica permite que você **bypasse técnicas comuns de proteção, como somente leitura, noexec, lista branca de nomes de arquivos, lista branca de hashes...**

## Dependências

O script final depende das seguintes ferramentas para funcionar, elas precisam estar acessíveis no sistema que você está atacando (por padrão, você encontrará todas elas em todos os lugares):
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

Se você for capaz de modificar arbitrariamente a memória de um processo, então você pode assumir o controle dele. Isso pode ser usado para sequestrar um processo já existente e substituí-lo por outro programa. Podemos alcançar isso usando a syscall `ptrace()` (que requer que você tenha a capacidade de executar syscalls ou que tenha o gdb disponível no sistema) ou, mais interessantemente, escrevendo em `/proc/$pid/mem`.

O arquivo `/proc/$pid/mem` é um mapeamento um-para-um de todo o espaço de endereços de um processo (_e. g._ de `0x0000000000000000` a `0x7ffffffffffff000` em x86-64). Isso significa que ler ou escrever neste arquivo em um deslocamento `x` é o mesmo que ler ou modificar o conteúdo no endereço virtual `x`.

Agora, temos quatro problemas básicos a enfrentar:

- Em geral, apenas o root e o proprietário do programa do arquivo podem modificá-lo.
- ASLR.
- Se tentarmos ler ou escrever em um endereço não mapeado no espaço de endereços do programa, receberemos um erro de I/O.

Esses problemas têm soluções que, embora não sejam perfeitas, são boas:

- A maioria dos interpretadores de shell permite a criação de descritores de arquivo que serão herdados por processos filhos. Podemos criar um fd apontando para o arquivo `mem` do shell com permissões de escrita... então os processos filhos que usam esse fd poderão modificar a memória do shell.
- ASLR não é nem mesmo um problema, podemos verificar o arquivo `maps` do shell ou qualquer outro do procfs para obter informações sobre o espaço de endereços do processo.
- Portanto, precisamos usar `lseek()` sobre o arquivo. A partir do shell, isso não pode ser feito a menos que usando o infame `dd`.

### Em mais detalhes

Os passos são relativamente fáceis e não requerem nenhum tipo de especialização para entendê-los:

- Analise o binário que queremos executar e o carregador para descobrir quais mapeamentos eles precisam. Em seguida, crie um código "shell" que realizará, de forma ampla, os mesmos passos que o kernel faz a cada chamada para `execve()`:
- Crie os mapeamentos mencionados.
- Leia os binários neles.
- Configure as permissões.
- Finalmente, inicialize a pilha com os argumentos para o programa e coloque o vetor auxiliar (necessário pelo carregador).
- Salte para o carregador e deixe-o fazer o resto (carregar bibliotecas necessárias para o programa).
- Obtenha do arquivo `syscall` o endereço para o qual o processo retornará após a syscall que está executando.
- Sobrescreva aquele lugar, que será executável, com nosso shellcode (através de `mem` podemos modificar páginas não graváveis).
- Passe o programa que queremos executar para a entrada padrão do processo (será `read()` por esse código "shell").
- Neste ponto, cabe ao carregador carregar as bibliotecas necessárias para nosso programa e saltar para ele.

**Confira a ferramenta em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

Existem várias alternativas ao `dd`, uma das quais, `tail`, é atualmente o programa padrão usado para `lseek()` através do arquivo `mem` (que era o único propósito para usar `dd`). Essas alternativas são:
```bash
tail
hexdump
cmp
xxd
```
Definindo a variável `SEEKER`, você pode alterar o seeker utilizado, _e. g._:
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Se você encontrar outro seeker válido não implementado no script, você ainda pode usá-lo definindo a variável `SEEKER_ARGS`:
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
Bloqueie isso, EDRs.

## Referências

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../banners/hacktricks-training.md}}

# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## Contexto

O Linux normalmente executa programas a partir de arquivos executáveis armazenados em disco ou na memória. Ele pode identificar um executável pelo nome do caminho ou pelo descritor de arquivo, portanto, nem sempre é necessário um nome de caminho normal do sistema de arquivos.<sup>[[2]](#references)</sup>

DDexec / EverythingExec usa a memória de um **processo já em execução**. A página [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) aborda a execução de arquivos anônimos e a detecção e coleta forense relacionadas; a [visão geral de Memory Bypasses](index.html#memory-bypasses) também inclui links para MemExec e Memdlopen.<sup>[[1]](#references)</sup>

Essa técnica permite **bypassar técnicas de proteção comuns, como read-only, noexec, whitelisting de nomes de arquivos e whitelisting de hashes**.<sup>[[1]](#references)</sup>

## Dependências

O script final depende das seguintes ferramentas para funcionar; elas precisam estar acessíveis no sistema que você está atacando (por padrão, você encontrará todas elas em qualquer lugar):

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

Se você consegue modificar arbitrariamente a memória de um processo, pode assumir o controle dele. Isso pode ser usado para sequestrar um processo existente e substituí-lo por outro programa. Podemos fazer isso usando a syscall `ptrace()` (que exige que você consiga executar syscalls ou que o gdb esteja disponível no sistema) ou, de forma mais interessante, escrevendo em `/proc/$pid/mem`.<sup>[[1]](#references)</sup>

O arquivo `/proc/$pid/mem` é um mapeamento um a um de todo o espaço de endereçamento de um processo (_por exemplo_, de `0x0000000000000000` a `0x7ffffffffffff000` em x86-64). Isso significa que ler ou escrever nesse arquivo no offset `x` equivale a ler ou modificar o conteúdo no endereço virtual `x`.

Agora, temos quatro problemas básicos a enfrentar:

- Em geral, somente o root e o proprietário do programa podem modificá-lo.
- ASLR.
- Se tentarmos ler ou escrever em um endereço não mapeado no espaço de endereçamento do programa, receberemos um erro de I/O.

Esses problemas têm soluções que, embora não sejam perfeitas, são boas:

- A maioria dos interpretadores de shell permite criar descritores de arquivo que serão herdados pelos processos filhos. Podemos criar um fd apontando para o arquivo `mem` do shell com permissões de escrita... assim, os processos filhos que usarem esse fd poderão modificar a memória do shell.
- ASLR nem chega a ser um problema: podemos verificar o arquivo `maps` do shell ou qualquer outro arquivo do procfs para obter informações sobre o espaço de endereçamento do processo.
- Portanto, precisamos usar `lseek()` no arquivo. No shell, isso não pode ser feito sem usar o infame `dd`.

### Em mais detalhes

As etapas são relativamente simples e não exigem nenhum tipo de conhecimento especializado para entendê-las:<sup>[[1]](#references)</sup>

- Analisar o binário que queremos executar e o loader para descobrir quais mapeamentos eles precisam. Em seguida, criar um "shell"code que executará, em linhas gerais, as mesmas etapas realizadas pelo kernel a cada chamada de `execve()`:
  - Criar esses mapeamentos.
  - Ler os binários para dentro deles.
  - Configurar as permissões.
  - Por fim, inicializar a stack com os argumentos do programa e inserir o vetor auxiliar (necessário para o loader).
  - Saltar para o loader e deixá-lo fazer o resto (carregar as bibliotecas necessárias para o programa).
- Obter do arquivo `syscall` o endereço para o qual o processo retornará após a syscall que está executando.
- Sobrescrever esse local, que será executável, com nosso shellcode (por meio de `mem`, podemos modificar páginas sem permissão de escrita).
- Passar o programa que queremos executar para o stdin do processo (ele será `read()` por esse "shell"code).
- Nesse ponto, cabe ao loader carregar as bibliotecas necessárias para o nosso programa e saltar para ele.

**Confira a ferramenta em** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec).<sup>[[1]](#references)</sup>

## EverythingExec

Há várias alternativas ao `dd`; uma delas, `tail`, é atualmente o programa padrão usado para executar `lseek()` no arquivo `mem` (que era o único motivo para usar `dd`). Essas alternativas são:<sup>[[1]](#references)</sup>

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

Se você encontrar outro seeker válido que não esteja implementado no script, ainda poderá usá-lo definindo a variável `SEEKER_ARGS`:

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

Bloqueiem isso, EDRs.

## References

- [1] [DDexec: Uma técnica para executar binários sem gravá-los em disco e furtivamente no Linux](https://github.com/arget13/DDexec)
- [2] [execveat(2) — página de manual do Linux](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}

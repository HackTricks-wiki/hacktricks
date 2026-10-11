# Abuso de bibliotecas compartilhadas e do linker SUID

{{#include ../../banners/hacktricks-training.md}}

Os binários SUID geralmente são analisados em busca de execução direta de comandos, mas programas SUID personalizados também podem ser vulneráveis por meio do dynamic linker. O tema comum é simples: um executável privilegiado carrega código de um caminho ou configuração que um usuário com menos privilégios pode influenciar.<sup>[[1]](#references)</sup>

Esta página se concentra em padrões genéricos de técnicas: bibliotecas ausentes, diretórios de bibliotecas com permissão de escrita, `RPATH`/`RUNPATH`, `LD_PRELOAD` por meio do sudo, configuração do linker e confusão com hardlinks SUID.

Para ver os cabeçalhos de programa ELF, a seção dinâmica e o comportamento do loader por trás dessas verificações, consulte [informações básicas sobre ELF](../../binary-exploitation/basic-stack-binary-exploitation-methodology/elf-tricks.md).

## Enumeração rápida

Comece procurando arquivos SUID incomuns e verificando se estão vinculados dinamicamente:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```

Use `readelf` para analisar um executável desconhecido: [`ldd` pode executar um interpretador ELF não confiável](https://man7.org/linux/man-pages/man1/ldd.1.html). `readelf` mostra as dependências diretas, então confirme separadamente o caminho realmente escolhido pelo loader.<sup>[[1]](#references)[[3]](#references)</sup>

Dê atenção a locais fora do padrão, caminhos personalizados de aplicações, binários pertencentes ao root, mas fora de diretórios gerenciados por pacotes, e dependências carregadas de diretórios graváveis.<sup>[[1]](#references)</sup>

Verificações úteis de permissões de escrita:

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```

## Injeção de Shared Object Ausente

Alguns binários SUID personalizados tentam carregar um shared object inexistente. Se o caminho ausente estiver dentro de um diretório controlado pelo atacante, o binário poderá carregar código fornecido pelo atacante com os privilégios do usuário efetivo.<sup>[[1]](#references)</sup>

O mesmo limite se aplica a um **binário personalizado permitido por meio do sudo** quando ele chama `dlopen()` usando um caminho absoluto para um arquivo `.so` em um diretório pessoal ou de configuração gravável pelo chamador. Esse carregamento tardio da biblioteca pode não aparecer na saída de `ldd` nem nas entradas ELF `NEEDED`. Uma análise limitada com `strings` ou um rastreamento de uma execução **sem privilégios** pode revelar o caminho tentado; uma senha do aplicativo ou uma opção de menu pode controlar essa busca. Confirme a regra exata do sudo, o caminho e as permissões do diretório pai, e que a execução privilegiada alcança essa busca antes de considerar isso uma escalada. Não invoque o alvo do sudo apenas para enumerá-lo.

Encontre buscas de bibliotecas malsucedidas com o filtro de chamadas de sistema do `strace`:<sup>[[2]](#references)</sup>

```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```

Se o binário procurar `libexample.so` em um caminho com permissão de escrita, uma biblioteca mínima para comprovar o impacto pode usar um construtor. Mantenha a comprovação de impacto inofensiva durante a validação:<sup>[[6]](#references)</sup>

```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
    setuid(0);
    setgid(0);
    system("id > /tmp/suid-so-ran");
}
```

Compile-o com o nome de arquivo exato que o binário tenta carregar:

```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```

A condição explorável não é apenas a biblioteca ausente. O atacante precisa conseguir colocar um objeto compartilhado compatível em um caminho que o loader privilegiado aceitará.<sup>[[1]](#references)</sup>

## Diretório de bibliotecas gravável

Às vezes, todas as dependências existem, mas um dos diretórios usados para resolvê-las permite gravação. Isso pode permitir substituir uma biblioteca carregada ou instalar uma biblioteca de prioridade mais alta com o mesmo nome.<sup>[[1]](#references)</sup>

A mesma análise se aplica a um ELF personalizado **permitido pelo sudo**, mesmo quando o ELF não tem o bit SUID e a conta RunAs permitida não é root. Compare as entradas `DT_NEEDED` com o caminho da biblioteca que o loader resolverá; depois, verifique se o usuário chamador pode gravar nesse arquivo ou substituí-lo por meio de um diretório pai gravável e pesquisável. Confirme a regra exata de RunAs do sudo, os symlinks e as ACLs, a política do loader e se o processo de destino carrega a biblioteca como a conta com privilégios mais altos. Um `.so` gravável ou apenas um nome de dependência é somente uma pista; inspecione os metadados sem executar o comando sudo.<sup>[[1]](#references)[[3]](#references)[[5]](#references)</sup>

Revise os caminhos das dependências:<sup>[[1]](#references)[[3]](#references)</sup>

```bash
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```

Se o diretório permitir escrita, valide com uma abordagem segura usando uma cópia em um laboratório. Substituir bibliotecas do sistema em um host ativo pode deixar processos iniciados simultaneamente com versões inconsistentes das bibliotecas.<sup>[[8]](#references)</sup>

### Bibliotecas graváveis dentro de um chroot

Um chroot, por si só, não fecha descritores de arquivo herdados nem restringe todo o acesso ao sistema de arquivos. Se um sandbox deixar um descritor de diretório apontando para fora da nova raiz e o processo isolado puder acessá-lo (por exemplo, por meio de uma entrada acessível em `/proc/<pid>/fd/`), os caminhos do host podem continuar acessíveis. Isso é um problema de limite do sistema de arquivos; por si só, não concede privilégios de root.<sup>[[11]](#references)[[12]](#references)</sup>

Verifique separadamente se o usuário isolado pode gravar em um diretório de bibliotecas que um **executável do host com SUID de root** usará quando iniciado a partir do chroot. O loader resolve as dependências na visão do sistema de arquivos do processo, então uma biblioteca controlada pelo atacante nesse diretório pode ser executada com a identidade efetiva do programa SUID. Confirme o executável exato, seu bit SUID e a política de montagem, o destino do descritor e as permissões de acesso, o caminho de busca de bibliotecas do chroot e se o programa realmente consegue acessar o executável do host. Uma capability de arquivo no launcher do sandbox, um chroot gravável ou apenas um binário SUID do host são apenas pistas; a cadeia completa depende da implementação do sandbox.<sup>[[1]](#references)[[11]](#references)[[12]](#references)</sup>

## RPATH e RUNPATH

`RPATH` e `RUNPATH` são entradas da seção dinâmica que informam ao loader onde procurar bibliotecas. São perigosos em programas SUID quando apontam para diretórios graváveis pelo atacante.<sup>[[1]](#references)</sup>

Detecte-os:<sup>[[3]](#references)[[10]](#references)</sup>

```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```

Exemplo de saída arriscada:

```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```

Se `/opt/app/lib` tiver permissão de escrita e o binário precisar de `libcustom.so`, o atacante poderá colocar um `libcustom.so` malicioso nesse diretório:<sup>[[1]](#references)</sup>

```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```

`RPATH` e `RUNPATH` não são idênticos em todos os detalhes de resolução, mas, para uma análise de escalada de privilégios, a questão prática é a mesma: o binário SUID procura uma biblioteca por nome em um diretório gravável pelo atacante?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Em programas normais, `LD_PRELOAD` e `LD_LIBRARY_PATH` podem forçar ou influenciar o carregamento de objetos compartilhados. Em programas SUID, o carregador dinâmico normalmente entra no modo de execução segura e ignora variáveis de ambiente perigosas.<sup>[[1]](#references)</sup>

Isso significa que um binário SUID simples geralmente não é vulnerável apenas porque o usuário pode definir `LD_PRELOAD`:<sup>[[1]](#references)</sup>

```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```

A exceção comum é uma política do sudo que permite uma atribuição de variável de ambiente na linha de comando para o alvo, como uma tag `SETENV` ou uma opção `setenv` aplicável. Se o alvo estiver vinculado dinamicamente e o sudo aceitar `LD_PRELOAD=/path/to/library`, o alvo poderá carregar código controlado pelo chamador. Verifique a regra efetiva e a identidade do alvo. Simplesmente adicionar `LD_PRELOAD` a `env_keep` não é suficiente em sistemas nos quais o carregador dinâmico remove um `LD_PRELOAD` herdado antes de o processo SUID do `sudo` iniciar; uma atribuição na linha de comando é avaliada pelo sudo após sua própria inicialização.<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

```bash
sudo -l
# Check SETENV/setenv and the target command's allowed arguments
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```

Não confunda estes casos; as regras do loader e da política do sudo acima os distinguem:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contra um binário SUID normal: geralmente bloqueado pela execução segura.
- `LD_PRELOAD` aceito como uma atribuição na linha de comando do sudo para um alvo privilegiado e vinculado dinamicamente: potencialmente explorável.
- `.so` ausente em um caminho gravável: explorável quando o binário SUID carrega esse caminho naturalmente.
- `RPATH`/`RUNPATH` para um diretório gravável: explorável quando uma biblioteca necessária pode ser controlada.
- Acesso de escrita a `/etc/ld.so.preload` ou à configuração do linker: impacto sistêmico e alto.

## Configuração do Linker

`ld.so` usa o cache do linker e `/etc/ld.so.preload`; `ldconfig` cria esse cache a partir de `/etc/ld.so.conf` e dos arquivos incluídos nele, geralmente em `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Verificações de alto valor:

```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```

Uma configuração do linker com permissões de escrita costuma ser mais grave do que um único binário SUID vulnerável, pois pode afetar muitos processos vinculados dinamicamente. `/etc/ld.so.preload` é especialmente perigoso porque pode forçar o carregamento de um objeto compartilhado em processos privilegiados.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## Confusão de Hardlink SUID

Hardlinks podem fazer o mesmo inode SUID aparecer com vários nomes.<sup>[[9]](#references)</sup> Isso é útil para ocultar um helper privilegiado, confundir a limpeza ou contornar uma análise ingênua baseada em caminhos.

Encontre arquivos SUID com mais de um link:<sup>[[9]](#references)</sup>

```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```

Inspecione todos os caminhos para o mesmo inode:<sup>[[9]](#references)</sup>

```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```

O abuso não está em um hardlink alterar permissões. O abuso está na confusão de caminhos: um inode privilegiado pode ser acessado por um nome que defensores ou scripts não esperam.<sup>[[9]](#references)</sup> Para conhecer melhor o fluxo de trabalho com inodes e hardlinks, consulte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notas de defesa

- Mantenha os binários SUID mínimos, auditados e gerenciados por pacotes sempre que possível.
- Evite entradas `RPATH`/`RUNPATH` que apontem para diretórios graváveis ou gerenciados por aplicações.<sup>[[1]](#references)[[8]](#references)</sup>
- Mantenha os diretórios de bibliotecas sob propriedade do root e não graváveis por usuários comuns.<sup>[[8]](#references)</sup>
- Não preserve `LD_PRELOAD`, `LD_LIBRARY_PATH` ou variáveis semelhantes do loader por meio do sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitore `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e arquivos SUID inesperados.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Revise arquivos SUID com hardlinks e investigue wrappers SUID personalizados fora dos caminhos padrão do sistema.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — página do manual do Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — página do manual do Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — página do manual do Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Atributos comuns (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — página do manual do Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Fortalecimento do linker dinâmico (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
- [11] [chroot(2) — página do manual do Linux](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [12] [proc_pid_fd(5) — página do manual do Linux](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
{{#include ../../banners/hacktricks-training.md}}

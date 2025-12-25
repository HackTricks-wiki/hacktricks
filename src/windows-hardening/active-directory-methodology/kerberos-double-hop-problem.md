# Problema de Double Hop do Kerberos

{{#include ../../banners/hacktricks-training.md}}


## Introdução

O problema de "Double Hop" do Kerberos aparece quando um atacante tenta usar **autenticação Kerberos através de dois** **saltos**, por exemplo usando **PowerShell**/**WinRM**.

Quando uma **autenticação** ocorre via **Kerberos**, as **credenciais** **não** são armazenadas em **memória.** Portanto, se você executar mimikatz você **não encontrará credenciais** do usuário na máquina mesmo que ele esteja executando processos.

Isto ocorre porque, ao conectar com Kerberos, estes são os passos:

1. User1 fornece credenciais e o **controlador de domínio** retorna um Kerberos **TGT** para o User1.
2. User1 usa o **TGT** para solicitar um **service ticket** para **conectar-se** ao Server1.
3. User1 **conecta-se** ao **Server1** e fornece o **service ticket**.
4. **Server1** **não** tem as **credenciais** do User1 em cache nem o **TGT** do User1. Portanto, quando o User1 a partir do Server1 tenta fazer login em um segundo servidor, ele **não consegue autenticar-se**.

### Unconstrained Delegation

Se a **unconstrained delegation** estiver habilitada no PC, isso não acontecerá, pois o **Server** receberá um **TGT** de cada usuário que o acessar. Além disso, se a unconstrained delegation for usada, você provavelmente poderá **comprometer o controlador de domínio** por meio dela.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Outra forma de evitar esse problema, que é [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), é o **Credential Security Support Provider**. Da Microsoft:

> A autenticação CredSSP delega as credenciais do usuário do computador local para um computador remoto. Essa prática aumenta o risco de segurança da operação remota. Se o computador remoto for comprometido, quando as credenciais forem passadas para ele, as credenciais podem ser usadas para controlar a sessão de rede.

É altamente recomendado que o **CredSSP** seja desativado em sistemas de produção, redes sensíveis e ambientes semelhantes devido a preocupações de segurança. Para determinar se o **CredSSP** está habilitado, o comando `Get-WSManCredSSP` pode ser executado. Esse comando permite a **verificação do status do CredSSP** e pode até ser executado remotamente, desde que o **WinRM** esteja habilitado.
```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
### Remote Credential Guard (RCG)

**Remote Credential Guard** mantém o TGT do usuário na estação de origem enquanto permite que a sessão RDP solicite novos tickets de serviço Kerberos no próximo salto.

Habilite **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** e selecione **Require Remote Credential Guard**, depois conecte com `mstsc.exe /remoteGuard /v:server1` em vez de recorrer ao CredSSP.

A Microsoft quebrou o RCG para acesso multi-hop no Windows 11 22H2+ até os **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Atualize o cliente e o servidor intermediário ou o segundo salto ainda irá falhar. Verificação rápida de hotfix:
```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```
Com essas builds instaladas, o RDP hop pode satisfazer os Kerberos challenges a jusante sem expor segredos reutilizáveis no primeiro servidor.

## Soluções alternativas

### Invoke Command

Para resolver o problema do double hop, é apresentado um método que envolve um `Invoke-Command` aninhado. Isso não resolve o problema diretamente, mas oferece uma solução alternativa sem precisar de configurações especiais. A abordagem permite executar um comando (`hostname`) em um servidor secundário através de um comando PowerShell executado a partir da máquina atacante inicial ou por meio de uma PS-Session previamente estabelecida com o primeiro servidor. Veja como é feito:
```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Como alternativa, é sugerido estabelecer uma PS-Session com o primeiro servidor e executar o `Invoke-Command` usando `$cred` para centralizar tarefas.

### Registrar Configuração de PSSession

Uma solução para contornar o problema double hop envolve usar `Register-PSSessionConfiguration` com `Enter-PSSession`. Este método requer uma abordagem diferente do `evil-winrm` e permite uma sessão que não sofre da limitação do double hop.
```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
klist
```
### PortForwarding

Para administradores locais em um alvo intermediário, port forwarding permite que requisições sejam enviadas para um servidor final. Usando `netsh`, é possível adicionar uma regra de port forwarding, além de uma regra do firewall do Windows para permitir a porta encaminhada.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` pode ser usado para encaminhar requisições WinRM, potencialmente como uma opção menos detectável se o monitoramento de PowerShell for uma preocupação. O comando abaixo demonstra seu uso:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

Instalar o OpenSSH no primeiro servidor possibilita uma solução alternativa para o problema do double-hop, particularmente útil em cenários de jump box. Este método exige instalação via CLI e configuração do OpenSSH for Windows. Quando configurado para Password Authentication, isso permite que o servidor intermediário obtenha um TGT em nome do usuário.

#### OpenSSH Installation Steps

1. Baixe e mova o zip da release mais recente do OpenSSH para o servidor alvo.
2. Descompacte e execute o script `Install-sshd.ps1`.
3. Adicione uma regra de firewall para abrir a porta 22 e verifique se os serviços SSH estão em execução.

Para resolver erros `Connection reset`, pode ser necessário atualizar as permissões para permitir que Everyone tenha acesso de leitura e execução no diretório do OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
### LSA Whisperer CacheLogon (Avançado)

**LSA Whisperer** (2024) expõe a chamada de package `msv1_0!CacheLogon` para que você possa semear um *logon de rede* existente com um NT hash conhecido em vez de criar uma nova sessão com `LogonUser`. Ao injetar o hash na sessão de logon que o WinRM/PowerShell já abriu no hop #1, esse host pode autenticar-se no hop #2 sem armazenar credenciais explícitas ou gerar eventos 4624 extras.

1. Obtenha execução de código dentro do LSASS (por exemplo, desative/abuse PPL ou execute em uma VM de laboratório que você controle).
2. Enumere as sessões de logon (ex.: `lsa.exe sessions`) e capture o LUID correspondente ao seu contexto de acesso remoto.
3. Pré-calcule o NT hash e alimente-o para `CacheLogon`, depois limpe-o quando terminar.
```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```
Após semear o cache, execute novamente `Invoke-Command`/`New-PSSession` a partir do hop #1: o LSASS reutilizará o hash injetado para satisfazer os desafios Kerberos/NTLM para o segundo hop, contornando elegantemente a restrição de double hop. O trade-off é telemetria mais pesada (execução de código no LSASS), então mantenha isso para ambientes de alta fricção onde CredSSP/RCG são proibidos.

## Referências

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}

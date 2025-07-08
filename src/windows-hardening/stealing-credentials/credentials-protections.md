# Windows Credentials Protections

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Il protocollo [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), introdotto con Windows XP, è progettato per l'autenticazione tramite il protocollo HTTP ed è **abilitato per impostazione predefinita su Windows XP fino a Windows 8.0 e Windows Server 2003 fino a Windows Server 2012**. Questa impostazione predefinita comporta **l'archiviazione delle password in chiaro in LSASS** (Local Security Authority Subsystem Service). Un attaccante può utilizzare Mimikatz per **estrarre queste credenziali** eseguendo:
```bash
sekurlsa::wdigest
```
Per **disattivare o attivare questa funzione**, le chiavi di registro _**UseLogonCredential**_ e _**Negotiate**_ all'interno di _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ devono essere impostate su "1". Se queste chiavi sono **assenti o impostate su "0"**, WDigest è **disabilitato**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Protezione LSA (processi protetti PP e PPL)

**Processo Protetto (PP)** e **Processo Protetto Leggero (PPL)** sono **protezioni a livello di kernel di Windows** progettate per prevenire accessi non autorizzati a processi sensibili come **LSASS**. Introdotto in **Windows Vista**, il **modello PP** è stato originariamente creato per l'applicazione del **DRM** e consentiva solo ai binari firmati con un **certificato media speciale** di essere protetti. Un processo contrassegnato come **PP** può essere accessibile solo da altri processi che sono **anch'essi PP** e hanno un **livello di protezione uguale o superiore**, e anche in tal caso, **solo con diritti di accesso limitati** a meno che non sia specificamente consentito.

**PPL**, introdotto in **Windows 8.1**, è una versione più flessibile di PP. Consente **casi d'uso più ampi** (ad es., LSASS, Defender) introducendo **"livelli di protezione"** basati sul campo **EKU (Enhanced Key Usage)** della **firma digitale**. Il livello di protezione è memorizzato nel campo `EPROCESS.Protection`, che è una struttura `PS_PROTECTION` con:
- **Tipo** (`Protected` o `ProtectedLight`)
- **Firmatario** (ad es., `WinTcb`, `Lsa`, `Antimalware`, ecc.)

Questa struttura è compressa in un singolo byte e determina **chi può accedere a chi**:
- **Valori di firmatario più alti possono accedere a quelli più bassi**
- **I PPL non possono accedere ai PP**
- **I processi non protetti non possono accedere a nessun PPL/PP**

### Cosa devi sapere da una prospettiva offensiva

- Quando **LSASS viene eseguito come PPL**, i tentativi di aprirlo utilizzando `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` da un contesto admin normale **falliscono con `0x5 (Access Denied)`**, anche se `SeDebugPrivilege` è abilitato.
- Puoi **controllare il livello di protezione di LSASS** utilizzando strumenti come Process Hacker o programmaticamente leggendo il valore `EPROCESS.Protection`.
- LSASS avrà tipicamente `PsProtectedSignerLsa-Light` (`0x41`), che può essere accessibile **solo da processi firmati con un firmatario di livello superiore**, come `WinTcb` (`0x61` o `0x62`).
- PPL è una **restrizione solo per Userland**; **il codice a livello di kernel può aggirarla completamente**.
- Il fatto che LSASS sia PPL non **preclude il dumping delle credenziali se puoi eseguire shellcode del kernel** o **sfruttare un processo con privilegi elevati con accesso appropriato**.
- **Impostare o rimuovere PPL** richiede un riavvio o **impostazioni di Secure Boot/UEFI**, che possono mantenere l'impostazione PPL anche dopo che le modifiche al registro sono state annullate.

**Opzioni per aggirare le protezioni PPL:**

Se desideri eseguire il dump di LSASS nonostante PPL, hai 3 opzioni principali:
1. **Utilizza un driver del kernel firmato (ad es., Mimikatz + mimidrv.sys)** per **rimuovere il flag di protezione di LSASS**:

![](../../images/mimidrv.png)

2. **Porta il tuo driver vulnerabile (BYOVD)** per eseguire codice del kernel personalizzato e disabilitare la protezione. Strumenti come **PPLKiller**, **gdrv-loader** o **kdmapper** rendono questo fattibile.
3. **Ruba un handle LSASS esistente** da un altro processo che lo ha aperto (ad es., un processo AV), quindi **duplicalo** nel tuo processo. Questa è la base della tecnica `pypykatz live lsa --method handledup`.
4. **Abusa di qualche processo privilegiato** che ti permetterà di caricare codice arbitrario nel suo spazio di indirizzamento o all'interno di un altro processo privilegiato, aggirando effettivamente le restrizioni PPL. Puoi controllare un esempio di questo in [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) o [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Controlla lo stato attuale della protezione LSA (PPL/PP) per LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Quando esegui **`mimikatz privilege::debug sekurlsa::logonpasswords`** probabilmente fallirà con il codice di errore `0x00000005` a causa di questo.

- Per ulteriori informazioni su questo controlla [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, una funzionalità esclusiva per **Windows 10 (edizioni Enterprise ed Education)**, migliora la sicurezza delle credenziali della macchina utilizzando **Virtual Secure Mode (VSM)** e **Virtualization Based Security (VBS)**. Sfrutta le estensioni di virtualizzazione della CPU per isolare i processi chiave all'interno di uno spazio di memoria protetto, lontano dalla portata del sistema operativo principale. Questa isolamento garantisce che anche il kernel non possa accedere alla memoria in VSM, proteggendo efficacemente le credenziali da attacchi come **pass-the-hash**. L'**Autorità di Sicurezza Locale (LSA)** opera all'interno di questo ambiente sicuro come un trustlet, mentre il processo **LSASS** nel sistema operativo principale funge semplicemente da comunicatore con l'LSA di VSM.

Per impostazione predefinita, **Credential Guard** non è attivo e richiede attivazione manuale all'interno di un'organizzazione. È fondamentale per migliorare la sicurezza contro strumenti come **Mimikatz**, che sono ostacolati nella loro capacità di estrarre credenziali. Tuttavia, le vulnerabilità possono ancora essere sfruttate attraverso l'aggiunta di **Security Support Providers (SSP)** personalizzati per catturare le credenziali in chiaro durante i tentativi di accesso.

Per verificare lo stato di attivazione di **Credential Guard**, è possibile ispezionare la chiave di registro _**LsaCfgFlags**_ sotto _**HKLM\System\CurrentControlSet\Control\LSA**_. Un valore di "**1**" indica attivazione con **UEFI lock**, "**2**" senza blocco, e "**0**" denota che non è abilitato. Questo controllo del registro, sebbene sia un forte indicatore, non è l'unico passo per abilitare Credential Guard. Sono disponibili online indicazioni dettagliate e uno script PowerShell per abilitare questa funzionalità.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Per una comprensione completa e istruzioni su come abilitare **Credential Guard** in Windows 10 e la sua attivazione automatica nei sistemi compatibili di **Windows 11 Enterprise e Education (versione 22H2)**, visita [la documentazione di Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Ulteriori dettagli sull'implementazione di SSP personalizzati per la cattura delle credenziali sono forniti [in questa guida](../active-directory-methodology/custom-ssp.md).

## Modalità RDP RestrictedAdmin

**Windows 8.1 e Windows Server 2012 R2** hanno introdotto diverse nuove funzionalità di sicurezza, inclusa la _**modalità Restricted Admin per RDP**_. Questa modalità è stata progettata per migliorare la sicurezza mitigando i rischi associati agli attacchi di [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradizionalmente, quando ci si connette a un computer remoto tramite RDP, le proprie credenziali vengono memorizzate sulla macchina di destinazione. Questo rappresenta un rischio significativo per la sicurezza, specialmente quando si utilizzano account con privilegi elevati. Tuttavia, con l'introduzione della _**modalità Restricted Admin**_, questo rischio è sostanzialmente ridotto.

Quando si avvia una connessione RDP utilizzando il comando **mstsc.exe /RestrictedAdmin**, l'autenticazione al computer remoto viene eseguita senza memorizzare le proprie credenziali su di esso. Questo approccio garantisce che, in caso di infezione da malware o se un utente malintenzionato ottiene accesso al server remoto, le proprie credenziali non siano compromesse, poiché non sono memorizzate sul server.

È importante notare che in **modalità Restricted Admin**, i tentativi di accesso alle risorse di rete dalla sessione RDP non utilizzeranno le proprie credenziali personali; invece, verrà utilizzata l'**identità della macchina**.

Questa funzionalità segna un passo significativo avanti nella sicurezza delle connessioni desktop remote e nella protezione delle informazioni sensibili da esposizioni in caso di violazione della sicurezza.

![](../../images/RAM.png)

Per ulteriori informazioni dettagliate visita [questa risorsa](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Credenziali memorizzate

Windows protegge le **credenziali di dominio** attraverso l'**Autorità di Sicurezza Locale (LSA)**, supportando i processi di accesso con protocolli di sicurezza come **Kerberos** e **NTLM**. Una caratteristica chiave di Windows è la sua capacità di memorizzare in cache i **ultimi dieci accessi al dominio** per garantire che gli utenti possano comunque accedere ai propri computer anche se il **controller di dominio è offline**—un vantaggio per gli utenti di laptop spesso lontani dalla rete della propria azienda.

Il numero di accessi memorizzati in cache è regolabile tramite una specifica **chiave di registro o policy di gruppo**. Per visualizzare o modificare questa impostazione, viene utilizzato il seguente comando:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
L'accesso a queste credenziali memorizzate nella cache è strettamente controllato, con solo l'account **SYSTEM** che ha i permessi necessari per visualizzarle. Gli amministratori che necessitano di accedere a queste informazioni devono farlo con i privilegi dell'utente SYSTEM. Le credenziali sono memorizzate in: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** può essere utilizzato per estrarre queste credenziali memorizzate nella cache utilizzando il comando `lsadump::cache`.

Per ulteriori dettagli, la [fonte](http://juggernaut.wikidot.com/cached-credentials) originale fornisce informazioni complete.

## Utenti Protetti

L'appartenenza al **gruppo Utenti Protetti** introduce diversi miglioramenti della sicurezza per gli utenti, garantendo livelli più elevati di protezione contro il furto e l'uso improprio delle credenziali:

- **Delegazione delle Credenziali (CredSSP)**: Anche se l'impostazione della Group Policy per **Consenti la delega delle credenziali predefinite** è abilitata, le credenziali in testo chiaro degli Utenti Protetti non verranno memorizzate nella cache.
- **Windows Digest**: A partire da **Windows 8.1 e Windows Server 2012 R2**, il sistema non memorizzerà nella cache le credenziali in testo chiaro degli Utenti Protetti, indipendentemente dallo stato di Windows Digest.
- **NTLM**: Il sistema non memorizzerà nella cache le credenziali in testo chiaro degli Utenti Protetti o le funzioni unidirezionali NT (NTOWF).
- **Kerberos**: Per gli Utenti Protetti, l'autenticazione Kerberos non genererà chiavi **DES** o **RC4**, né memorizzerà nella cache credenziali in testo chiaro o chiavi a lungo termine oltre l'acquisizione iniziale del Ticket-Granting Ticket (TGT).
- **Accesso Offline**: Gli Utenti Protetti non avranno un verificatore memorizzato nella cache creato all'accesso o sblocco, il che significa che l'accesso offline non è supportato per questi account.

Queste protezioni vengono attivate nel momento in cui un utente, che è membro del **gruppo Utenti Protetti**, accede al dispositivo. Questo garantisce che misure di sicurezza critiche siano in atto per proteggere contro vari metodi di compromissione delle credenziali.

Per informazioni più dettagliate, consultare la [documentazione](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group) ufficiale.

**Tabella da** [**la documentazione**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

{{#include ../../banners/hacktricks-training.md}}

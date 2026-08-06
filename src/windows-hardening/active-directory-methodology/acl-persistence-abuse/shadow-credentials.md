# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#3f17" id="3f17"></a>

**Angalia chapisho la awali kwa [maelezo yote kuhusu technique hii](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Kwa **muhtasari**: ikiwa unaweza kuandika kwenye property ya **msDS-KeyCredentialLink** ya user/computer, unaweza kupata **NT hash ya object hiyo**.<sup>[[1]](#references)</sup>

Katika chapisho hilo, kuna maelezo ya method ya kusanidi **public-private key authentication credentials** ili kupata **Service Ticket** ya kipekee inayojumuisha NTLM hash ya target. Mchakato huu unahusisha NTLM_SUPPLEMENTAL_CREDENTIAL iliyosimbwa kwa njia fiche ndani ya Privilege Attribute Certificate (PAC), ambayo inaweza kufichuliwa.<sup>[[1]](#references)</sup>

### Masharti

Ili kutumia technique hii, masharti fulani lazima yatimizwe:<sup>[[1]](#references)</sup>

- Angalau Windows Server 2016 Domain Controller mmoja anahitajika.
- Domain Controller lazima iwe na server authentication digital certificate iliyosakinishwa.
- Active Directory lazima iwe kwenye Windows Server 2016 Functional Level.
- Account yenye delegated rights za kubadilisha attribute ya msDS-KeyCredentialLink ya target object inahitajika.

## Matumizi mabaya

Matumizi mabaya ya Key Trust kwa computer objects yanajumuisha hatua zaidi ya kupata Ticket Granting Ticket (TGT) na NTLM hash. Chaguo hizo ni pamoja na:<sup>[[1]](#references)</sup>

1. Kuunda **RC4 silver ticket** ili kufanya kazi kama privileged users kwenye host iliyokusudiwa.
2. Kutumia TGT pamoja na **S4U2Self** kwa impersonation ya **privileged users**, huku ikihitaji kubadilishwa kwa Service Ticket ili kuongeza service class kwenye service name.

Faida muhimu ya kutumia vibaya Key Trust ni kwamba inategemea private key iliyoundwa na attacker pekee, hivyo kuepuka delegation kwa accounts zinazoweza kuwa vulnerable na kutohitaji kuunda computer account, ambayo inaweza kuwa vigumu kuiondoa.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Imejengwa juu ya DSInternals na inatoa C# interface kwa ajili ya attack hii. Whisker na counterpart yake ya Python, **pyWhisker**, huwezesha manipulation ya attribute ya `msDS-KeyCredentialLink` ili kupata control ya Active Directory accounts. Tools hizi zinaunga mkono operations mbalimbali kama vile kuongeza, kuorodhesha, kuondoa na kufuta key credentials kutoka kwenye target object.

**Whisker** functions zinajumuisha:

- **Add**: Hutengeneza key pair na kuongeza key credential.
- **List**: Huonyesha key credential entries zote.
- **Remove**: Huondoa key credential iliyobainishwa.
- **Clear**: Hufuta key credentials zote, jambo linaloweza kuvuruga matumizi halali ya WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Inaongeza functionality ya Whisker kwenye **UNIX-based systems**, ikitumia Impacket na PyDSInternals kwa uwezo mpana wa exploitation, ikijumuisha kuorodhesha, kuongeza na kuondoa KeyCredentials, pamoja na kuzi-import na kuzi-export katika muundo wa JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray inalenga **kutumia vibaya ruhusa za GenericWrite/GenericAll ambazo makundi mapana ya watumiaji yanaweza kuwa nazo kwenye vitu vya kikoa** ili kutumia ShadowCredentials kwa upana. Inahusisha kuingia kwenye kikoa, kuthibitisha kiwango cha utendaji cha kikoa, kuorodhesha vitu vya kikoa, na kujaribu kuongeza KeyCredentials kwa ajili ya upatikanaji wa TGT na ufichuaji wa NT hash. Chaguo za usafishaji na mbinu za exploitation za kujirudia huongeza matumizi yake.

## Marejeo

- [1] [Shadow Credentials: Abusing Key Trust Account Mapping for Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool for taking over AD accounts by manipulating msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool to spray Shadow Credentials across a domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python version of the Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}

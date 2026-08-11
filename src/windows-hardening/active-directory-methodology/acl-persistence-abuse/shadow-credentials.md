# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#3f17" id="3f17"></a>

**Angalia chapisho la awali kwa [maelezo yote kuhusu technique hii](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Kwa muhtasari, udhibiti wa **`msDS-KeyCredentialLink`** ya user au computer unaweza kumruhusu attacker kuongeza key credential, ku-authenticate kama object hiyo kwa kutumia PKINIT, na—wakati KDC na account zinaunga mkono flows zinazohitajika—kutumia ticket inayopatikana pamoja na `S4U2Self`/user-to-user ili kurejesha NT hash ya object hiyo.<sup>[[1]](#references)</sup>

Katika chapisho hilo, kuna method iliyoelezwa ya kusanidi **public-private key authentication credentials** ili kupata **Service Ticket** ya kipekee inayojumuisha NTLM hash ya target. Mchakato huu unahusisha NTLM_SUPPLEMENTAL_CREDENTIAL iliyosimbwa kwa njia fiche ndani ya Privilege Attribute Certificate (PAC), ambayo inaweza kufasiriwa.<sup>[[1]](#references)</sup>

### Mahitaji

Ili kutumia technique hii, masharti fulani lazima yatimizwe:<sup>[[1]](#references)</sup>

- Angalau Windows Server 2016 Domain Controller mmoja anahitajika.
- Domain Controller lazima iwe na server authentication digital certificate iliyosakinishwa.
- Directory schema lazima iwe na `msDS-KeyCredentialLink`; Windows Server 2016 au DC mpya zaidi pamoja na certificate inayoweza kutumiwa na PKINIT kwenye KDC ndizo platform requirements za kiutendaji zilizoelezwa na utafiti. Thibitisha mchanganyiko wa schema/DC wa domain badala ya kudhani kuwa label ya domain functional level pekee ndiyo huamua exploitability.
- Account yenye delegated rights za kurekebisha attribute ya msDS-KeyCredentialLink ya target object inahitajika.

## Matumizi mabaya

Matumizi mabaya ya Key Trust kwa computer objects yanajumuisha hatua zaidi ya kupata Ticket Granting Ticket (TGT) na NTLM hash. Chaguo hizo ni pamoja na:<sup>[[1]](#references)</sup>

1. Kuunda **RC4 silver ticket** ili kutenda kama privileged users kwenye host iliyokusudiwa.
2. Kutumia TGT pamoja na **S4U2Self** kwa impersonation ya **privileged users**, jambo linalohitaji mabadiliko kwenye Service Ticket ili kuongeza service class kwenye service name.

Faida kubwa ya Key Trust abuse ni kwamba inabaki kwenye private key iliyotengenezwa na attacker, hivyo kuepuka delegation kwa accounts zinazoweza kuwa vulnerable na kutohitaji kuunda computer account, ambayo inaweza kuwa vigumu kuiondoa.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker hutumia DSInternals ku-manipulate `msDS-KeyCredentialLink` kutoka C#. Whisker na counterpart yake ya Python, **pyWhisker**, zinaunga mkono kuongeza, kuorodhesha, kuondoa na kufuta key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker** functions ni pamoja na:

- **Add**: Hutengeneza key pair na kuongeza key credential.
- **List**: Huonyesha entries zote za key credential.
- **Remove**: Huondoa key credential iliyobainishwa.
- **Clear**: Hufuta key credentials zote, jambo linaloweza kuvuruga matumizi halali ya WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker huleta workflow kwenye **UNIX-like systems** kwa kutumia Impacket na PyDSInternals, ikijumuisha operations za list/add/remove na import/export ya JSON.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray huorodhesha vitu vya domain ambavyo operator ana haki juu yake kama vile `GenericWrite`/`GenericAll`, hujaribu kuongeza key credentials kwa upana, na inajumuisha cleanup/recursive modes. Broad spraying inaweza kuvuruga na kuonekana wazi; tumia targets zilizobainishwa na hifadhi kila DeviceID iliyoongezwa kwa ajili ya kuiondoa kwa usahihi.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Kutumia vibaya Key Trust Account Mapping kwa Account Takeover](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool ya kuchukua udhibiti wa AD accounts kwa kubadilisha msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool ya kusambaza Shadow Credentials kwenye domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Toleo la Python la Shadow Credentials tool](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}

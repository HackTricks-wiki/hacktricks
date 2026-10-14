# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Utangulizi <a href="#3f17" id="3f17"></a>

**Angalia chapisho la awali kwa [all the information about this technique](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Kwa muhtasari, kudhibiti **`msDS-KeyCredentialLink`** ya mtumiaji au kompyuta kunaweza kumwezesha mshambuliaji kuongeza key credential, kuthibitishwa kama kitu hicho kwa kutumia PKINIT, na—ikiwa KDC na akaunti zinaunga mkono mtiririko unaohitajika—kutumia tiketi inayopatikana pamoja na `S4U2Self`/user-to-user ili kurejesha NT hash ya kitu hicho.<sup>[[1]](#references)</sup>

Katika chapisho hilo, mbinu inaelezwa ya kusanidi **public-private key authentication credentials** ili kupata **Service Ticket** ya kipekee inayojumuisha NTLM hash ya lengwa. Mchakato huu unahusisha NTLM_SUPPLEMENTAL_CREDENTIAL iliyosimbwa kwa njia fiche ndani ya Privilege Attribute Certificate (PAC), ambayo inaweza kufumbuliwa.<sup>[[1]](#references)</sup>

### Mahitaji

Ili kutumia mbinu hii, masharti fulani lazima yatimizwe:<sup>[[1]](#references)</sup>

- Angalau Domain Controller moja ya Windows Server 2016 inahitajika.
- Domain Controller lazima iwe na digital certificate ya server authentication iliyosakinishwa.
- Schema ya directory lazima iwe na `msDS-KeyCredentialLink`; DC ya Windows Server 2016 au mpya zaidi na certificate ya KDC inayoweza kutumia PKINIT ndizo mahitaji ya vitendo ya mfumo yaliyoelezwa kwenye utafiti. Hakikisha mchanganyiko wa schema/DC wa domain badala ya kudhani kuwa lebo ya kiwango cha utendaji cha domain ndiyo pekee huamua kama udhaifu unaweza kutumiwa.
- Akaunti yenye haki zilizokabidhiwa za kurekebisha sifa ya msDS-KeyCredentialLink ya kitu lengwa inahitajika.

## Matumizi Mabaya

Matumizi mabaya ya Key Trust kwa vitu vya kompyuta yanajumuisha hatua zaidi ya kupata Ticket Granting Ticket (TGT) na NTLM hash. Chaguo ni pamoja na:<sup>[[1]](#references)</sup>

1. Kuunda **RC4 silver ticket** ili kutenda kama watumiaji wenye upendeleo kwenye host iliyokusudiwa.
2. Kutumia TGT pamoja na **S4U2Self** kujifanya watumiaji **wenye upendeleo**, jambo linalohitaji kurekebisha Service Ticket ili kuongeza service class kwenye jina la huduma.

Faida kubwa ya kutumia vibaya Key Trust ni kwamba kunategemea private key iliyozalishwa na mshambuliaji pekee, hivyo kuepuka delegation kwa akaunti zinazoweza kuwa na udhaifu na kuondoa hitaji la kuunda akaunti ya kompyuta, ambayo inaweza kuwa vigumu kuiondoa.<sup>[[1]](#references)</sup>

## Zana

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker hutumia DSInternals kurekebisha `msDS-KeyCredentialLink` kutoka C#. Whisker na mwenzake wa Python **pyWhisker** wanaunga mkono kuongeza, kuorodhesha, kuondoa na kufuta kabisa key credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Kazi za **Whisker** ni pamoja na:

- **Add**: Hutengeneza key pair na kuongeza key credential.
- **List**: Huonyesha maingizo yote ya key credential.
- **Remove**: Hufuta key credential iliyobainishwa.
- **Clear**: Hufuta key credentials zote, jambo linaloweza kuvuruga matumizi halali ya WHfB.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker huleta mtiririko huu wa kazi kwenye **UNIX-like systems** kwa kutumia Impacket na PyDSInternals, ikijumuisha shughuli za list/add/remove na JSON import/export.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray huhesabu objects za domain ambazo operator ana haki kama `GenericWrite`/`GenericAll`, hujaribu kuongeza key credentials kwa upana, na ina modes za cleanup/recursive. Broad spraying inaweza kusababisha usumbufu na kuvutia macho; tumia targets mahususi na hifadhi kila DeviceID iliyoongezwa ili kuiondoa kwa usahihi.<sup>[[3]](#references)</sup>

ADWS inaweza kusafirisha uandishi wa key-credential wakati LDAP ya moja kwa moja imechujwa. Tazama [SOAPy ADWS workflow](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Kutumia vibaya ulinganishaji wa akaunti kwa Key Trust ili kutwaa akaunti](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Zana ya kutwaa akaunti za AD kwa kuchezea msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Zana ya kusambaza Shadow Credentials katika domain](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Toleo la Python la zana ya Shadow Credentials](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}

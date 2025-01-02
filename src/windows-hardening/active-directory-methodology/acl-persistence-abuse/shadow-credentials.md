# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#3f17" id="3f17"></a>

**Angalia chapisho la asili kwa [maelezo yote kuhusu mbinu hii](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**

Kama **muhtasari**: ikiwa unaweza kuandika kwenye mali ya **msDS-KeyCredentialLink** ya mtumiaji/kompyuta, unaweza kupata **NT hash ya kitu hicho**.

Katika chapisho, mbinu imeelezewa kwa kuanzisha **ithibitisho la ufunguo wa umma-binafsi** ili kupata **Tiketi ya Huduma** ya kipekee inayojumuisha NTLM hash ya lengo. Mchakato huu unahusisha NTLM_SUPPLEMENTAL_CREDENTIAL iliyosimbwa ndani ya Cheti cha Sifa za Haki (PAC), ambacho kinaweza kufichuliwa.

### Requirements

Ili kutumia mbinu hii, masharti fulani lazima yatekelezwe:

- Inahitajika angalau Kituo kimoja cha Windows Server 2016 Domain.
- Kituo cha Domain lazima kiwe na cheti cha kidijitali cha uthibitishaji wa seva kilichosakinishwa.
- Active Directory lazima iwe katika Kiwango cha Kazi cha Windows Server 2016.
- Inahitajika akaunti yenye haki za kuhamasisha kubadilisha sifa ya msDS-KeyCredentialLink ya kitu kilichokusudiwa.

## Abuse

Kunyanyaswa kwa Key Trust kwa vitu vya kompyuta kunajumuisha hatua zaidi ya kupata Tiketi ya Kutoa Tiketi (TGT) na NTLM hash. Chaguzi ni pamoja na:

1. Kuunda **tiketi ya fedha ya RC4** ili kutenda kama watumiaji wenye mamlaka kwenye mwenyeji anayokusudiwa.
2. Kutumia TGT na **S4U2Self** kwa ajili ya kujifanya **watumiaji wenye mamlaka**, ikihitaji mabadiliko ya Tiketi ya Huduma ili kuongeza darasa la huduma kwenye jina la huduma.

Faida kubwa ya kunyanyaswa kwa Key Trust ni ukomo wake kwa ufunguo wa binafsi ulioanzishwa na mshambuliaji, kuepusha ugawaji kwa akaunti zinazoweza kuwa hatarini na kutohitaji kuunda akaunti ya kompyuta, ambayo inaweza kuwa ngumu kuondoa.

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Inategemea DSInternals ikitoa kiolesura cha C# kwa shambulio hili. Whisker na sawa yake ya Python, **pyWhisker**, zinawezesha kudhibiti sifa ya `msDS-KeyCredentialLink` ili kupata udhibiti wa akaunti za Active Directory. Zana hizi zinasaidia operesheni mbalimbali kama kuongeza, kuorodhesha, kuondoa, na kufuta ithibitisho za ufunguo kutoka kwa kitu kilichokusudiwa.

**Whisker** inafanya kazi zifuatazo:

- **Add**: Inaunda jozi ya ufunguo na kuongeza ithibitisho la ufunguo.
- **List**: Inaonyesha kila kipengee cha ithibitisho la ufunguo.
- **Remove**: Inafuta ithibitisho maalum la ufunguo.
- **Clear**: Inafuta ithibitisho zote za ufunguo, huenda ikaharibu matumizi halali ya WHfB.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Inapanua kazi za Whisker kwa **mifumo ya UNIX**, ikitumia Impacket na PyDSInternals kwa uwezo wa kina wa unyakuzi, ikiwa ni pamoja na orodha, kuongeza, na kuondoa KeyCredentials, pamoja na kuagiza na kusafirisha katika muundo wa JSON.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray inalenga **kufaidika na ruhusa za GenericWrite/GenericAll ambazo vikundi vya watumiaji vinaweza kuwa navyo juu ya vitu vya kikoa** ili kutumia ShadowCredentials kwa upana. Inahusisha kuingia kwenye kikoa, kuthibitisha kiwango cha kazi cha kikoa, kuorodhesha vitu vya kikoa, na kujaribu kuongeza KeyCredentials kwa ajili ya kupata TGT na kufichua NT hash. Chaguzi za kusafisha na mbinu za unyakuzi wa kurudiwa zinaboresha matumizi yake.

## References

- [https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [https://github.com/eladshamir/Whisker](https://github.com/eladshamir/Whisker)
- [https://github.com/Dec0ne/ShadowSpray/](https://github.com/Dec0ne/ShadowSpray/)
- [https://github.com/ShutdownRepo/pywhisker](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}

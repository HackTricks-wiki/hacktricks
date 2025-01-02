# ACLs - DACLs/SACLs/ACEs

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) kujenga na **kujiendesha kiotomatiki** kwa urahisi kazi zinazotolewa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

{{#include ../../banners/hacktricks-training.md}}

## **Orodha ya Udhibiti wa Ufikiaji (ACL)**

Orodha ya Udhibiti wa Ufikiaji (ACL) inajumuisha seti iliyopangwa ya Kuingilia Udhibiti wa Ufikiaji (ACEs) ambazo zinaelekeza ulinzi wa kitu na mali zake. Kwa msingi, ACL inafafanua ni vitendo vipi na ni wakala gani wa usalama (watumiaji au vikundi) vinavyoruhusiwa au kukataliwa kwenye kitu fulani.

Kuna aina mbili za ACLs:

- **Orodha ya Udhibiti wa Ufikiaji wa Hiari (DACL):** Inabainisha ni watumiaji na vikundi gani wana au hawana ufikiaji wa kitu.
- **Orodha ya Udhibiti wa Ufikiaji wa Mfumo (SACL):** Inasimamia ukaguzi wa majaribio ya ufikiaji wa kitu.

Mchakato wa kufikia faili unahusisha mfumo kuangalia descriptor ya usalama wa kitu dhidi ya token ya ufikiaji wa mtumiaji ili kubaini kama ufikiaji unapaswa kuruhusiwa na kiwango cha ufikiaji huo, kulingana na ACEs.

### **Vipengele Muhimu**

- **DACL:** Inajumuisha ACEs ambazo zinatoa au kukataa ruhusa za ufikiaji kwa watumiaji na vikundi kwa kitu. Kimsingi, ndiyo ACL kuu inayodhibiti haki za ufikiaji.
- **SACL:** Inatumika kwa ukaguzi wa ufikiaji wa vitu, ambapo ACEs zinaeleza aina za ufikiaji ambazo zinapaswa kurekodiwa katika Kumbukumbu ya Matukio ya Usalama. Hii inaweza kuwa muhimu sana kwa kugundua majaribio yasiyoidhinishwa ya ufikiaji au kutatua matatizo ya ufikiaji.

### **Mwingiliano wa Mfumo na ACLs**

Kila kikao cha mtumiaji kinahusishwa na token ya ufikiaji ambayo ina taarifa za usalama zinazohusiana na kikao hicho, ikiwa ni pamoja na mtumiaji, vitambulisho vya kikundi, na mamlaka. Token hii pia inajumuisha SID ya kuingia ambayo inatambulisha kwa kipekee kikao hicho.

Mamlaka ya Usalama wa Mitaa (LSASS) inashughulikia maombi ya ufikiaji wa vitu kwa kuchunguza DACL kwa ACEs zinazolingana na wakala wa usalama anayejaribu ufikiaji. Ufikiaji unaruhusiwa mara moja ikiwa hakuna ACEs zinazohusiana zinazopatikana. Vinginevyo, LSASS inalinganisha ACEs dhidi ya SID ya wakala wa usalama katika token ya ufikiaji ili kubaini sifa za ufikiaji.

### **Mchakato wa Muhtasari**

- **ACLs:** Zinabainisha ruhusa za ufikiaji kupitia DACLs na sheria za ukaguzi kupitia SACLs.
- **Token ya Ufikiaji:** Inajumuisha taarifa za mtumiaji, kikundi, na mamlaka kwa kikao.
- **Uamuzi wa Ufikiaji:** Unafanywa kwa kulinganisha DACL ACEs na token ya ufikiaji; SACLs zinatumika kwa ukaguzi.

### ACEs

Kuna **aina tatu kuu za Kuingilia Udhibiti wa Ufikiaji (ACEs)**:

- **ACE ya Kukataa Ufikiaji:** ACE hii inakataza kwa wazi ufikiaji wa kitu kwa watumiaji au vikundi maalum (katika DACL).
- **ACE ya Kuruhusu Ufikiaji:** ACE hii inaruhusu kwa wazi ufikiaji wa kitu kwa watumiaji au vikundi maalum (katika DACL).
- **ACE ya Ukaguzi wa Mfumo:** Iko ndani ya Orodha ya Udhibiti wa Ufikiaji wa Mfumo (SACL), ACE hii inawajibika kwa kuzalisha kumbukumbu za ukaguzi wakati wa majaribio ya ufikiaji wa kitu na watumiaji au vikundi. Inarekodi ikiwa ufikiaji uliruhusiwa au kukataliwa na asili ya ufikiaji.

Kila ACE ina **vipengele vinne muhimu**:

1. **Kitambulisho cha Usalama (SID)** cha mtumiaji au kikundi (au jina lao la msingi katika uwakilishi wa picha).
2. **bendera** inayotambulisha aina ya ACE (ufikiaji umekataliwa, umekubaliwa, au ukaguzi wa mfumo).
3. **bendera za urithi** zinazobainisha ikiwa vitu vya watoto vinaweza kurithi ACE kutoka kwa mzazi wao.
4. [**mask ya ufikiaji**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), thamani ya bit 32 inayobainisha haki zilizotolewa za kitu.

Uamuzi wa ufikiaji unafanywa kwa kuchunguza kwa mfululizo kila ACE hadi:

- **ACE ya Kukataa Ufikiaji** inakataza kwa wazi haki zilizohitajika kwa mtunza mali aliyeainishwa katika token ya ufikiaji.
- **ACE za Kuruhusu Ufikiaji** zinatoa kwa wazi haki zote zilizohitajika kwa mtunza mali katika token ya ufikiaji.
- Baada ya kuangalia ACE zote, ikiwa haki yoyote iliyohitajika **haijaruhusiwa kwa wazi**, ufikiaji unakataliwa **kimya kimya**.

### Mpangilio wa ACEs

Jinsi **ACEs** (sheria zinazosema nani anaweza au hawezi kufikia kitu) zinavyowekwa katika orodha inayoitwa **DACL** ni muhimu sana. Hii ni kwa sababu mara mfumo unaporuhusu au kukataa ufikiaji kulingana na sheria hizi, unakoma kuangalia zingine.

Kuna njia bora ya kupanga ACEs hizi, na inaitwa **"mpangilio wa kanuni."** Njia hii inasaidia kuhakikisha kila kitu kinafanya kazi kwa urahisi na kwa haki. Hapa kuna jinsi inavyofanya kazi kwa mifumo kama **Windows 2000** na **Windows Server 2003**:

- Kwanza, weka sheria zote ambazo zimeandikwa **haswa kwa kitu hiki** kabla ya zile zinazotoka mahali pengine, kama folda ya mzazi.
- Katika sheria hizo maalum, weka zile zinazosema **"hapana" (kukataa)** kabla ya zile zinazosema **"ndiyo" (kuruhusu)**.
- Kwa sheria zinazotoka mahali pengine, anza na zile kutoka **chanzo cha karibu**, kama mzazi, kisha rudi nyuma kutoka hapo. Tena, weka **"hapana"** kabla ya **"ndiyo."**

Mpangilio huu unasaidia kwa njia mbili kubwa:

- Inahakikisha kwamba ikiwa kuna **"hapana"** maalum, inaheshimiwa, bila kujali sheria nyingine za **"ndiyo"** zilizopo.
- Inamruhusu mmiliki wa kitu kuwa na **neno la mwisho** kuhusu nani anayeweza kuingia, kabla ya sheria zozote kutoka folda za mzazi au mbali zaidi kuingia kwenye mchezo.

Kwa kufanya mambo hivi, mmiliki wa faili au folda anaweza kuwa sahihi sana kuhusu nani anayeweza kufikia, kuhakikisha watu sahihi wanaweza kuingia na wale wasiostahili hawawezi.

![](https://www.ntfs.com/images/screenshots/ACEs.gif)

Hivyo, **"mpangilio wa kanuni"** ni kuhusu kuhakikisha sheria za ufikiaji ni wazi na zinafanya kazi vizuri, kuweka sheria maalum kwanza na kupanga kila kitu kwa njia ya busara.

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) kujenga na **kujiendesha kiotomatiki** kwa urahisi kazi zinazotolewa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### Mfano wa GUI

[**Mfano kutoka hapa**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

Hii ni tab ya usalama wa kawaida ya folda ikionyesha ACL, DACL na ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Ikiwa tutabonyeza **Kitufe cha Juu** tutapata chaguzi zaidi kama urithi:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Na ikiwa unongeza au kuhariri Msingi wa Usalama:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Na mwisho tuna SACL katika tab ya Ukaguzi:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Kufafanua Udhibiti wa Ufikiaji kwa Njia Rahisi

Wakati wa kusimamia ufikiaji wa rasilimali, kama folda, tunatumia orodha na sheria zinazojulikana kama Orodha za Udhibiti wa Ufikiaji (ACLs) na Kuingilia Udhibiti wa Ufikiaji (ACEs). Hizi zinaeleza nani anaweza au hawezi kufikia data fulani.

#### Kukataa Ufikiaji kwa Kikundi Maalum

Fikiria una folda inayoitwa Gharama, na unataka kila mtu aifike isipokuwa timu ya masoko. Kwa kuweka sheria vizuri, tunaweza kuhakikisha kwamba timu ya masoko inakataliwa ufikiaji kwa wazi kabla ya kuruhusu wengine wote. Hii inafanywa kwa kuweka sheria ya kukataa ufikiaji kwa timu ya masoko kabla ya sheria inayoruhusu ufikiaji kwa kila mtu.

#### Kuruhusu Ufikiaji kwa Mwanachama Maalum wa Kikundi Kilichokataliwa

Hebu sema Bob, mkurugenzi wa masoko, anahitaji ufikiaji wa folda ya Gharama, ingawa timu ya masoko kwa ujumla haipaswi kuwa na ufikiaji. Tunaweza kuongeza sheria maalum (ACE) kwa Bob inayomruhusu ufikiaji, na kuiweka kabla ya sheria inayokatisha ufikiaji kwa timu ya masoko. Kwa njia hii, Bob anapata ufikiaji licha ya vizuizi vya jumla kwa timu yake.

#### Kuelewa Kuingilia Udhibiti wa Ufikiaji

ACEs ni sheria za kibinafsi katika ACL. Zinazitambulisha watumiaji au vikundi, zinaeleza ni ufikiaji upi unaruhusiwa au kukataliwa, na zinabainisha jinsi sheria hizi zinavyotumika kwa vitu vidogo (urithi). Kuna aina mbili kuu za ACEs:

- **ACEs za Kawaida:** Hizi zinatumika kwa upana, zikihusisha aina zote za vitu au kutofautisha tu kati ya vyombo (kama folda) na visivyo vyombo (kama faili). Kwa mfano, sheria inayoruhusu watumiaji kuona maudhui ya folda lakini si kufikia faili ndani yake.
- **ACEs za Kitu Maalum:** Hizi zinatoa udhibiti wa kina zaidi, kuruhusu sheria kuwekwa kwa aina maalum za vitu au hata mali za kibinafsi ndani ya kitu. Kwa mfano, katika directory ya watumiaji, sheria inaweza kuruhusu mtumiaji kuboresha nambari yake ya simu lakini si masaa yake ya kuingia.

Kila ACE ina taarifa muhimu kama nani sheria inahusiana nayo (kwa kutumia Kitambulisho cha Usalama au SID), ni nini sheria inaruhusu au kukataa (kwa kutumia mask ya ufikiaji), na jinsi inavyorithiwa na vitu vingine.

#### Tofauti Kuu Kati ya Aina za ACE

- **ACEs za Kawaida** zinafaa kwa hali rahisi za udhibiti wa ufikiaji, ambapo sheria moja inatumika kwa vipengele vyote vya kitu au kwa vitu vyote ndani ya chombo.
- **ACEs za Kitu Maalum** zinatumika kwa hali ngumu zaidi, hasa katika mazingira kama Active Directory, ambapo unaweza kuhitaji kudhibiti ufikiaji wa mali maalum za kitu tofauti.

Kwa muhtasari, ACLs na ACEs husaidia kufafanua udhibiti sahihi wa ufikiaji, kuhakikisha kwamba ni watu au vikundi sahihi tu wanaweza kufikia taarifa au rasilimali nyeti, huku wakitoa uwezo wa kubinafsisha haki za ufikiaji hadi kiwango cha mali au aina za vitu binafsi.

### Mpangilio wa Kuingilia Udhibiti wa Ufikiaji

| Uwanja wa ACE | Maelezo                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Aina         | Bendera inayotambulisha aina ya ACE. Windows 2000 na Windows Server 2003 zinasaidia aina sita za ACE: Aina tatu za ACE za kawaida ambazo zimeunganishwa na vitu vyote vinavyoweza kulindwa. Aina tatu za ACE maalum za kitu ambazo zinaweza kutokea kwa vitu vya Active Directory.                                                                                                                                                                                                                                                            |
| Bendera      | Seti ya bendera za bit ambazo zinadhibiti urithi na ukaguzi.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Ukubwa       | Idadi ya bytes za kumbukumbu ambazo zimepewa ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Mask ya ufikiaji | Thamani ya bit 32 ambayo bits zake zinahusiana na haki za ufikiaji kwa kitu. Bits zinaweza kuwekwa ama juu au chini, lakini maana ya kuweka inategemea aina ya ACE. Kwa mfano, ikiwa bit inayohusiana na haki ya kusoma ruhusa imewashwa, na aina ya ACE ni Kukataa, ACE inakataza haki ya kusoma ruhusa za kitu. Ikiwa bit hiyo hiyo imewashwa lakini aina ya ACE ni Kuruhusu, ACE inaruhusu haki ya kusoma ruhusa za kitu. Maelezo zaidi ya mask ya ufikiaji yanaonekana katika jedwali linalofuata. |
| SID          | Inatambulisha mtumiaji au kikundi ambacho ufikiaji wake unadhibitiwa au unakaguliwa na ACE hii.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Mpangilio wa Mask ya Ufikiaji

| Bit (Muktadha) | Maana                            | Maelezo/Mfano                       |
| --------------- | -------------------------------- | ----------------------------------- |
| 0 - 15          | Haki za Ufikiaji Maalum         | Kusoma data, Kutekeleza, Kuongeza data           |
| 16 - 22         | Haki za Ufikiaji za Kawaida     | Kufuta, Kuandika ACL, Kuandika Mmiliki            |
| 23              | Inaweza kufikia ACL ya usalama   |                                       |
| 24 - 27         | Imetengwa                        |                                       |
| 28              | Kawaida ZOTE (Kusoma, Kuandika, Kutekeleza) | Kila kitu kilichopo chini                          |
| 29              | Kawaida Kutekeleza              | Mambo yote muhimu kutekeleza programu |
| 30              | Kawaida Kuandika                | Mambo yote muhimu kuandika kwenye faili   |
| 31              | Kawaida Kusoma                  | Mambo yote muhimu kusoma faili       |

## Marejeo

- [https://www.ntfs.com/ntfs-permissions-acl-use.htm](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [https://secureidentity.se/acl-dacl-sacl-and-the-ace/](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
- [https://www.coopware.in2.info/\_ntfsacl_ht.htm](https://www.coopware.in2.info/_ntfsacl_ht.htm)

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="../../images/image (48).png" alt=""><figcaption></figcaption></figure>

\
Tumia [**Trickest**](https://trickest.com/?utm_source=hacktricks&utm_medium=text&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces) kujenga na **kujiendesha kiotomatiki** kwa urahisi kazi zinazotolewa na zana za jamii **zilizoendelea zaidi** duniani.\
Pata Ufikiaji Leo:

{% embed url="https://trickest.com/?utm_source=hacktricks&utm_medium=banner&utm_campaign=ppc&utm_content=acls-dacls-sacls-aces" %}

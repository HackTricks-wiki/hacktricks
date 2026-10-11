# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) ina seti iliyopangwa ya Access Control Entries (ACEs) zinazoamua ulinzi wa kifaa na sifa zake. Kimsingi, ACL hufafanua ni vitendo gani vinavyoruhusiwa au kukataliwa kwa principals wa usalama (watumiaji au vikundi) kwenye kifaa fulani.

Kuna aina mbili za ACL:

- **Discretionary Access Control List (DACL):** Hubainisha ni watumiaji na vikundi gani vina au havina ruhusa ya kufikia kifaa.
- **System Access Control List (SACL):** Hudhibiti ukaguzi wa majaribio ya kufikia kifaa.

Mchakato wa kufikia faili huhusisha mfumo kulinganisha security descriptor ya kifaa na access token ya mtumiaji ili kubaini kama ufikiaji unapaswa kuruhusiwa na kiwango cha ufikiaji huo, kulingana na ACEs.<sup>[[1]](#references)</sup>

Wakati directory ya mzazi inatoa Full Control lakini faili ya ndani inazuia usomaji, kagua effective DACL, mmiliki na urithi wa **faili ya ndani** kivyake. Kubadilisha DACL ya faili hiyo kunahitaji `WRITE_DAC` kwenye faili au haki husika ya mmiliki; [Microsoft hufafanua `WRITE_DAC`](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights) na [hueleza ufikiaji usiohitaji ruhusa ya ziada wa mmiliki](https://learn.microsoft.com/en-us/windows/win32/secauthz/owner-of-a-new-object). Ruhusa za directory ya mzazi pekee hazithibitishi kwamba faili ya ndani inaweza kusomwa au kwamba DACL yake inaweza kubadilishwa.

### **Vipengele Muhimu**

- **DACL:** Ina ACEs zinazotoa au kukataa ruhusa za ufikiaji kwa watumiaji na vikundi kwenye kifaa. Kimsingi, hii ndiyo ACL kuu inayoamua haki za ufikiaji.
- **SACL:** Hutumika kukagua ufikiaji wa vifaa; ACEs zake hufafanua aina za ufikiaji zitakazoandikwa kwenye Security Event Log. Hii inaweza kusaidia sana kugundua majaribio ya ufikiaji yasiyoidhinishwa au kutatua matatizo ya ufikiaji.<sup>[[1]](#references)</sup>

### **Mwingiliano wa Mfumo na ACLs**

Kila kikao cha mtumiaji huhusishwa na access token yenye maelezo ya usalama yanayohusiana na kikao hicho, yakiwemo utambulisho wa mtumiaji na vikundi, pamoja na privileges. Tokeni hii pia ina logon SID inayotambulisha kikao hicho kipekee.

Local Security Authority (LSASS) hushughulikia maombi ya kufikia vifaa kwa kuchunguza DACL ili kupata ACEs zinazolingana na principal wa usalama anayejaribu kufikia kifaa. Ufikiaji hutolewa mara moja ikiwa hakuna ACEs husika zinazopatikana. Vinginevyo, LSASS hulinganisha ACEs na SID ya principal wa usalama iliyo kwenye access token ili kubaini kama ufikiaji unaruhusiwa.<sup>[[1]](#references)</sup>

### **Muhtasari wa Mchakato**

- **ACLs:** Hufafanua ruhusa za ufikiaji kupitia DACLs na kanuni za ukaguzi kupitia SACLs.
- **Access Token:** Ina maelezo ya mtumiaji, vikundi na privileges za kikao.
- **Uamuzi wa Ufikiaji:** Hufanywa kwa kulinganisha ACEs za DACL na access token; SACLs hutumika kwa ukaguzi.<sup>[[1]](#references)</sup>

### ACEs

Kuna **aina tatu kuu za Access Control Entries (ACEs)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: ACE hii hukataa waziwazi ufikiaji wa kifaa kwa watumiaji au vikundi maalum (kwenye DACL).
- **Access Allowed ACE**: ACE hii hutoa waziwazi ufikiaji wa kifaa kwa watumiaji au vikundi maalum (kwenye DACL).
- **System Audit ACE**: Ikiwa ndani ya System Access Control List (SACL), ACE hii hutengeneza audit logs watumiaji au vikundi vinapojaribu kufikia kifaa. Hurekodi ikiwa ufikiaji uliruhusiwa au ulikataliwa na aina ya ufikiaji ulioombwa.

Kila ACE ina **vipengele vinne muhimu**:<sup>[[1]](#references)</sup>

1. **Security Identifier (SID)** ya mtumiaji au kikundi (au jina la principal wake linaloonekana kwenye uwakilishaji wa picha).
2. **Flag** inayobainisha aina ya ACE (ufikiaji uliokataliwa, ulioruhusiwa au ukaguzi wa mfumo).
3. **Inheritance flags** zinazoamua kama vifaa vya ndani vinaweza kurithi ACE kutoka kwa mzazi wake.
4. [**Access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), thamani ya biti 32 inayobainisha haki ambazo kifaa kimetoa.

Uamuzi wa ufikiaji hufanywa kwa kuchunguza kila ACE kwa mfuatano hadi:<sup>[[1]](#references)</sup>

- **Access-Denied ACE** ikatae waziwazi haki zilizoombwa kwa trustee aliyetambuliwa kwenye access token.
- **Access-Allowed ACE(s)** zitoe waziwazi haki zote zilizoombwa kwa trustee aliye kwenye access token.
- Baada ya ACEs zote kukaguliwa, ikiwa haki yoyote iliyoombwa **haikuruhusiwa waziwazi**, ufikiaji **hukatazwa** moja kwa moja.

### Mpangilio wa ACEs

Jinsi **ACEs** (kanuni zinazobainisha ni nani anayeweza au asiyeweza kufikia kitu) zinavyopangwa kwenye orodha inayoitwa **DACL** ni muhimu sana. Hii ni kwa sababu mfumo unaposhaamua kutoa au kukataa ufikiaji kwa kutumia kanuni hizi, huacha kukagua zilizobaki.<sup>[[1]](#references)</sup>

Kuna njia bora ya kupanga ACEs hizi, inayoitwa **"canonical order."** Njia hii husaidia kuhakikisha kila kitu kinafanya kazi vizuri na kwa haki. Hivi ndivyo inavyopangwa katika mifumo kama **Windows 2000** na **Windows Server 2003**:

- Kwanza, weka kanuni zilizowekwa **mahususi kwa kifaa hiki** kabla ya zile zilizotoka mahali pengine, kama vile folda ya mzazi.
- Ndani ya kanuni hizo mahususi, weka zile zinazosema **"hapana" (deny)** kabla ya zile zinazosema **"ndiyo" (allow)**.
- Kwa kanuni zilizotoka mahali pengine, anza na zile kutoka **chanzo kilicho karibu zaidi**, kama vile mzazi, kisha endelea kwa mpangilio wa kurudi nyuma. Tena, weka **"hapana"** kabla ya **"ndiyo."**

Mpangilio huu una manufaa mawili makuu:

- Unahakikisha kwamba ikiwa kuna **"hapana"** mahususi, inazingatiwa bila kujali kanuni nyingine za **"ndiyo"** zilizopo.
- Unampa mmiliki wa kifaa **uamuzi wa mwisho** kuhusu nani anayeruhusiwa kuingia, kabla ya kanuni kutoka kwenye folda za mzazi au sehemu nyingine za juu kutumika.

Kwa kupanga mambo hivi, mmiliki wa faili au folda anaweza kubainisha kwa usahihi nani anayeweza kufikia, ili watu wanaofaa waweze kuingia na wengine wasiweze.

![Mchoro wa mpangilio wa NTFS access control entries](https://www.ntfs.com/images/screenshots/ACEs.gif)

Kwa hiyo, **"canonical order"** huhakikisha kanuni za ufikiaji ziko wazi na zinafanya kazi vizuri kwa kuweka kanuni mahususi kwanza na kupanga nyingine kwa njia inayofaa.

### Mfano wa GUI

[**Mfano kutoka hapa**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Hii ni kichupo cha kawaida cha usalama cha folda kinachoonyesha ACL, DACL na ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Tukibofya **kitufe cha Advanced**, tutapata chaguo zaidi kama vile urithi:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Na ukiongeza au kuhariri Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Mwisho, tuna SACL kwenye kichupo cha Auditing:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Maelezo Rahisi ya Access Control

Tunaposimamia ufikiaji wa rasilimali, kama vile folda, tunatumia orodha na kanuni zinazoitwa Access Control Lists (ACLs) na Access Control Entries (ACEs). Hivi hufafanua ni nani anayeweza au asiyeweza kufikia data fulani.<sup>[[1]](#references)</sup>

#### Kukataa Ufikiaji kwa Kikundi Maalum

Fikiria una folda inayoitwa Cost, na unataka kila mtu aweze kuifikia isipokuwa timu ya marketing. Kwa kuweka kanuni kwa usahihi, tunaweza kuhakikisha timu ya marketing inakataliwa ufikiaji waziwazi kabla ya kuruhusu kila mtu mwingine. Hili hufanywa kwa kuweka kanuni ya kukataa ufikiaji kwa timu ya marketing kabla ya kanuni ya kuruhusu ufikiaji kwa kila mtu.

#### Kuruhusu Ufikiaji kwa Mwanachama Maalum wa Kikundi Kilichozuiwa

Tuseme Bob, mkurugenzi wa marketing, anahitaji kufikia folda ya Cost, ingawa timu ya marketing kwa ujumla haipaswi kuipata. Tunaweza kuongeza kanuni maalum (ACE) kwa Bob inayomruhusu kuifikia, na kuiweka kabla ya kanuni inayokataa ufikiaji kwa timu ya marketing. Kwa njia hii, Bob anapata ufikiaji licha ya kizuizi cha jumla cha timu yake.

#### Kuelewa Access Control Entries

ACEs ni kanuni mahususi ndani ya ACL. Hutambua watumiaji au vikundi, hubainisha ufikiaji unaoruhusiwa au unaokataliwa, na huamua jinsi kanuni hizo zinavyotumika kwa vipengee vya ndani (urithi). Kuna aina mbili kuu za ACEs:

- **Generic ACEs**: Hutumika kwa upana, na kuathiri aina zote za vifaa au kutofautisha tu kati ya containers (kama folda) na zisizo containers (kama faili). Kwa mfano, kanuni inayowaruhusu watumiaji kuona yaliyomo kwenye folda lakini isiwaruhusu kufikia faili zilizo ndani yake.
- **Object-Specific ACEs**: Hutoa udhibiti sahihi zaidi, kwa kuruhusu kanuni kuwekwa kwa aina mahususi za vifaa au hata sifa binafsi ndani ya kifaa. Kwa mfano, kwenye directory ya watumiaji, kanuni inaweza kumruhusu mtumiaji kusasisha nambari yake ya simu lakini isimruhusu kubadilisha saa zake za kuingia.

Kila ACE ina taarifa muhimu kama vile kanuni inamhusu nani (kwa kutumia Security Identifier au SID), kanuni inaruhusu au inakataa nini (kwa kutumia access mask), na jinsi inavyorithiwa na vifaa vingine.

#### Tofauti Muhimu Kati ya Aina za ACE

- **Generic ACEs** zinafaa kwa hali rahisi za udhibiti wa ufikiaji, ambapo kanuni ileile inatumika kwa vipengele vyote vya kifaa au vifaa vyote vilivyo ndani ya container.
- **Object-Specific ACEs** hutumika kwa hali changamano zaidi, hasa katika mazingira kama Active Directory, ambapo unaweza kuhitaji kudhibiti ufikiaji wa sifa mahususi za kifaa kwa njia tofauti.

Kwa muhtasari, ACLs na ACEs husaidia kufafanua udhibiti sahihi wa ufikiaji, kuhakikisha ni watu au vikundi vinavyofaa pekee vinavyoweza kufikia taarifa au rasilimali nyeti, na kuruhusu haki za ufikiaji kubinafsishwa hadi kiwango cha sifa binafsi au aina za vifaa.

### Muundo wa Access Control Entry

| Sehemu ya ACE | Maelezo |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag inayoonyesha aina ya ACE. Windows 2000 na Windows Server 2003 zinaunga mkono aina sita za ACE: Aina tatu za jumla za ACE zinazohusishwa na vifaa vyote vinavyoweza kulindwa. Aina tatu za ACE mahususi kwa kifaa zinazoweza kutumika kwa vifaa vya Active Directory. |
| Flags       | Seti ya bit flags zinazodhibiti urithi na ukaguzi. |
| Size        | Idadi ya bytes za kumbukumbu zilizotengwa kwa ajili ya ACE. |
| Access mask | Thamani ya biti 32 ambayo biti zake zinahusiana na haki za ufikiaji wa kifaa. Biti zinaweza kuwashwa au kuzimwa, lakini maana ya mpangilio huo hutegemea aina ya ACE. Kwa mfano, ikiwa biti inayohusiana na haki ya kusoma ruhusa imewashwa, na aina ya ACE ni Deny, ACE hukataa haki ya kusoma ruhusa za kifaa. Ikiwa biti hiyo hiyo imewashwa lakini aina ya ACE ni Allow, ACE hutoa haki ya kusoma ruhusa za kifaa. Maelezo zaidi kuhusu Access mask yako kwenye jedwali linalofuata. |
| SID         | Humtambulisha mtumiaji au kikundi ambacho ufikiaji wake unadhibitiwa au kufuatiliwa na ACE hii. |

### Muundo wa Access Mask

| Bit (Range) | Maana                            | Maelezo/Mfano                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Haki Mahususi za Ufikiaji wa Kifaa | Kusoma data, kutekeleza, kuongeza data           |
| 16 - 22     | Haki za Kawaida za Ufikiaji             | Kufuta, kuandika ACL, kuandika mmiliki            |
| 23          | Inaweza kufikia security ACL            |                                           |
| 24 - 27     | Zimehifadhiwa                           |                                           |
| 28          | Generic ALL (kusoma, kuandika, kutekeleza) | Kila kitu kilicho hapa chini                          |
| 29          | Generic Execute                    | Kila kitu kinachohitajika kutekeleza programu |
| 30          | Generic Write                      | Kila kitu kinachohitajika kuandika kwenye faili   |
| 31          | Generic Read                       | Kila kitu kinachohitajika kusoma faili       |

## References

- [1] [Jinsi Mfumo Unavyotumia ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL na ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)
{{#include ../../banners/hacktricks-training.md}}

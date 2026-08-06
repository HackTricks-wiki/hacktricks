# ACLs - DACLs/SACLs/ACEs

{{#include ../../banners/hacktricks-training.md}}

## **Access Control List (ACL)**

Access Control List (ACL) inajumuisha seti iliyopangwa ya Access Control Entries (ACEs) zinazoeleza ulinzi wa kitu na sifa zake. Kwa ujumla, ACL hufafanua ni vitendo gani vinavyoruhusiwa au kukataliwa kwa security principals (users au groups) fulani kwenye kitu fulani.

Kuna aina mbili za ACL:

- **Discretionary Access Control List (DACL):** Hubainisha users na groups walio na au wasio na ruhusa ya kufikia kitu.
- **System Access Control List (SACL):** Hudhibiti auditing ya majaribio ya kufikia kitu.

Mchakato wa kufikia faili unahusisha mfumo kulinganisha security descriptor ya kitu na access token ya user ili kubaini ikiwa ufikiaji uruhusiwe na kiwango cha ufikiaji huo, kwa kutegemea ACEs.<sup>[[1]](#references)</sup>

### **Key Components**

- **DACL:** Ina ACEs zinazotoa au kukataa ruhusa za kufikia kitu kwa users na groups. Kimsingi, hii ndiyo ACL kuu inayobainisha haki za ufikiaji.
- **SACL:** Hutumika ku-audit ufikiaji wa vitu, ambapo ACEs hufafanua aina za ufikiaji zitakazorekodiwa kwenye Security Event Log. Hii inaweza kuwa muhimu sana katika kugundua majaribio ya ufikiaji yasiyoidhinishwa au kutatua matatizo ya ufikiaji.<sup>[[1]](#references)</sup>

### **System Interaction with ACLs**

Kila user session inahusishwa na access token yenye taarifa za usalama zinazohusiana na session hiyo, ikiwemo utambulisho wa user, group na privileges. Token hii pia ina logon SID inayotambulisha session hiyo kwa njia ya kipekee.

Local Security Authority (LSASS) huchakata maombi ya kufikia vitu kwa kuchunguza DACL ili kutafuta ACEs zinazolingana na security principal anayejaribu kufikia kitu. Ufikiaji hutolewa mara moja ikiwa hakuna ACEs zinazohusika zinazopatikana. Vinginevyo, LSASS hulinganisha ACEs na SID ya security principal iliyo kwenye access token ili kubaini kama ufikiaji unastahili kuruhusiwa.<sup>[[1]](#references)</sup>

### **Summarized Process**

- **ACLs:** Hufafanua ruhusa za ufikiaji kupitia DACLs na sheria za auditing kupitia SACLs.
- **Access Token:** Ina taarifa za user, group na privileges za session.
- **Access Decision:** Hufanywa kwa kulinganisha DACL ACEs na access token; SACLs hutumika kwa auditing.<sup>[[1]](#references)</sup>

### ACEs

Kuna **aina tatu kuu za Access Control Entries (ACEs)**:<sup>[[1]](#references)</sup>

- **Access Denied ACE**: ACE hii hukataa kwa uwazi ufikiaji wa kitu kwa users au groups waliobainishwa (kwenye DACL).
- **Access Allowed ACE**: ACE hii hutoa kwa uwazi ufikiaji wa kitu kwa users au groups waliobainishwa (kwenye DACL).
- **System Audit ACE**: Ikiwa ndani ya System Access Control List (SACL), ACE hii inawajibika kutengeneza audit logs wakati users au groups wanapojaribu kufikia kitu. Hurekodi ikiwa ufikiaji uliruhusiwa au ulikataliwa na aina ya ufikiaji huo.

Kila ACE ina **vipengele vinne muhimu**:<sup>[[1]](#references)</sup>

1. **Security Identifier (SID)** ya user au group (au principal name yao katika graphical representation).
2. **flag** inayotambua aina ya ACE (access denied, allowed, au system audit).
3. **Inheritance flags** zinazoamua ikiwa child objects zinaweza kurithi ACE kutoka kwa parent wao.
4. [**access mask**](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN), thamani ya bits 32 inayobainisha haki ambazo object imepewa.

Uamuzi wa ufikiaji hufanywa kwa kuchunguza kila ACE kwa mpangilio hadi:<sup>[[1]](#references)</sup>

- **Access-Denied ACE** ikatae waziwazi rights zilizoombwa kwa trustee aliyetambuliwa kwenye access token.
- **Access-Allowed ACE(s)** itoe waziwazi rights zote zilizoombwa kwa trustee aliye kwenye access token.
- Baada ya kuchunguza ACEs zote, ikiwa right yoyote iliyoombwa **haijaidhinishwa waziwazi**, ufikiaji **hukatalika kwa njia isiyo ya moja kwa moja**.

### Order of ACEs

Namna **ACEs** (sheria zinazoeleza ni nani anayeweza au asiyeweza kufikia kitu) zinavyopangwa kwenye list inayoitwa **DACL** ni muhimu sana. Hii ni kwa sababu mfumo unapotoa au kukataa ufikiaji kwa kutegemea sheria hizi, huacha kuchunguza sheria zilizobaki.<sup>[[1]](#references)</sup>

Kuna njia bora ya kupanga ACEs, inayoitwa **"canonical order."** Njia hii husaidia kuhakikisha kila kitu kinafanya kazi vizuri na kwa usawa. Hivi ndivyo inavyofanya kazi kwenye systems kama **Windows 2000** na **Windows Server 2003**:

- Kwanza, weka sheria zote zilizoundwa **mah mahususi kwa ajili ya kitu hiki** kabla ya zile zinazotoka sehemu nyingine, kama parent folder.
- Ndani ya sheria hizo mahususi, weka zile zinazosema **"hapana" (deny)** kabla ya zile zinazosema **"ndiyo" (allow)**.
- Kwa sheria zinazotoka sehemu nyingine, anza na zile kutoka **chanzo kilicho karibu zaidi**, kama parent, kisha endelea kurudi nyuma. Tena, weka **"hapana"** kabla ya **"ndiyo."**

Mpangilio huu husaidia kwa njia mbili kuu:

- Huhakikisha kwamba ikiwa kuna **"hapana"** mahususi, inaheshimiwa bila kujali ni sheria gani nyingine za **"ndiyo"** zilizopo.
- Humruhusu owner wa kitu kutoa **uamuzi wa mwisho** kuhusu ni nani anayeingia, kabla sheria kutoka parent folders au sehemu za mbali zaidi hazijaanza kutumika.

Kwa kupanga mambo hivi, owner wa faili au folder anaweza kubainisha kwa usahihi sana ni nani anayepewa ufikiaji, na kuhakikisha watu sahihi wanaweza kuingia huku wasio sahihi wakizuiwa.

![NTFS access control entry ordering diagram](https://www.ntfs.com/images/screenshots/ACEs.gif)

Kwa hiyo, **"canonical order"** inahusu kuhakikisha sheria za ufikiaji ziko wazi na zinafanya kazi vizuri, kwa kuweka sheria mahususi kwanza na kupanga kila kitu kwa njia inayofaa.

### GUI Example

[**Mfano kutoka hapa**](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)<sup>[[2]](#references)</sup>

Hii ni security tab ya kawaida ya folder inayoonyesha ACL, DACL na ACEs:

![http://secureidentity.se/wp-content/uploads/2014/04/classicsectab.jpg](../../images/classicsectab.jpg)

Tukibofya **Advanced button** tutapata options zaidi kama inheritance:

![http://secureidentity.se/wp-content/uploads/2014/04/aceinheritance.jpg](../../images/aceinheritance.jpg)

Na ukiongeza au kuhariri Security Principal:

![http://secureidentity.se/wp-content/uploads/2014/04/editseprincipalpointers1.jpg](../../images/editseprincipalpointers1.jpg)

Mwisho, tuna SACL kwenye Auditing tab:

![http://secureidentity.se/wp-content/uploads/2014/04/audit-tab.jpg](../../images/audit-tab.jpg)

### Explaining Access Control in a Simplified Manner

Tunapodhibiti ufikiaji wa resources, kama folder, tunatumia lists na rules zinazojulikana kama Access Control Lists (ACLs) na Access Control Entries (ACEs). Hizi hufafanua ni nani anayeweza au asiyeweza kufikia data fulani.<sup>[[1]](#references)</sup>

#### Denying Access to a Specific Group

Fikiria una folder linaloitwa Cost, na unataka kila mtu aweze kulifikia isipokuwa marketing team. Kwa kuweka rules kwa usahihi, tunaweza kuhakikisha marketing team inanyimwa ufikiaji waziwazi kabla ya kumruhusu kila mtu mwingine. Hili hufanywa kwa kuweka rule inayokataa ufikiaji wa marketing team kabla ya rule inayoruhusu ufikiaji kwa kila mtu.

#### Allowing Access to a Specific Member of a Denied Group

Tuseme Bob, marketing director, anahitaji kufikia folder la Cost, ingawa marketing team kwa ujumla haipaswi kuwa na ufikiaji. Tunaweza kuongeza rule mahususi (ACE) ya Bob inayompa ufikiaji, na kuiweka kabla ya rule inayokataa ufikiaji wa marketing team. Kwa njia hii, Bob anapata ufikiaji licha ya restriction ya jumla kwa team yake.

#### Understanding Access Control Entries

ACEs ni rules binafsi ndani ya ACL. Hutambua users au groups, hubainisha ni ufikiaji gani unaruhusiwa au kukataliwa, na huamua jinsi rules hizi zinavyotumika kwa sub-items (inheritance). Kuna aina mbili kuu za ACEs:

- **Generic ACEs**: Hizi hutumika kwa upana, zikiathiri aina zote za objects au kutofautisha tu kati ya containers (kama folders) na non-containers (kama files). Kwa mfano, rule inayowaruhusu users kuona contents za folder lakini isiwaruhusu kufikia files zilizo ndani yake.
- **Object-Specific ACEs**: Hizi hutoa udhibiti sahihi zaidi, kwa kuruhusu rules ziwekwe kwa aina mahususi za objects au hata properties binafsi ndani ya object. Kwa mfano, katika directory ya users, rule inaweza kumruhusu user kusasisha namba yake ya simu lakini isimruhusu kubadilisha login hours zake.

Kila ACE ina taarifa muhimu kama vile rule inamhusu nani (kwa kutumia Security Identifier au SID), rule inaruhusu au inakataa nini (kwa kutumia access mask), na jinsi inavyorithishwa na objects nyingine.

#### Key Differences Between ACE Types

- **Generic ACEs** zinafaa kwa scenarios rahisi za access control, ambapo rule ileile inatumika kwa vipengele vyote vya object au kwa objects zote zilizo ndani ya container.
- **Object-Specific ACEs** hutumika kwa scenarios changamano zaidi, hasa katika environments kama Active Directory, ambapo unaweza kuhitaji kudhibiti ufikiaji wa properties mahususi za object kwa njia tofauti.

Kwa muhtasari, ACLs na ACEs husaidia kufafanua access controls sahihi, na kuhakikisha kuwa individuals au groups sahihi pekee ndio wanaoweza kufikia taarifa au resources nyeti, huku zikiruhusu rights za ufikiaji kurekebishwa hadi kiwango cha properties binafsi au aina za objects.

### Access Control Entry Layout

| ACE Field   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Type        | Flag inayoonyesha aina ya ACE. Windows 2000 na Windows Server 2003 zinaunga mkono aina sita za ACE: Aina tatu za generic ACE zinazohusishwa na securable objects zote. Aina tatu za object-specific ACE zinazoweza kutokea kwa Active Directory objects.                                                                                                                                                                                                                                                            |
| Flags       | Seti ya bit flags zinazodhibiti inheritance na auditing.                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Size        | Idadi ya bytes za memory zilizotengwa kwa ajili ya ACE.                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| Access mask | Thamani ya bits 32 ambayo bits zake zinahusiana na access rights za object. Bits zinaweza kuwekwa on au off, lakini maana ya setting hiyo hutegemea aina ya ACE. Kwa mfano, ikiwa bit inayohusiana na right ya kusoma permissions imewashwa, na aina ya ACE ni Deny, ACE hiyo inakataa right ya kusoma permissions za object. Ikiwa bit hiyo hiyo imewashwa lakini aina ya ACE ni Allow, ACE inatoa right ya kusoma permissions za object. Maelezo zaidi ya Access mask yanaonekana kwenye jedwali linalofuata. |
| SID         | Hutambua user au group ambaye ufikiaji wake unadhibitiwa au kufuatiliwa na ACE hii.                                                                                                                                                                                                                                                                                                                                                                                                                                 |

### Access Mask Layout

| Bit (Range) | Meaning                            | Description/Example                       |
| ----------- | ---------------------------------- | ----------------------------------------- |
| 0 - 15      | Object Specific Access Rights      | Kusoma data, Execute, Kuongeza data           |
| 16 - 22     | Standard Access Rights             | Delete, Write ACL, Write Owner            |
| 23          | Can access security ACL            |                                           |
| 24 - 27     | Reserved                           |                                           |
| 28          | Generic ALL (Read, Write, Execute) | Kila kitu kilicho hapa chini                          |
| 29          | Generic Execute                    | Kila kitu kinachohitajika ku-execute program |
| 30          | Generic Write                      | Kila kitu kinachohitajika kuandika kwenye faili   |
| 31          | Generic Read                       | Kila kitu kinachohitajika kusoma faili       |

## References

- [1] [How the System Uses ACLs - NTFS.com](https://www.ntfs.com/ntfs-permissions-acl-use.htm)
- [2] [ACL, DACL, SACL and the ACE - secureidentity.se](https://secureidentity.se/acl-dacl-sacl-and-the-ace/)

{{#include ../../banners/hacktricks-training.md}}

# Hacking ya Mifumo ya Udhibiti wa Viwandani

{{#include ../banners/hacktricks-training.md}}

## Kuhusu Sehemu Hii

Sehemu hii inatanguliza vipengele, usanifu, itifaki na mbinu za tathmini ya usalama za mifumo ya udhibiti wa viwandani (ICS). ICS ni sehemu ya eneo pana la teknolojia ya uendeshaji (OT): mifumo na vifaa vinavyoweza kuratibiwa, vinavyofuatilia au kusababisha mabadiliko katika michakato halisi. Mifano ya kawaida ni mifumo ya udhibiti na ukusanyaji wa data kwa usimamizi (SCADA), mifumo ya udhibiti iliyosambazwa (DCSs), na vidhibiti vya mantiki vinavyoweza kuratibiwa (PLCs).<sup>[[1]](#references)</sup>

Kazi ya usalama katika mazingira haya lazima izingatie mahitaji yanayotofautiana na yale ya IT ya kawaida, yakiwemo usalama wa michakato, kutegemewa, upatikanaji, uendeshaji wa uhakika, na mizunguko ya maisha ya vifaa. Udhibiti wa usalama unaweza kuwa sahihi kitaalamu lakini usifae ikiwa utavuruga mchakato halisi, kwa hiyo majaribio na marekebisho yanapaswa kuratibiwa na mmiliki wa mfumo na wafanyakazi wa uendeshaji.<sup>[[1]](#references)</sup>

Kuvamiwa au kuvurugwa kwa bahati mbaya kunaweza kusimamisha uzalishaji, kuharibu vifaa, kusababisha kuvuja kwa vitu hatari, kudhuru mazingira, au kusababisha majeraha na vifo. Athari hizi zinazoweza kutokea katika ulimwengu halisi ndizo sababu ya kuelewa mchakato unaodhibitiwa na mipaka yake ya uendeshaji salama kabla ya kuanza majaribio yanayotumika.<sup>[[1]](#references)</sup>

Usambazaji mwingi wa OT bado hutumia mifumo ya uendeshaji, programu na itifaki za zamani kwa sababu vifaa vina muda mrefu wa matumizi na mabadiliko yanahitaji majaribio ya kiutendaji na kiusalama. Baadhi ya itifaki ziliundwa bila uthibitishaji au usimbaji fiche wa kisasa, na uwekaji wa viraka unaweza kuzuiwa na usaidizi wa muuzaji au vipindi vya matengenezo; tumia ugawaji wa mtandao, udhibiti wa ufikiaji na ufuatiliaji kama njia mbadala pale ambapo uboreshaji wa moja kwa moja hauwezekani.<sup>[[1]](#references)</sup>

## Vipaumbele vya Tathmini

Anza kwa kuelewa mchakato unaodhibitiwa, mipaka ya mfumo, topolojia ya mtandao, mali, mtiririko wa data, mahusiano ya uaminifu na miunganisho ya nje. Aina zinazofanana za vifaa zinaweza kutekeleza kazi tofauti katika maeneo mbalimbali, kwa hiyo usidhani kuwa usanifu au modeli ya athari ya usambazaji mmoja inatumika kwa mwingine.<sup>[[1]](#references)</sup>

Pendelea ugunduzi tulivu na nyaraka zilizopo za uhandisi inapowezekana. Uchunguzi wowote tendaji au exploitation unapaswa kufuata mpango wa majaribio ulioidhinishwa unaobainisha vikwazo vya usalama, vipindi vya matengenezo, taratibu za urejeshaji na masharti ya kusitisha. Matokeo yanapaswa kutathminiwa kwa kuzingatia athari za usalama wa mtandao na athari zinazoweza kuathiri mchakato halisi.<sup>[[1]](#references)</sup>

Ujuzi huohuo wa usanifu husaidia shughuli za ulinzi kama vile kuorodhesha mali, kugawa mtandao, ufuatiliaji, kukabiliana na matukio na usimamizi wa udhaifu unaotegemea hatari.<sup>[[1]](#references)</sup>

## Matumizi mabaya ya kidhibiti cha juu cha jokofu

Kidhibiti cha mfumo wa majokofu huratibu vidhibiti vya kompresor na vya kabati za bidhaa, lakini hakipoezi kabati chenyewe. Kwa hiyo, ufikiaji wa kiolesura chake cha usimamizi unaweza kumpa mtu udhibiti wa vifaa vingi tegemezi kupitia usambazaji wa kawaida wa usanidi. Hii ni tofauti na kubadilisha kidhibiti joto kimoja au kuendesha kompresor moja kwa moja.<sup>[[3]](#references)[[4]](#references)</sup>

### Kuingia kwa msimbo wa matengenezo unaotokana na tarehe

Kwenye vidhibiti vya mfumo vya Danfoss vilivyoathiriwa, login mbadala ya XML inakubali msimbo unaotokana na tarehe ya kidhibiti badala ya nenosiri la akaunti.<sup>[[2]](#references)[[3]](#references)</sup> Kwenye SM800 na SC255, Synacktiv ilifuatilia sifa za `eds_only` na `quantum_only` kupitia `xml_load_file` na `check_authorize` hadi `check_code_of_day`. Ushauri wake pia unaonyesha kuwa `read_date_time` kwenye `xml.cgi` hufichua tarehe ya kidhibiti bila uthibitishaji.<sup>[[2]](#references)</sup> Claroty iligundua njia inayolingana ya `getauth` kwenye AK-SM 800A, lakini ilificha sifa zinazoianzisha; majina ya sifa za modeli za zamani hayapaswi kudhaniwa kuwa yatafanya kazi kwenye jukwaa hilo.<sup>[[3]](#references)</sup>

Synacktiv inaandika ombi la tarehe lisilohitaji uthibitishaji kama ifuatavyo:<sup>[[2]](#references)</sup>

```bash
curl -k -d '<cmd action="read_date_time"/>' https://<controller>/xml.cgi
```

Msimbo hauna siri mahususi ya kifaa: kurejesha algorithm kutoka kwenye [firmware](../hardware-physical-access/firmware-analysis/) kunaweza kutoa credential inayotumika kwa tarehe husika kwa vifaa vilivyo na utekelezaji uleule ulioathiriwa.<sup>[[2]](#references)[[3]](#references)</sup> Thibitisha modeli na firmware kwanza. Jibu la tarehe pekee halithibitishi kwamba njia mbadala ya login ipo au kwamba session imepatikana.

### Usanidi wa wingi na matumizi mabaya ya hita ya kuyeyusha barafu

Baada ya kupata ufikiaji wa kiutawala, tambua vidhibiti vya makabati vilivyounganishwa na msimamizi wa mfumo na kama kipengele chake cha usambazaji wa usanidi kinaweza kuvisasisha vyote kwa pamoja. Kubadilisha setpoint ya kabati kwa kawaida hulipasha joto hadi karibu na halijoto ya chumba. Ili kulipasha joto zaidi ya halijoto ya mazingira, kidhibiti husika ni hita ya umeme ya kuyeyusha barafu kwenye evaporator ya kidhibiti cha kabati: kuyeyusha barafu husimamisha kupoza na kuwasha hita hiyo hadi kihisi au kipima muda kisitishe mzunguko. Kubadilisha mbinu ya kuyeyusha barafu, ratiba, halijoto ya kukatisha, na kikomo cha muda kunaweza kuweka hita ikiwa imewashwa badala yake. Msimamizi anaweza kusambaza mabadiliko hayo kwenye makabati mengi na kuzuia kengele zinazohusiana, na hivyo kugeuza uingiliaji mmoja wa mfumo wa usimamizi kuwa mabadiliko ya mchakato yanayoathiri duka zima.<sup>[[4]](#references)</sup>

Hii ni hatari kwa mchakato wa kimwili, si uthibitisho salama wa dhana kwenye mfumo unaotumika. Ikiwa zipo, vifaa vya kukata joto vinaweza kuzuia hita kufanya kazi kupita kiasi, lakini kuifanya ifanye kazi mfululizo bado kunaweza kupasha joto kupita kiasi muunganisho dhaifu wa umeme uliokuwepo awali. Thibitisha usanidi na athari katika maabara iliyoidhinishwa pekee, au kwa kufuata mpango wa usalama wa mchakato wa operator.<sup>[[4]](#references)</sup>

## Sehemu za kuingilia za itifaki

- [Upimaji wa Modbus](../network-services-pentesting/pentesting-modbus.md) unahusu Modbus TCP, matoleo ya serial, function codes, na ufikiaji wa rejista.
- [Upimaji wa OPC UA](../network-services-pentesting/4840-pentesting-opc-ua.md) unahusu huduma ya kubadilishana data za viwandani.
- [Upimaji wa BACnet](../network-services-pentesting/47808-udp-bacnet.md) unahusu mitandao ya udhibiti wa automatisering ya majengo.

## References

- [1] [NIST SP 800-82 Rev. 3 - Mwongozo wa Usalama wa Operational Technology (OT)](https://csrc.nist.gov/pubs/sp/800/82/r3/final)
- [2] [Synacktiv - Njia ya kukwepa uthibitishaji katika Danfoss System-Managers SM800 na SC255](https://www.synacktiv.com/sites/default/files/2023-10/synacktiv-danfoss-sm800-sc255-sc355-auth-bypass.pdf)
- [3] [Claroty Team82 - Gandisha Kidhibiti, Yeyusha Barafu kwenye Chakula](https://claroty.com/team82/research/freeze-the-controller-defrost-the-food-uncovering-vulnerabilities-in-danfoss-refrigeration-controllers)
- [4] [Pen Test Partners - Huhitaji taifa lenye uwezo mkubwa ili kupasha friji joto](https://pentestpartners.com/security-blog/you-dont-need-a-nation-state-to-warm-up-a-fridge)
{{#include ../banners/hacktricks-training.md}}

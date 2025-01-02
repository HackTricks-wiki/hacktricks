# Infrared

{{#include ../../banners/hacktricks-training.md}}

## Jinsi Infrarouge Inavyofanya Kazi <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**Mwanga wa infrarouge hauonekani kwa wanadamu**. Wavelength ya IR ni kutoka **0.7 hadi 1000 microns**. Remote za nyumbani hutumia ishara ya IR kwa ajili ya uhamasishaji wa data na zinafanya kazi katika wigo wa wavelength wa 0.75..1.4 microns. Microcontroller katika remote inafanya LED ya infrarouge kung'ara kwa mzunguko maalum, ikigeuza ishara ya kidijitali kuwa ishara ya IR.

Ili kupokea ishara za IR, **photoreceiver** hutumiwa. In **geuza mwanga wa IR kuwa mapigo ya voltage**, ambayo tayari ni **ishara za kidijitali**. Kawaida, kuna **filter ya mwanga mweusi ndani ya mpokeaji**, ambayo inaruhusu **tu wavelength inayotakiwa kupita** na kuondoa kelele.

### Aina za Itifaki za IR <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

Itifaki za IR zinatofautiana katika mambo 3:

- uandishi wa bit
- muundo wa data
- mzunguko wa kubeba — mara nyingi katika wigo wa 36..38 kHz

#### Njia za uandishi wa bit <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Uandishi wa Umbali wa Pulse**

Bits zinaandikwa kwa kubadilisha muda wa nafasi kati ya mapigo. Upana wa pigo lenyewe ni thabiti.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Uandishi wa Upana wa Pulse**

Bits zinaandikwa kwa kubadilisha upana wa pigo. Upana wa nafasi baada ya mlipuko wa pigo ni thabiti.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Uandishi wa Awamu**

Inajulikana pia kama uandishi wa Manchester. Thamani ya mantiki inafafanuliwa na polarity ya mpito kati ya mlipuko wa pigo na nafasi. "Nafasi hadi mlipuko wa pigo" inaashiria mantiki "0", "mlipuko wa pigo hadi nafasi" inaashiria mantiki "1".

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. Mchanganyiko wa zile za awali na nyingine za kipekee**

> [!NOTE]
> Kuna itifaki za IR ambazo **zinajaribu kuwa za ulimwengu** kwa aina kadhaa za vifaa. Zile maarufu ni RC5 na NEC. Kwa bahati mbaya, maarufu zaidi **haimaanishi maarufu zaidi**. Katika mazingira yangu, nilikutana na remote mbili za NEC na hakuna RC5.
>
> Watengenezaji wanapenda kutumia itifaki zao za kipekee za IR, hata ndani ya safu sawa za vifaa (kwa mfano, TV-boxes). Kwa hivyo, remotes kutoka kampuni tofauti na wakati mwingine kutoka mifano tofauti kutoka kampuni moja, hazina uwezo wa kufanya kazi na vifaa vingine vya aina hiyo.

### Kuchunguza ishara ya IR

Njia ya kuaminika zaidi kuona jinsi ishara ya IR ya remote inavyoonekana ni kutumia oscilloscope. Haitaondoa au kubadilisha ishara iliyopokelewa, inaonyeshwa tu "kama ilivyo". Hii ni muhimu kwa ajili ya kupima na kutatua matatizo. Nitaonyesha ishara inayotarajiwa kwa mfano wa itifaki ya NEC IR.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

Kawaida, kuna preamble mwanzoni mwa pakiti iliyoundwa. Hii inaruhusu mpokeaji kubaini kiwango cha gain na mandhari. Pia kuna itifaki bila preamble, kwa mfano, Sharp.

Kisha data inatumwa. Muundo, preamble, na njia ya uandishi wa bit zinatolewa na itifaki maalum.

**Itifaki ya NEC IR** ina amri fupi na nambari ya kurudia, ambayo inatumwa wakati kifungo kinashinikizwa. Zote amri na nambari ya kurudia zina preamble sawa mwanzoni.

**Amri ya NEC**, mbali na preamble, ina byte ya anwani na byte ya nambari ya amri, ambayo kifaa kinaelewa kinachohitajika kutekelezwa. Byte za anwani na nambari ya amri zinajirudia kwa thamani za kinyume, ili kuangalia uadilifu wa uhamasishaji. Kuna bit ya kusitisha ya ziada mwishoni mwa amri.

**Nambari ya kurudia** ina "1" baada ya preamble, ambayo ni bit ya kusitisha.

Kwa **mantiki "0" na "1"** NEC inatumia Uandishi wa Umbali wa Pulse: kwanza, mlipuko wa pigo unatumwa baada ya hapo kuna pause, urefu wake unakamilisha thamani ya bit.

### Mashine za Hewa

Tofauti na remotes nyingine, **mashine za hewa hazitumii tu nambari ya kifungo kilichoshinikizwa**. Pia **hutoa taarifa zote** wakati kifungo kinashinikizwa ili kuhakikisha kwamba **mashine ya hewa na remote zinapatana**.\
Hii itazuia mashine iliyowekwa kama 20ºC kuongezeka hadi 21ºC kwa remote moja, na kisha wakati remote nyingine, ambayo bado ina joto kama 20ºC, inatumika kuongeza zaidi joto, itakuwa "inaongeza" hadi 21ºC (na si 22ºC ikidhani iko katika 21ºC).

### Mashambulizi

Unaweza kushambulia Infrarouge kwa Flipper Zero:

{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

## Marejeo

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../banners/hacktricks-training.md}}

# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Tofauti na Kernel Extensions, **System Extensions huendeshwa katika user space** badala ya kernel space, hivyo kupunguza hatari ya mfumo ku-crash kutokana na hitilafu ya extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Kuna aina tatu za system extensions: **DriverKit** Extensions, **Network** Extensions, na **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit ni mbadala wa kernel extensions ambazo **hutoa usaidizi wa hardware**. Huwezesha device drivers (kama vile USB, Serial, NIC, na HID drivers) kuendeshwa katika user space badala ya kernel space. Framework ya DriverKit inajumuisha **user space versions za baadhi ya I/O Kit classes**, na kernel hupeleka matukio ya kawaida ya I/O Kit kwenye user space, hivyo kutoa mazingira salama zaidi kwa drivers hizi kuendeshwa.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions hutoa uwezo wa kubinafsisha mienendo ya mtandao. Kuna aina kadhaa za Network Extensions:

- **App Proxy**: Hutumika kuunda VPN client inayotekeleza flow-oriented, custom VPN protocol. Hii inamaanisha hushughulikia traffic ya mtandao kulingana na connections (au flows) badala ya packets binafsi.
- **Packet Tunnel**: Hutumika kuunda VPN client inayotekeleza packet-oriented, custom VPN protocol. Hii inamaanisha hushughulikia traffic ya mtandao kulingana na packets binafsi.
- **Filter Data**: Hutumika kuchuja network "flows". Inaweza kufuatilia au kurekebisha data ya mtandao katika kiwango cha flow.
- **Filter Packet**: Hutumika kuchuja packets binafsi za mtandao. Inaweza kufuatilia au kurekebisha data ya mtandao katika kiwango cha packet.
- **DNS Proxy**: Hutumika kuunda custom DNS provider. Inaweza kutumika kufuatilia au kurekebisha DNS requests na responses.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security ni framework inayotolewa na Apple katika macOS, ambayo hutoa seti ya APIs kwa ajili ya usalama wa mfumo. Imekusudiwa kutumiwa na **security vendors na developers kujenga bidhaa zinazoweza kufuatilia na kudhibiti shughuli za mfumo** ili kutambua na kujilinda dhidi ya shughuli hasidi.

Framework hii hutoa **mkusanyiko wa APIs za kufuatilia na kudhibiti shughuli za mfumo**, kama vile process executions, file system events, network events na kernel events.

Msingi wa framework hii umewekwa katika kernel, kama Kernel Extension (KEXT) iliyoko kwenye **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> KEXT hii imeundwa na vipengele kadhaa muhimu:

- **EndpointSecurityDriver**: Hii hufanya kazi kama "entry point" ya kernel extension. Ndiyo sehemu kuu ya mawasiliano kati ya OS na Endpoint Security framework.
- **EndpointSecurityEventManager**: Kipengele hiki kinawajibika kutekeleza kernel hooks. Kernel hooks huwezesha framework kufuatilia matukio ya mfumo kwa ku-intercept system calls.
- **EndpointSecurityClientManager**: Huidhibiti mawasiliano na user space clients, huku ikifuatilia clients zilizounganishwa na zinazohitaji kupokea event notifications.
- **EndpointSecurityMessageManager**: Hutuma messages na event notifications kwa user space clients.

Matukio ambayo Endpoint Security framework inaweza kufuatilia yameainishwa katika:

- File events
- Process events
- Socket events
- Kernel events (kama vile kupakia/kutoa kernel extension au kufungua I/O Kit device)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**User-space communication** na Endpoint Security framework hufanyika kupitia IOUserClient class. Subclasses mbili tofauti hutumika, kulingana na aina ya caller:

- **EndpointSecurityDriverClient**: Hii inahitaji entitlement ya `com.apple.private.endpoint-security.manager`, ambayo inamilikiwa tu na system process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Hii inahitaji entitlement ya `com.apple.developer.endpoint-security.client`. Kwa kawaida ingetumiwa na third-party security software inayohitaji kuwasiliana na Endpoint Security framework.<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** ni C library ambayo system extensions hutumia kuwasiliana na kernel. Library hii hutumia I/O Kit (`IOKit`) kuwasiliana na Endpoint Security KEXT.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** ni system daemon muhimu inayohusika na kusimamia na kuzindua endpoint security system extensions, hasa wakati wa early boot process. **Ni system extensions pekee** zilizo na **`NSEndpointSecurityEarlyBoot`** katika faili yao ya `Info.plist` zinazopokea utaratibu huu wa early boot.<sup>[[2]](#references)</sup>

System daemon nyingine, **`sysextd`**, **huthibitisha system extensions** na kuzipeleka katika maeneo sahihi ya mfumo. Kisha huiomba daemon husika ipakie extension. **`SystemExtensions.framework`** ndiyo inayowajibika ku-activate na ku-deactivate system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF hutumiwa na security tools ambazo zitajaribu kumtambua red teamer, kwa hiyo taarifa yoyote kuhusu jinsi ya kuepuka hili inaonekana kuwa ya kuvutia.

### CVE-2021-30965

Jambo ni kwamba security application inahitaji kuwa na **Full Disk Access permissions**. Kwa hiyo, ikiwa attacker angeweza kuondoa ruhusa hizo, angeweza kuzuia software hiyo kufanya kazi:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Kwa **maelezo zaidi** kuhusu bypass hii na zinazohusiana nayo, angalia talk [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Mwishowe, hili lilirekebishwa kwa kuipa security app inayosimamiwa na **`tccd`** permission mpya **`kTCCServiceEndpointSecurityClient`**, ili `tccutil` isiweze kufuta permissions zake na kuizuia kuendelea kufanya kazi.<sup>[[3]](#references)</sup>

## Marejeo

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}

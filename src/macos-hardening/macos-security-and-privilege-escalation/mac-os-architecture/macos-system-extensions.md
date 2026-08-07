# macOS System Extensions

{{#include ../../../banners/hacktricks-training.md}}

## System Extensions / Endpoint Security Framework

Tofauti na Kernel Extensions, **System Extensions huendeshwa katika user space** badala ya kernel space, hivyo kupunguza hatari ya mfumo kuanguka kutokana na hitilafu ya extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Kuna aina tatu za system extensions: **DriverKit** Extensions, **Network** Extensions, na **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit ni mbadala wa kernel extensions ambao **hutoa usaidizi wa hardware**. Huruhusu device drivers (kama vile USB, Serial, NIC, na HID drivers) kuendeshwa katika user space badala ya kernel space. DriverKit framework inajumuisha **user space versions of certain I/O Kit classes**, na kernel hutuma matukio ya kawaida ya I/O Kit kwenye user space, ikitoa mazingira salama zaidi kwa drivers hizi kuendeshwa.<sup>[[2]](#references)</sup>

### **Network Extensions**

Network Extensions hutoa uwezo wa kubinafsisha tabia za network. Kuna aina kadhaa za Network Extensions:

- **App Proxy**: Hii hutumika kuunda VPN client inayotekeleza flow-oriented, custom VPN protocol. Hii inamaanisha hushughulikia network traffic kulingana na connections (au flows) badala ya packets moja moja.
- **Packet Tunnel**: Hii hutumika kuunda VPN client inayotekeleza packet-oriented, custom VPN protocol. Hii inamaanisha hushughulikia network traffic kulingana na packets moja moja.
- **Filter Data**: Hii hutumika kuchuja network "flows". Inaweza kufuatilia au kurekebisha network data katika kiwango cha flow.
- **Filter Packet**: Hii hutumika kuchuja network packets moja moja. Inaweza kufuatilia au kurekebisha network data katika kiwango cha packet.
- **DNS Proxy**: Hii hutumika kuunda custom DNS provider. Inaweza kutumika kufuatilia au kurekebisha DNS requests na responses.<sup>[[2]](#references)</sup>

## Endpoint Security Framework

Endpoint Security ni framework iliyotolewa na Apple katika macOS inayotoa seti ya APIs kwa ajili ya usalama wa mfumo. Imekusudiwa kutumiwa na **security vendors na developers kuunda products zinazoweza kufuatilia na kudhibiti shughuli za mfumo** ili kutambua na kulinda dhidi ya shughuli hasidi.

Framework hii hutoa **mkusanyiko wa APIs za kufuatilia na kudhibiti shughuli za mfumo**, kama vile process executions, file system events, network events na kernel events.

Kiini cha framework hii kimetekelezwa katika kernel, kama Kernel Extension (KEXT) iliyoko kwenye **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[[2]](#references)</sup> KEXT hii imeundwa na vipengele kadhaa muhimu:

- **EndpointSecurityDriver**: Hiki hufanya kazi kama "entry point" ya kernel extension. Ni sehemu kuu ya mwingiliano kati ya OS na Endpoint Security framework.
- **EndpointSecurityEventManager**: Kipengele hiki kinawajibika kutekeleza kernel hooks. Kernel hooks huruhusu framework kufuatilia system events kwa kuingilia system calls.
- **EndpointSecurityClientManager**: Hiki hudhibiti mawasiliano na clients wa user space, kikifuatilia clients waliounganishwa na wanaohitaji kupokea event notifications.
- **EndpointSecurityMessageManager**: Hiki hutuma messages na event notifications kwa clients wa user space.

Events ambazo Endpoint Security framework inaweza kufuatilia zimegawanywa katika:

- File events
- Process events
- Socket events
- Kernel events (kama vile kupakia/kutoa kernel extension au kufungua I/O Kit device)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Mawasiliano ya user space** na Endpoint Security framework hufanyika kupitia IOUserClient class. Subclasses mbili tofauti hutumika, kulingana na aina ya caller:

- **EndpointSecurityDriverClient**: Hii inahitaji entitlement ya `com.apple.private.endpoint-security.manager`, ambayo inamilikiwa tu na system process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Hii inahitaji entitlement ya `com.apple.developer.endpoint-security.client`. Kwa kawaida hii hutumiwa na third-party security software inayohitaji kuingiliana na Endpoint Security framework.<sup>[[1]](#references)</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** ni C library ambayo system extensions hutumia kuwasiliana na kernel. Library hii hutumia I/O Kit (`IOKit`) kuwasiliana na Endpoint Security KEXT.<sup>[[2]](#references)</sup>

**`endpointsecurityd`** ni system daemon muhimu inayohusika na kudhibiti na kuzindua endpoint security system extensions, hasa wakati wa early boot process. **Ni system extensions tu** zilizowekwa alama ya **`NSEndpointSecurityEarlyBoot`** katika faili yao ya `Info.plist` hupokea utaratibu huu wa early boot.<sup>[[2]](#references)</sup>

System daemon nyingine, **`sysextd`**, **huthibitisha system extensions** na kuzipeleka kwenye system locations zinazofaa. Kisha huiomba daemon husika ipakie extension. **`SystemExtensions.framework`** inawajibika kuactivate na ku-deactivate system extensions.<sup>[[2]](#references)</sup>

## Bypassing ESF

ESF hutumiwa na security tools ambazo zitajaribu kumtambua red teamer, kwa hiyo taarifa yoyote kuhusu jinsi hili linavyoweza kuepukwa inavutia.

### CVE-2021-30965

Jambo ni kwamba security application inahitaji kuwa na **Full Disk Access permissions**. Kwa hiyo, ikiwa attacker angeweza kuiondoa, angeweza kuzuia software hiyo kufanya kazi:<sup>[[3]](#references)</sup>
```bash
tccutil reset All
```
Kwa **maelezo zaidi** kuhusu bypass hii na nyingine zinazohusiana nayo, angalia mazungumzo [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)<sup>[[3]](#references)</sup>

Mwishowe, hili lilirekebishwa kwa kuipa ruhusa mpya **`kTCCServiceEndpointSecurityClient`** security app inayodhibitiwa na **`tccd`**, ili `tccutil` isifute ruhusa zake na kuizuia kufanya kazi.<sup>[[3]](#references)</sup>

## Marejeo

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}

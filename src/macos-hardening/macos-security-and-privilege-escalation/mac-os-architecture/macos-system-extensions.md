# Viendelezi vya Mfumo vya macOS

{{#include ../../../banners/hacktricks-training.md}}

## Viendelezi vya Mfumo / Endpoint Security Framework

Tofauti na Kernel Extensions, **System Extensions huendeshwa katika user space** badala ya kernel space, hivyo kupunguza hatari ya mfumo ku-crash kutokana na hitilafu ya extension.

<figure><img src="../../../images/image (606).png" alt="https://knight.sc/images/system-extension-internals-1.png"><figcaption></figcaption></figure>

Kuna aina tatu za system extensions: **DriverKit** Extensions, **Network** Extensions, na **Endpoint Security** Extensions.

### **DriverKit Extensions**

DriverKit ni mbadala wa kernel extensions ambazo **hutoa hardware support**. Huwawezesha device drivers (kama USB, Serial, NIC, na HID drivers) kuendeshwa katika user space badala ya kernel space. DriverKit framework inajumuisha **user space versions za baadhi ya I/O Kit classes**, na kernel hutuma matukio ya kawaida ya I/O Kit kwenda user space, hivyo kutoa mazingira salama zaidi kwa drivers hizi kuendeshwa.<sup>[2]</sup>

### **Network Extensions**

Network Extensions hutoa uwezo wa kubinafsisha tabia za mtandao. Kuna aina kadhaa za Network Extensions:

- **App Proxy**: Hii hutumiwa kuunda VPN client inayotekeleza flow-oriented, custom VPN protocol. Hii inamaanisha hushughulikia traffic ya mtandao kulingana na connections (au flows) badala ya packets binafsi.
- **Packet Tunnel**: Hii hutumiwa kuunda VPN client inayotekeleza packet-oriented, custom VPN protocol. Hii inamaanisha hushughulikia traffic ya mtandao kulingana na packets binafsi.
- **Filter Data**: Hii hutumiwa kuchuja network "flows". Inaweza kufuatilia au kurekebisha network data katika kiwango cha flow.
- **Filter Packet**: Hii hutumiwa kuchuja network packets binafsi. Inaweza kufuatilia au kurekebisha network data katika kiwango cha packet.
- **DNS Proxy**: Hii hutumiwa kuunda custom DNS provider. Inaweza kutumiwa kufuatilia au kurekebisha DNS requests na responses.<sup>[2]</sup>

## Endpoint Security Framework

Endpoint Security ni framework inayotolewa na Apple katika macOS, ambayo hutoa seti ya APIs kwa ajili ya system security. Imekusudiwa kutumiwa na **security vendors na developers kuunda products zinazoweza kufuatilia na kudhibiti shughuli za mfumo** ili kutambua na kulinda dhidi ya shughuli hasidi.

Framework hii hutoa **mkusanyiko wa APIs za kufuatilia na kudhibiti shughuli za mfumo**, kama vile process executions, file system events, network na kernel events.

Msingi wa framework hii umeimplementiwa katika kernel, kama Kernel Extension (KEXT) iliyoko katika **`/System/Library/Extensions/EndpointSecurity.kext`**.<sup>[2]</sup> KEXT hii imeundwa na components kadhaa muhimu:

- **EndpointSecurityDriver**: Hii hufanya kazi kama "entry point" ya kernel extension. Ndiyo sehemu kuu ya interaction kati ya OS na Endpoint Security framework.
- **EndpointSecurityEventManager**: Component hii inawajibika kuimplement kernel hooks. Kernel hooks huwezesha framework kufuatilia system events kwa ku-intercept system calls.
- **EndpointSecurityClientManager**: Hii husimamia mawasiliano na user space clients, huku ikifuatilia clients zilizounganishwa na zinazohitaji kupokea event notifications.
- **EndpointSecurityMessageManager**: Hii hutuma messages na event notifications kwa user space clients.

Events ambazo Endpoint Security framework inaweza kufuatilia zimeainishwa katika:

- File events
- Process events
- Socket events
- Kernel events (kama vile kupakia/kupakua kernel extension au kufungua I/O Kit device)

### Endpoint Security Framework Architecture

<figure><img src="../../../images/image (1068).png" alt="https://www.youtube.com/watch?v=jaVkpM1UqOs"><figcaption></figcaption></figure>

**Mawasiliano ya user space** na Endpoint Security framework hufanyika kupitia IOUserClient class. Subclasses mbili tofauti hutumiwa, kulingana na aina ya caller:

- **EndpointSecurityDriverClient**: Hii inahitaji entitlement ya `com.apple.private.endpoint-security.manager`, ambayo inamilikiwa tu na system process `endpointsecurityd`.
- **EndpointSecurityExternalClient**: Hii inahitaji entitlement ya `com.apple.developer.endpoint-security.client`. Kwa kawaida hii ingetumiwa na third-party security software inayohitaji kuingiliana na Endpoint Security framework.<sup>[1]</sup>

Endpoint Security Extensions:**`libEndpointSecurity.dylib`** ni C library ambayo system extensions hutumia kuwasiliana na kernel. Library hii hutumia I/O Kit (`IOKit`) kuwasiliana na Endpoint Security KEXT.<sup>[2]</sup>

**`endpointsecurityd`** ni system daemon muhimu inayohusika na kusimamia na kuzindua endpoint security system extensions, hasa wakati wa early boot process. **Ni system extensions tu** zilizo na alama ya **`NSEndpointSecurityEarlyBoot`** katika file yao ya `Info.plist` ndizo zinazopokea utaratibu huu wa early boot.<sup>[2]</sup>

System daemon nyingine, **`sysextd`**, **huthibitisha system extensions** na kuzihamisha kwenda system locations zinazofaa. Kisha huiomba daemon husika ipakie extension hiyo. **`SystemExtensions.framework`** inawajibika ku-activate na ku-deactivate system extensions.<sup>[2]</sup>

## Kubypass ESF

ESF hutumiwa na security tools ambazo zitajaribu kumtambua red teamer, kwa hiyo taarifa yoyote kuhusu jinsi hili linavyoweza kuepukwa inaonekana kuwa ya kuvutia.

### CVE-2021-30965

Jambo ni kwamba security application inahitaji kuwa na **Full Disk Access permissions**. Kwa hiyo ikiwa attacker angeweza kuiondoa, angeweza kuzuia software hiyo ku-run:<sup>[3]</sup>
```bash
tccutil reset All
```
Kwa **maelezo zaidi** kuhusu bypass hii na bypass nyingine zinazohusiana nayo, angalia talk [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

Mwishowe, hili lilirekebishwa kwa kuipa security app inayosimamiwa na **`tccd`** permission mpya **`kTCCServiceEndpointSecurityClient`**, ili `tccutil` isiweze kufuta permissions zake na kuizuia kufanya kazi.<sup>[3]</sup>

## Marejeo

- [1] [OBTS v3.0: "Endpoint Security & Insecurity" - Scott Knight](https://www.youtube.com/watch?v=jaVkpM1UqOs)
- [2] [Knight.sc - System Extension Internals](https://knight.sc/reverse%20engineering/2019/08/24/system-extension-internals.html)
- [3] [#OBTS v5.0: "The Achilles Heel of EndpointSecurity" - Fitzl Csaba](https://www.youtube.com/watch?v=lQO7tvNCoTI)

{{#include ../../../banners/hacktricks-training.md}}

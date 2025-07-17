# macOS Kernel Vulnerabilities

{{#include ../../../banners/hacktricks-training.md}}

## [Pwning OTA](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/)

[**Katika ripoti hii**](https://jhftss.github.io/The-Nightmare-of-Apple-OTA-Update/) zinaelezewa udhaifu kadhaa ambao uliruhusu kuathiri kernel kwa kuathiri mchakato wa sasisho la programu.\
[**PoC**](https://github.com/jhftss/POC/tree/main/CVE-2022-46722).

---

## 2024: In-the-wild Kernel 0-days (CVE-2024-23225 & CVE-2024-23296)

Apple ilirekebisha makosa mawili ya uharibifu wa kumbukumbu ambayo yalitumiwa kwa nguvu dhidi ya iOS na macOS mnamo Machi 2024 (iliyorekebishwa katika macOS 14.4/13.6.5/12.7.4).

* **CVE-2024-23225 – Kernel**
• Kuandika nje ya mipaka katika mfumo wa kumbukumbu wa XNU kunaruhusu mchakato usio na haki kupata kusoma/kuandika bila kikomo katika nafasi ya anwani ya kernel, ikipita PAC/KTRR.
• Imeanzishwa kutoka kwa nafasi ya mtumiaji kupitia ujumbe wa XPC ulioandaliwa ambao unavunja buffer katika `libxpc`, kisha inahamia kwenye kernel wakati ujumbe unachambuliwa.
* **CVE-2024-23296 – RTKit**
• Uharibifu wa kumbukumbu katika RTKit ya Apple Silicon (co-processor wa wakati halisi).
• Mnyororo wa unyakuzi ulioonekana ulitumia CVE-2024-23225 kwa R/W ya kernel na CVE-2024-23296 kutoroka kwenye sandbox ya co-processor salama na kuzima PAC.

Patch level detection:
```bash
sw_vers                 # ProductVersion 14.4 or later is patched
authenticate sudo sysctl kern.osversion  # 23E214 or later for Sonoma
```
Ikiwa kuboresha si iwezekanavyo, punguza hatari kwa kuzima huduma zenye udhaifu:
```bash
launchctl disable system/com.apple.analyticsd
launchctl disable system/com.apple.rtcreportingd
```
---

## 2023: MIG Type-Confusion – CVE-2023-41075

`mach_msg()` maombi yanayotumwa kwa mteja wa IOKit asiye na haki yanaweza kusababisha **kuchanganya aina** katika glue-code inayozalishwa na MIG. Wakati ujumbe wa majibu unavyoeleweka tena kwa desktopu kubwa zaidi ya ile iliyotengwa awali, mshambuliaji anaweza kufikia **OOB write** iliyo na udhibiti katika maeneo ya kernel heap na hatimaye
kuinua hadhi hadi `root`.

Muhtasari wa msingi (Sonoma 14.0-14.1, Ventura 13.5-13.6):
```c
// userspace stub
typed_port_t p = get_user_client();
uint8_t spray[0x4000] = {0x41};
// heap-spray via IOSurfaceFastSetValue
io_service_open_extended(...);
// malformed MIG message triggers confusion
mach_msg(&msg.header, MACH_SEND_MSG|MACH_RCV_MSG, ...);
```
Public exploits zinatumia hitilafu kwa:
1. Kuweka `ipc_kmsg` buffers na viashiria vya bandari vilivyo hai.
2. Kuandika upya `ip_kobject` ya bandari isiyo na mwelekeo.
3. Kuruka kwenye shellcode iliyopangwa kwenye anwani iliyoundwa na PAC kwa kutumia `mprotect()`.

---

## 2024-2025: SIP Bypass kupitia Kexts za Watu wa Tatu – CVE-2024-44243 (aka “Sigma”)

Watafiti wa usalama kutoka Microsoft walionyesha kwamba daemon yenye mamlaka ya juu `storagekitd` inaweza kulazimishwa kupakia **kext ya kernel isiyo na saini** na hivyo kabisa kuzima **Ulinzi wa Uadilifu wa Mfumo (SIP)** kwenye macOS iliyopatikana kikamilifu (kabla ya 15.2). Mchakato wa shambulio ni:

1. Kutumia haki ya kibinafsi `com.apple.storagekitd.kernel-management` ili kuanzisha msaidizi chini ya udhibiti wa mshambuliaji.
2. Msaidizi anaita `IOService::AddPersonalitiesFromKernelModule` na kamusi ya habari iliyoundwa ikielekeza kwenye kifurushi cha kext chenye uharibifu.
3. Kwa sababu ukaguzi wa kuaminika wa SIP unafanywa *baada* ya kext kupangwa na `storagekitd`, msimbo unatekelezwa katika ring-0 kabla ya uthibitisho na SIP inaweza kuzimwa kwa `csr_set_allow_all(1)`.

Vidokezo vya kugundua:
```bash
kmutil showloaded | grep -v com.apple   # list non-Apple kexts
log stream --style syslog --predicate 'senderImagePath contains "storagekitd"'   # watch for suspicious child procs
```
Haraka kurekebisha ni kusasisha hadi macOS Sequoia 15.2 au baadaye.

---

### Kijitabu cha Haraka cha Kuorodhesha
```bash
uname -a                          # Kernel build
kmutil showloaded                 # List loaded kernel extensions
kextstat | grep -v com.apple      # Legacy (pre-Catalina) kext list
sysctl kern.kaslr_enable          # Verify KASLR is ON (should be 1)
csrutil status                    # Check SIP from RecoveryOS
spctl --status                    # Confirms Gatekeeper state
```
---

## Fuzzing & Research Tools

* **Luftrauser** – Mach message fuzzer that targets MIG subsystems (`github.com/preshing/luftrauser`).
* **oob-executor** – IPC out-of-bounds primitive generator used in CVE-2024-23225 research.
* **kmutil inspect** – Built-in Apple utility (macOS 11+) to statically analyse kexts before loading: `kmutil inspect -b io.kext.bundleID`.



## References

* Apple. “Kuhusu maudhui ya usalama ya macOS Sonoma 14.4.” https://support.apple.com/en-us/120895
* Microsoft Security Blog. “Kuchambua CVE-2024-44243, bypass ya Ulinzi wa Uadilifu wa Mfumo wa macOS kupitia nyongeza za kernel.” https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/
{{#include ../../../banners/hacktricks-training.md}}

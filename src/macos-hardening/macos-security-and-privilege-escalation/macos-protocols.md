# macOS Network Services & Protocols

{{#include ../../banners/hacktricks-training.md}}

## Remote Access Services

Hizi ni huduma za kawaida za macOS za kuziweza kufikia kwa mbali.\
Unaweza kuwasha/kuzima huduma hizi katika `System Settings` --> `Sharing`

- **VNC**, inajulikana kama “Screen Sharing” (tcp:5900)
- **SSH**, inaitwa “Remote Login” (tcp:22)
- **Apple Remote Desktop** (ARD), au “Remote Management” (tcp:3283, tcp:5900)
- **AppleEvent**, inajulikana kama “Remote Apple Event” (tcp:3031)

Angalia kama yoyote imewashwa kwa kukimbia:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) ni toleo lililoboreshwa la [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) lililoundwa kwa macOS, likitoa vipengele vya ziada. Uthibitisho wa udhaifu katika ARD ni njia yake ya uthibitishaji kwa ajili ya nenosiri la skrini ya udhibiti, ambayo inatumia tu herufi 8 za kwanza za nenosiri, na kuifanya iwe hatarini kwa [brute force attacks](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) kwa kutumia zana kama Hydra au [GoRedShell](https://github.com/ahhh/GoRedShell/), kwani hakuna mipaka ya kiwango cha kawaida.

Mifano iliyo hatarini inaweza kutambuliwa kwa kutumia **nmap**'s `vnc-info` script. Huduma zinazounga mkono `VNC Authentication (2)` zina hatari zaidi kwa mashambulizi ya brute force kutokana na kukatwa kwa nenosiri la herufi 8.

Ili kuwezesha ARD kwa kazi mbalimbali za kiutawala kama vile kupandisha hadhi, ufikiaji wa GUI, au ufuatiliaji wa mtumiaji, tumia amri ifuatayo:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD inatoa viwango tofauti vya udhibiti, ikiwa ni pamoja na ufuatiliaji, udhibiti wa pamoja, na udhibiti kamili, huku vikao vikidumu hata baada ya mabadiliko ya nenosiri la mtumiaji. Inaruhusu kutuma amri za Unix moja kwa moja, kuzitekeleza kama root kwa watumiaji wa kiutawala. Upangaji wa kazi na utafutaji wa Remote Spotlight ni vipengele vya kutambulika, vinavyorahisisha utafutaji wa mbali, wa athari ndogo kwa faili nyeti katika mashine nyingi.

## Bonjour Protocol

Bonjour, teknolojia iliyoundwa na Apple, inaruhusu **vifaa kwenye mtandao mmoja kugundua huduma zinazotolewa na kila mmoja**. Inajulikana pia kama Rendezvous, **Zero Configuration**, au Zeroconf, inaruhusu kifaa kujiunga na mtandao wa TCP/IP, **kujichagulia anwani ya IP kiotomatiki**, na kutangaza huduma zake kwa vifaa vingine vya mtandao.

Zero Configuration Networking, inayotolewa na Bonjour, inahakikisha kwamba vifaa vinaweza:

- **Kujipatia Anwani ya IP kiotomatiki** hata bila kuwepo kwa seva ya DHCP.
- Kufanya **tafsiri ya jina hadi anwani** bila kuhitaji seva ya DNS.
- **Gundua huduma** zinazopatikana kwenye mtandao.

Vifaa vinavyotumia Bonjour vitajipatia **anwani ya IP kutoka kwenye anuwai ya 169.254/16** na kuthibitisha upekee wake kwenye mtandao. Macs huhifadhi kipengele cha jedwali la routing kwa subnet hii, kinachoweza kuthibitishwa kupitia `netstat -rn | grep 169`.

Kwa DNS, Bonjour inatumia **Multicast DNS (mDNS) protocol**. mDNS inafanya kazi juu ya **port 5353/UDP**, ikitumia **maswali ya kawaida ya DNS** lakini ikilenga **anwani ya multicast 224.0.0.251**. Njia hii inahakikisha kwamba vifaa vyote vinavyosikiliza kwenye mtandao vinaweza kupokea na kujibu maswali, na hivyo kurahisisha sasisho la rekodi zao.

Pale kifaa kinapojiunga na mtandao, kila kifaa kinajichagulia jina, ambacho kwa kawaida kinamalizika kwa **.local**, ambacho kinaweza kutokana na jina la mwenyeji au kutengenezwa kwa bahati nasibu.

Gundua huduma ndani ya mtandao inarahisishwa na **DNS Service Discovery (DNS-SD)**. Kwa kutumia muundo wa rekodi za DNS SRV, DNS-SD inatumia **rekodi za DNS PTR** kuwezesha orodha ya huduma nyingi. Mteja anayepata huduma maalum atahitaji rekodi ya PTR kwa `<Service>.<Domain>`, akipokea orodha ya rekodi za PTR zilizoundwa kama `<Instance>.<Service>.<Domain>` ikiwa huduma inapatikana kutoka kwa mwenyeji wengi.

Zana ya `dns-sd` inaweza kutumika kwa **kugundua na kutangaza huduma za mtandao**. Hapa kuna mifano ya matumizi yake:

### Kutafuta Huduma za SSH

Ili kutafuta huduma za SSH kwenye mtandao, amri ifuatayo inatumika:
```bash
dns-sd -B _ssh._tcp
```
Amri hii inaanzisha kuvinjari huduma za \_ssh.\_tcp na kutoa maelezo kama vile alama ya muda, bendera, kiunganishi, kikoa, aina ya huduma, na jina la mfano.

### Kutangaza Huduma ya HTTP

Ili kutangaza huduma ya HTTP, unaweza kutumia:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Amri hii inasajili huduma ya HTTP iitwayo "Index" kwenye bandari 80 yenye njia ya `/index.html`.

Ili kutafuta huduma za HTTP kwenye mtandao:
```bash
dns-sd -B _http._tcp
```
Wakati huduma inaanza, inatangaza upatikanaji wake kwa vifaa vyote kwenye subnet kwa kutangaza uwepo wake. Vifaa vinavyovutiwa na huduma hizi havihitaji kutuma maombi bali vinahitaji kusikiliza matangazo haya.

Kwa kiolesura kinachofaa kwa mtumiaji, programu ya **Discovery - DNS-SD Browser** inayopatikana kwenye Apple App Store inaweza kuonyesha huduma zinazotolewa kwenye mtandao wako wa ndani.

Vinginevyo, skripti maalum zinaweza kuandikwa ili kuvinjari na kugundua huduma kwa kutumia maktaba ya `python-zeroconf`. Skripti ya [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) inaonyesha jinsi ya kuunda kivinjari cha huduma kwa huduma za `_http._tcp.local.`, ikichapisha huduma zilizoongezwa au kuondolewa:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Kuondoa Bonjour

Ikiwa kuna wasiwasi kuhusu usalama au sababu nyingine za kuondoa Bonjour, inaweza kuzimwa kwa kutumia amri ifuatayo:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Marejeo

- [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt_other?_encoding=UTF8&me=&qid=)
- [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
- [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{{#include ../../banners/hacktricks-training.md}}

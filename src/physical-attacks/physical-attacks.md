# Fizički Napadi

{{#include ../banners/hacktricks-training.md}}

## BIOS Oporavak Lozinke i Bezbednost Sistema

**Resetovanje BIOS-a** može se postići na nekoliko načina. Većina matičnih ploča uključuje **bateriju** koja, kada se ukloni na oko **30 minuta**, resetuje BIOS podešavanja, uključujući lozinku. Alternativno, **jumper na matičnoj ploči** može se prilagoditi za resetovanje ovih podešavanja povezivanjem specifičnih pinova.

Za situacije u kojima prilagođavanje hardvera nije moguće ili praktično, **softverski alati** nude rešenje. Pokretanje sistema sa **Live CD/USB** sa distribucijama kao što je **Kali Linux** omogućava pristup alatima kao što su **_killCmos_** i **_CmosPWD_**, koji mogu pomoći u oporavku BIOS lozinke.

U slučajevima kada je BIOS lozinka nepoznata, pogrešno unošenje **tri puta** obično rezultira kodom greške. Ovaj kod se može koristiti na sajtovima kao što je [https://bios-pw.org](https://bios-pw.org) da bi se potencijalno povratila upotrebljiva lozinka.

### UEFI Bezbednost

Za moderne sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** može se koristiti za analizu i modifikaciju UEFI podešavanja, uključujući onemogućavanje **Secure Boot**. To se može postići sledećom komandom:

`python chipsec_main.py -module exploits.secure.boot.pk`

### Analiza RAM-a i Hladni Napadi

RAM zadržava podatke kratko nakon isključenja napajanja, obično od **1 do 2 minuta**. Ova postojanost može se produžiti na **10 minuta** primenom hladnih supstanci, kao što je tečni azot. Tokom ovog produženog perioda, može se napraviti **memory dump** koristeći alate kao što su **dd.exe** i **volatility** za analizu.

### Napadi Direktnog Pristupa Memoriji (DMA)

**INCEPTION** je alat dizajniran za **fizičku manipulaciju memorijom** putem DMA, kompatibilan sa interfejsima kao što su **FireWire** i **Thunderbolt**. Omogućava zaobilaženje procedura prijavljivanja patchovanjem memorije da prihvati bilo koju lozinku. Međutim, nije efikasan protiv **Windows 10** sistema.

### Live CD/USB za Pristup Sistemu

Promena sistemskih binarnih fajlova kao što su **_sethc.exe_** ili **_Utilman.exe_** kopijom **_cmd.exe_** može omogućiti komandnu liniju sa sistemskim privilegijama. Alati kao što su **chntpw** mogu se koristiti za uređivanje **SAM** fajla Windows instalacije, omogućavajući promene lozinke.

**Kon-Boot** je alat koji olakšava prijavljivanje na Windows sisteme bez poznavanja lozinke tako što privremeno modifikuje Windows kernel ili UEFI. Više informacija može se naći na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

### Rukovanje Windows Bezbednosnim Funkcijama

#### Prečice za Pokretanje i Oporavak

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u režim oporavka.
- Pritiskom na **Shift** nakon Windows banera može se zaobići automatsko prijavljivanje.

#### BAD USB Uređaji

Uređaji kao što su **Rubber Ducky** i **Teensyduino** služe kao platforme za kreiranje **bad USB** uređaja, sposobnih za izvršavanje unapred definisanih payload-a kada su povezani na ciljni računar.

#### Volume Shadow Copy

Administratorske privilegije omogućavaju kreiranje kopija osetljivih fajlova, uključujući **SAM** fajl, putem PowerShell-a.

### Zaobilaženje BitLocker Enkripcije

BitLocker enkripcija može se potencijalno zaobići ako se **recovery password** pronađe unutar fajla sa memory dump-om (**MEMORY.DMP**). Alati kao što su **Elcomsoft Forensic Disk Decryptor** ili **Passware Kit Forensic** mogu se koristiti u tu svrhu.

### Socijalno Inženjerstvo za Dodavanje Ključa za Oporavak

Novi BitLocker recovery key može se dodati putem taktika socijalnog inženjeringa, ubeđujući korisnika da izvrši komandu koja dodaje novi recovery key sastavljen od nula, čime se pojednostavljuje proces dekripcije.

{{#include ../banners/hacktricks-training.md}}

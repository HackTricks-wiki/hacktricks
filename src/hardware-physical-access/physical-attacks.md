# Fizički napadi

{{#include ../banners/hacktricks-training.md}}

## Oporavak BIOS lozinke i bezbednost sistema

**Resetovanje BIOS-a** može se postići na nekoliko načina. Većina matičnih ploča uključuje **bateriju** koja, kada se ukloni na oko **30 minuta**, resetuje BIOS podešavanja, uključujući lozinku. Alternativno, **jumper na matičnoj ploči** može se prilagoditi da resetuje ova podešavanja povezivanjem specifičnih pinova.

Za situacije u kojima prilagođavanje hardvera nije moguće ili praktično, **softverski alati** nude rešenje. Pokretanje sistema sa **Live CD/USB** sa distribucijama kao što je **Kali Linux** omogućava pristup alatima kao što su **_killCmos_** i **_CmosPWD_**, koji mogu pomoći u oporavku BIOS lozinke.

U slučajevima kada je BIOS lozinka nepoznata, pogrešno unošenje **tri puta** obično rezultira kodom greške. Ovaj kod se može koristiti na sajtovima kao što je [https://bios-pw.org](https://bios-pw.org) da bi se potencijalno povratila upotrebljiva lozinka.

### UEFI bezbednost

Za moderne sisteme koji koriste **UEFI** umesto tradicionalnog BIOS-a, alat **chipsec** može se koristiti za analizu i modifikaciju UEFI podešavanja, uključujući onemogućavanje **Secure Boot**. To se može postići sledećom komandom:
```bash
python chipsec_main.py -module exploits.secure.boot.pk
```
---

## RAM analiza i Cold Boot napadi

RAM zadržava podatke kratko nakon isključenja napajanja, obično **1 do 2 minuta**. Ova postojanost može se produžiti na **10 minuta** primenom hladnih supstanci, kao što je tečni azot. Tokom ovog produženog perioda, može se napraviti **memory dump** koristeći alate kao što su **dd.exe** i **volatility** za analizu.

---

## Napadi direktnog pristupa memoriji (DMA)

**INCEPTION** je alat dizajniran za **fizičku manipulaciju memorijom** putem DMA, kompatibilan sa interfejsima kao što su **FireWire** i **Thunderbolt**. Omogućava zaobilaženje procedura prijavljivanja patchovanjem memorije da prihvati bilo koju lozinku. Međutim, nije efikasan protiv **Windows 10** sistema.

---

## Live CD/USB za pristup sistemu

Promena sistemskih binarnih datoteka kao što su **_sethc.exe_** ili **_Utilman.exe_** kopijom **_cmd.exe_** može omogućiti komandnu liniju sa sistemskim privilegijama. Alati kao što su **chntpw** mogu se koristiti za uređivanje **SAM** datoteke Windows instalacije, omogućavajući promene lozinki.

**Kon-Boot** je alat koji olakšava prijavljivanje na Windows sisteme bez poznavanja lozinke tako što privremeno menja Windows kernel ili UEFI. Više informacija može se naći na [https://www.raymond.cc](https://www.raymond.cc/blog/login-to-windows-administrator-and-linux-root-account-without-knowing-or-changing-current-password/).

---

## Rukovanje Windows bezbednosnim funkcijama

### Prečice za pokretanje i oporavak

- **Supr**: Pristup BIOS podešavanjima.
- **F8**: Ulazak u režim oporavka.
- Pritiskom na **Shift** nakon Windows banera može se zaobići automatsko prijavljivanje.

### BAD USB uređaji

Uređaji kao što su **Rubber Ducky** i **Teensyduino** služe kao platforme za kreiranje **bad USB** uređaja, sposobnih za izvršavanje unapred definisanih payload-a kada su povezani na ciljni računar.

### Volume Shadow Copy

Administratorske privilegije omogućavaju kreiranje kopija osetljivih datoteka, uključujući **SAM** datoteku, putem PowerShell-a.

---

## Zaobilaženje BitLocker enkripcije

BitLocker enkripcija može se potencijalno zaobići ako se **oporavak lozinka** pronađe unutar datoteke memory dump (**MEMORY.DMP**). Alati kao što su **Elcomsoft Forensic Disk Decryptor** ili **Passware Kit Forensic** mogu se koristiti u tu svrhu.

---

## Socijalni inženjering za dodavanje ključa za oporavak

Novi BitLocker ključ za oporavak može se dodati putem taktika socijalnog inženjeringa, ubeđujući korisnika da izvrši komandu koja dodaje novi ključ za oporavak sastavljen od nula, čime se pojednostavljuje proces dekripcije.

---

## Iskorišćavanje prekidača za ulaz u kućište / održavanje za vraćanje BIOS-a na fabrička podešavanja

Mnogi moderni laptopi i desktop računari malih formata uključuju **prekidač za ulaz u kućište** koji nadgleda Embedded Controller (EC) i BIOS/UEFI firmware. Dok je primarna svrha prekidača da podiže alarm kada se uređaj otvori, proizvođači ponekad implementiraju **nedokumentovanu prečicu za oporavak** koja se aktivira kada se prekidač prebacuje u određenom obrascu.

### Kako napad funkcioniše

1. Prekidač je povezan na **GPIO prekid** na EC.
2. Firmware koji radi na EC prati **vreme i broj pritisaka**.
3. Kada se prepozna hard-kodirani obrazac, EC pokreće *mainboard-reset* rutinu koja **briše sadržaj sistemskog NVRAM/CMOS**.
4. Pri sledećem pokretanju, BIOS učitava podrazumevane vrednosti – **supervizorska lozinka, Secure Boot ključevi i sve prilagođene konfiguracije se brišu**.

> Kada je Secure Boot onemogućen i lozinka firmware-a nestane, napadač može jednostavno pokrenuti bilo koju eksternu OS sliku i dobiti neograničen pristup unutrašnjim diskovima.

### Primer iz stvarnog sveta – Framework 13 laptop

Prečica za oporavak za Framework 13 (11. / 12. / 13. generacija) je:
```text
Press intrusion switch  →  hold 2 s
Release                 →  wait 2 s
(repeat the press/release cycle 10× while the machine is powered)
```
Nakon desete petlje, EC postavlja zastavicu koja naređuje BIOS-u da obriše NVRAM pri sledećem ponovnom pokretanju. Cela procedura traje ~40 s i zahteva **samo odvijač**.

### Opšta Procedura Eksploatacije

1. Uključite ili suspendujte-cvrcnite cilj kako bi EC radio.
2. Uklonite donji poklopac da biste otkrili prekidač za intruziju/održavanje.
3. Ponovite specifičan obrazac prebacivanja proizvođača (proverite dokumentaciju, forume ili obavite reverzno inženjerstvo EC firmvera).
4. Ponovo sastavite i ponovo pokrenite – zaštite firmvera bi trebale biti onemogućene.
5. Pokrenite live USB (npr. Kali Linux) i izvršite uobičajene post-eksploatacione radnje (izvlačenje kredencijala, eksfiltracija podataka, implantacija zlonamernih EFI binarnih datoteka, itd.).

### Detekcija i Ublažavanje

* Zabeležite događaje o intruziji šasije u OS upravljačkoj konzoli i povežite ih sa neočekivanim BIOS resetovanjima.
* Koristite **pečate otpora** na šrafovima/poklopcima da biste otkrili otvaranje.
* Držite uređaje u **fizički kontrolisanim oblastima**; pretpostavite da fizički pristup znači potpunu kompromitaciju.
* Gde je dostupno, onemogućite funkciju "reset prekidača za održavanje" proizvođača ili zahtevajte dodatnu kriptografsku autorizaciju za NVRAM resetovanja.

---

## Reference

- [Pentest Partners – “Framework 13. Press here to pwn”](https://www.pentestpartners.com/security-blog/framework-13-press-here-to-pwn/)
- [FrameWiki – Vodič za resetovanje glavne ploče](https://framewiki.net/guides/mainboard-reset)

{{#include ../banners/hacktricks-training.md}}

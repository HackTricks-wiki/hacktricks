{{#include ../../banners/hacktricks-training.md}}

# Vremenske oznake

Napadač može biti zainteresovan za **promenu vremenskih oznaka datoteka** kako bi izbegao otkrivanje.\
Moguće je pronaći vremenske oznake unutar MFT u atributima `$STANDARD_INFORMATION` ** i ** `$FILE_NAME`.

Oba atributa imaju 4 vremenske oznake: **Izmena**, **pristup**, **kreiranje** i **izmena MFT registra** (MACE ili MACB).

**Windows explorer** i drugi alati prikazuju informacije iz **`$STANDARD_INFORMATION`**.

## TimeStomp - Anti-forenzički alat

Ovaj alat **menja** informacije o vremenskim oznakama unutar **`$STANDARD_INFORMATION`** **ali** **ne** informacije unutar **`$FILE_NAME`**. Stoga, moguće je **identifikovati** **sumnjivu** **aktivnost**.

## Usnjrnl

**USN Journal** (Dnevnik broja ažuriranja) je funkcija NTFS (Windows NT datotečni sistem) koja prati promene na volumenu. Alat [**UsnJrnl2Csv**](https://github.com/jschicht/UsnJrnl2Csv) omogućava ispitivanje ovih promena.

![](<../../images/image (449).png>)

Prethodna slika je **izlaz** prikazan od strane **alata** gde se može primetiti da su neke **promene izvršene** na datoteci.

## $LogFile

**Sve promene metapodataka na datotečnom sistemu se beleže** u procesu poznatom kao [write-ahead logging](https://en.wikipedia.org/wiki/Write-ahead_logging). Beleženi metapodaci se čuvaju u datoteci nazvanoj `**$LogFile**`, koja se nalazi u korenskom direktorijumu NTFS datotečnog sistema. Alati kao što su [LogFileParser](https://github.com/jschicht/LogFileParser) mogu se koristiti za analizu ove datoteke i identifikaciju promena.

![](<../../images/image (450).png>)

Ponovo, u izlazu alata moguće je videti da su **neke promene izvršene**.

Korišćenjem istog alata moguće je identifikovati **na koji način su vremenske oznake promenjene**:

![](<../../images/image (451).png>)

- CTIME: Vreme kreiranja datoteke
- ATIME: Vreme izmene datoteke
- MTIME: Izmena MFT registra datoteke
- RTIME: Vreme pristupa datoteci

## Poređenje `$STANDARD_INFORMATION` i `$FILE_NAME`

Još jedan način da se identifikuju sumnjivo izmenjene datoteke bio bi da se uporede vremena na oba atributa tražeći **neusklađenosti**.

## Nanosekunde

**NTFS** vremenske oznake imaju **preciznost** od **100 nanosekundi**. Stoga, pronalaženje datoteka sa vremenskim oznakama poput 2010-10-10 10:10:**00.000:0000 je veoma sumnjivo**.

## SetMace - Anti-forenzički alat

Ovaj alat može izmeniti oba atributa `$STARNDAR_INFORMATION` i `$FILE_NAME`. Međutim, od Windows Vista, potrebno je da živi OS izmeni ove informacije.

# Sakrivanje podataka

NFTS koristi klaster i minimalnu veličinu informacija. To znači da ako datoteka koristi i klaster i po i po, **preostala polovina nikada neće biti korišćena** dok se datoteka ne obriše. Stoga, moguće je **sakriti podatke u ovom slobodnom prostoru**.

Postoje alati poput slacker koji omogućavaju sakrivanje podataka u ovom "skrivenom" prostoru. Međutim, analiza `$logfile` i `$usnjrnl` može pokazati da su neki podaci dodati:

![](<../../images/image (452).png>)

Stoga, moguće je povratiti slobodan prostor koristeći alate poput FTK Imager. Imajte na umu da ovaj tip alata može sačuvati sadržaj obfuskovan ili čak enkriptovan.

# UsbKill

Ovo je alat koji će **isključiti računar ako se otkrije bilo kakva promena na USB** portovima.\
Jedan od načina da se to otkrije bio bi da se ispita pokrenuti procesi i **pregleda svaki python skript koji se izvršava**.

# Live Linux distribucije

Ove distribucije se **izvršavaju unutar RAM** memorije. Jedini način da ih otkrijete je **ukoliko je NTFS datotečni sistem montiran sa dozvolama za pisanje**. Ako je montiran samo sa dozvolama za čitanje, neće biti moguće otkriti upad.

# Sigurno brisanje

[https://github.com/Claudio-C/awesome-data-sanitization](https://github.com/Claudio-C/awesome-data-sanitization)

# Windows konfiguracija

Moguće je onemogućiti nekoliko metoda beleženja u Windows-u kako bi se forenzička istraga učinila mnogo težom.

## Onemogući vremenske oznake - UserAssist

Ovo je ključ registra koji održava datume i sate kada je svaki izvršni program pokrenut od strane korisnika.

Onemogućavanje UserAssist zahteva dva koraka:

1. Postavite dva ključa registra, `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackProgs` i `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_TrackEnabled`, oba na nulu kako bismo signalizirali da želimo da onemogućimo UserAssist.
2. Očistite svoje podključeve registra koji izgledaju kao `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\<hash>`.

## Onemogući vremenske oznake - Prefetch

Ovo će sačuvati informacije o aplikacijama koje su izvršene sa ciljem poboljšanja performansi Windows sistema. Međutim, ovo može biti korisno i za forenzičke prakse.

- Izvršite `regedit`
- Izaberite putanju datoteke `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\PrefetchParameters`
- Desni klik na `EnablePrefetcher` i `EnableSuperfetch`
- Izaberite Izmeni na svakom od ovih da promenite vrednost sa 1 (ili 3) na 0
- Ponovo pokrenite

## Onemogući vremenske oznake - Vreme poslednjeg pristupa

Kad god se folder otvori sa NTFS volumena na Windows NT serveru, sistem uzima vreme da **ažurira polje vremenske oznake na svakom navedenom folderu**, koje se naziva vreme poslednjeg pristupa. Na NTFS volumenu koji se često koristi, ovo može uticati na performanse.

1. Otvorite Registry Editor (Regedit.exe).
2. Pretražite do `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem`.
3. Potražite `NtfsDisableLastAccessUpdate`. Ako ne postoji, dodajte ovaj DWORD i postavite njegovu vrednost na 1, što će onemogućiti proces.
4. Zatvorite Registry Editor i ponovo pokrenite server.

## Obriši USB istoriju

Sve **USB Device Entries** se čuvaju u Windows Registry pod ključem **USBSTOR** koji sadrži podključeve koji se kreiraju svaki put kada priključite USB uređaj na svoj PC ili laptop. Možete pronaći ovaj ključ ovde `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR`. **Brisanjem ovog** obrišete USB istoriju.\
Takođe možete koristiti alat [**USBDeview**](https://www.nirsoft.net/utils/usb_devices_view.html) da biste bili sigurni da ste ih obrisali (i da ih obrišete).

Još jedna datoteka koja čuva informacije o USB-ima je datoteka `setupapi.dev.log` unutar `C:\Windows\INF`. Ova datoteka takođe treba da bude obrisana.

## Onemogući senčne kopije

**Prikaz** senčnih kopija sa `vssadmin list shadowstorage`\
**Obrišite** ih pokretanjem `vssadmin delete shadow`

Takođe ih možete obrisati putem GUI prateći korake predložene na [https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html](https://www.ubackup.com/windows-10/how-to-delete-shadow-copies-windows-10-5740.html)

Da biste onemogućili senčne kopije [koraci odavde](https://support.waters.com/KB_Inf/Other/WKB15560_How_to_disable_Volume_Shadow_Copy_Service_VSS_in_Windows):

1. Otvorite program Services tako što ćete otkucati "services" u tekstualnu pretragu nakon što kliknete na Windows dugme za pokretanje.
2. Na listi pronađite "Volume Shadow Copy", izaberite ga, a zatim pristupite Svojstvima desnim klikom.
3. Izaberite Onemogućeno iz padajućeg menija "Tip pokretanja", a zatim potvrdite promenu klikom na Primeni i U redu.

Takođe je moguće izmeniti konfiguraciju koje datoteke će biti kopirane u senčnu kopiju u registru `HKLM\SYSTEM\CurrentControlSet\Control\BackupRestore\FilesNotToSnapshot`

## Prepiši obrisane datoteke

- Možete koristiti **Windows alat**: `cipher /w:C` Ovo će označiti cipher da ukloni sve podatke iz dostupnog neiskorišćenog prostora na disku unutar C diska.
- Takođe možete koristiti alate poput [**Eraser**](https://eraser.heidi.ie)

## Obriši Windows događaje

- Windows + R --> eventvwr.msc --> Proširite "Windows Logs" --> Desni klik na svaku kategoriju i izaberite "Clear Log"
- `for /F "tokens=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"`
- `Get-EventLog -LogName * | ForEach { Clear-EventLog $_.Log }`

## Onemogući Windows događaje

- `reg add 'HKLM\SYSTEM\CurrentControlSet\Services\eventlog' /v Start /t REG_DWORD /d 4 /f`
- Unutar sekcije servisa onemogućite servis "Windows Event Log"
- `WEvtUtil.exec clear-log` ili `WEvtUtil.exe cl`

## Onemogući $UsnJrnl

- `fsutil usn deletejournal /d c:`

{{#include ../../banners/hacktricks-training.md}}

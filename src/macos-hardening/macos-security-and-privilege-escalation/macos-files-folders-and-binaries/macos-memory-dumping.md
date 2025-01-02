# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Swap datoteke, kao što je `/private/var/vm/swapfile0`, služe kao **keš kada je fizička memorija puna**. Kada više nema prostora u fizičkoj memoriji, njeni podaci se prebacuju u swap datoteku i zatim vraćaju u fizičku memoriju po potrebi. Mogu postojati više swap datoteka, sa imenima kao što su swapfile0, swapfile1, i tako dalje.

### Hibernate Image

Datoteka koja se nalazi na `/private/var/vm/sleepimage` je ključna tokom **hibernacije**. **Podaci iz memorije se čuvaju u ovoj datoteci kada OS X hibernira**. Kada se računar probudi, sistem preuzima podatke iz memorije iz ove datoteke, omogućavajući korisniku da nastavi gde je stao.

Vredno je napomenuti da je na modernim MacOS sistemima ova datoteka obično enkriptovana iz bezbednosnih razloga, što otežava oporavak.

- Da biste proverili da li je enkripcija omogućena za sleepimage, može se pokrenuti komanda `sysctl vm.swapusage`. Ovo će pokazati da li je datoteka enkriptovana.

### Memory Pressure Logs

Još jedna važna datoteka vezana za memoriju u MacOS sistemima je **log pritiska memorije**. Ovi logovi se nalaze u `/var/log` i sadrže detaljne informacije o korišćenju memorije sistema i događajima pritiska. Mogu biti posebno korisni za dijagnostikovanje problema vezanih za memoriju ili razumevanje kako sistem upravlja memorijom tokom vremena.

## Dumping memory with osxpmem

Da biste dumpovali memoriju na MacOS mašini, možete koristiti [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Napomena**: Sledeće instrukcije će raditi samo za Mac računare sa Intel arhitekturom. Ovaj alat je sada arhiviran i poslednje izdanje je bilo 2017. godine. Binarna datoteka preuzeta koristeći sledeće instrukcije cilja Intel čipove, jer Apple Silicon nije postojao 2017. godine. Možda će biti moguće kompajlirati binarnu datoteku za arm64 arhitekturu, ali to ćete morati da probate sami.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Ako pronađete ovu grešku: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Možete je popraviti na sledeći način:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Drugi problemi** mogu biti rešeni **dozvoljavanjem učitavanja kext-a** u "Bezbednost i privatnost --> Opšte", samo **dozvolite** to.

Takođe možete koristiti ovaj **oneliner** za preuzimanje aplikacije, učitavanje kext-a i dumpovanje memorije:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}

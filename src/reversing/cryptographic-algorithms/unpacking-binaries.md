{{#include ../../banners/hacktricks-training.md}}

# Identifikacija pakovanih binarnih datoteka

- **nedostatak stringova**: Uobičajeno je da pakovane binarne datoteke gotovo da nemaju stringove
- Puno **neiskorišćenih stringova**: Takođe, kada malware koristi neku vrstu komercijalnog pakera, uobičajeno je pronaći puno stringova bez međureferenci. Čak i ako ovi stringovi postoje, to ne znači da binarna datoteka nije pakovana.
- Takođe možete koristiti neke alate da pokušate da otkrijete koji je pakera korišćen za pakovanje binarne datoteke:
- [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
- [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
- [Language 2000](http://farrokhi.net/language/)

# Osnovne preporuke

- **Počnite** analizu pakovane binarne datoteke **od dna u IDA i pomerajte se ka vrhu**. Alati za dekompresiju izlaze kada dekompresovani kod završi, tako da je malo verovatno da će dekompresor preneti izvršenje na dekompresovani kod na početku.
- Pretražujte za **JMP-ovima** ili **CALL-ovima** ka **registrima** ili **regionima** **memorije**. Takođe pretražujte za **funkcijama koje prosleđuju argumente i adresu, a zatim pozivaju `retn`**, jer povratak funkcije u tom slučaju može pozvati adresu koja je upravo stavljena na stek pre poziva.
- Postavite **prekidač** na `VirtualAlloc` jer ovo alocira prostor u memoriji gde program može pisati dekompresovani kod. "Pokreni do korisničkog koda" ili koristite F8 da **dobijete vrednost unutar EAX** nakon izvršavanja funkcije i "**pratite tu adresu u dump-u**". Nikada ne znate da li je to region gde će dekompresovani kod biti sačuvan.
- **`VirtualAlloc`** sa vrednošću "**40**" kao argument znači Čitanje+Pisanje+Izvršavanje (neki kod koji treba da se izvrši će biti kopiran ovde).
- **Tokom dekompresije** koda normalno je pronaći **several calls** ka **aritmetičkim operacijama** i funkcijama kao što su **`memcopy`** ili **`Virtual`**`Alloc`. Ako se nađete u funkciji koja očigledno samo vrši aritmetičke operacije i možda neki `memcopy`, preporuka je da pokušate da **pronađete kraj funkcije** (možda JMP ili poziv nekom registru) **ili** barem **poziv poslednje funkcije** i trčite do nje jer kod nije zanimljiv.
- Tokom dekompresije koda **obratite pažnju** kada **promenite region memorije** jer promena regiona memorije može ukazivati na **početak dekompresionog koda**. Možete lako dump-ovati region memorije koristeći Process Hacker (process --> properties --> memory).
- Dok pokušavate da dekompresujete kod, dobar način da **znate da li već radite sa dekompresovanim kodom** (tako da ga možete samo dump-ovati) je da **proverite stringove binarne datoteke**. Ako u nekom trenutku izvršite skok (možda menjajući region memorije) i primetite da su **dodati mnogi više stringova**, tada možete znati **da radite sa dekompresovanim kodom**.\
Međutim, ako pakera već sadrži puno stringova, možete videti koliko stringova sadrži reč "http" i proveriti da li se ovaj broj povećava.
- Kada dump-ujete izvršnu datoteku iz regiona memorije, možete ispraviti neke zaglavlja koristeći [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

{{#include ../../banners/hacktricks-training.md}}

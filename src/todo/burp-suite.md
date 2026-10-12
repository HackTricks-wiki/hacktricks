# Burp Suite

{{#include ../banners/hacktricks-training.md}}

## Intruder tipovi payload-a

Burp Intruder sadrži sledeće ugrađene generatore i transformacije payload-a:<sup>[[1]](#references)</sup>

- **Simple list:** Koristi podešenu listu stringova kao payload-e.
- **Runtime file:** Čita po jedan payload iz svakog reda u trenutku izvršavanja. Ovo je korisno za velike liste jer Burp ne učitava celu datoteku u memoriju.
- **Case modification:** Generiše neizmenjenu vrednost, verziju sa malim i velikim slovima, `Propername` (prvo slovo veliko, a ostala mala) ili `ProperName` (prvo slovo veliko, a ostali znakovi nepromenjeni). Burp odbacuje duplikate.
- **Numbers:** Generiše sekvencijalne ili nasumične brojeve u podešenom opsegu.
- **Brute forcer:** Generiše sve permutacije za izabrani skup znakova i minimalnu/maksimalnu dužinu.

## Ekstenzije i prateći alati

- **Collabfiltrator** generiše payload-e koji izvršavaju komande i eksfiltriraju njihov izlaz putem DNS upita ka Burp Collaborator-u.<sup>[[2]](#references)</sup>
- **Burp Suite Exporter** izvozi nalaze iz Burp-a za upotrebu u drugim izveštajnim tokovima rada.<sup>[[3]](#references)</sup>
- **HTTP Script Generator** pretvara HTTP zahteve u skripte na nekoliko jezika.<sup>[[4]](#references)</sup>

## Testiranje autorizacije sa više sesija pomoću Session Switcher-a

[Session Switcher](https://github.com/doyensec/burp-session-switcher) je Java ekstenzija za Burp Suite `2025.5+` koja čuva kolačiće i neuobičajena zaglavlja u imenovanim profilima akreditiva. Izbor profila u uređivaču zahteva koji se može menjati, uključujući Repeater ili presretnuti Proxy zahtev, zamenjuje autentikacione podatke zahteva. Ovo služi za ponovno slanje zahteva, **ne za zaobilaženje autorizacije**: koristite ga da pošaljete isti zahtev kao različiti nalozi pri proveri horizontalnog pristupa, granica uloga, izolacije tenanata i [IDOR/BOLA](../pentesting-web/idor.md), u okviru [metodologije testiranja web aplikacija](../pentesting-web/web-vulnerabilities-methodology.md).<sup>[[5]](#references)[[8]](#references)</sup>

### Ponovljiv tok rada za poređenje identiteta

Sledeći tok rada drži resurs/radnju i identitet korisnika kao odvojene testne promenljive, čime se smanjuju lažno pozitivni rezultati uzrokovani zastarelim tokenima ili pogrešnom sesijom pregledača.<sup>[[5]](#references)[[8]](#references)</sup>

1. Prijavite testne naloge koji predstavljaju svakog relevantnog korisnika, ulogu i tenant u zasebnim profilima pregledača ili kontejnerima.
2. Otvorite zahtev koji sadrži kolačiće i zaglavlja jednog identiteta, izaberite **Sessions > New** i dajte profilu jasno ime, na primer `tenant-a-user` ili `tenant-b-admin`. Ponovite za svaki testni identitet.
3. Pošaljite zahtev u Repeater i ponovo ga pošaljite bez menjanja metode, krajnje tačke, parametara ili identifikatora objekta, menjajući samo izabranu sesiju. Uporedite podatke iz odgovora i uočljive promene stanja, a ne samo statusne kodove.
4. Za provere na nivou objekta, ponovo pošaljite zahtev za objekat za koji se zna da pripada nalogu A, izabravši profil naloga B. Za provere na nivou funkcije, ponovo pošaljite istu privilegovanu radnju koristeći profile sa nižim privilegijama.
5. Nakon ponovne autentikacije ili rotacije tokena, upotrebite **Update** na aktuelnom zahtevu pregledača ili konfigurišite pravilo Auto Update pre ponavljanja poređenja.

### Semantika hvatanja i ubacivanja

Pre testiranja pregledajte režime ažuriranja/ubacivanja, jer hibridni zahtev koji sadrži akreditive dva identiteta može da poništi validnost poređenja. Podrazumevana podešavanja kopiraju sve kolačiće zahteva u profil, ažuriraju samo već sačuvana neuobičajena zaglavlja, kopiraju kolačiće izabranog profila u odredišni zahtev (uklanjajući njegove postojeće kolačiće) i dodaju zaglavlja profila. Izbor profila može se ograničiti na tačan poddomen, domen aplikacije najvišeg nivoa (podrazumevano) ili sve sačuvane profile.<sup>[[7]](#references)</sup>

- **Mirror** je koristan kada ceo skup kolačića određuje identitet i treba ukloniti zastarele kolačiće odredišnog zahteva.
- **Update existing** prati vrednosti koje se rotiraju, bez preuzimanja nepovezanih kolačića ili zaglavlja iz saobraćaja pregledača.
- **Add all** čuva dodatne vrednosti koje su već sačuvane u profilu ili zahtevu; proverite da time ne ostanu podaci prethodne sesije koji otkrivaju identitet.
- **Do nothing** isključuje kolačiće ili zaglavlja iz ažuriranja profila kada ta klasa akreditiva nije relevantna.

### Sinhronizacija sesija preko Proxy-ja

Pravila Auto Update povezuju saobraćaj Proxy-ja sa sačuvanim profilom i osvežavaju njegove kolačiće/zaglavlja. Dajte prednost stabilnom diskriminatoru kao što je namensko zaglavlje zahteva, oznaka specifična za profil u `User-Agent`, identifikacioni kolačić, `X-PwnFox-Color` ili JWT claim; kombinujte ga sa uslovima opsega/domena/putanje kako nepovezane aplikacije ne bi mogle da ažuriraju profil. Svi uslovi u jednom pravilu proveravaju se redom kao logičko `AND`, zato prvo navedite restriktivne provere; `OR` ostvarite kreiranjem više pravila koja ciljaju isti profil. Podržano je i negativno podudaranje.<sup>[[6]](#references)</sup>

Za svako pravilo koje se podudara nezavisno izaberite **Mirror request**, **Add all**, **Update existing** ili **Do nothing** za kolačiće i zaglavlja. Pravila koja proveravaju samo zahtev pokreću se kada Proxy primi zahtev; dodavanje uslova za status odgovora, zaglavlje odgovora ili telo odgovora odlaže proveru dok odgovor ne stigne. Boja za isticanje može označiti saobraćaj koji se podudara, što olakšava proveru da svaki identitet pregledača ažurira samo predviđeni profil.<sup>[[6]](#references)</sup>

Sačuvani profili nalaze se u Burp projektu, a JSON izvozi podataka projekta uključuju sesije, odnosno njihove kolačiće i zaglavlja. Tretirajte obe vrste datoteka kao aktivne akreditive, ograničite im pristup i obrišite sačuvane podatke ekstenzije nakon angažmana.<sup>[[7]](#references)[[8]](#references)</sup>

## References

- [1] [PortSwigger dokumentacija - tipovi payload-a za Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/payload-types)
- [2] [GitHub - 0xC01DF00D/Collabfiltrator](https://github.com/0xC01DF00D/Collabfiltrator)
- [3] [ArtsSEC - Burp Suite Exporter](https://medium.com/@ArtsSEC/burp-suite-exporter-462531be24e)
- [4] [GitHub - h3xstream/http-script-generator](https://github.com/h3xstream/http-script-generator)
- [5] [Doyensec - dokumentacija za izvorni kod i upotrebu Session Switcher-a](https://github.com/doyensec/burp-session-switcher)
- [6] [Doyensec - pravila Auto Update za Session Switcher](https://github.com/doyensec/burp-session-switcher/blob/main/docs/auto_update_rules.md)
- [7] [Doyensec - podešavanja Session Switcher-a](https://github.com/doyensec/burp-session-switcher/blob/main/docs/settings.md)
- [8] [Doyensec - Session Switcher: pojednostavljeno testiranje autorizacije sa više sesija u Burp Suite-u](https://blog.doyensec.com/2026/06/17/session-switcher.html)
{{#include ../banners/hacktricks-training.md}}

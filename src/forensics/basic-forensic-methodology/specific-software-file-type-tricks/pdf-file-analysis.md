# PDF analiza

{{#include ../../../banners/hacktricks-training.md}}

**Za više detalja proverite:** [**https://trailofbits.github.io/ctf/forensics/**](https://trailofbits.github.io/ctf/forensics/)

PDF format je poznat po svojoj složenosti i potencijalu za prikrivanje podataka, što ga čini centralnom tačkom za CTF forenzičke izazove. Kombinuje elemente običnog teksta sa binarnim objektima, koji mogu biti kompresovani ili enkriptovani, i može uključivati skripte u jezicima kao što su JavaScript ili Flash. Da bi se razumeo PDF struktura, može se konsultovati [uvodni materijal](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/) Didiera Stevensa, ili koristiti alate kao što su tekstualni editor ili PDF-specifični editor kao što je Origami.

Za dubinsko istraživanje ili manipulaciju PDF-ova, dostupni su alati kao što su [qpdf](https://github.com/qpdf/qpdf) i [Origami](https://github.com/mobmewireless/origami-pdf). Sakriveni podaci unutar PDF-ova mogu biti prikriveni u:

- Nevidljivim slojevima
- XMP metapodacima formata od Adobe-a
- Inkrementalnim generacijama
- Tekstu iste boje kao pozadina
- Tekstu iza slika ili preklapajućih slika
- Neprikazanim komentarima

Za prilagođenu analizu PDF-a, Python biblioteke kao što su [PeepDF](https://github.com/jesparza/peepdf) mogu se koristiti za izradu specijalizovanih skripti za parsiranje. Pored toga, potencijal PDF-a za skladištenje skrivenih podataka je toliko ogroman da resursi poput NSA vodiča o rizicima i protivmera vezanim za PDF, iako više nisu dostupni na svojoj originalnoj lokaciji, i dalje nude dragocene uvide. [Kopija vodiča](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf) i kolekcija [trikova za PDF format](https://github.com/corkami/docs/blob/master/PDF/PDF.md) od Ange Albertinija mogu pružiti dodatno čitanje o ovoj temi.

{{#include ../../../banners/hacktricks-training.md}}

# ZIPs trikovi

{{#include ../../../banners/hacktricks-training.md}}

**Alatke za komandnu liniju** za upravljanje **zip datotekama** su neophodne za dijagnostikovanje, popravku i probijanje zip datoteka. Evo nekoliko ključnih alata:

- **`unzip`**: Otkriva zašto zip datoteka možda ne može da se raspakuje.
- **`zipdetails -v`**: Pruža detaljnu analizu polja formata zip datoteke.
- **`zipinfo`**: Navodi sadržaj zip datoteke bez vađenja.
- **`zip -F input.zip --out output.zip`** i **`zip -FF input.zip --out output.zip`**: Pokušavaju da poprave oštećene zip datoteke.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Alat za brute-force probijanje zip lozinki, efikasan za lozinke do oko 7 karaktera.

[Specifikacija formata zip datoteka](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) pruža sveobuhvatne detalje o strukturi i standardima zip datoteka.

Važno je napomenuti da zip datoteke zaštićene lozinkom **ne enkriptuju imena datoteka ili veličine datoteka** unutar, što je sigurnosni propust koji RAR ili 7z datoteke ne dele, jer enkriptuju te informacije. Pored toga, zip datoteke enkriptovane starijom metodom ZipCrypto su podložne **napadu u običnom tekstu** ako je dostupna neenkriptovana kopija kompresovane datoteke. Ovaj napad koristi poznati sadržaj za probijanje zip lozinke, ranjivost detaljno opisanu u [HackThis članku](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) i dodatno objašnjenu u [ovoj akademskoj studiji](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Međutim, zip datoteke zaštićene **AES-256** enkripcijom su imune na ovaj napad u običnom tekstu, što pokazuje važnost izbora sigurnih metoda enkripcije za osetljive podatke.

## Reference

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}

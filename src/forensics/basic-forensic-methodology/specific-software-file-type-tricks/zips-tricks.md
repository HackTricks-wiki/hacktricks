# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Narzędzia wiersza poleceń** do zarządzania **plikami zip** są niezbędne do diagnozowania, naprawiania i łamania plików zip. Oto kilka kluczowych narzędzi:

- **`unzip`**: Ujawni, dlaczego plik zip może nie dekompresować się.
- **`zipdetails -v`**: Oferuje szczegółową analizę pól formatu pliku zip.
- **`zipinfo`**: Wyświetla zawartość pliku zip bez jego ekstrakcji.
- **`zip -F input.zip --out output.zip`** oraz **`zip -FF input.zip --out output.zip`**: Próbują naprawić uszkodzone pliki zip.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Narzędzie do łamania haseł zip metodą brute-force, skuteczne dla haseł do około 7 znaków.

Specyfikacja [formatu pliku Zip](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) dostarcza szczegółowych informacji na temat struktury i standardów plików zip.

Ważne jest, aby zauważyć, że pliki zip chronione hasłem **nie szyfrują nazw plików ani rozmiarów plików** wewnątrz, co stanowi lukę w zabezpieczeniach, której nie mają pliki RAR ani 7z, które szyfrują te informacje. Ponadto, pliki zip szyfrowane starszą metodą ZipCrypto są podatne na **atak jawny**, jeśli dostępna jest nieszyfrowana kopia skompresowanego pliku. Atak ten wykorzystuje znaną zawartość do złamania hasła zip, co jest szczegółowo opisane w artykule [HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) oraz dalej wyjaśnione w [tym artykule naukowym](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Jednak pliki zip zabezpieczone szyfrowaniem **AES-256** są odporne na ten atak jawny, co podkreśla znaczenie wyboru bezpiecznych metod szyfrowania dla wrażliwych danych.

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}

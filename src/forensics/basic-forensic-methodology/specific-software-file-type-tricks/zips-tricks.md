# ZIPs tricks

{{#include ../../../banners/hacktricks-training.md}}

**Zana za mistari wa amri** kwa usimamizi wa **zip files** ni muhimu kwa ajili ya kugundua, kurekebisha, na kuvunja zip files. Hapa kuna zana muhimu:

- **`unzip`**: Inaonyesha kwa nini zip file inaweza isifunguke.
- **`zipdetails -v`**: Inatoa uchambuzi wa kina wa maeneo ya muundo wa zip file.
- **`zipinfo`**: Inataja maudhui ya zip file bila kuyatoa.
- **`zip -F input.zip --out output.zip`** na **`zip -FF input.zip --out output.zip`**: Jaribu kurekebisha zip files zilizoharibika.
- **[fcrackzip](https://github.com/hyc/fcrackzip)**: Zana ya kuvunja nenosiri la zip kwa nguvu, inafanya kazi kwa nenosiri hadi karibu herufi 7.

Maelezo ya [Zip file format specification](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) yanatoa maelezo ya kina kuhusu muundo na viwango vya zip files.

Ni muhimu kutambua kwamba zip files zilizo na nenosiri **hazifichi majina ya faili au ukubwa wa faili** ndani, kasoro ya usalama ambayo haipatikani kwa RAR au 7z files ambazo huficha taarifa hii. Zaidi ya hayo, zip files zilizofichwa kwa njia ya zamani ya ZipCrypto zinaweza kuathiriwa na **shambulio la plaintext** ikiwa nakala isiyo na usalama ya faili iliyoshinikizwa inapatikana. Shambulio hili linatumia maudhui yanayojulikana kuvunja nenosiri la zip, udhaifu huu umeelezwa kwa kina katika [makala ya HackThis](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files) na kufafanuliwa zaidi katika [karatasi hii ya kitaaluma](https://www.cs.auckland.ac.nz/~mike/zipattacks.pdf). Hata hivyo, zip files zilizolindwa kwa **AES-256** encryption hazihusiki na shambulio hili la plaintext, ikionyesha umuhimu wa kuchagua mbinu za usimbaji salama kwa data nyeti.

## References

- [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)

{{#include ../../../banners/hacktricks-training.md}}

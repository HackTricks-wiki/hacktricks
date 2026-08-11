# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Sažetak

"Carbonara" zloupotrebljava MediaTek-ov XFlash download path za pokretanje izmenjene Download Agent stage 2 (DA2) uprkos proverama integriteta DA1. DA1 čuva očekivani SHA-256 vrednost DA2 u RAM-u i poredi je pre grananja. Kod mnogih loadera, host u potpunosti kontroliše adresu/veličinu učitavanja DA2, čime dobija neprovereni upis u memoriju koji može da prepiše taj hash u memoriji i preusmeri izvršavanje na proizvoljne payload-e (pre-OS kontekst, uz invalidaciju cache-a koju obrađuje DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Granica poverenja u XFlash-u (DA1 → DA2)

- **DA1** potpisuje/učitava BootROM/Preloader. Kada je Download Agent Authorization (DAA) omogućen, trebalo bi da se izvršava samo potpisani DA1.
- **DA2** se šalje preko USB-a. DA1 prima **veličinu**, **adresu učitavanja** i **SHA-256**, zatim hash-uje primljeni DA2 i poredi ga sa **očekivanim hash-om ugrađenim u DA1** (kopiranim u RAM).
- **Slabost:** Kod nezakrpljenih loadera, DA1 ne proverava adresu/veličinu učitavanja DA2 i očekivani hash ostaje upisiv u memoriji, što omogućava hostu da manipuliše proverom.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara tok ("two BOOT_TO" trik)

1. **Prvi `BOOT_TO`:** Ulazi u DA1→DA2 staging flow (DA1 alocira, priprema DRAM i izlaže bafer očekivanog hash-a u RAM-u).
2. **Prepisivanje hash-slota:** Šalje mali payload koji pretražuje memoriju DA1 za sačuvanim očekivanim hash-om DA2 i prepisuje ga SHA-256 vrednošću napadačevog izmenjenog DA2. Ovo koristi load koji kontroliše korisnik kako bi payload dospeo na mesto gde se nalazi hash.
3. **Drugi `BOOT_TO` + digest:** Pokreće drugi `BOOT_TO` sa izmenjenim DA2 metadata podacima i šalje neobrađeni 32-bajtni digest koji odgovara izmenjenom DA2. DA1 ponovo izračunava SHA-256 nad primljenim DA2, poredi ga sa sada izmenjenim očekivanim hash-om i skok uspeva u napadačev kod.

Kod pogođenih loadera, neproverena adresa i veličina mogu napadaču da obezbede pre-OS primitive za upis u memoriju po njegovom izboru, izvan hash-slota. U zavisnosti od memory map-a SoC-a i kasnijih faza verifikacije, ovo može podržati early-boot implants, secure-boot-bypass helpers ili payload-e nalik rootkit-u. Samo izvršavanje DA koda ne obezbeđuje automatski persistence niti potpun secure-boot bypass; i dalje su potrebni zaseban persistence mehanizam i kompatibilan verification chain.<sup>[[1]](#references)[[2]](#references)</sup>

## Minimalni PoC obrazac (u stilu mtkclient-a)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- 16-bajtni `payload` reprodukuje blob uočen u workflow-u plaćenog alata i koji je objavljena implementacija koristila za patch-ovanje bafera očekivanog hash-a. Specifičan je za loader i nije prenosivi patch hash slota za svaki SoC ili DA.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` šalje sirove bajtove (ne hex), kako bi DA1 mogao da ih uporedi sa patch-ovanim baferom.
- Na ranjivom loaderu koji se podudara, DA2 može biti image koji je napravio napadač, a izabrani load metapodaci kontrolišu njegovo smeštanje u memoriju. Validirajte kombinaciju DA/SoC pre slanja, jer netačne adrese mogu da blokiraju ili oštete target.<sup>[[3]](#references)</sup>

## Patch landscape (hardened loaders)

- **Uočena mitigacija**: Hardened DA-ovi koje su istraživači ispitali prisiljavaju DA2 load adresu na `0x40000000` i ignorišu adresu koju šalje host, čime sprečavaju upise u uočeni DA1 hash region oko `0x200000`. Obe adrese tretirajte kao specifične za implementaciju, a ne kao arhitektonske konstante.
- **Detektovanje patch-ovanih DA-ova**: mtkclient/penumbra skeniraju DA1 u potrazi za pattern-ima koji ukazuju na address-hardening; ako ih pronađu, Carbonara se preskače. Stari DA-ovi izlažu upisive hash slotove (često oko offseta kao što je `0x22dea4` u V5 DA1) i ostaju exploitable.
- **V5 naspram V6**: Neki V6 (XML) loaderi i dalje prihvataju adrese koje zadaje korisnik; noviji V6 binariji obično primenjuju fiksnu adresu i imuni su na Carbonara, osim ako se ne izvrši downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) note

MediaTek je patch-ovao Carbonara; novija ranjivost, **heapb8**, cilja DA2 USB file download handler na patch-ovanim V6 loaderima i omogućava izvršavanje koda čak i kada je `boot_to` hardened. Zloupotrebljava heap overflow tokom chunked file transfera kako bi preuzela kontrolu nad DA2 control flow-om. Exploit je javan u Penumbra/mtk-payloads i pokazuje da Carbonara fix-evi ne zatvaraju celu DA attack površinu.<sup>[[4]](#references)</sup>

## Notes for triage and hardening

- Uređaji kod kojih se DA2 adresa/veličina ne proveravaju, a DA1 zadržava upisiv očekivani hash, ranjivi su. Ako noviji Preloader/DA primenjuje ograničenja adresa ili hash održava nepromenljivim, Carbonara je mitigovan.
- Omogućavanje DAA i obezbeđivanje da DA1/Preloader validiraju BOOT_TO parametre (bounds + autentičnost DA2) zatvara ovaj primitive. Zatvaranje samo hash patch-a bez ograničavanja load-a i dalje ostavlja rizik od proizvoljnog upisa.

## References

- [1] [Carbonara: MediaTek exploit koji niko nije poslužio](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Dokumentacija Carbonara exploit-a](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Izvorni kod Penumbra Carbonara exploit-a](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploitation patch-ovanih V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}

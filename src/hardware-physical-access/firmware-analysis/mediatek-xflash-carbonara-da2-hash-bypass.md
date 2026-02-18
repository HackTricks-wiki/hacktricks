# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Sažetak

"Carbonara" zloupotrebljava MediaTek-ov XFlash download path da pokrene modifikovani Download Agent stage 2 (DA2) uprkos DA1 proverama integriteta. DA1 čuva očekivani SHA-256 za DA2 u RAM i upoređuje ga pre skoka. Na mnogim loader-ima host potpuno kontroliše DA2 load address/size, što omogućava nekontrolisani upis u memoriju koji može prepisati taj heš u memoriji i preusmeriti izvršavanje na proizvoljne payloads (pre-OS kontekst uz invalidaciju keša koju obavlja DA).

## Granica poverenja u XFlash (DA1 → DA2)

- **DA1** je potpisan/učitan od strane BootROM/Preloader. Kada je Download Agent Authorization (DAA) omogućen, samo potpisani DA1 bi trebalo da se izvršava.
- **DA2** se šalje preko USB-a. DA1 prima **size**, **load address**, i **SHA-256** i izračunava heš primljenog DA2, upoređujući ga sa **očekivanim hešom ugrađenim u DA1** (kopiranim u RAM).
- **Slabost:** Na nenadograđenim loader-ima, DA1 ne sanitizuje DA2 load address/size i drži očekivani heš upisivim u memoriji, omogućavajući hostu da manipuliše proverom.

## Carbonara tok ("two BOOT_TO" trik)

1. **First `BOOT_TO`:** Uđite u DA1→DA2 staging flow (DA1 alocira, priprema DRAM i izlaže expected-hash buffer u RAM).
2. **Hash-slot overwrite:** Pošaljite mali payload koji pretražuje DA1 memoriju za sačuvanim očekivanim DA2 hešom i prepiše ga SHA-256 vrednošću napadačem modifikovanog DA2. Ovo iskorišćava user-controlled load da smesti payload tamo gde se heš nalazi.
3. **Second `BOOT_TO` + digest:** Pokrenite još jedan `BOOT_TO` sa izmenjenim DA2 metadata i pošaljite sirovi 32-bajtni digest koji odgovara modifikovanom DA2. DA1 ponovo izračunava SHA-256 nad primljenim DA2, upoređuje ga sa sada izmenjenim očekivanim hešom, i skok uspeva u kod napadača.

Pošto su load address/size pod kontrolom napadača, ista primitiva može da upisuje bilo gde u memoriji (ne samo u hash buffer), omogućavajući early-boot implantate, pomoćne alate za zaobilaženje secure-boot-a, ili zlonamerne rootkits.

## Minimalni PoC obrazac (mtkclient-style)
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
- `payload` replicira blob iz plaćenog alata koji zakrpa expected-hash buffer unutar DA1.
- `sha256(...).digest()` šalje sirove bajtove (ne hex) tako da DA1 upoređuje protiv zakrpanog buffera.
- DA2 može biti bilo koja slika koju napadač napravi; izbor load address/size omogućava proizvoljno postavljanje u memoriji pri čemu cache invalidation rešava DA.

## Patch landscape (hardened loaders)

- **Mitigation**: Ažurirani DAs hardcode DA2 load address na `0x40000000` i ignorišu adresu koju host prosleđuje, tako da write-ovi ne mogu dosegnuti DA1 hash slot (~0x200000 opseg). Hash se i dalje izračunava, ali više nije attacker-writable.
- **Detecting patched DAs**: mtkclient/penumbra skeniraju DA1 za obrasce koji ukazuju na address-hardening; ako se pronađu, Carbonara se preskače. Stari DAs izlažu writable hash slotove (češće oko offseta poput `0x22dea4` u V5 DA1) i ostaju iskoristivi.
- **V5 vs V6**: Neki V6 (XML) loader-i i dalje prihvataju adrese koje korisnik prosledi; noviji V6 binarni obično forsiraju fiksnu adresu i imuni su na Carbonara osim ako se ne downgrade-uju.

## Post-Carbonara (heapb8) note

MediaTek je zakrpio Carbonara; novija ranjivost, **heapb8**, cilja DA2 USB file download handler na zakrpljenim V6 loader-ima, omogućavajući izvršenje koda čak i kada je `boot_to` hardenovan. Iskorišćava heap overflow tokom chunked file transfera da preuzme kontrolni tok DA2. Eksploit je javan u Penumbra/mtk-payloads i pokazuje da popravke za Carbonara ne zatvaraju celu DA attack surface.

## Notes for triage and hardening

- Uređaji gde DA2 address/size nisu proveravani i DA1 ostavlja expected hash writable su ranjivi. Ako kasniji Preloader/DA primenjuje ograničenja adresa ili drži hash nepromenljivim, Carbonara je mitigovan.
- Omogućavanje DAA i osiguranje da DA1/Preloader validiraju BOOT_TO parametre (bounds + autentičnost DA2) zatvara primitiv. Zatvaranje samo hash patch-a bez ograničavanja load-a i dalje ostavlja rizik proizvoljnog upisa.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}

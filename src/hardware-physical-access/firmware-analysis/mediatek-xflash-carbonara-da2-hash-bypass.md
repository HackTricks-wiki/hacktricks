# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Sažetak

"Carbonara" zloupotrebljava MediaTek XFlash download putanju kako bi pokrenuo izmenjeni Download Agent stage 2 (DA2) uprkos proverama integriteta DA1. DA1 čuva očekivani SHA-256 za DA2 u RAM-u i poredi ga pre grananja. Kod mnogih loadera, host u potpunosti kontroliše adresu učitavanja i veličinu DA2, što omogućava nekontrolisani upis u memoriju koji može da prepiše hash u memoriji i preusmeri izvršavanje na proizvoljne payload-e (u pre-OS kontekstu, uz invalidaciju cache-a koju obavlja DA).<sup>[[1]](#references)[[2]](#references)</sup>

## Granica poverenja u XFlash-u (DA1 → DA2)

- **DA1** potpisuju/učitavaju BootROM/Preloader. Kada je Download Agent Authorization (DAA) omogućen, trebalo bi da se izvršava samo potpisani DA1.
- **DA2** se šalje preko USB-a. DA1 prima **veličinu**, **adresu učitavanja** i **SHA-256**, izračunava hash primljenog DA2 i poredi ga sa **očekivanim hash-om ugrađenim u DA1** (kopiranim u RAM).
- **Slabost:** Na nepatchovanim loaderima, DA1 ne sanitizuje adresu učitavanja/veličinu DA2 i očekivani hash ostaje upisiv u memoriji, što omogućava hostu da manipuliše proverom.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara tok ("two BOOT_TO" trik)

1. **Prvi `BOOT_TO`:** Ulazi u DA1→DA2 staging tok (DA1 alocira memoriju, priprema DRAM i izlaže bafer očekivanog hash-a u RAM-u).
2. **Prepisivanje hash slota:** Pošalji mali payload koji skenira memoriju DA1 za sačuvanim očekivanim hash-om DA2 i prepisuje ga SHA-256 vrednošću napadačevog izmenjenog DA2. Ovo koristi učitavanje pod kontrolom korisnika da bi payload dospeo na mesto gde se nalazi hash.
3. **Drugi `BOOT_TO` + digest:** Pokreni novi `BOOT_TO` sa izmenjenim metapodacima DA2 i pošalji raw 32-byte digest koji odgovara izmenjenom DA2. DA1 ponovo izračunava SHA-256 nad primljenim DA2, poredi ga sa sada izmenjenim očekivanim hash-om i skok uspeva ka napadačevom kodu.

Pošto su adresa učitavanja/veličina pod kontrolom napadača, isti primitiv može da upisuje bilo gde u memoriji (ne samo u hash bafer), čime se omogućavaju early-boot implantati, pomoćni alati za zaobilaženje secure-boot-a ili zlonamerni rootkit-i.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload` replicira blob plaćenog alata koji patchuje bafer očekivanog hash-a unutar DA1.
- `sha256(...).digest()` šalje raw bytes (ne hex), tako da DA1 poredi vrednost sa patchovanim baferom.
- DA2 može biti bilo koja slika koju je izgradio attacker; izbor load adrese/veličine omogućava proizvoljno postavljanje u memoriju, pri čemu DA upravlja invalidacijom cache-a.<sup>[[3]](#references)</sup>

## Pregled zakrpa (ojačani loaders)

- **Mitigacija**: Ažurirani DA-ovi hardkoduju DA2 load adresu na `0x40000000` i ignorišu adresu koju host prosleđuje, tako da upisi ne mogu da dosegnu DA1 hash slot (oko opsega `0x200000`). Hash se i dalje izračunava, ali više nije podložan upisu od strane attackera.
- **Detekcija patchovanih DA-ova**: mtkclient/penumbra skeniraju DA1 u potrazi za obrascima koji ukazuju na hardening adrese; ako ih pronađu, Carbonara se preskače. Stari DA-ovi izlažu hash slotove za upis (često oko offseta kao što je `0x22dea4` u V5 DA1) i ostaju exploitable.
- **V5 u odnosu na V6**: Neki V6 (XML) loaders i dalje prihvataju adrese koje zadaje korisnik; noviji V6 binariji obično zahtevaju fiksnu adresu i imuni su na Carbonara, osim ako se izvrši downgrade.<sup>[[2]](#references)[[3]](#references)</sup>

## Napomena nakon Carbonara (heapb8)

MediaTek je patchovao Carbonara; novija ranjivost, **heapb8**, cilja DA2 USB handler za download datoteka na patchovanim V6 loaders, omogućavajući izvršavanje koda čak i kada je `boot_to` ojačan. Ona zloupotrebljava heap overflow tokom chunked transfera datoteka kako bi preuzela kontrolu nad tokom izvršavanja DA2. Exploit je javno dostupan u Penumbra/mtk-payloads i pokazuje da Carbonara ispravke ne zatvaraju čitavu DA attack površinu.<sup>[[4]](#references)</sup>

## Napomene za triage i hardening

- Uređaji kod kojih DA2 adresa/veličina nisu proverene i kod kojih DA1 zadržava očekivani hash koji može da se menja ranjivi su. Ako noviji Preloader/DA zahteva ograničenja adrese ili hash održava nepromenljivim, Carbonara je mitigovan.
- Omogućavanje DAA i obezbeđivanje da DA1/Preloader validiraju BOOT_TO parametre (granice + autentičnost DA2) zatvara primitive. Zatvaranje samo hash patch-a bez ograničavanja load-a i dalje ostavlja rizik od proizvoljnog upisa.

## Reference

- [1] [Carbonara: MediaTek exploit koji niko nije servirao](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit dokumentacija](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patchovanih V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}

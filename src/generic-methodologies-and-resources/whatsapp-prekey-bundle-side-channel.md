# Side Channel za iscrpljivanje i dopunu WhatsApp Prekey Bundle-a

{{#include ../banners/hacktricks-training.md}}

WhatsApp čuva identity key, signed prekey i rezervu jednokratnih prekey ključeva za svaki uređaj. Preuzimanje bundle-a uređaja troši jedan jednokratni prekey koji čuva server, čak i ako podnosilac zahteva ne pošalje nijednu poruku. To napadaču koji ima WhatsApp nalog i broj telefona mete omogućava **server-side** probu, različitu od [vremenskog određivanja potvrda o isporuci na klijentu](side-channel-attacks-on-messaging-protocols.md). Nedostatak jednokratnog prekey ključa takođe slabi forward secrecy za *početne* poruke novouspostavljene sesije; sam po sebi ne otkriva otvoreni tekst.<sup>[[1]](#references)[[2]](#references)</sup>

## Pregled bundle-ova uređaja mete

[Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo) uparuje se kao prateća WhatsApp sesija i podržava **ručne** upite o uređajima i prekey ključevima. Uparite ga sa testnim nalogom, a zatim koristite njegove interaktivne komande `target`, `devices`, `prekey` (primarni uređaj) i `combine` (svi uređaji). Objavljeni artifact namerno izostavlja funkcije za automatizovano iscrpljivanje i zagušivanje servera.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Za svaki odgovor zabeležite JID uređaja, vremensku oznaku paketa `t`, ID potpisanog preključa `skey.id` i da li je prisutan jednokratni `key.id`. ID uređaja `0` označava telefon; ID-jevi koji nisu nula označavaju prateće uređaje. U implementacijama testiranim u radu, početni ID potpisanog preključa takođe razlikuje neke klijente: Android počinje od `0`, iOS i macOS koriste nasumičnu vrednost, a WhatsApp Web i Windows Desktop počinju od `1`. Tretirajte ovo kao otisak implementacije, a ne kao nepromenljivo pravilo protokola.<sup>[[1]](#references)</sup>

## Pretvorite dopune u online-status oracle

Najpre izvršite kalibraciju na uređaju koji kontrolišete: više puta zatražite njegov paket dok server ne prestane da vraća jednokratni `key`, uz beleženje poslednje vremenske oznake i ID-jeva ključeva. Za ciljni uređaj ponovite pražnjenje, pa ponovo pošaljite upit nakon kontrolisanog intervala: novi jednokratni ključ i pomerena vremenska oznaka paketa ukazuju na to da je uređaj otpremio novu grupu ključeva. U testovima WhatsApp-a opisanima u radu, server je tražio dopunu kada je preostalo manje od 11 ključeva, a klijenti su otpremali 812 novih ključeva. Primenite postupak za svaki JID uređaja da biste razlikovali telefon od pratećih uređaja. Odložena dopuna samo **ukazuje** na to da je uređaj van mreže: pozadinsko zakazivanje, gubitak mreže i kašnjenje dopune specifično za klijenta mogu dati isto zapažanje. Za razliku od RTT-a potvrde prijema, za ovu proveru nije potreban dostavljen šifrat niti potvrda sa žrtvinog uređaja.<sup>[[1]](#references)[[2]](#references)</sup>

Svaki upit troši jedan jednokratni ključ, pa je za stalno korišćenje oracle-a potreban prilagođeni klijent koji može ponavljano da preuzima preključeve; javni artefakt prikazuje samo ručno slanje upita. Pražnjenje rezerve može dovesti do toga da drugi korisnici uspostave nove sesije bez jednokratnog preključa. To smanjuje forward secrecy za početne poruke do sledećeg svežeg koraka ratchet-a, ali iskorišćavanje snimljenog šifrata dodatno zahteva pristup E2EE šifratu i naknadno kompromitovanje relevantnih dugoročnih i srednjoročnih privatnih ključeva. Postojeće uspostavljene sesije ne prelaze automatski na slabiju zaštitu.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Istraživanje bezbednosnih i privatnosnih problema u mehanizmu rukovanja WhatsApp-a](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [Protokol usaglašavanja ključeva X3DH](https://signal.org/docs/specifications/x3dh/)
- [3] [Artefakti Prekey Pogo](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}

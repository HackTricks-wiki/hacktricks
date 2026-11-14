# WhatsApp Prekey-bundeluitputting en hervul-sykanaal

{{#include ../banners/hacktricks-training.md}}

WhatsApp stoor ’n identiteitsleutel, ’n ondertekende prekey en ’n reserwe eenmalige prekeys vir elke toestel. Wanneer ’n toestel se bundel opgehaal word, word een eenmalige prekey wat deur die bediener gehou word, verbruik, selfs al stuur die versoeker geen boodskap nie. Dit gee ’n aanvaller met ’n WhatsApp-rekening en die teiken se telefoonnommer ’n **server-side** probe, wat verskil van [client delivery-receipt timing](side-channel-attacks-on-messaging-protocols.md). Die afwesigheid van ’n eenmalige prekey verswak ook forward secrecy vir die *aanvanklike* boodskappe van ’n nuut gevestigde sessie; dit stel nie op sigself gewone teks bloot nie.<sup>[[1]](#references)[[2]](#references)</sup>

## Ondersoek ’n teiken se toestelbundels

Die [Prekey Pogo artifact](https://github.com/sbaresearch/prekey-pogo) koppel as ’n WhatsApp-metgeselsessie en ondersteun **handmatige** toestel- en prekey-navrae. Koppel dit met ’n toetsrekening en gebruik dan die interaktiewe `target`-, `devices`-, `prekey`- (primêre toestel) en `combine`- (alle toestelle)-opdragte. Die vrygestelde artifact laat doelbewus outomatiese uitputtings- en bediener-verstoppingsfunksies weg.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Vir elke antwoord, teken die toestel-JID, bundeltydstempel `t`, signed-prekey-ID `skey.id` en aan of die eenmalige `key.id` teenwoordig is, aan. Toestel-ID `0` is die foon; nie-nul-ID’s is metgeselle. In die implementasies wat in die artikel getoets is, onderskei die aanvanklike signed-prekey-ID ook sommige kliënte: Android begin by `0`, iOS en macOS gebruik ’n ewekansige waarde, en WhatsApp Web en Windows Desktop begin by `1`. Beskou dit as ’n implementasievingerafdruk, nie as ’n onveranderlike protokolreël nie.<sup>[[1]](#references)</sup>

## Verander hervullings in ’n aanlynstatus-orakel

Kalibreer eers op ’n toestel wat jy beheer: versoek herhaaldelik die toestel se bundel totdat die bediener ophou om ’n eenmalige `key` terug te stuur, en teken die laaste tydstempel en sleutel-ID’s aan. Herhaal die uitputting vir ’n teikentoestel en doen ná ’n beheerde interval weer ’n navraag: ’n nuwe eenmalige sleutel en ’n gevorderde bundeltydstempel dui aan dat die toestel ’n nuwe bondel opgelaai het. In die gerapporteerde WhatsApp-toetse het die bediener ’n hervulling aangevra wanneer minder as 11 sleutels oorgebly het, en kliënte het 812 nuwe sleutels opgelaai. Pas die prosedure per toestel-JID toe om ’n foon van metgeselle te onderskei. ’n Vertraagde hervulling **dui moontlik** daarop dat ’n toestel vanlyn is: agtergrondskedulering, netwerkverlies en kliëntspesifieke hervullatensie kan dieselfde waarneming veroorsaak. Anders as ’n kwitansie-RTT vereis hierdie ondersoek nie ’n afgelewerde ciphertext of ’n erkenning vanaf die slagoffer se toestel nie.<sup>[[1]](#references)[[2]](#references)</sup>

Elke navraag verbruik ’n eenmalige sleutel, dus vereis ’n volgehoue orakel ’n pasgemaakte kliënt wat herhaalde prekey-opvraging kan doen; die publieke artefak demonstreer slegs handmatige navrae. As die reserwe leeg gehou word, kan ander gebruikers nuwe sessies vestig sonder ’n eenmalige prekey. Dit verminder forward secrecy vir aanvanklike boodskappe totdat ’n nuwe ratchet-stap plaasvind, maar om opgeneemde ciphertext te ontgin, vereis ook toegang tot die E2EE-ciphertext en latere kompromittering van die betrokke langtermyn- en mediumtermyn-private sleutels. Bestaande gevestigde sessies word nie outomaties afgegradeer nie.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: Ondersoek na sekuriteits- en privaatheidskwessies in WhatsApp se handdrukmeganisme](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [Die X3DH-sleutelooreenkomsprotokol](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo-artefakte](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}

# Bedreigingsmodellering & Identiteitskeiding

{{#include ../banners/hacktricks-training.md}}

Die algemeenste anonimiteitsmislukking is nie gebroke kriptografie nie. Dit is **koppeling**: een identifiseerder, tydsberekeningpatroon, toestel, rekening, betaling, lêer of menslike gewoonte verbind twee kontekste wat veronderstel was om apart te bly.

## Bou 'n privaatheidsbedreigingsmodel

EFF se ses-vrae-sekuriteitsplan is 'n sterk basis: wat beskerm moet word, teen wie, die impak en waarskynlikheid van mislukking, die beskikbare moeite, en bondgenote wat kan help.<sup>[[1]](#references)</sup> Maak dit operasioneel met 'n klein tabel:

| Bate/handeling | Waarnemer | Waarneembare data | Korrelasieroute | Beheer | Oorblywende risiko |
|---|---|---|---|---|---|
| Navorsing oor 'n kliënt | ISP | Bestemming/tydsberekening-metadata | Tuisintekenaarrekord | Tor Browser | Tor-gebruik sigbaar; end-tot-end-korrelasie |
| Pseudonieme rekening | Platform | IP, blaaier, hersteldata | Hergebruikte foon/e-pos/foto | Toegewyde konteks en alias | Skryf-/sosiale-grafiekkorrelasie |
| Aanlyn-aankoop | Handelaar | Rekening, aflewering, getokeniseerde kaart | Adres- en rekeninggeskiedenis | Gaskassie, minimale velde, virtuele kaart | Uitreiker en vervoerder behou rekords |
| Red-team-verkeer | Teiken/kliënt | Bron-IP en gedrag | Verskaffer-/opdragrekords | Toegewyde gemagtigde uitgang | Opsetlik toeskryfbaar tydens eskalasie |

Hersien die tabel wanneer die ligging, verskaffer, toestel, teenparty of gevolge verander.

## Teken die koppelbaarheidsgrafiek

Behandel elke identiteit as 'n aparte nodus. Voeg 'n rand by vir elke gedeelde attribuut:

- e-pos of hersteladres;
- telefoonnommer of oplaaïng van kontakboek;
- gebruikersnaam, avatar, foto, bio, of skryf-/koderingstyl;
- wagwoord, passkey-sinkronisasierekening, of herstelvraag;
- toestel, advertensie-ID, blaaierprofiel, koekies, lettertipes, of uitbreidings;
- IP-adres, tydsone, taal, skedule, of gelyktydige aanlynstatus;
- bankkaart, exchange-rekening, wallet-kluster, versendingsadres, of lojaliteitsprogram;
- dokumentouteurvelde, EXIF-ligging, drukkermerke, of eienaar van wolkdeling;
- kollega, groeplidmaatskap, en sosiale grafiek.

'n Rand is nie outomaties fataal nie, maar dit wys watter waarnemer die verbinding kan maak. EFF waarsku spesifiek dat telefoonnommers, e-posadresse en hergebruikte foto's profiele kan koppel.<sup>[[2]](#references)</sup>

## Skep 'n kompartement stap vir stap

1. **Benoem die konteks en verbode skakels.** Voorbeeld: `client-red-2026`, verbied van persoonlike e-pos, tuisblaaierprofiele, persoonlike betaalmetodes, en onverwante kliënte.
2. **Kies die isolasiegrens.** In toenemende sterkte: aparte blaaierprofiel → aparte OS-rekening → aparte VM/qube → toegewyde toestel. 'n Aparte oortjie of private venster is nie 'n sekuriteitsgrens nie.
3. **Skep vars identifiseerders binne daardie grens.** Gebruik 'n konteks-spesifieke e-pos/alias, gebruikersnaam, wagwoordbestuurder-kluis of -versameling, en verifikasiesleutels. Moenie 'n persoonlike herstelkanaal byvoeg as onkoppelbaarheid van die verskaffer belangrik is nie.
4. **Kies een netwerkbeleid.** Besluit of die konteks altyd 'n kliënt-VPN, opdrag-VPS, vertroude VPN, of Tor gebruik. Dwing fail-closed-roetering af waar moontlik.
5. **Kies 'n betaalbeleid.** Die betaalmetode moet by die waarnemermodel pas; 'n virtuele kaart kan die PAN vir 'n handelaar verberg, maar identifiseer steeds die kliënt aan die uitreiker.
6. **Stel data-oordragreëls.** Verkies noukeurig afgebakende, doelbewuste oordragte. Behandel die knipbord, gedeelde vouers, USB-toestelle, wolksinkronisering, drukkers, en skermskote as moontlike brûe.
7. **Teken skeppings- en aftakelingsdatums aan.** Definieer watter bewyse vir kontrakte/belasting/nakoming behou moet word en watter tydelike data moet verval.
8. **Toets vir skakels voor gebruik.** Inspekteer rekeninginstellings, herstelvelde, openbare profiel, IP/DNS, blaaierstatus, lêermetadata, en verskaffer-kontroleskerms.

{% hint style="warning" %}
Moenie identiteitsinligting uitdink waar 'n diens of wet akkurate identifikasie vereis nie. 'n Privaatheidskompartement gaan oor dataminimalisering en skeiding, nie identiteitsbedrog of die omseiling van kliëntediensondersoek nie.
{% endhint %}

## Eindpunt- en rekeningbasislyn

- Gebruik ondersteunde hardeware en installeer OS-, blaaier-, wallet- en firmware-opdaterings stiptelik.
- Aktiveer toestelenkripsie en gebruik 'n sterk toestelkode. Enkripsie in rus help wanneer 'n afgeskakelde toestel verloor of gekonfiskeer word, maar nie terwyl malware of 'n ontsluite sessie data kan lees nie.<sup>[[3]](#references)</sup>
- Gebruik unieke, lukraak gegenereerde wagwoorde in 'n wagwoordbestuurder.
- Verkies phishing-bestande verifikasie soos WebAuthn/passkeys of hardeware-sekuriteitsleutels waar die bedreigingsmodel hul herstel-/sinkronisasiemodel toelaat. NIST merk op dat handmatig ingevoerde OTP's nie phishing-bestand is nie omdat 'n bedrieër dit kan deurgee.<sup>[[4]](#references)</sup>
- Hou herstelkodes vanlyn en geskei van die eindpunt. Hersien of 'n gesinkroniseerde passkey-rekening identiteite saamvoeg wat apart moet bly.
- Deaktiveer onnodige ligging-, kontakte-, mikrofoon-, kamera-, Bluetooth-, advertensie-ID- en agtergrondtoestemmings.
- Moenie persoonlike wolksinkronisering, blaaier-sinkronisering, wagwoordbestuurderrekeninge, of toepassingwinkels in 'n hoë-skeidingskonteks meng nie.

## Blaaierprivaatheid

Blaaier-vingerafdrukneming gebruik waarneembare konfigurasie, toestel, omgewing, en gedrag om 'n gebruiker te identifiseer of te korreleer. Die uitvee van koekies of verandering van IP-adresse verslaan dit nie betroubaar nie, en die W3C beskou volledige tegniese uitskakeling deur wyd ontplooide metodes as onwaarskynlik.<sup>[[5]](#references)</sup>

Vir gewone privaatheid:

1. Gebruik 'n onderhoude blaaier met HTTPS-only-modus en sterk opsporingsbeskerming.
2. Blokkeer derdeparty-opsporing en partisioneer toestand waar dit ondersteun word.
3. Gebruik aparte blaaierprofiele vir werklik aparte kontekste.
4. Deaktiveer onnodige toestemmings en vee werfdata volgens 'n vasgestelde skedule uit.
5. Vermy aanmelding by identiteitsryke rekeninge terwyl jy onverwante sensitiewe navorsing doen.

Vir webanonimiteit, gebruik **Tor Browser in sy standaardkonfigurasie**. Moenie 'n normale blaaier deur Tor proxy nie: Tor Project waarsku dat gewone blaaiers deur DNS/WebRTC, aanhoudende toestand, lettertipes, plugins, en vingerafdrukverskille kan leak.<sup>[[6]](#references)</sup> Vermy ekstra uitbreidings, ongewone venstergroottes, pasgemaakte lettertipes, en voorkeure wat die blaaier laat uitstaan.<sup>[[7]](#references)</sup>

## Kommunikasie en metadata

Metadata sluit sender, ontvanger, tyd, ligging, en ander konteks in, selfs wanneer boodskapinhoud geënkripteer is.<sup>[[8]](#references)</sup>

- Verkies end-tot-end-geënkripteerde gereedskap met geminimaliseerde bedienerkant-metadata en oop protokolle/kliente waar dit prakties is.
- Verifieer sensitiewe kontakte deur 'n onafhanklike kanaal of persoonlik. Signal-veiligheidsnommers is vir hierdie kontrole ontwerp.<sup>[[9]](#references)</sup>
- Signal-gebruikersname kan kontak inisieer sonder om 'n telefoonnommer te deel, maar 'n telefoonnommer word steeds vereis om te registreer; stel telefoonnommer-sigbaarheid/ontdekbaarheid doelbewus op.<sup>[[9]](#references)</sup>
- Boodskappe wat verdwyn verminder behoue kopieë; ontvangers kan steeds inhoud fotografeer, kopieer, aanstuur, of argiveer.
- E-pos stel normaalweg roeteringsmetadata bloot. Selfs privaatheidsgefokusde verskaffers kan nie 'n boodskap end-tot-end-geënkripteer maak wanneer die ander kant gewone e-pos gebruik nie, tensy albei partye 'n versoenbare E2EE-metode gebruik. Proton dokumenteer byvoorbeeld dat gewone pos aan ander verskaffers TLS gebruik en vir die ontvangende verskaffer leesbaar bly.<sup>[[10]](#references)</sup>
- Hou adresboeke apart en moenie persoonlike kontakte na 'n pseudonieme rekening oplaai nie.

## Lêers, foto's en outeurskap

Tails waarsku dat foto's kamera- en liggingdata kan bevat en dat kantoordokumente outeur- en skeppingstyd-velde kan bevat.<sup>[[11]](#references)</sup>

Voor deling:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Maak dan die skoongemaakte kopie weer in ’n geïsoleerde kyker oop en kontroleer:

- dokumenteienskappe, opmerkings, nagespoorde veranderinge, versteekte velle/skyfies, duimnaels en aanhegsels;
- EXIF/XMP/IPTC, GPS, tydstempels, toestel-/sagtewarename en unieke ID’s;
- sigbare weerkaatsings, landmerke, skerminhoud, stemme, gesigte en agtergrondklanke;
- lêernaam, argiefpaaie, cloud-share-eienaar, ondertekeningsertifikaat en hersieningsgeskiedenis.

Sanitisering kan bewyse of egtheid beskadig. Bewaar ’n geënkripteerde oorspronklike wanneer chain of custody of latere verifikasie belangrik is. Stylometrie en koderingstyl kan outeurskap ook verbind; die verwydering van metadata verander nie menslike styl nie.

## Algemene mislukkingspatrone

- Om deur ’n “anonieme” verbinding by ’n persoonlike rekening aan te meld.
- Om ’n hersteltelefoonnommer, avatar, gebruikersnaam, publieke sleutel, wallet of skenkingsadres te hergebruik.
- Om twee identiteite terselfdertyd vanuit gekorreleerde kontekste te bedryf.
- Om teks/lêers deur ’n persoonlike cloud clipboard of gedeelde vouer te kopieer.
- Om kenmerkende Tor Browser-uitbreidings te installeer of baie verstekwaardes te verander.
- Om ’n “geen logs”-aanspraak te vertrou sonder om te verstaan wat aangeteken word, vir hoe lank, en deur watter subkontrakteurs.
- Om aan te neem dat ’n sekondêre telefoon anoniem is terwyl dit saam met ’n persoonlike telefoon beweeg. EFF merk op dat sellulêre ligging en saamreis van toestelle die toestelle kan korreleer.<sup>[[3]](#references)</sup>
- Om enkripsie as uitwissing te behandel; endpoints en ontvangers kan plaintext behou.

## Verifikasiekontrolelys

- [ ] Die konteks bevat geen persoonlike hersteladres, telefoon, sync-rekening of hergebruikte media nie, tensy dit doelbewus aanvaar is.
- [ ] Die beoogde netwerkpad is aktief en fails closed.
- [ ] Blaaier/toestel se tydsone, locale, uitbreidings en toestemmings stem met die plan ooreen.
- [ ] Geen persoonlike rekeninge is in die kompartement oop nie.
- [ ] Lêers is geïnspekteer en gesaniteer; oorspronklikes word afsonderlik hanteer.
- [ ] Kontakte word deur ’n tweede kanaal geverifieer.
- [ ] Die metadata wat vir die provider sigbaar is en die retensieperiode word verstaan.
- [ ] Teardown-, bewysretensie- en rekeningherstelprosedures is gedokumenteer.

## References

- [1] [EFF Surveillance Self-Defense — Jou sekuriteitsplan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Beskerming van jouself op sosiale netwerke](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Bywoning van ’n protes](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Verifikasie en bestuur van verifikasiefaktore](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Versagting van browser fingerprinting in webspesifikasies](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Gebruik van Tor met ander browsers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Plugins en byvoegings in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Waarom kommunikasiemetadata belangrik is](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Privaatheid van telefoonnommers en gebruikersname: ’n dieper bespreking](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Wat word binne Proton Mail geënkripteer?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Waarskuwings: Tails is veilig maar nie magies nie](https://tails.net/doc/about/warnings/index.en.html)
{{#include ../banners/hacktricks-training.md}}

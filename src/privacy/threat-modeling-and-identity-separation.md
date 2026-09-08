# Threat Modeling & Identity Separation

Die algemeenste anonimiteitsmislukking is nie gebrekkige cryptography nie. Dit is **linkage**: een identifier, tydspatroon, toestel, rekening, betaling, lêer of menslike gewoonte verbind twee kontekste wat veronderstel was om apart te bly.

## Bou 'n privacy threat model

EFF se ses-vrae-sekuriteitsplan is 'n sterk grondslag: wat beskerm moet word, teen wie, die impak en waarskynlikheid van mislukking, die beskikbare moeite, en bondgenote wat kan help.<sup>[[1]](#references)</sup> Maak dit operasioneel met 'n klein tabel:

| Asset/action | Observer | Observable data | Correlation route | Control | Residual risk |
|---|---|---|---|---|---|
| Navorsing oor 'n kliënt | ISP | Bestemming-/tydmetadata | Tuisintekenaarrekord | Tor Browser | Tor-gebruik sigbaar; end-to-end correlation |
| Pseudonieme rekening | Platform | IP, browser, recovery-data | Hergebruikte telefoon/e-pos/foto | Toegewyde konteks en alias | Skryf-/sosiale-graaf-correlation |
| Aanlyn aankoop | Handelaar | Rekening, aflewering, tokenized card | Adres- en rekeninggeskiedenis | Guest checkout, minimale velde, virtuele kaart | Issuer en carrier behou rekords |
| Red-team-verkeer | Teiken/kliënt | Bron-IP en gedrag | Provider-/engagement-rekords | Toegewyde gemagtigde egress | Opsetlik toeskryfbaar onder eskalasie |

Hersien die tabel wanneer die ligging, provider, toestel, teenparty of gevolge verander.

## Teken die linkability graph

Behandel elke identiteit as 'n aparte node. Voeg 'n edge by vir elke gedeelde attribuut:

- e-pos of recovery-adres;
- telefoonnommer of kontakboek-oplaai;
- gebruikersnaam, avatar, foto, bio, of skryf-/code-styl;
- wagwoord, passkey-sync-rekening, of recovery-vraag;
- toestel, advertising ID, browser-profiel, cookies, fonts, of extensions;
- IP-adres, tydsone, taal, skedule, of gelyktydige aanlynstatus;
- bankkaart, exchange-rekening, wallet-cluster, afleweringsadres, of lojaliteitsprogram;
- dokument-outeursvelde, EXIF-ligging, drukkermerke, of cloud-share-eienaar;
- kollega, groeplidmaatskap, en sosiale graaf.

'n Edge is nie outomaties fataal nie, maar dit wys watter observer die verbinding kan maak. EFF waarsku spesifiek dat telefoonnommers, e-posadresse en hergebruikte foto's profiele kan verbind.<sup>[[2]](#references)</sup>

## Skep 'n kompartement stap vir stap

1. **Benoem die konteks en verbode skakels.** Voorbeeld: `client-red-2026`, verbied van persoonlike e-pos, tuisbrowser-profiele, persoonlike betaalmetodes, en onverwante kliënte.
2. **Kies die isolasiegrens.** In toenemende sterkte: aparte browser-profiel → aparte OS-rekening → aparte VM/qube → toegewyde toestel. 'n Aparte tab of private window is nie 'n security boundary nie.
3. **Skep nuwe identifiers binne daardie grens.** Gebruik 'n konteks-spesifieke e-pos/alias, gebruikersnaam, password-manager vault of collection, en authentication keys. Moenie 'n persoonlike recovery-kanaal byvoeg as unlinkability van die provider belangrik is nie.
4. **Kies een netwerkbeleid.** Besluit of die konteks altyd 'n kliënt-VPN, engagement VPS, trusted VPN, of Tor gebruik. Dwing fail-closed routing af waar moontlik.
5. **Kies 'n betalingsbeleid.** Die betaalmetode moet by die observer-model pas; 'n virtuele kaart kan die PAN vir 'n handelaar verberg, maar identifiseer steeds die kliënt aan die issuer.
6. **Stel data-oordragreëls.** Verkies noukeurig beperkte, doelbewuste oordragte. Behandel clipboard, gedeelde vouers, USB-toestelle, cloud sync, drukkers, en screenshots as moontlike brûe.
7. **Teken skeppings- en afbreekdatums aan.** Definieer watter bewyse vir kontrakte/belasting/compliance behou moet word en watter tydelike data moet expire.
8. **Toets vir skakels voor gebruik.** Inspekteer rekeninginstellings, recovery-velde, publieke profiel, IP/DNS, browser-status, lêermetadata, en provider-dashboards.

{% hint style="warning" %}
Moenie identiteitsinligting uitdink waar 'n diens of wet akkurate identifikasie vereis nie. 'n Privacy-kompartement gaan oor dataminimalisering en skeiding, nie identiteitsbedrog of die omseiling van customer due diligence nie.
{% endhint %}

## Endpoint- en rekening-baseline

- Gebruik ondersteunde hardeware en installeer OS-, browser-, wallet- en firmware-opdaterings dadelik.
- Aktiveer toestel-encryption en gebruik 'n sterk toestel-passcode. Encryption at rest help wanneer 'n afgeskakelde toestel verlore raak of beslag gelê word, maar nie terwyl malware of 'n ontsluite sessie data kan lees nie.<sup>[[3]](#references)</sup>
- Gebruik unieke, willekeurig gegenereerde wagwoorde in 'n password manager.
- Verkies phishing-resistant authentication soos WebAuthn/passkeys of hardware security keys waar die threat model hul recovery/sync-model toelaat. NIST merk op dat handmatig ingevoerde OTPs nie phishing-resistant is nie omdat 'n impersonator dit kan relay.<sup>[[4]](#references)</sup>
- Hou recovery codes offline en apart van die endpoint. Hersien of 'n gesinkroniseerde passkey-rekening identiteite verbind wat apart moet bly.
- Deaktiveer onnodige ligging-, kontakte-, mikrofoon-, kamera-, Bluetooth-, advertising-ID- en agtergrondtoestemmings.
- Moenie persoonlike cloud sync, browser sync, password-manager-rekeninge, of app stores in 'n hoë-separasie-konteks meng nie.

## Browser-privaatheid

Browser fingerprinting gebruik waarneembare konfigurasie, toestel, omgewing en gedrag om 'n gebruiker te identifiseer of te correlate. Die uitvee van cookies of verandering van IP-adresse verslaan dit nie betroubaar nie, en die W3C beskou volledige tegniese uitskakeling deur wyd ontplooide metodes as onwaarskynlik.<sup>[[5]](#references)</sup>

Vir gewone privaatheid:

1. Gebruik 'n onderhoude browser met HTTPS-only mode en sterk tracking protection.
2. Blokkeer third-party tracking en partition state waar dit ondersteun word.
3. Gebruik aparte browser-profiele vir werklik aparte kontekste.
4. Deaktiveer onnodige toestemmings en vee site data volgens 'n vasgestelde skedule uit.
5. Vermy aanmelding by identity-rich-rekeninge terwyl jy onverwante sensitiewe navorsing doen.

Vir web-anonimiteit, gebruik **Tor Browser in its standard configuration**. Moenie 'n gewone browser deur Tor proxy nie: Tor Project waarsku dat gewone browsers deur DNS/WebRTC, persistente state, fonts, plugins, en fingerprint-verskille kan leak.<sup>[[6]](#references)</sup> Vermy ekstra extensions, ongewone venstergroottes, custom fonts, en voorkeure wat die browser laat uitstaan.<sup>[[7]](#references)</sup>

## Kommunikasie en metadata

Metadata sluit sender, ontvanger, tyd, ligging, en ander konteks in, selfs wanneer boodskapinhoud encrypted is.<sup>[[8]](#references)</sup>

- Verkies end-to-end-encrypted tools met geminimaliseerde server-side metadata en oop protokolle/clients waar prakties.
- Verifieer sensitiewe kontakte deur 'n onafhanklike kanaal of persoonlik. Signal safety numbers is vir hierdie kontrole ontwerp.<sup>[[9]](#references)</sup>
- Signal usernames kan kontak inisieer sonder om 'n telefoonnommer te deel, maar 'n telefoonnommer word steeds benodig vir registrasie; stel telefoonnommer-sigbaarheid/ontdekbaarheid doelbewus op.<sup>[[9]](#references)</sup>
- Disappearing messages verminder behoue kopieë; ontvangers kan steeds inhoud afneem, kopieer, aanstuur, of argiveer.
- E-pos stel gewoonlik routing-metadata bloot. Selfs privacy-focused providers kan nie 'n boodskap end-to-end encrypted maak wanneer die ander kant gewone e-pos gebruik nie, tensy albei partye 'n compatible E2EE-metode gebruik. Proton dokumenteer byvoorbeeld dat gewone pos aan ander providers TLS gebruik en vir die ontvangende provider leesbaar bly.<sup>[[10]](#references)</sup>
- Hou adresboeke apart en moenie persoonlike kontakte na 'n pseudonieme rekening oplaai nie.

## Lêers, foto's en outeurskap

Tails waarsku dat foto's kamera- en liggingsdata kan bevat en dat office-dokumente outeur- en skeppingstyd-velde kan bevat.<sup>[[11]](#references)</sup>

Voor deling:
```bash
# Inspect recursively; do not assume the extension tells the whole story
exiftool -a -u -g1 path/to/file

# Create a cleaned copy. Verify the copy before publishing.
exiftool -all= -o cleaned-file path/to/file
```
Heropen dan die skoongemaakte kopie in ’n geïsoleerde kyker en kontroleer:

- dokumenteienskappe, opmerkings, nagespoorde veranderinge, versteekte velle/skyfies, duimnaels en aanhegsels;
- EXIF/XMP/IPTC, GPS, tydstempels, toestel-/sagtewarename en unieke ID’s;
- sigbare weerkaatsings, landmerke, skerminhoud, stemme, gesigte en agtergrondklanke;
- lêernaam, argiefpaaie, eienaar van wolkdeling, ondertekeningssertifikaat en hersieningsgeskiedenis.

Sanitisering kan bewyse of egtheid beskadig. Bewaar ’n geënkripteerde oorspronklike wanneer bewysbewaringsketting of latere verifikasie belangrik is. Stylometrie en koderingstyl kan ook outeurskap verbind; die verwydering van metadata verander nie menslike styl nie.

## Algemene mislukkingspatrone

- Meld by ’n persoonlike rekening aan deur ’n “anonieme” verbinding.
- Hergebruik ’n herwinningstelefoon, avatar, gebruikersnaam, publieke sleutel, wallet of skenkingsadres.
- Bedryf twee identiteite terselfdertyd vanuit gekorreleerde kontekste.
- Kopieer teks/lêers deur ’n persoonlike wolk-knipbord of gedeelde vouer.
- Installeer kenmerkende Tor Browser-uitbreidings of verander baie verstekinstellings.
- Vertrou ’n “geen logs”-eis sonder om te verstaan wat gelog word, vir hoe lank, en deur watter subkontrakteurs.
- Neem aan ’n sekondêre telefoon is anoniem terwyl dit saam met ’n persoonlike telefoon beweeg. EFF merk op dat sellulêre ligging en gesamentlike beweging die toestelle kan korreleer.<sup>[[3]](#references)</sup>
- Behandel enkripsie as skrapping; eindpunte en ontvangers kan plaintext behou.

## Verifikasiekontrolelys

- [ ] Die konteks bevat geen persoonlike herwinningsadres, telefoon, sinkronisasierekening of hergebruikte media nie, tensy dit doelbewus aanvaar is.
- [ ] Die beoogde netwerkpad is aktief en faal gesluit.
- [ ] Blaaier/toestel se tydsone, lokalisering, uitbreidings en toestemmings stem met die plan ooreen.
- [ ] Geen persoonlike rekeninge is in die kompartement oop nie.
- [ ] Lêers is geïnspekteer en gesaniteer; oorspronklikes word afsonderlik hanteer.
- [ ] Kontakte word deur ’n tweede kanaal geverifieer.
- [ ] Die metadata wat vir die verskaffer sigbaar is en die bewaringstydperk word verstaan.
- [ ] Afbreek-, bewaring-van-bewyse- en rekeningherwinningsprosedures is gedokumenteer.

## References

- [1] [EFF Surveillance Self-Defense — Jou sekuriteitsplan](https://ssd.eff.org/module/your-security-plan)
- [2] [EFF Surveillance Self-Defense — Beskerm jouself op sosiale netwerke](https://ssd.eff.org/module/protecting-yourself-social-networks)
- [3] [EFF Surveillance Self-Defense — Bywoning van ’n protes](https://ssd.eff.org/module/attending-protest)
- [4] [NIST SP 800-63B-4 — Verifikasie en bestuur van verifieerders](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [5] [W3C — Versagting van blaaier-fingerprinting in webspesifikasies](https://www.w3.org/TR/fingerprinting-guidance/)
- [6] [Tor Project — Gebruik Tor met ander blaaiers](https://support.torproject.org/tor-browser/security/using-tor-with-other-browsers/)
- [7] [Tor Project — Inproppe en byvoegings in Tor Browser](https://support.torproject.org/tor-browser/features/plugins/)
- [8] [EFF Surveillance Self-Defense — Waarom kommunikasie- metadata saak maak](https://ssd.eff.org/module/why-metadata-matters)
- [9] [Signal — Telefoonnommerprivaatheid en gebruikersname: ’n dieper ontleding](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [10] [Proton — Wat word binne Proton Mail geënkripteer?](https://proton.me/support/what-is-encrypted-within-protonmail)
- [11] [Tails — Waarskuwings: Tails is veilig, maar nie towerkrag nie](https://tails.net/doc/about/warnings/index.en.html)

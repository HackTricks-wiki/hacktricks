# Covert Physical and Wireless Access

Outbound rendezvous, power/uplink recovery, cihaz üzerinde tutulan sırların en aza indirilmesi, capture testing ve olası keşfe karşı monitoring dahil olmak üzere, sahibi tarafından onaylanmış ayrıntılı bir uygulama için [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md) bölümüne bakın.

Network path'i değiştirmek, görünürdeki fiziksel origin'i de değiştirebilir. Sophisticated bir actor; hedef loglarının operatörden uzağı göstermesi için yakındaki compromised bir system, gizli bir device, public access, cellular backhaul veya satellite receiver kullanabilir. Bunların hiçbiri fiziksel, radio veya provider kanıtlarını ortadan kaldırmaz; attribution'ı farklı dataset'lere taşır.

## Technique matrisi

| Technique | Görünürdeki origin | Gerekli koşul | Yüksek değerli kanıt |
|---|---|---|---|
| Yakındaki wireless pivot | hedefin yanındaki bir business/home | compromised dual-homed host ve hedef Wi-Fi access'i | neighbor-host endpoint log'ları, RF association ve hedef RADIUS/DHCP |
| Public/guest network | venue NAT'i veya tunnel exit'i | yasal access veya access-control bypass | captive portal, DHCP, AP association, CCTV ve payment/location kayıtları |
| Covert drop device | hedefte/yakınında wired, Wi-Fi veya cellular address | fiziksel yerleştirme veya delivery | switchport/USB, RF, inventory, power ve outbound tunnel telemetry |
| Cellular router/eSIM | carrier NAT'i veya dedicated APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier account ve traffic timing |
| Satellite-link abuse | beam footprint içindeki subscriber address'i | protocol- ve service-specific weakness | RF location, uplink flow, impossible RTT/routing ve provider kayıtları |

## Nearest-neighbor attack

Volexity, 2022 yılında actor'ün nihai hedefinden uzakta olduğu bir APT28/GRU operasyonunu belgeledi. Actor, valid credential'lar elde etmek için hedefin public service'ine password spraying uyguladı, ancak MFA doğrudan Internet login'ini engelledi. Hedefin enterprise Wi-Fi'ı bu credential'ları MFA olmadan kabul ediyordu. Actor, hedefe fiziksel olarak yakın kuruluşları compromise etti, wireless reach'e sahip dual-homed bir system buldu ve bu system'i kullanarak hedef Wi-Fi'ında authenticate oldu. Volexity bu yöntemi **Nearest Neighbor Attack** olarak adlandırdı.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Yenilik bileşimden kaynaklanır. Hiçbir operatör hedefe gitmez ve Internet-facing service'in MFA'sı hâlâ çalışır. Ele geçirilmiş komşu fiziksel yakınlığı sağlar; çalınan hedef kimlik bilgisi logical access sağlar; hedef Wi-Fi ise sınırları aşan yol hâline gelir.

### Ön koşullar ve görünürlük

- Yakındaki bir sistem uzaktan kontrol edilebilir olmalı ve uyumlu bir radio'ya veya başka bir yakındaki pivot'a erişebilmelidir.
- Hedef SSID bu sisteme ulaşmalı ve Wi-Fi admission yeniden kullanılabilir bir credential/certificate/device state kabul etmelidir.
- Pivot'un çoğu zaman iki eşzamanlı path'e ihtiyacı vardır: biri operatöre geri dönüş, diğeri hedef WLAN'a giriş için.
- Hedef, yeni bir station MAC ve meşru bir username görebilir; ancak buna karşılık gelen managed-device certificate, posture, history veya beklenen bina girişi bulunmayabilir.
- Neighbor endpoint log'larında wireless scans, new profiles, interface changes, tunneling ve remote-control activity görülebilir.

### Tespit ve önleme

1. Enterprise Wi-Fi için certificate-backed EAP-TLS ve managed-device posture zorunlu tutun; Internet'te MFA'yı geçemeyen bir password'ü yalnızca radio üzerinden geldiği için yeterli kabul etmeyin.
2. RADIUS authentication verilerini MDM/NAC identity, geçmiş station/device binding, AP location, physical-access events ve eşzamanlı sessions ile ilişkilendirin.
3. Bir account ilk kez associate olduğunda, alışılmadık bir AP edge'den geldiğinde, managed certificate olmadan kullanıldığında veya aynı identity başka bir yerde aktifken alarm üretin.
4. Interface'leri bridge edebilen endpoint'leri izleyin. Windows, Linux ve network appliances üzerinde beklenmeyen WLAN profiles, forwarding/NAT configuration, virtual adapters ve persistent tunnels durumlarını araştırın.
5. Makul AP placement ve power planning kullanarak gereksiz signal spill'i azaltın. Bu, authentication yerine geçen değil, destekleyici bir kontroldür.
6. Incident response çalışmalarını komşu tenant'larla koordine edin: nihai radio source'un kendisi de bir victim olabilir.

[İki kuruluşun sahip olduğu lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot), bir komşuya saldırmadan bu observable'ları yeniden oluşturur.

## Public venues and third-party Wi-Fi

Café, hotel, airport veya municipal Wi-Fi kullanmak hedefte görünen IP'yi değiştirir. Anonymity oluşturmaz. Venue veya sağlayıcısı AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation ve flow logs verilerini saklayabilir. Physical entry, CCTV, purchase, mobile-location ve travel records dijital olayı bir kişiyle ilişkilendirebilir.

Bir actor randomized MAC addresses, separate device, cash veya tunnel kullanarak bir izden kurtulmaya çalışabilir. Cross-layer correlation yine de arrival time, tekrarlanan venue pattern, radio fingerprints, portal behavior, traffic timing, camera footage ve tunnel provider üzerinden mümkün olabilir. VPN, destination bilgisini venue logs'tan VPN logs'a taşır; cihazın orada bulunduğuna ilişkin venue bilgisini ortadan kaldırmaz.

Public access sistemlerinin savunucuları clients'ı isolate etmeli, lateral traffic'i block etmeli, mümkün olduğunda WPA2/3-Enterprise veya per-device keys kullanmalı, orantılı DHCP/RADIUS/security logs saklamalı, captive portals'ı korumalı ve bir abuse process yayımlamalıdır. Red teams, bu tür bir venue'yu yalnızca koşulları ve engagement buna izin verdiğinde kullanmalıdır; bir portalı bypass etmek, access çalmak veya diğer guests'leri hedef almak authorized testing için bir kestirme yol değildir.

## Covert drop devices and warshipping

Bir drop, bir site'a yerleştirilen veya gönderilen, ardından outbound Ethernet, Wi-Fi veya cellular üzerinden kontrol edilen küçük bir sistemdir. “Warshipping”, cihazı ordinary delivery'nin onu radio perimeter'ın içine taşıyacağı şekilde paketler. Olası hardware, single-board computer'dan modified charger, USB peripheral, network appliance veya battery-powered modem'e kadar değişebilir.

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Cihaz uzaktan bir foothold sağlayabilir, wireless ölçümleri gerçekleştirebilir, yetkilendirilmiş bir exercise peripheral'ını taklit edebilir veya trafiği relay edebilir. Görünürdeki kaynağı yereldir; ancak seri numaraları, ambalaj, fingerprints, kameralar, erişim günlükleri, güç tüketimi, USB descriptors, switchport negotiation, DHCP fingerprints, MAC OUI/randomization behavior, RF emissions ve tekrarlanan rendezvous connections gibi fiziksel izler oluşturur.

### Defensive controls

- Teslim alma odası ve asset-inventory prosedürlerini sürdürün; beklenmeyen elektronik cihazları ve var olmayan personele gönderilmiş paketleri inceleyin.
- Kablolu ve wireless erişimde 802.1X/NAC kullanın, kullanılmayan portları devre dışı bırakın ve bilinmeyen cihazları kısıtlı bir remediation VLAN'a yerleştirin.
- Yeni DHCP fingerprints, kalıcı olarak kullanılan locally administered MAC'ler, yeni USB network/HID cihazları, yetkisiz Wi-Fi Direct/Bluetooth ve uzun süreli outbound tunnel'lar için alert oluşturun.
- Switchport, power-over-Ethernet, DNS ve TLS davranışları için baseline oluşturun. Inventory kaydı olmayan ve periyodik encrypted connections oluşturan küçük bir host, tek başına “Raspberry Pi OUI” bilgisinden daha güçlü bir sinyaldir.
- Bir exercise sırasında inventory oluşturun, etiketleyin, kapsamı belirleyin, encrypt edin, remote kill sağlayın, retrieval deadline belirleyin ve kaybın yeniden kullanılabilir credentials'ları açığa çıkaramayacağından emin olun.

## Cellular and eSIM backhaul

Bir cellular modem, target'ın Internet gateway'ini atlar ve outbound bir rendezvous üzerinden carrier NAT arkasındaki drop'ın erişilebilir kalmasını sağlayabilir. Mobile adresler değişebilir veya paylaşılabilir; cellular operator yine de güçlü subscriber ve network kanıtlarına sahiptir: SIM/eSIM identity, IMSI, atanmış adresler/portlar, cell/sector timing, account/payment ve roaming kayıtları.

Enterprise açısından beklenmeyen modemleri ve personal hotspot'ları wireless/RF surveys, endpoint USB/PCI inventory, MDM restrictions, rogue-SSID monitoring ve fiziksel incelemeyle tespit edin. Control için cellular kullanan bir drop, yine de yerel Ethernet/Wi-Fi davranışı ve radio emissions üzerinden yakalanabilir.

Yetkilendirilmiş exercise'lar için kuruluş subscription'ı ve modemi kendisi sahiplenmeli, identifier'ları controller ile birlikte kaydetmeli ve carrier/provider terms'ün trafiğe izin verdiğini doğrulamalıdır. Prepaid bir label veya cryptocurrency ile yapılan satın alma, tower, device veya retail kayıtlarını ortadan kaldırmaz.

## MAC randomization and device fingerprinting

Modern sistemler her network için locally administered random MAC kullanabilir. Bu, sabit bir factory MAC üzerinden yapılan pasif ve uzun süreli tracking'i azaltır; ancak şunları gizlemez:

- probe/association timing ve istenen network capabilities kümesi;
- 802.11 information elements, supported rates ve vendor-specific behavior;
- DHCP options/hostname, IPv6 identifiers ve captive-portal/browser fingerprint;
- authenticated 802.1X identity veya certificate;
- higher-layer account, tunnel ve traffic pattern; veya
- fiziksel gözlem.

Defenders, MAC allowlists'i authentication olarak kullanmamalıdır. Radio identity'yi certificate/device posture ile ilişkilendirin ve diğer bağlam anormal olmadığı sürece değişen MAC'leri normal kabul edin.

## Satellite-link hijacking

Kaspersky, Turla'nın eski tek yönlü DVB-S satellite Internet sistemlerindeki zayıflıkları kullandığını belgeledi. Bildirilen modelde meşru bir remote subscriber, outbound requests'leri terrestrial bir link üzerinden gönderiyor; ancak downstream data'yı encrypted olmayan geniş alanlı bir satellite broadcast üzerinden alıyordu. Satellite footprint içindeki bir actor, downlink'i gözlemleyebilir, aktif bir subscriber IP'si seçebilir ve C2 replies'lerinin bu IP'ye adreslenmesini sağlayabilirdi. Hem meşru subscriber hem de actor broadcast'i alıyordu; actor seçilen port için trafiği çıkarırken meşru subscriber unsolicited packets'leri discarded ediyordu. C2 operator'ü daha sonra başka bir coğrafyadaki bir satellite-provider adresini kullanıyor gibi görünüyordu.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Bu, protokole/hizmete özgü, bant genişliği kısıtlı bir yöntemdi ve modern, çift yönlü şifrelenmiş bir uydu terminalinin ele geçirilmesine eşdeğer değildi. Ayrıca yeterli kapasiteye sahip bir gözlemciden aktörün giden istek yolunu gizlemiyordu. Tespit fırsatları arasında asimetrik/imkansız yönlendirme, akışı başlatmamış bir aboneye giden trafik, olağandışı hedef portları, sağlayıcı telemetrisi, alıcı konumu/RF incelemesi ve malware yapılandırması bulunur. Bu vakayı, bir C2 IP'sinin coğrafi konumunu belirlemenin onun controller'ının konumunu da belirlediği varsayımını sorgulamak için kullanın; bunu bir kurulum tarifi olarak kullanmayın.

## Physical-to-digital correlation worksheet

Görünüşte yerel olan bir kaynak şüpheli olduğunda tek bir zaman çizelgesi oluşturun:

1. AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch ve fiziksel erişim saatlerini normalize edin;
2. yalnızca ilk alert'e değil, ilk radio association veya link-up olayına odaklanın;
3. istasyonu sertifika, cihaz duruşu, DHCP fingerprint'i ve switch/AP konumuyla eşleştirin;
4. yakındaki sistemlerde eşzamanlı remote-control/tunnel etkinliği olup olmadığını araştırın;
5. geçerli politika/hukuk kapsamında teslimatları, ziyaretçileri, envanter istisnalarını, kameraları ve RF bulgularını inceleyin;
6. şüpheli cihazı ve uçucu ağ durumunu koruyun; düşünmeden güç döngüsü uygulamayın;
7. görünürdeki kaynağın aktör tarafından kontrol edilen bir altyapı mı yoksa başka bir victim mı olduğunu belirleyin.

## References

- [1] [Volexity — The Nearest Neighbor Attack: Bir Rus APT'sinin yakındaki Wi-Fi ağlarını weaponize etmesi](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: Gökyüzündeki APT command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wireless Local Area Networks güvenliği için yönergeler](https://csrc.nist.gov/pubs/sp/800/153/final)

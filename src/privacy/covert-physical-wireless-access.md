# Gizli Fiziksel ve Wireless Erişim

{{#include ../banners/hacktricks-training.md}}

Outbound rendezvous, güç/uplink kurtarma, cihazda tutulan sırların en aza indirilmesi, capture testing ve olası keşfe yönelik izleme işlemlerini kapsayan, ayrıntılı ve sahip tarafından onaylanmış bir uygulama için bkz. [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Ağ yolunun değiştirilmesi, görünen fiziksel kaynağı da değiştirebilir. Gelişmiş bir saldırgan, hedef günlüklerinin operatörden uzağı göstermesi için yakındaki ele geçirilmiş bir sistemi, gizli bir cihazı, public access'i, cellular backhaul'u veya bir uydu alıcısını kullanabilir. Bunların hiçbiri fiziksel, radyo veya provider kanıtlarını ortadan kaldırmaz; attribution'ı farklı veri kümelerine taşır.

## Teknik matrisi

| Teknik | Görünen kaynak | Gerekli koşul | Yüksek değerli kanıt |
|---|---|---|---|
| Yakındaki wireless pivot | hedefin yanındaki bir işletme/ev | ele geçirilmiş dual-homed host ve hedef Wi-Fi erişimi | komşu host endpoint günlükleri, RF association ve hedef RADIUS/DHCP |
| Public/guest network | venue NAT veya tunnel exit | hukuka uygun erişim veya access-control bypass | captive portal, DHCP, AP association, CCTV ve ödeme/konum kayıtları |
| Gizli drop cihazı | hedefin/yakının wired, Wi-Fi veya cellular adresi | fiziksel yerleştirme veya teslimat | switchport/USB, RF, envanter, güç ve outbound tunnel telemetrisi |
| Cellular router/eSIM | carrier NAT veya özel APN | modem/SIM/subscription | IMEI/IMSI/eSIM, cell-sector, carrier hesabı ve trafik zamanlaması |
| Satellite-link abuse | beam footprint içindeki subscriber adresi | protokole ve servise özgü zayıflık | RF konumu, uplink akışı, imkânsız RTT/routing ve provider kayıtları |

## Nearest-neighbor attack

Volexity, 2022 yılında aktörün nihai hedefinden uzakta olduğu bir APT28/GRU operasyonunu belgeledi. Aktör, geçerli kimlik bilgileri elde etmek için hedefin public service'ine password spraying uyguladı; ancak MFA, doğrudan Internet girişini engelledi. Hedefin enterprise Wi-Fi'ı bu kimlik bilgilerini MFA olmadan kabul ediyordu. Aktör, hedefe fiziksel olarak yakın kuruluşları ele geçirdi, wireless erişimi olan dual-homed bir sistem buldu ve bu sistemi hedef Wi-Fi'a authenticate olmak için kullandı. Volexity bu yöntemi **Nearest Neighbor Attack** olarak adlandırdı.<sup>[[1]](#references)</sup>
```text
remote operator
|
compromised organization C
|
compromised organization B -- Wi-Fi radio --> target organization A
|
internal service
```
Yenilik, bileşimden kaynaklanır. Hiçbir operatör hedefe gitmez ve Internet-facing service'in MFA'sı çalışmaya devam eder. Ele geçirilmiş komşu fiziksel yakınlığı sağlar; çalınmış hedef kimlik bilgisi mantıksal erişimi sağlar; hedef Wi-Fi'ı ise sınırları aşan yol haline gelir.

### Ön koşullar ve görünürlük

- Yakındaki bir sistemin uzaktan kontrol edilebilir olması ve uyumlu bir radio'ya veya yakındaki başka bir pivot'a erişimi bulunması gerekir.
- Hedef SSID bu sisteme ulaşmalı ve Wi-Fi admission yeniden kullanılabilir bir kimlik bilgisi/certificate/device state kabul etmelidir.
- Pivot'un çoğu zaman iki eş zamanlı yola ihtiyacı vardır: biri operatöre geri dönüş, diğeri hedef WLAN'a giriş için.
- Hedef, yeni bir station MAC ve geçerli bir username görebilir; ancak buna karşılık gelen managed-device certificate, posture, history veya beklenen building entry bulunmayabilir.
- Komşu endpoint log'larında wireless scans, yeni profiles, interface changes, tunneling ve remote-control activity görülebilir.

### Detection and prevention

1. Enterprise Wi-Fi için certificate-backed EAP-TLS ve managed-device posture zorunlu kılın; Internet üzerinde MFA'dan geçemeyen bir password yalnızca radio üzerinden geldiği için yeterli kabul edilmemelidir.
2. RADIUS authentication'ı MDM/NAC identity, historical station/device binding, AP location, physical-access events ve concurrent sessions ile ilişkilendirin.
3. Bir account ilk kez associate olduğunda, unusual AP edge üzerinden, managed certificate olmadan veya aynı identity başka bir yerde etkinken kullanıldığında alert üretin.
4. Interface'leri bridge edebilen endpoint'leri izleyin. Windows, Linux ve network appliances üzerinde beklenmeyen WLAN profiles, forwarding/NAT configuration, virtual adapters ve persistent tunnels durumlarını araştırın.
5. Uygun AP placement ve power planning ile gereksiz signal spill'i azaltın. Bu, authentication yerine geçen değil, destekleyici bir kontroldür.
6. Incident response'u komşu tenant'larla koordine edin: son radio source'un kendisi de bir victim olabilir.

[İki kuruluşun sahip olduğu lab](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot), bir komşuya saldırmadan bu gözlemlenebilir durumları yeniden oluşturur.

## Public venues and third-party Wi-Fi

Café, hotel, airport veya municipal Wi-Fi kullanmak, bir destination'a gösterilen IP'yi değiştirir. Anonymity oluşturmaz. Venue veya provider'ı AP association, device MAC, DHCP lease, captive-portal account, SMS/email validation ve flow logs tutabilir. Physical entry, CCTV, purchase, mobile-location ve travel records, digital event'i bir kişiyle ilişkilendirebilir.

Bir actor, randomized MAC addresses, ayrı bir device, cash veya tunnel kullanarak bir iz bilgisini azaltmaya çalışabilir. Cross-layer correlation yine de arrival time, tekrarlanan venue pattern, radio fingerprints, portal behavior, traffic timing, camera footage ve tunnel provider üzerinden mümkün olabilir. VPN ayrıca destination'ı venue logs'tan VPN logs'a taşır; device'ın venue'da bulunduğuna dair venue bilgisini ortadan kaldırmaz.

Public access savunucuları client'ları izole etmeli, lateral traffic'i engellemeli, mümkün olduğunda WPA2/3-Enterprise veya per-device keys kullanmalı, orantılı DHCP/RADIUS/security logs tutmalı, captive portals'ı korumalı ve bir abuse process yayımlamalıdır. Red teams, böyle bir venue'yu yalnızca venue şartları ve engagement buna izin verdiğinde kullanmalıdır; portal'ı bypass etmek, access çalmak veya diğer guest'leri hedeflemek authorized testing için bir shortcut değildir.

## Covert drop devices and warshipping

Bir drop, bir site'a yerleştirilen veya teslim edilen, ardından outbound Ethernet, Wi-Fi ya da cellular üzerinden kontrol edilen küçük bir sistemdir. “Warshipping”, cihazı sıradan bir teslimatın onu radio perimeter'ın içine taşımasını sağlayacak şekilde paketler. Olası hardware, single-board computer'dan modified charger'a, USB peripheral'a, network appliance'a veya battery-powered modem'e kadar değişebilir.

Operational architecture:
```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
|
scoped local interface
```
Cihaz uzaktan bir foothold sağlayabilir, wireless ölçümleri gerçekleştirebilir, yetkili bir exercise peripheral'ını taklit edebilir veya trafiği relay edebilir. Görünürdeki kaynağı yereldir; ancak seri numaraları, ambalaj, fingerprint'ler, kameralar, erişim logları, güç tüketimi, USB descriptor'ları, switchport negotiation, DHCP fingerprint'leri, MAC OUI/randomization davranışı, RF emissions ve tekrarlanan rendezvous bağlantıları gibi fiziksel izler oluşturur.

### Defensive controls

- Receiving-room ve asset-inventory prosedürlerini sürdürün; beklenmeyen elektronik cihazları ve var olmayan personele adreslenmiş paketleri inceleyin.
- Kablolu ve wireless erişimde 802.1X/NAC kullanın, kullanılmayan portları devre dışı bırakın ve bilinmeyen cihazları kısıtlı bir remediation VLAN'a yerleştirin.
- Yeni DHCP fingerprint'leri, kalıcı olarak kullanılan locally administered MAC'leri, yeni USB network/HID cihazlarını, yetkisiz Wi-Fi Direct/Bluetooth kullanımını ve uzun süreli outbound tunnel'ları alert ile izleyin.
- Switchport, power-over-Ethernet, DNS ve TLS davranışlarını baseline edin. Inventory kaydı olmayan ve periyodik encrypted bağlantılar oluşturan küçük bir host, tek başına “Raspberry Pi OUI” sinyalinden daha güçlüdür.
- Bir exercise sırasında inventory oluşturun, etiketleyin, kapsamı belirleyin, encrypt edin, remote kill sağlayın, retrieval deadline belirleyin ve kaybın yeniden kullanılabilir credential'ları açığa çıkaramayacağından emin olun.

## Cellular and eSIM backhaul

Bir cellular modem, hedefin Internet gateway'ini atlar ve outbound bir rendezvous üzerinden carrier NAT arkasındaki drop'un erişilebilir kalmasını sağlayabilir. Mobile adresler değişebilir veya paylaşılabilir; ancak cellular operatöründe hâlâ güçlü subscriber ve network kanıtları bulunur: SIM/eSIM kimliği, IMSI, atanmış adresler/portlar, cell/sector zamanlaması, hesap/ödeme ve roaming kayıtları.

Enterprise açısından beklenmeyen modemleri ve kişisel hotspot'ları wireless/RF survey'leri, endpoint USB/PCI inventory'si, MDM kısıtlamaları, rogue-SSID monitoring ve fiziksel inceleme ile tespit edin. Control için cellular kullanan bir drop, yerel Ethernet/Wi-Fi davranışı ve radio emissions üzerinden yine yakalanabilir.

Yetkili exercise'lar için kuruluş subscription'a ve modeme sahip olmalı, identifier'ları controller ile kaydetmeli ve carrier/provider şartlarının trafiğe izin verdiğini doğrulamalıdır. Prepaid bir etiket veya cryptocurrency ile yapılan satın alma, tower, cihaz veya perakende kayıtlarını ortadan kaldırmaz.

## MAC randomization and device fingerprinting

Modern sistemler her network için locally administered random MAC kullanabilir. Bu, sabit bir factory MAC üzerinden pasif uzun vadeli tracking'i azaltır; ancak şunları gizlemez:

- probe/association zamanlamasını ve istenen network capability'leri kümesini;
- 802.11 information element'lerini, desteklenen rate'leri ve vendor-specific davranışı;
- DHCP option/hostname'ı, IPv6 identifier'larını ve captive-portal/browser fingerprint'ini;
- authenticated 802.1X identity veya certificate'ı;
- daha üst katmandaki account, tunnel ve traffic pattern'ini; veya
- fiziksel gözlemi.

Defenders, MAC allowlist'lerini authentication olarak kullanmamalıdır. Radio identity'yi certificate/device posture ile ilişkilendirin ve diğer bağlam anomalik olmadığı sürece değişen MAC'leri normal kabul edin.

## Satellite-link hijacking

Kaspersky, Turla'nın eski tek yönlü DVB-S satellite Internet'teki zayıflıkları kullandığını belgeledi. Bildirilen modelde meşru bir remote subscriber, outbound request'leri terrestrial link üzerinden gönderiyor; ancak downstream data'yı unencrypted wide-area satellite broadcast üzerinden alıyordu. Satellite footprint içinde bulunan bir actor, downlink'i gözlemleyebilir, aktif bir subscriber IP'si seçebilir ve C2 yanıtlarının bu IP'ye adreslenmesini sağlayabilirdi. Hem meşru subscriber hem de actor broadcast'i alıyordu; actor seçilen portun trafiğini ayıklarken meşru subscriber unsolicited packet'ları discard ediyordu. C2 operator'ü daha sonra başka bir coğrafyadaki bir satellite-provider adresini kullanıyor gibi görünüyordu.<sup>[[2]](#references)</sup>
```text
actor uplink request -> C2 server -> Internet -> satellite gateway
satellite broadcast
+--------------+-------------+
|                            |
legitimate subscriber          actor receiver
```
Bu, protokol/hizmete özgü ve bant genişliği kısıtlıydı; ayrıca modern, çift yönlü şifrelenmiş bir uydu terminalinin ele geçirilmesine eşdeğer değildi. Yeterli kapasiteye sahip bir gözlemciden aktörün dışa yönelik istek yolunu da gizlemiyordu. Tespit fırsatları arasında asimetrik/imkânsız yönlendirme, akışı başlatmamış bir aboneye yönelik trafik, olağandışı hedef portları, sağlayıcı telemetrisi, alıcının konumu/RF incelemesi ve malware yapılandırması bulunur. Bu vakayı, bir C2 IP'sini coğrafi olarak konumlandırmanın onun controller'ını da coğrafi olarak konumlandırdığı varsayımını sorgulamak için kullanın; bunu bir kurulum tarifi olarak kullanmayın.

## Fizikselden dijitale korelasyon çalışma sayfası

Görünüşte yerel olan bir kaynak şüpheli olduğunda tek bir zaman çizelgesi oluşturun:

1. AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch ve fiziksel erişim saatlerini normalize edin;
2. yalnızca ilk alert'i değil, ilk radyo ilişkilendirmesini veya link-up olayını belirleyin;
3. istasyonu sertifika, cihaz duruşu, DHCP fingerprint'i ve switch/AP konumuyla eşleştirin;
4. yakındaki sistemlerde eş zamanlı remote-control/tunnel etkinliği olup olmadığını araştırın;
5. geçerli politika/yasa kapsamında teslimatları, ziyaretçileri, envanter istisnalarını, kameraları ve RF bulgularını inceleyin;
6. şüpheli cihazı ve uçucu ağ durumunu koruyun; düşünmeden power-cycle yapmayın;
7. görünürdeki kaynağın aktör tarafından kontrol edilen bir altyapı mı yoksa başka bir victim mı olduğunu belirleyin.

## References

- [1] [Volexity — En Yakın Komşu Saldırısı: Bir Russian APT'nin yakındaki Wi-Fi ağlarını weaponize etmesi](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Satellite Turla: Gökyüzünde APT command and control](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Wireless Local Area Networks'i Güvenli Hale Getirme Kılavuzu](https://csrc.nist.gov/pubs/sp/800/153/final)
{{#include ../banners/hacktricks-training.md}}

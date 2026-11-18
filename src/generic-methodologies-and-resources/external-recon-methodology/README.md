# Phương pháp External Recon

{{#include ../../banners/hacktricks-training.md}}

## Khám phá tài sản

Để xem danh sách phân loại các dự án OSINT và khám phá web khác, hãy xem [Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint).

> Bạn được thông báo rằng mọi thứ thuộc về một công ty đều nằm trong scope, và bạn muốn tìm hiểu công ty đó thực sự sở hữu những gì.

Mục tiêu của giai đoạn này là xác định tất cả **các công ty thuộc sở hữu của công ty chính**, sau đó tìm tất cả **tài sản** của những công ty này. Để làm vậy, chúng ta sẽ:<sup>[[1]](#references)</sup>

1. Tìm các thương vụ mua lại của công ty chính để xác định những công ty nằm trong scope.
2. Tìm ASN (nếu có) của từng công ty để xác định các dải IP thuộc sở hữu của từng công ty.
3. Dùng reverse WHOIS lookup để tìm các mục khác (tên tổ chức, domain...) có liên quan đến mục đầu tiên (có thể thực hiện đệ quy).
4. Dùng các kỹ thuật khác như bộ lọc `org` và `ssl` của shodan để tìm các tài sản khác (có thể áp dụng đệ quy thủ thuật `ssl`).

Để xem quy trình bàn giao theo từng giai đoạn từ subdomain đã phân giải sang HTTP crawling và dò tìm port, hãy xem [Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline).

### **Các thương vụ mua lại**

Trước tiên, chúng ta cần biết **công ty nào khác thuộc sở hữu của công ty chính**.\
Một cách là truy cập [https://www.crunchbase.com/](https://www.crunchbase.com), **tìm kiếm** **công ty chính** rồi **nhấp** vào "**acquisitions**". Tại đó, bạn sẽ thấy những công ty đã được công ty chính mua lại.\
Một cách khác là truy cập trang **Wikipedia** của công ty chính và tìm mục **acquisitions**.\
Với các công ty đại chúng, hãy kiểm tra hồ sơ **SEC/EDGAR**, trang **quan hệ nhà đầu tư** hoặc sổ đăng ký doanh nghiệp địa phương (ví dụ: **Companies House** ở UK).\
Để tìm sơ đồ tập đoàn toàn cầu và các công ty con, hãy thử **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) và cơ sở dữ liệu **GLEIF LEI** ([https://www.gleif.org/](https://www.gleif.org/)).

> Đến đây, bạn đã biết tất cả các công ty nằm trong scope. Hãy cùng tìm hiểu cách xác định tài sản của họ.

### **ASN**

Số hiệu hệ thống tự trị (**ASN**) là một **số duy nhất** được **Internet Assigned Numbers Authority (IANA)** cấp cho một **hệ thống tự trị** (AS).\
Một **AS** gồm các **khối** **địa chỉ IP** có chính sách truy cập mạng bên ngoài được xác định rõ ràng và do một tổ chức duy nhất quản lý, nhưng có thể bao gồm nhiều nhà vận hành.

Việc xác định xem **công ty có được cấp ASN nào không** để tìm ra **các dải IP** của công ty là rất hữu ích. Bạn nên thực hiện **kiểm tra lỗ hổng** trên tất cả **host** trong **scope** và **tìm domain** trong các IP này.\
Bạn có thể **tìm kiếm** theo **tên** công ty, **IP** hoặc **domain** trên [**https://bgp.he.net/**](https://bgp.he.net) **hoặc** [**https://ipinfo.io/**](https://ipinfo.io/).\
**Tùy vào khu vực của công ty, các liên kết sau có thể hữu ích để thu thập thêm dữ liệu:** [**AFRINIC**](https://www.afrinic.net) **(Châu Phi),** [**Arin**](https://www.arin.net/about/welcome/region/)**(Bắc Mỹ),** [**APNIC**](https://www.apnic.net) **(Châu Á),** [**LACNIC**](https://www.lacnic.net) **(Mỹ Latinh),** [**RIPE NCC**](https://www.ripe.net) **(Châu Âu). Dù vậy, có lẽ mọi thông tin** hữu ích **(dải IP và Whois)** đã có trong liên kết đầu tiên.

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

Ngoài ra, tính năng enumeration **của** [**BBOT**](https://github.com/blacklanternsecurity/bbot) tự động tổng hợp và tóm tắt các ASN ở cuối lượt quét.

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

Bạn cũng có thể tìm các dải IP của một tổ chức bằng [ASNLookup](https://asnlookup.com/), dịch vụ có gói API miễn phí giới hạn.

### **Tìm lỗ hổng**

Ở thời điểm này, chúng ta đã biết **tất cả tài sản trong phạm vi**, vì vậy nếu được phép, bạn có thể chạy một **máy quét lỗ hổng** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) trên tất cả các host.\
Ngoài ra, bạn có thể thực hiện một số [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **hoặc dùng các dịch vụ như** Shodan, Censys hoặc ZoomEye **để tìm** các port đang mở. **Tùy vào những gì tìm được, bạn nên** tham khảo cuốn sách này để biết cách pentest một số dịch vụ có thể đang chạy.\
**Ngoài ra, cũng nên lưu ý rằng bạn có thể chuẩn bị một số danh sách** username **và** password **mặc định rồi thử** bruteforce các dịch vụ bằng [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> Chúng ta đã biết tất cả công ty trong phạm vi và tài sản của họ; đã đến lúc tìm các domain trong phạm vi.

_Lưu ý rằng các kỹ thuật được đề xuất dưới đây cũng có thể giúp bạn tìm được subdomain, và không nên xem nhẹ thông tin đó._

Trước tiên, bạn nên tìm **domain chính** của từng công ty. Ví dụ, với _Tesla Inc._ thì đó sẽ là _tesla.com_.

### **Reverse DNS**

Vì bạn đã tìm thấy tất cả dải IP của các domain, bạn có thể thử thực hiện **reverse DNS lookup** trên những **IP đó để tìm thêm domain trong phạm vi**. Hãy thử dùng DNS server của nạn nhân hoặc một DNS server phổ biến nào đó (1.1.1.1, 8.8.8.8)

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

Để việc này hoạt động, quản trị viên phải bật PTR theo cách thủ công.\
Bạn cũng có thể dùng [SecurityTrails](https://securitytrails.com/) để lấy thông tin này, mặc dù cần gói trả phí để xem dữ liệu DNS lịch sử.\
Với các dải lớn, những công cụ như [**massdns**](https://github.com/blechschmidt/massdns) và [**dnsx**](https://github.com/projectdiscovery/dnsx) rất hữu ích để tự động hóa việc tra cứu ngược và bổ sung thông tin.

### **Reverse Whois (loop)**

Trong một bản ghi **whois**, bạn có thể tìm thấy nhiều **thông tin** thú vị như **tên tổ chức**, **địa chỉ**, **email**, số điện thoại... Nhưng điều thú vị hơn là bạn có thể tìm thêm **tài sản liên quan đến công ty** bằng cách **tra cứu reverse whois theo bất kỳ trường nào trong số đó** (ví dụ: các bản ghi whois khác có cùng địa chỉ email).\
Bạn có thể dùng các công cụ trực tuyến như:

- [https://ip.thc.org/](https://ip.thc.org/) - **Miễn phí** (Web và API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Miễn phí**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Miễn phí**
- [https://www.whoxy.com/](https://www.whoxy.com) - Giao diện web **miễn phí**; API trả phí.
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - Trả phí
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Không miễn phí (chỉ có **100 lượt tìm kiếm miễn phí**)
- [https://www.domainiq.com/](https://www.domainiq.com) - Không miễn phí
- [https://securitytrails.com/](https://securitytrails.com/) - Quyền truy cập API miễn phí có giới hạn cho DNS/subdomain hiện tại; cần gói trả phí để tra cứu lịch sử và reverse.
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 500 credit API miễn phí khi đăng ký; sau đó tính phí.

Bạn có thể tự động hóa tác vụ này bằng [**DomLink** ](https://github.com/vysecurity/DomLink)(cần khóa API whoxy).\
Bạn cũng có thể tự động tìm kiếm reverse whois bằng [amass](https://github.com/owasp-amass/amass): `amass intel -d tesla.com -whois`

**Lưu ý rằng bạn có thể dùng kỹ thuật này để tìm thêm tên miền mỗi khi phát hiện một tên miền mới.**

### **Trackers**

Nếu tìm thấy **cùng một ID của cùng một tracker** trên 2 trang khác nhau, bạn có thể giả định rằng **cả hai trang** đều **do cùng một nhóm quản lý**.\
Ví dụ: nếu bạn thấy cùng một **Google Analytics ID** hoặc **Adsense ID** trên nhiều trang.

Một số trang và công cụ cho phép bạn tìm kiếm theo các tracker này và nhiều thông tin khác:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - Dịch vụ web và API **trả phí** ([bảng giá](https://www.stackscan.com/pricing)); hiện không quảng bá gói miễn phí. Tìm kiếm dựa trên bất kỳ tài sản nào được phân phối, không chỉ ID tracker: đường dẫn script, tên bundle tự host hoặc host tải tài sản, để tìm tất cả các site có chứa tài sản đó.

API trả về tech stack của một domain, hữu ích để xác nhận một tài sản tiềm năng thuộc cùng một hệ thống:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

Trả về từng công nghệ được phát hiện cùng với danh mục tương ứng. Asset pivoting hiện chỉ hỗ trợ web; API hỗ trợ tra cứu theo từng domain.

### **Favicon**

Bạn có biết chúng ta có thể tìm các domain và subdomain liên quan đến mục tiêu bằng cách tìm những domain có cùng hash favicon không? Đây chính xác là chức năng của công cụ [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) do [@m4ll0k2](https://twitter.com/m4ll0k2) tạo ra. Cách sử dụng như sau:

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Kết quả Favihash dùng để phát hiện các domain có cùng hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

Nói đơn giản, favihash cho phép chúng ta phát hiện các domain có cùng hash biểu tượng favicon với mục tiêu.

![Đầu ra favihash dùng để phát hiện các domain có cùng hash favicon](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

Dùng một hash favicon đã biết làm điểm pivot trên Shodan hoặc FOFA để tìm các instance khác của cùng công nghệ đang bị lộ ra ngoài.<sup>[[5]](#references)</sup>

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

Bạn cũng có thể thu thập favicon hash ở quy mô lớn bằng [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`), rồi pivot trong Shodan/Censys.

Hãy xem dấu vân tay favicon là manh mối và xác thực chúng bằng các tín hiệu xung quanh.<sup>[[3]](#references)[[4]](#references)</sup>

- **Xem hash là chỉ báo, không phải bằng chứng**: MMH3 có kích thước nhỏ; có thể xảy ra va chạm, dùng lại icon và giả mạo có chủ ý.
- **Kiểm tra nhiều đường dẫn hơn** `/favicon.ico`: xem các đường dẫn framework/build, tệp manifest, `browserconfig.xml`, `site.webmanifest`, `apple-touch-icon*`, data URL nội tuyến và thẻ HTML `<link rel="icon">`.
- **Các static asset vẫn có thể truy cập được phía sau các biện pháp kiểm soát WAF/SSO/IdP**: yêu cầu trực tiếp icon và kiểm tra `ETag`, `Last-Modified`, redirect và cache header.
- **Xác thực kết quả khớp bằng các tín hiệu xung quanh**: so sánh title, HTML/body hash, header, subject/SAN của chứng chỉ TLS, thành phần sản phẩm và port đang mở.
- **Phân cụm theo HTML/body hash**: template nhất quán làm tăng độ tin cậy của dấu vân tay; template không đồng nhất có thể cho thấy icon chung chung hoặc được dùng chung.
- **Coi hash xuất hiện trên các signature, port và sản phẩm không liên quan là dấu hiệu tiềm ẩn của honeypot hoặc placeholder.**
- **Với các mục tiêu chưa rõ ràng, hãy so sánh một trang thật với một đường dẫn không tồn tại**, chẳng hạn `/_favicon_probe_<8-hex>`; phản hồi hosting hoặc parking giống nhau có thể giải thích việc dùng chung icon.
- **Bắt đầu phân loại bằng các quy tắc phát hiện của Nuclei hoặc bộ dữ liệu công khai** ánh xạ favicon hash với sản phẩm và CPE.
- **Lưu ý khoảng trống về phạm vi theo IP**: các bề mặt dùng CDN, định tuyến SNI, anycast và chỉ có domain có thể không xuất hiện trong các bộ dữ liệu kiểu Shodan.

### **Bản quyền / Chuỗi duy nhất**

Tìm trong các trang web những **chuỗi có thể được dùng chung giữa các website trong cùng một tổ chức**. **Chuỗi bản quyền** có thể là một ví dụ phù hợp. Sau đó tìm chuỗi đó trên **google**, trong các **browser** khác hoặc thậm chí trên **shodan**: `shodan search http.html:"Copyright string"`

### **Thời gian CRT**

Việc có một cron job như sau là phổ biến:

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

để gia hạn tất cả chứng chỉ trên một máy chủ cùng lúc. Đối chiếu dấu thời gian của chứng chỉ hoặc vị trí trong nhật ký Certificate Transparency có thể tiết lộ các domain liên quan.<sup>[[6]](#references)</sup>

Ngoài ra, hãy sử dụng trực tiếp nhật ký **certificate transparency**:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Thông tin DMARC của email

Bạn có thể dùng một trang web như [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) hoặc một công cụ như [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) để tìm **các domain và subdomain dùng chung thông tin DMARC**.\
Một dịch vụ hữu ích khác là [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

Một bản ghi A bị bỏ quên có thể truy cập được khi nhà cung cấp cloud cấp lại một IP. Nghiên cứu được dẫn chứng mô tả một quy trình tận dụng cơ hội bằng cách tạo một instance và đối chiếu địa chỉ của nó với dữ liệu passive DNS; chỉ kiểm tra các tình huống takeover trong phạm vi được cho phép.<sup>[[7]](#references)</sup>

### **Các cách khác**

Lặp lại các hướng tìm kiếm phù hợp mỗi khi bạn tìm thấy một domain mới: mỗi kết quả có thể tiết lộ thêm tên chứng chỉ, mối liên hệ passive DNS, kết quả trùng favicon và mã định danh tổ chức mà bạn không thấy được từ domain ban đầu.<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

Vì bạn đã biết tên tổ chức sở hữu không gian IP, bạn có thể tìm kiếm dữ liệu đó trên Shodan bằng: `org:"Tesla, Inc."` Kiểm tra các host tìm được để phát hiện những domain mới, bất ngờ trong chứng chỉ TLS.

Bạn có thể truy cập **chứng chỉ TLS** của trang web chính, lấy **tên tổ chức**, rồi tìm tên đó trong **chứng chỉ TLS** của tất cả trang web mà **Shodan** biết bằng bộ lọc: `ssl:"Tesla Motors"` hoặc sử dụng một công cụ như [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) là một công cụ tìm **các domain liên quan** đến một domain chính và **subdomain** của chúng, rất ấn tượng.

**Passive DNS / DNS lịch sử**

Dữ liệu passive DNS rất hữu ích để tìm **các bản ghi cũ và bị lãng quên** vẫn phân giải được hoặc có thể bị takeover. Hãy xem:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **Tìm lỗ hổng**

Kiểm tra xem có thể thực hiện [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) nào không. Có thể một công ty đang **sử dụng một domain** nhưng đã **mất quyền sở hữu**. Chỉ cần đăng ký domain đó (nếu đủ rẻ) rồi thông báo cho công ty.

Nếu bạn tìm thấy **domain có IP khác** với những IP đã phát hiện trong quá trình tìm kiếm tài sản, hãy thực hiện **quét lỗ hổng cơ bản** (bằng Nessus hoặc OpenVAS) và [**quét cổng**](../pentesting-network/index.html#discovering-hosts-from-the-outside) bằng **nmap/masscan/shodan**. Tùy thuộc vào các dịch vụ đang chạy, bạn có thể tìm thấy trong **cuốn sách này một số thủ thuật để "tấn công" chúng**.\
_Lưu ý rằng đôi khi domain được host trên một IP không do khách hàng kiểm soát, vì vậy domain đó không thuộc phạm vi; hãy cẩn thận._

## Subdomains

> Chúng ta đã biết tất cả các công ty trong phạm vi, tất cả tài sản của mỗi công ty và tất cả domain liên quan đến các công ty đó.

Đã đến lúc tìm tất cả các subdomain có thể có của mỗi domain đã tìm được.

> [!TIP]
> Lưu ý rằng một số công cụ và kỹ thuật tìm domain cũng có thể giúp tìm subdomain

### **DNS**

Hãy thử tìm **subdomain** từ các bản ghi **DNS**. Chúng ta cũng nên thử **Zone Transfer** (Nếu phát hiện lỗ hổng, hãy báo cáo).

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

Để tìm các API và nền tảng cung cấp thông tin về hạ tầng, danh tiếng, hồ sơ rò rỉ và enrichment ngoài việc khám phá subdomain, xem [catalog API Reconnaissance và Threat-Intelligence](reconnaissance-and-threat-intelligence-apis.md).

Cách nhanh nhất để thu thập nhiều subdomain là tìm kiếm trong các nguồn bên ngoài. Các **tool** được sử dụng nhiều nhất là (để có kết quả tốt hơn, hãy cấu hình API key):


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

Có **những tools/API thú vị khác** dù không chuyên tìm subdomains nhưng vẫn có thể hữu ích, chẳng hạn:

- [**IP.THC.ORG**](https://ip.thc.org) API miễn phí

```bash
curl https://ip.thc.org/tesla.com
```

- [**API miễn phí của AnubisDB**](https://github.com/jonluca/Anubis-DB)

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

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Chúng crawl web để tìm các tệp JS và trích xuất subdomain từ đó.

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

- [**Công cụ tìm subdomain Censys**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) cung cấp quyền truy cập API miễn phí có giới hạn cho dữ liệu DNS và subdomain hiện tại; dữ liệu DNS/IP lịch sử yêu cầu gói trả phí.
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

Dự án này cung cấp **miễn phí tất cả subdomain liên quan đến các chương trình bug-bounty**. Bạn cũng có thể truy cập dữ liệu này bằng [chaospy](https://github.com/Moaaz-0x/chaospy) hoặc truy cập phạm vi được dự án này sử dụng tại [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

Bạn có thể xem **so sánh** nhiều công cụ trong số này tại đây: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

Hãy thử tìm các **subdomain** mới bằng cách brute-force các DNS server với những tên subdomain có thể có.

Để thực hiện việc này, bạn sẽ cần một số **wordlist subdomain phổ biến như**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

Bạn cũng cần IP của các DNS resolver tốt. Để tạo danh sách DNS resolver đáng tin cậy, bạn có thể tải các resolver từ [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) và dùng [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) để lọc chúng. Hoặc bạn có thể dùng: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

Các công cụ được khuyên dùng nhiều nhất để DNS brute-force là:

- [**massdns**](https://github.com/blechschmidt/massdns): Đây là công cụ đầu tiên thực hiện DNS brute-force hiệu quả. Công cụ này rất nhanh, tuy nhiên dễ tạo ra kết quả dương tính giả.

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): Công cụ này, tôi nghĩ, chỉ sử dụng 1 resolver.

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) là một wrapper cho `massdns`, được viết bằng Go, cho phép bạn liệt kê các subdomain hợp lệ bằng active bruteforce, cũng như phân giải subdomain có xử lý wildcard và hỗ trợ đầu vào/đầu ra dễ dàng.

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): Nó cũng sử dụng `massdns`.

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) dùng asyncio để brute force tên miền không đồng bộ.

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### Vòng brute-force DNS thứ hai

Sau khi tìm thấy các subdomain bằng nguồn mở và brute-force, bạn có thể tạo các biến thể từ những subdomain đã tìm thấy để thử tìm thêm. Một số công cụ hữu ích cho mục đích này:

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** Tạo các hoán vị dựa trên các domain và subdomain được cung cấp.

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): Tạo các hoán vị từ các domain và subdomain.
  - Bạn có thể lấy **wordlist** các hoán vị của goaltdns [**tại đây**](https://github.com/subfinder/goaltdns/blob/master/words.txt).

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** Với các domain và subdomain được cung cấp, công cụ sẽ tạo các biến thể. Nếu không chỉ định file chứa các biến thể, gotator sẽ sử dụng file riêng của nó.

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): Ngoài việc tạo các hoán vị subdomain, công cụ này còn có thể thử phân giải chúng (nhưng tốt hơn nên dùng các công cụ đã đề cập trước đó).
  - Bạn có thể lấy **wordlist** hoán vị của altdns [**tại đây**](https://github.com/infosec-au/altdns/blob/master/words.txt).

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): Một công cụ khác để tạo các hoán vị, biến thể và thay đổi của subdomain. Công cụ này sẽ brute force kết quả (không hỗ trợ DNS wildcard).
  - Bạn có thể tải wordlist permutations của dmut [**tại đây**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt).

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** Dựa trên một domain, công cụ **tạo các tên subdomain tiềm năng mới** theo những pattern được chỉ định để thử tìm thêm subdomain.

#### Tạo permutation thông minh

- [**regulator**](https://github.com/cramppet/regulator): Học các pattern dạng regex từ những subdomain đã phát hiện và tạo tên ứng viên để phân giải.<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ là một công cụ fuzzing brute-force subdomain, kết hợp với thuật toán đơn giản nhưng hiệu quả, được định hướng bằng phản hồi DNS. Công cụ sử dụng một tập dữ liệu đầu vào, chẳng hạn như wordlist được tùy chỉnh hoặc các bản ghi DNS/TLS lịch sử, để tạo chính xác thêm các tên miền tương ứng và tiếp tục mở rộng chúng theo vòng lặp dựa trên thông tin thu thập được trong quá trình quét DNS.

```
echo www | subzuf facebook.com
```

### **Quy trình khám phá subdomain**

Các ví dụ workflow của Trickest kết hợp OSINT, DNS brute force và các bước permutation để enumeration subdomain có thể lặp lại.<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

Nếu tìm thấy một địa chỉ IP có **một hoặc vài trang web** thuộc các subdomain, bạn có thể thử **tìm các subdomain khác có website trên IP đó** bằng cách tìm trong **các nguồn OSINT** những domain trỏ đến IP hoặc **brute force tên domain VHost trên IP đó**.

#### OSINT

Bạn có thể tìm một số **VHost trên IP bằng cách dùng** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **hoặc các API khác**.

**Brute Force**

Nếu nghi ngờ một subdomain nào đó bị ẩn trên web server, bạn có thể thử brute force:

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

### **Buckets Brute Force**

Trong khi tìm **subdomains**, hãy để ý xem chúng có **trỏ** đến loại **bucket** nào không; nếu có, hãy [**kiểm tra quyền**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**.**\
Ngoài ra, vì lúc này bạn đã biết tất cả domain trong phạm vi, hãy thử [**brute force các tên bucket có thể có và kiểm tra quyền**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

### **Giám sát**

Bạn có thể **giám sát** việc tạo **subdomain mới** cho một domain bằng cách theo dõi log **Certificate Transparency**; [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)thực hiện việc này.

### **Tìm kiếm lỗ hổng**

Kiểm tra khả năng xảy ra [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover).\
Nếu **subdomain** trỏ đến một **S3 bucket**, hãy [**kiểm tra quyền**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum).

Nếu tìm thấy **subdomain có IP khác** với những IP đã tìm được trong quá trình khám phá tài sản, bạn nên thực hiện **quét lỗ hổng cơ bản** (dùng Nessus hoặc OpenVAS) và [**quét port**](../pentesting-network/index.html#discovering-hosts-from-the-outside) bằng **nmap/masscan/shodan**. Tùy vào các dịch vụ đang chạy, bạn có thể tìm thấy trong **cuốn sách này một số thủ thuật để "tấn công" chúng**.\
_Lưu ý rằng đôi khi subdomain được host trên một IP không do khách hàng kiểm soát, nên IP đó không nằm trong phạm vi cho phép; hãy cẩn thận._

## IPs

Trong các bước đầu, có thể bạn đã **tìm thấy một số dải IP, domain và subdomain**.\
Đã đến lúc **thu thập tất cả IP trong các dải đó** và các IP của **domain/subdomain (truy vấn DNS).**

Bạn cũng có thể dùng các dịch vụ như sau để tìm **những IP trước đây từng được domain và subdomain sử dụng**. Những IP này có thể vẫn thuộc sở hữu của khách hàng (và có thể giúp bạn tìm ra [**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md))

- [**SecurityTrails**](https://securitytrails.com/) (dữ liệu DNS/IP lịch sử cần gói trả phí)

Bạn cũng có thể kiểm tra các domain trỏ đến một địa chỉ IP cụ thể bằng công cụ [**hakip2host**](https://github.com/hakluke/hakip2host)

### **Tìm kiếm lỗ hổng**

**Quét port tất cả IP không thuộc CDN** (vì rất có thể bạn sẽ không tìm thấy điều gì đáng chú ý ở đó). Bạn có thể **tìm thấy lỗ hổng** trong các dịch vụ đang chạy được phát hiện.

**Tìm một** [**hướng dẫn**](../pentesting-network/index.html) **về cách quét host.**

## Săn tìm web server

> Chúng ta đã tìm thấy tất cả công ty và tài sản của họ, đồng thời biết các dải IP, domain và subdomain trong phạm vi. Đã đến lúc tìm kiếm web server.

Ở các bước trước, có lẽ bạn đã thực hiện một số **recon các IP và domain được phát hiện**, nên có thể bạn **đã tìm thấy tất cả web server có thể có**. Tuy nhiên, nếu chưa, chúng ta sẽ xem một số **thủ thuật nhanh để tìm web server** trong phạm vi.

Lưu ý rằng nội dung này sẽ **tập trung vào việc khám phá web app**, vì vậy bạn cũng nên **thực hiện quét lỗ hổng** và **quét port** (**nếu phạm vi cho phép**).

Bạn có thể tìm thấy [**cách nhanh để khám phá các port mở liên quan đến web server bằng masscan tại đây**](../pentesting-network/index.html#http-port-discovery).\
Một công cụ thân thiện khác để tìm web server là [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) và [**httpx**](https://github.com/projectdiscovery/httpx). Bạn chỉ cần truyền vào danh sách domain, công cụ sẽ thử kết nối đến port 80 (http) và 443 (https). Ngoài ra, bạn có thể chỉ định thử các port khác:

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Ảnh chụp màn hình**

Giờ đây, khi đã tìm ra **tất cả web server** trong phạm vi (bao gồm các **IP** của công ty và tất cả **domain** cùng **subdomain**), có lẽ bạn **chưa biết nên bắt đầu từ đâu**. Vậy hãy bắt đầu thật đơn giản bằng cách chụp ảnh màn hình tất cả chúng. Chỉ cần **xem qua** **trang chính**, bạn có thể tìm thấy các endpoint **bất thường** có khả năng **dễ bị tổn thương** hơn.

Để thực hiện việc này, bạn có thể dùng [**EyeWitness**](https://github.com/RedSiege/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) hoặc [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

Ngoài ra, bạn có thể dùng [**eyeballer**](https://github.com/BishopFox/eyeballer) để quét tất cả **ảnh chụp màn hình** và cho biết **những ảnh nào có khả năng chứa lỗ hổng**, và ảnh nào thì không.

## Tài sản trên Public Cloud

Để tìm các tài sản cloud tiềm năng thuộc về một công ty, trước tiên bạn nên bắt đầu với **danh sách từ khóa nhận diện công ty đó**. Ví dụ, với một công ty crypto, bạn có thể dùng các từ như: `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`.

Bạn cũng sẽ cần wordlist gồm **các từ thường dùng trong tên bucket**:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

Sau đó, hãy dùng các từ này để tạo **các hoán vị** (xem [**Vòng brute-force DNS thứ hai**](#second-dns-bruteforce-round) để biết thêm thông tin).

Với các wordlist thu được, bạn có thể dùng những công cụ như [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **hoặc** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

Hãy nhớ rằng khi tìm kiếm tài sản Cloud, bạn nên tìm **nhiều thứ hơn là chỉ bucket trên AWS**.

### **Tìm lỗ hổng**

Nếu tìm thấy những thứ như **bucket mở hoặc cloud function bị lộ**, bạn nên **truy cập chúng** và thử xem chúng cung cấp gì, cũng như liệu bạn có thể khai thác chúng hay không.

## Email

Với các **domain** và **subdomain** trong phạm vi, về cơ bản bạn đã có mọi thứ **cần thiết để bắt đầu tìm email**. Đây là những **API** và **công cụ** hoạt động hiệu quả nhất với tôi khi tìm email của một công ty:

- [**theHarvester**](https://github.com/laramies/theHarvester) - với API
- API của [**https://hunter.io/**](https://hunter.io/) (phiên bản miễn phí)
- API của [**https://app.snov.io/**](https://app.snov.io/) (phiên bản miễn phí)
- API của [**https://minelead.io/**](https://minelead.io/) (phiên bản miễn phí)

### **Tìm lỗ hổng**

Email sẽ hữu ích về sau khi **brute-force đăng nhập web và các dịch vụ xác thực** (chẳng hạn như SSH). Chúng cũng cần thiết cho các chiến dịch **phishing**. Ngoài ra, những API này sẽ cung cấp thêm **thông tin về người đứng sau email**, rất hữu ích cho chiến dịch phishing.

## Rò rỉ thông tin xác thực

Với **domain,** **subdomain** và **email**, bạn có thể bắt đầu tìm thông tin xác thực bị rò rỉ trước đây có liên quan đến các email đó:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Tìm lỗ hổng**

Nếu tìm được thông tin xác thực **bị rò rỉ còn hợp lệ**, đây là một chiến thắng rất dễ dàng.

## Rò rỉ bí mật

Rò rỉ thông tin xác thực có liên quan đến các vụ tấn công vào công ty, trong đó **thông tin nhạy cảm bị rò rỉ và đem bán**. Tuy nhiên, công ty cũng có thể bị ảnh hưởng bởi **những vụ rò rỉ khác** mà thông tin không có trong các cơ sở dữ liệu đó:

### Rò rỉ trên Github

Thông tin xác thực và API có thể bị rò rỉ trong **repository công khai** của **công ty** hoặc của **người dùng làm việc tại công ty github đó**.\
Bạn có thể dùng **công cụ** [**Leakos**](https://github.com/carlospolop/Leakos) để **tải xuống** tất cả **repo công khai** của một **tổ chức** và các **nhà phát triển** của tổ chức đó, rồi tự động chạy [**gitleaks**](https://github.com/gitleaks/gitleaks) trên chúng.

Bạn cũng có thể dùng **Leakos** để chạy **gitleaks** trên tất cả **văn bản** được cung cấp qua **các URL truyền vào**, vì đôi khi **trang web cũng chứa bí mật**.

#### Github Dorks

Xem trang [GitHub dorks and leaks](github-leaked-secrets.md) để tìm các **GitHub dorks** tiềm năng dùng để tìm kiếm trong tổ chức.

### Rò rỉ trên Paste

Đôi khi kẻ tấn công, hoặc đơn giản là nhân viên, sẽ **đăng nội dung công ty lên một trang paste**. Nội dung này có thể chứa hoặc không chứa **thông tin nhạy cảm**, nhưng vẫn rất đáng để tìm kiếm.\
Bạn có thể dùng công cụ [**Pastos**](https://github.com/carlospolop/Pastos) để tìm kiếm trên hơn 80 trang paste cùng lúc.

### Google Dorks

Google dorks tuy cũ nhưng vẫn hiệu quả, luôn hữu ích để tìm **thông tin bị lộ mà lẽ ra không nên công khai**. Vấn đề duy nhất là [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) có hàng **nghìn** truy vấn tiềm năng mà bạn không thể chạy thủ công. Vì vậy, bạn có thể chọn 10 truy vấn yêu thích hoặc dùng **công cụ như** [**Gorks**](https://github.com/carlospolop/Gorks) **để chạy tất cả**.

_Lưu ý rằng những công cụ dự kiến chạy toàn bộ cơ sở dữ liệu bằng trình duyệt Google thông thường sẽ không bao giờ chạy xong, vì Google sẽ chặn bạn rất nhanh._

### **Tìm lỗ hổng**

Nếu tìm được thông tin xác thực hoặc API token **bị rò rỉ còn hợp lệ**, đây là một chiến thắng rất dễ dàng.

## Lỗ hổng trong mã nguồn công khai

Nếu phát hiện công ty có **mã nguồn mở**, bạn có thể **phân tích** mã nguồn đó và tìm **lỗ hổng**.

**Tùy thuộc vào ngôn ngữ**, sẽ có các **công cụ** khác nhau để sử dụng; xem danh sách [công cụ review mã nguồn](../../network-services-pentesting/pentesting-web/code-review-tools.md).

Ngoài ra còn có các dịch vụ miễn phí cho phép bạn **quét các repository công khai**, chẳng hạn như:

- [**Snyk**](https://app.snyk.io/)

## [**Phương pháp Pentesting Web**](../../network-services-pentesting/pentesting-web/index.html)

**Phần lớn lỗ hổng** do bug hunter tìm thấy nằm trong **ứng dụng web**, vì vậy ở thời điểm này tôi muốn giới thiệu một **phương pháp kiểm thử ứng dụng web**. Bạn có thể [**tìm thông tin tại đây**](../../network-services-pentesting/pentesting-web/index.html).

Tôi cũng muốn đặc biệt nhắc đến mục [**Công cụ mã nguồn mở quét web tự động**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners), vì dù không nên kỳ vọng chúng tìm ra các lỗ hổng cực kỳ nghiêm trọng, chúng rất hữu ích khi được tích hợp vào **workflow để thu thập một số thông tin web ban đầu.**

## Tóm tắt

> Xin chúc mừng! Đến đây, bạn đã hoàn tất **toàn bộ quá trình enumeration cơ bản**. Đúng vậy, đây chỉ là mức cơ bản vì còn có thể thực hiện nhiều enumeration hơn nữa (sau này sẽ tìm hiểu thêm các thủ thuật).

Vậy là bạn đã:

1. Tìm thấy tất cả **công ty** trong phạm vi
2. Tìm thấy tất cả **tài sản** thuộc về các công ty (và thực hiện một số vuln scan nếu nằm trong phạm vi)
3. Tìm thấy tất cả **domain** thuộc về các công ty
4. Tìm thấy tất cả **subdomain** của các domain (có subdomain takeover nào không?)
5. Tìm thấy tất cả **IP** (cả **từ CDN** lẫn **không từ CDN**) trong phạm vi.
6. Tìm thấy tất cả **web server** và chụp **ảnh màn hình** của chúng (có gì bất thường đáng để xem xét kỹ hơn không?)
7. Tìm thấy tất cả **tài sản public cloud tiềm năng** thuộc về công ty.
8. **Email**, **thông tin xác thực bị rò rỉ** và **bí mật bị rò rỉ** có thể giúp bạn **đạt được chiến thắng lớn rất dễ dàng**.
9. **Pentesting tất cả trang web đã tìm thấy**

## **Công cụ Recon tự động toàn diện**

Có nhiều công cụ giúp thực hiện một phần các bước được đề xuất trên một phạm vi nhất định.

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - Hơi cũ và không được cập nhật



## References

- [1] [Jason Haddix – Phương pháp của Bug Hunter phiên bản 4.0: Recon](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Về favicon: Từ biểu tượng trình duyệt đến thông tin tình báo về bề mặt tấn công](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Biến favicon.ico thành vũ khí cho BugBounties, OSINT và nhiều mục đích khác](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Khám phá domain thông qua tấn công tương quan thời gian trên Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Phát hiện (và mô phỏng) một chiến dịch subdomain takeover tốn kém](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: Một phương pháp độc đáo để enumeration subdomain](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Quy trình khám phá subdomain toàn diện, Phần 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Khám phá subdomain bằng brute-force toàn diện với Trickest Workflow tự động, Phần 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – Ảnh chụp màn hình đầu ra favihash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}

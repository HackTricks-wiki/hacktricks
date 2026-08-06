# Modbus Protocol

{{#include ../../banners/hacktricks-training.md}}

## Modbus Protocol का परिचय

Modbus protocol Industrial Automation और Control Systems में व्यापक रूप से उपयोग किया जाने वाला protocol है। Modbus programmable logic controllers (PLCs), sensors, actuators और अन्य industrial devices जैसे विभिन्न devices के बीच communication की अनुमति देता है। Modbus Protocol को समझना आवश्यक है, क्योंकि यह ICS में सबसे अधिक उपयोग किया जाने वाला communication protocol है और इसमें sniffing तथा PLCs में commands inject करने के लिए attack surface की काफी संभावना होती है।

यहाँ concepts को point-wise बताया गया है, जिससे protocol और इसके operation की प्रकृति का context मिल सके। ICS system security में सबसे बड़ी चुनौती implementation और upgradation की लागत है। ये protocols और standards 80s और 90s के शुरुआती समय में design किए गए थे और आज भी व्यापक रूप से उपयोग किए जाते हैं। चूँकि किसी industry में बहुत सारे devices और connections होते हैं, इसलिए devices को upgrade करना बहुत कठिन होता है। इससे hackers को outdated protocols के साथ काम करने का लाभ मिलता है। Modbus पर attacks लगभग practically inevitable हैं, क्योंकि यदि इसका operation industry के लिए critical है, तो इसे बिना upgradation के उपयोग किया जाता रहेगा।

## Client-Server Architecture

Modbus Protocol का उपयोग आमतौर पर Client Server Architecture में किया जाता है, जहाँ एक master device (client) एक या अधिक slave devices (servers) के साथ communication शुरू करता है। इसे Master-Slave architecture भी कहा जाता है, जिसका electronics और IoT में SPI, I2C आदि के साथ व्यापक रूप से उपयोग होता है।

## Serial और Etherent Versions

Modbus Protocol को Serial Communication और Ethernet Communications, दोनों के लिए design किया गया है। Serial Communication का उपयोग legacy systems में व्यापक रूप से किया जाता है, जबकि modern devices Ethernet को support करते हैं, जो high data rates प्रदान करता है और modern industrial networks के लिए अधिक उपयुक्त है।

## Data Representation

Modbus protocol में data को ASCII या Binary के रूप में transmit किया जाता है, हालांकि older devices के साथ इसकी compactibility के कारण binary format का उपयोग किया जाता है।

## Function Codes

ModBus Protocol specific function codes के transmission के साथ काम करता है, जिनका उपयोग PLCs और विभिन्न control devices को operate करने के लिए किया जाता है। इस हिस्से को समझना महत्वपूर्ण है, क्योंकि function codes को retransmit करके replay attacks किए जा सकते हैं। Legacy devices data transmission के लिए encryption support नहीं करते और आमतौर पर इनमें लंबे wires का उपयोग होता है, जो devices को connect करते हैं। इसके परिणामस्वरूप इन wires के साथ tampering की जा सकती है और data को capture/inject किया जा सकता है।

## Modbus का Addressing

Network में प्रत्येक device का एक unique address होता है, जो devices के बीच communication के लिए आवश्यक है। Modbus RTU, Modbus TCP आदि protocols का उपयोग addressing को implement करने के लिए किया जाता है और ये data transmission के लिए transport layer की तरह कार्य करते हैं। Transferred data Modbus protocol format में होता है, जिसमें message शामिल होता है।

इसके अतिरिक्त, Modbus transmitted data की integrity सुनिश्चित करने के लिए error checks भी implement करता है। लेकिन सबसे महत्वपूर्ण बात यह है कि Modbus एक Open Standard है और कोई भी इसे अपने devices में implement कर सकता है। इसके कारण यह protocol global standard बन गया और industrial automation industry में व्यापक रूप से फैल गया।

इसके बड़े पैमाने पर उपयोग और upgradations की कमी के कारण, Modbus पर हमला करना इसके attack surface के कारण महत्वपूर्ण लाभ प्रदान करता है। ICS devices के बीच communication पर अत्यधिक निर्भर है और इन पर किए गए कोई भी attacks industrial systems के operation के लिए खतरनाक हो सकते हैं। यदि attacker transmission medium की पहचान कर ले, तो replay, data injection, data sniffing और leaking, Denial of Service, data forgery आदि attacks किए जा सकते हैं।

{{#include ../../banners/hacktricks-training.md}}

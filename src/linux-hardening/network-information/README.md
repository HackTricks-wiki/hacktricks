# नेटवर्क जानकारी

{{#include ../../banners/hacktricks-training.md}}

लोकल listeners, Unix sockets और नेटवर्क-facing सॉफ़्टवेयर ऐसे रास्ते उजागर कर सकते हैं जो बाहरी scan में दिखाई नहीं देते। सबसे पहले होस्ट की listening services और हर endpoint के स्वामी process की जाँच करें।

- [ट्रैफ़िक capture, firewall और egress triage](traffic-capture-and-firewall-egress.md) में packet capture, filtering, proxies और connectivity tests शामिल हैं।
- [लोकल नेटवर्क और socket triage](local-network-and-socket-triage.md) में loopback services, Unix sockets और container networks शामिल हैं।
- [Socket command injection](socket-command-injection.md) में exposed local sockets के ज़रिए स्वीकार किए जाने वाले commands शामिल हैं।
- [Cisco vManage](cisco-vmanage.md) में किसी खास product को target करने और उससे संबंधित जाँचों का विवरण है।
{{#include ../../banners/hacktricks-training.md}}

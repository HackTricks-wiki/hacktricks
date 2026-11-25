# नेटवर्क जानकारी

{{#include ../../banners/hacktricks-training.md}}

Local listeners, Unix sockets और network-facing software ऐसे रास्ते उजागर कर सकते हैं जो external scan में दिखाई नहीं देते। सबसे पहले host की listening services और हर endpoint के स्वामी process की जाँच करें।

- [Traffic capture, firewall, और egress triage](traffic-capture-and-firewall-egress.md) में packet capture, filtering, proxies, और connectivity tests शामिल हैं।
- [Local network और socket triage](local-network-and-socket-triage.md) में loopback services, Unix sockets, और container networks शामिल हैं।
- [Socket command injection](socket-command-injection.md) में exposed local sockets के ज़रिए स्वीकार किए जाने वाले commands शामिल हैं।
- Cisco SD-WAN Manager appliance पर foothold के लिए, [vManage local privilege escalation](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md) देखें; इसका ConfD CLI, REST API, और root-owned import paths सामान्य socket triage से अलग हैं।
{{#include ../../banners/hacktricks-training.md}}

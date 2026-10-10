# प्रक्रियाएँ, Crontab, Systemd और D-Bus

{{#include ../../banners/hacktricks-training.md}}

शेड्यूल किए गए जॉब और इंटरप्रोसेस कम्युनिकेशन, कॉल करने वाले से अलग विशेषाधिकारों के साथ कोड चला सकते हैं। किसी सर्विस या जॉब को टेस्ट करने से पहले उसके मालिक, कमांड और लिखने योग्य इनपुट की जाँच करें।

- [प्रोसेस की गणना और सर्विस पाथ](process-enumeration-and-service-paths.md) में प्रोसेस ट्री, रनटाइम फ़ाइलें और systemd एक्ज़ीक्यूशन चेन शामिल हैं।
- [Cron जॉब और systemd टाइमर](cron-and-systemd-timers.md) में शेड्यूल किए गए टास्क की खोज और लिखने योग्य इनपुट शामिल हैं।
- [D-Bus की गणना और कमांड इंजेक्शन से विशेषाधिकार वृद्धि](d-bus-enumeration-and-command-injection-privilege-escalation.md) में मैसेज बस और विशेषाधिकार प्राप्त सर्विस मेथड शामिल हैं।
- [एक्ज़ीक्यूट करने के लिए पेलोड](payloads-to-execute.md) में ऐसे पेलोड संकलित हैं जिनका उपयोग एक्ज़ीक्यूशन पाथ की पहचान होने पर किया जा सकता है।

Cron जॉब और systemd सर्विस की व्यापक समीक्षा के लिए [Linux विशेषाधिकार वृद्धि चेकलिस्ट](../main-system-information/linux-privilege-escalation-checklist.md) का उपयोग करें।
{{#include ../../banners/hacktricks-training.md}}

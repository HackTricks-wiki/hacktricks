# Kontenery i przestrzenie nazw

{{#include ../../banners/hacktricks-training.md}}

Kontener to proces Linux uruchomiony z konfiguracją izolacji i uprawnień. Oceniaj łącznie środowisko uruchomieniowe, zamontowane zasoby hosta, przyznane capabilities oraz konfigurację przestrzeni nazw. [Omówienie bezpieczeństwa kontenerów](container-security/README.md) wyjaśnia te warstwy i zawiera odnośniki do poszczególnych mechanizmów kontroli.

- [Containerd (`ctr`) privilege escalation](containerd-ctr-privilege-escalation.md) skupia się na dostępie do interfejsu zarządzania containerd.
- [RunC privilege escalation](runc-privilege-escalation.md) omawia zagadnienia eskalacji specyficzne dla tego środowiska uruchomieniowego.
- [Bezpieczeństwo kontenerów](container-security/README.md) wyjaśnia środowiska uruchomieniowe, ujawnione API, zagrożenia związane z obrazami, wrażliwe montowania, kontenery uprzywilejowane, ocenę bezpieczeństwa oraz zabezpieczenia, takie jak przestrzenie nazw, seccomp i obowiązkowa kontrola dostępu.
{{#include ../../banners/hacktricks-training.md}}

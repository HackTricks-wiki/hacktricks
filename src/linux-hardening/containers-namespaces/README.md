# Kontenery i przestrzenie nazw

{{#include ../../banners/hacktricks-training.md}}

Kontener to proces systemu Linux działający z konfiguracją izolacji i uprawnień. Oceniaj łącznie środowisko uruchomieniowe, zamontowane zasoby hosta, przyznane capabilities i ustawienia przestrzeni nazw. [Omówienie bezpieczeństwa kontenerów](container-security/README.md) wyjaśnia te warstwy i zawiera odnośniki do poszczególnych mechanizmów kontroli.

- [Eskalacja uprawnień w Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) skupia się na dostępie do interfejsu zarządzania containerd.
- [Eskalacja uprawnień w RunC](runc-privilege-escalation.md) omawia zagadnienia związane z eskalacją specyficzne dla środowiska uruchomieniowego.
- [Bezpieczeństwo kontenerów](container-security/README.md) wyjaśnia środowiska uruchomieniowe, ujawnione API, zagrożenia związane z obrazami, wrażliwe montowania, kontenery uprzywilejowane, ocenę bezpieczeństwa oraz zabezpieczenia, takie jak przestrzenie nazw, seccomp i mandatory access control.
{{#include ../../banners/hacktricks-training.md}}

# Kontenery i przestrzenie nazw

{{#include ../../banners/hacktricks-training.md}}

Kontener to proces Linux działający z konfiguracją izolacji i uprawnień. Oceniaj łącznie środowisko uruchomieniowe, zamontowane zasoby hosta, przyznane capabilities i ustawienia przestrzeni nazw. [Przegląd bezpieczeństwa kontenerów](container-security/README.md) omawia te warstwy i zawiera odnośniki do poszczególnych mechanizmów kontroli.

- [Eskalacja uprawnień przez Containerd (`ctr`)](containerd-ctr-privilege-escalation.md) dotyczy dostępu do interfejsu zarządzania containerd.
- [Eskalacja uprawnień przez RunC](runc-privilege-escalation.md) omawia materiały dotyczące eskalacji specyficznej dla środowiska uruchomieniowego.
- [Bezpieczeństwo kontenerów](container-security/README.md) omawia środowiska uruchomieniowe, udostępnione API, zagrożenia związane z obrazami, wrażliwe montowania, kontenery uprzywilejowane, ocenę oraz zabezpieczenia, takie jak przestrzenie nazw, seccomp i obowiązkowa kontrola dostępu.
{{#include ../../banners/hacktricks-training.md}}

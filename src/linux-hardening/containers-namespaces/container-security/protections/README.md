# Przegląd zabezpieczeń kontenerów

{{#include ../../../../banners/hacktricks-training.md}}

Najważniejszą ideą hardeningu kontenerów jest to, że nie istnieje pojedynczy mechanizm nazywany „container security”. To, co nazywa się izolacją kontenera, jest w rzeczywistości wynikiem współdziałania kilku mechanizmów bezpieczeństwa Linux oraz zarządzania zasobami. Jeśli dokumentacja opisuje tylko jeden z nich, czytelnicy mają tendencję do przeceniania jego siły. Jeśli dokumentacja wymienia je wszystkie bez wyjaśnienia ich wzajemnego działania, czytelnicy otrzymują katalog nazw, ale nie mają rzeczywistego modelu. Ta sekcja stara się uniknąć obu tych błędów.

W centrum tego modelu znajdują się **namespaces**, które izolują to, co workload może zobaczyć. Zapewniają one procesowi prywatny lub częściowo prywatny widok mountów systemu plików, PID-ów, sieci, obiektów IPC, hostname'ów, mapowań użytkowników/grup, ścieżek cgroup oraz niektórych zegarów. Jednak same namespaces nie decydują o tym, co proces może robić. Tym zajmują się kolejne warstwy.

**cgroups** kontrolują zużycie zasobów. Nie są przede wszystkim granicą izolacji w tym samym sensie co mount lub PID namespaces, ale mają kluczowe znaczenie operacyjne, ponieważ ograniczają pamięć, CPU, liczbę PID-ów, operacje I/O oraz dostęp do urządzeń. Mają również znaczenie dla bezpieczeństwa, ponieważ historyczne techniki breakout wykorzystywały zapisywalne funkcje cgroup, szczególnie w środowiskach cgroup v1.

**Capabilities** dzielą dawny, wszechwładny model root na mniejsze jednostki uprawnień. Ma to fundamentalne znaczenie dla kontenerów, ponieważ wiele workloadów nadal działa jako UID 0 wewnątrz kontenera. Pytanie nie brzmi więc wyłącznie „czy proces jest rootem?”, lecz raczej „które capabilities przetrwały, wewnątrz których namespaces oraz pod jakimi ograniczeniami seccomp i MAC?”. Dlatego proces root w jednym kontenerze może być stosunkowo ograniczony, podczas gdy proces root w innym kontenerze może być w praktyce niemal nieodróżnialny od root na hoście.

**seccomp** filtruje syscalle i zmniejsza powierzchnię ataku kernela udostępnioną workloadowi. Jest to często mechanizm blokujący oczywiście niebezpieczne wywołania, takie jak `unshare`, `mount`, `keyctl` lub inne syscalle używane w łańcuchach breakout. Nawet jeśli proces posiada capability, która w innych okolicznościach pozwalałaby na wykonanie operacji, seccomp może nadal zablokować ścieżkę syscalla, zanim kernel w pełni go przetworzy.

**AppArmor** i **SELinux** dodają Mandatory Access Control ponad standardowe kontrole systemu plików i uprawnień. Są szczególnie ważne, ponieważ nadal mają znaczenie, gdy kontener posiada więcej capabilities, niż powinien. Workload może posiadać teoretyczne uprawnienie do podjęcia próby wykonania działania, ale mimo to może zostać powstrzymany, ponieważ jego etykieta lub profil zabrania dostępu do odpowiedniej ścieżki, obiektu lub operacji.

Na koniec istnieją dodatkowe warstwy hardeningu, którym poświęca się mniej uwagi, ale które regularnie mają znaczenie podczas rzeczywistych ataków: `no_new_privs`, zamaskowane ścieżki procfs, ścieżki systemowe tylko do odczytu, główne systemy plików tylko do odczytu oraz starannie dobrane domyślne ustawienia runtime. Mechanizmy te często zatrzymują „ostatni etap” kompromitacji, szczególnie gdy atakujący próbuje przekształcić wykonanie kodu w szersze uzyskanie uprawnień.

Pozostała część tego folderu szczegółowo wyjaśnia każdy z tych mechanizmów, w tym to, co faktycznie robi dana konstrukcja kernela, jak obserwować ją lokalnie, jak korzystają z niej popularne runtime'y oraz jak operatorzy przypadkowo ją osłabiają.

## Przeczytaj dalej

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Wiele rzeczywistych escape zależy również od tego, jaka zawartość hosta została zamontowana wewnątrz workloadu, dlatego po zapoznaniu się z podstawowymi zabezpieczeniami warto przejść do:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}

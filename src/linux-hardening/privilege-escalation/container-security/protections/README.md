# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

Najważniejsza idea hardenowania kontenerów jest taka, że nie istnieje pojedyncza kontrola nazwana "container security". To, co ludzie nazywają izolacją kontenera, jest w rzeczywistości wynikiem współdziałania kilku mechanizmów bezpieczeństwa i zarządzania zasobami w Linuxie. Jeśli dokumentacja opisuje tylko jeden z nich, czytelnicy mają tendencję do przeceniania jego siły. Jeśli dokumentacja wylicza je wszystkie bez wyjaśnienia, jak ze sobą współdziałają, czytelnicy otrzymują katalog nazw, ale bez rzeczywistego modelu. Ta sekcja stara się unikać obu tych błędów.

W centrum modelu znajdują się **namespaces**, które izolują to, co workload może zobaczyć. Dają procesowi prywatny lub częściowo prywatny widok montowań systemu plików, PID-ów, sieci, obiektów IPC, nazw hostów, mapowania użytkowników/grup, ścieżek cgroup i niektórych zegarów. Jednak same namespaces nie decydują o tym, co proces ma prawo zrobić. Tu wchodzą kolejne warstwy.

**cgroups** zarządzają użyciem zasobów. Nie są one przede wszystkim granicą izolacji w tym samym sensie co mount czy PID namespaces, ale mają kluczowe znaczenie operacyjne, ponieważ ograniczają pamięć, CPU, PIDs, I/O i dostęp do urządzeń. Mają też znaczenie dla bezpieczeństwa, ponieważ historyczne techniki ucieczek wykorzystywały zapisywalne funkcje cgroup, szczególnie w środowiskach cgroup v1.

**Capabilities** dzielą stary, wszechmocny model root na mniejsze jednostki przywilejów. To jest fundamentalne dla kontenerów, ponieważ wiele workloadów wciąż działa jako UID 0 wewnątrz kontenera. Pytanie więc nie brzmi tylko "czy proces jest root?", lecz raczej "które capabilities przetrwały, wewnątrz których namespaces, pod jakimi ograniczeniami seccomp i MAC?" Dlatego proces działający jako root w jednym kontenerze może być stosunkowo ograniczony, podczas gdy proces root w innym kontenerze może w praktyce być niemal nieodróżnialny od host root.

**seccomp** filtruje syscalle i zmniejsza powierzchnię ataku jądra eksponowaną dla workloadu. Często to właśnie ten mechanizm blokuje oczywiście niebezpieczne wywołania, takie jak `unshare`, `mount`, `keyctl` lub inne syscall-e używane w łańcuchach ucieczek. Nawet jeśli proces ma capability, które w innym wypadku pozwoliłoby na operację, seccomp może nadal zablokować ścieżkę syscall przed pełnym przetworzeniem jej przez jądro.

**AppArmor** i **SELinux** dodają Mandatory Access Control ponad normalne kontrole systemu plików i przywilejów. Są one szczególnie istotne, ponieważ nadal mają znaczenie nawet wtedy, gdy kontener ma więcej capabilities, niż powinien. Workload może posiadać teoretyczny przywilej do podjęcia działania, ale wciąż być powstrzymany przed jego wykonaniem, ponieważ jego label lub profil zabrania dostępu do odpowiedniej ścieżki, obiektu lub operacji.

Na koniec istnieją dodatkowe warstwy hardenowania, które otrzymują mniej uwagi, ale regularnie mają znaczenie w prawdziwych atakach: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems oraz ostrożne domyślne ustawienia runtime. Te mechanizmy często zatrzymują "ostatni etap" kompromitacji, zwłaszcza gdy atakujący próbuje przekształcić wykonanie kodu w szersze uzyskanie przywilejów.

Reszta tego folderu wyjaśnia każdy z tych mechanizmów bardziej szczegółowo, włączając w to, co dany prymityw jądra faktycznie robi, jak go zaobserwować lokalnie, jak powszechne runtimy go używają i jak operatorzy przypadkowo go osłabiają.

## Czytaj dalej

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

Wiele rzeczywistych ucieczek zależy także od tego, jakie treści hosta zostały zamontowane do workloadu, więc po przeczytaniu podstawowych ochron warto kontynuować lekturę:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}

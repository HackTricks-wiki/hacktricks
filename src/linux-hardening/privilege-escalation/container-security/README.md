# Bezpieczeństwo kontenerów

{{#include ../../../banners/hacktricks-training.md}}

## Czym właściwie jest kontener

Praktyczny sposób zdefiniowania kontenera jest taki: kontener to **zwykłe drzewo procesów Linuxa**, które zostało uruchomione z określoną konfiguracją w stylu OCI tak, że widzi kontrolowany system plików, kontrolowany zestaw zasobów jądra i ograniczony model uprawnień. Proces może sądzić, że jest PID 1, może sądzić, że ma własny stos sieciowy, może sądzić, że posiada własną nazwę hosta i zasoby IPC, a nawet może działać jako root wewnątrz własnej przestrzeni użytkownika. Ale pod maską wciąż jest to proces hosta, który jądro planuje jak każdy inny.

Dlatego bezpieczeństwo kontenerów to w gruncie rzeczy badanie, jak ta iluzja jest skonstruowana i jak zawodzi. Jeśli namespace montowania jest słaby, proces może zobaczyć system plików hosta. Jeśli namespace użytkownika jest nieobecny lub wyłączony, root wewnątrz kontenera może mapować się zbyt blisko do roota na hoście. Jeśli seccomp jest niekonfigurowany, a zestaw capability jest zbyt szeroki, proces może uzyskać dostęp do syscalli i uprzywilejowanych funkcji jądra, które powinny pozostać poza zasięgiem. Jeśli socket runtime'u jest zamontowany wewnątrz kontenera, kontener wcale nie musi robić breakoutu do jądra, ponieważ może po prostu poprosić runtime o uruchomienie silniejszego kontenera‑rodzeństwa lub bezpośrednie zamontowanie rootfs hosta.

## Jak kontenery różnią się od maszyn wirtualnych

VM zazwyczaj ma własne jądro i granicę abstrakcji sprzętowej. Oznacza to, że jądro gościa może się zrestartować, zapaść lub zostać wykorzystane bez automatycznego przejęcia kontroli nad jądrem hosta. W kontenerach obciążenie nie otrzymuje oddzielnego jądra. Zamiast tego dostaje starannie przefiltrowany i namespacowany widok tego samego jądra, którego używa host. W efekcie kontenery są zwykle lżejsze, szybciej się uruchamiają, łatwiejsze do upakowania gęsto na maszynie i lepiej nadają się do wdrożeń krótkotrwałych aplikacji. Ceną jest to, że granica izolacji zależy znacznie bardziej bezpośrednio od poprawnej konfiguracji hosta i runtime'u.

To nie znaczy, że kontenery są „niebezpieczne”, a VM „bezpieczne”. Chodzi o to, że model bezpieczeństwa jest inny. Dobrze skonfigurowany stos kontenerowy z rootless execution, user namespaces, domyślnym seccomp, ścisłym zestawem capabilities, bez udostępniania namespace'ów hosta i z mocnym egzekwowaniem SELinux lub AppArmor może być bardzo odporny. Natomiast kontener uruchomiony z `--privileged`, udostępnianiem PID/sieci hosta, socketem Docker zamontowanym wewnątrz i zapisywalnym bind mountem `/` funkcjonalnie jest znacznie bliższy dostępowi do roota hosta niż bezpiecznej piaskownicy aplikacji. Różnica wynika z warstw, które zostały włączone lub wyłączone.

Istnieje także obszar pośredni, który czytelnicy powinni rozumieć, ponieważ pojawia się coraz częściej w rzeczywistych środowiskach. **Sandboxed container runtimes** takie jak **gVisor** i **Kata Containers** celowo wzmacniają granicę poza klasyczny kontener `runc`. gVisor umieszcza warstwę jądra w przestrzeni użytkownika między obciążeniem a wieloma interfejsami jądra hosta, podczas gdy Kata uruchamia obciążenie wewnątrz lekkiej maszyny wirtualnej. Nadal używa się ich przez ekosystemy kontenerowe i workflowy orkiestracyjne, ale ich właściwości bezpieczeństwa różnią się od zwykłych runtime'ów OCI i nie powinny być mentalnie grupowane z „normalnymi kontenerami Docker” tak, jakby wszystko działało tak samo.

## Stos kontenera: kilka warstw, nie jedna

Kiedy ktoś mówi „ten kontener jest niebezpieczny”, użytecznym pytaniem uzupełniającym jest: **która warstwa go uczyniła niebezpiecznym?** Obciążenie kontenerowe zwykle jest wynikiem kilku współpracujących komponentów.

Na górze często znajduje się warstwa **image build** taka jak BuildKit, Buildah lub Kaniko, która tworzy obraz OCI i metadane. Nad niskopoziomowym runtime'em może być **engine lub manager** taki jak Docker Engine, Podman, containerd, CRI-O, Incus lub systemd-nspawn. W środowiskach klastrowych może też działać **orchestrator** taki jak Kubernetes, który decyduje o żądanej postawie bezpieczeństwa poprzez konfigurację obciążenia. W końcu to **jądro** faktycznie egzekwuje namespaces, cgroups, seccomp i politykę MAC.

Ten model warstwowy jest ważny do rozumienia domyślnych ustawień. Ograniczenie może być zadane przez Kubernetes, przetłumaczone przez CRI przez containerd lub CRI-O, skonwertowane do specyfikacji OCI przez wrapper runtime'u i dopiero wtedy egzekwowane przez `runc`, `crun`, `runsc` lub inny runtime względem jądra. Kiedy domyślne ustawienia różnią się między środowiskami, często dlatego, że któraś z tych warstw zmieniła końcową konfigurację. Ten sam mechanizm może więc występować w Dockerze lub Podman jako flaga CLI, w Kubernetes jako pole Pod lub `securityContext`, a w niższych warstwach runtime'u jako wygenerowana specyfikacja OCI dla obciążenia. Z tego powodu przykłady CLI w tej sekcji należy czytać jako **składnię specyficzną dla runtime'u opisującą ogólny koncept kontenera**, a nie jako uniwersalne flagi wspierane przez każde narzędzie.

## Rzeczywista granica bezpieczeństwa kontenera

W praktyce bezpieczeństwo kontenerów pochodzi z **nakładających się mechanizmów kontroli**, nie z jednego doskonałego zabezpieczenia. Namespaces izolują widoczność. cgroups zarządzają i ograniczają użycie zasobów. Capabilities redukują to, co proces wyglądający na uprzywilejowany faktycznie może zrobić. seccomp blokuje niebezpieczne syscalli zanim dotrą do jądra. AppArmor i SELinux dodają Mandatory Access Control ponad normalne sprawdzenia DAC. `no_new_privs`, zamaskowane ścieżki procfs i ścieżki systemowe w trybie tylko do odczytu utrudniają typowe łańcuchy eskalacji uprawnień i nadużyć proc/sys. Sam runtime też ma znaczenie, ponieważ decyduje, jak tworzone są mounty, sockety, labelki i dołączania namespace'ów.

Dlatego dokumentacja dotycząca bezpieczeństwa kontenerów często wydaje się powtarzalna. Ten sam łańcuch ucieczki często zależy od wielu mechanizmów jednocześnie. Na przykład zapisywalny host bind mount jest zły, ale staje się znacznie gorszy, jeśli kontener również działa jako real root na hoście, ma `CAP_SYS_ADMIN`, jest nieograniczony przez seccomp i nie jest ograniczony przez SELinux lub AppArmor. Podobnie udostępnianie PID hosta to poważna ekspozycja, ale staje się dramatycznie bardziej użyteczne dla atakującego, gdy połączone jest z `CAP_SYS_PTRACE`, słabymi zabezpieczeniami procfs lub narzędziami do wejścia w namespace'y takimi jak `nsenter`. Właściwy sposób dokumentowania tematu to zatem nie powtarzanie tego samego ataku na każdej stronie, lecz wyjaśnienie, co każda warstwa wnosi do końcowej granicy.

## Jak czytać tę sekcję

Sekcja jest zorganizowana od najbardziej ogólnych koncepcji do najbardziej szczegółowych.

Zacznij od przeglądu runtime'u i ekosystemu:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Następnie przejrzyj płaszczyzny kontroli i powierzchnie supply‑chain, które często decydują, czy atakujący w ogóle potrzebuje breakoutu do jądra:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

Potem przejdź do modelu ochrony:

{{#ref}}
protections/
{{#endref}}

Strony dotyczące namespace'ów wyjaśniają jądrowe prymitywy izolacji indywidualnie:

{{#ref}}
protections/namespaces/
{{#endref}}

Strony o cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, zamaskowanych ścieżkach i ścieżkach tylko do odczytu wyjaśniają mechanizmy, które zwykle są nakładane na namespaces:

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## Dobry początkowy sposób myślenia o enumeracji

Podczas oceny celu konteneryzowanego znacznie bardziej użyteczne jest zadanie małego zestawu precyzyjnych pytań technicznych niż natychmiastowe przechodzenie do znanych PoC‑ów ucieczki. Najpierw zidentyfikuj **stack**: Docker, Podman, containerd, CRI-O, Incus/LXC, systemd-nspawn, Apptainer lub coś bardziej wyspecjalizowanego. Potem zidentyfikuj **runtime**: `runc`, `crun`, `runsc`, `kata-runtime` lub inna implementacja zgodna z OCI. Następnie sprawdź, czy środowisko jest **rootful czy rootless**, czy aktywne są **user namespaces**, czy jakieś **namespace'y hosta** są udostępnione, jakie **capabilities** pozostały, czy **seccomp** jest włączony, czy polityka MAC jest rzeczywiście egzekwowana, czy obecne są **niebezpieczne mounty lub sockety**, oraz czy proces może wchodzić w interakcję z API runtime'u kontenera.

Te odpowiedzi mówią znacznie więcej o rzeczywistej postawie bezpieczeństwa niż sama nazwa obrazu bazowego. W wielu ocenach możesz przewidzieć prawdopodobną rodzinę breakoutów zanim przeczytasz pojedynczy plik aplikacji, tylko na podstawie zrozumienia końcowej konfiguracji kontenera.

## Zakres

Ta sekcja obejmuje stare materiały skoncentrowane na Dockerze w organizacji ukierunkowanej na kontenery: exposure runtime'u i demona, authorization plugins, zaufanie do obrazów i build secrets, wrażliwe mounty hosta, distroless workloads, privileged containers i ochrony jądra zwykle nakładane wokół wykonania kontenera.
{{#include ../../../banners/hacktricks-training.md}}

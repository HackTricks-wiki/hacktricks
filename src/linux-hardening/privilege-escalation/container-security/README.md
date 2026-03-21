# Bezpieczeństwo kontenerów

{{#include ../../../banners/hacktricks-training.md}}

## Czym tak naprawdę jest kontener

Praktyczne zdefiniowanie kontenera: kontener to zwykłe drzewo procesów Linux uruchomione zgodnie ze specyficzną konfiguracją w stylu OCI, tak że widzi kontrolowany filesystem, ograniczony zestaw zasobów jądra i zredukowany model uprawnień. Proces może wierzyć, że jest PID 1, że ma własny stos sieciowy, że posiada własny hostname i zasoby IPC, a nawet może działać jako root wewnątrz własnego user namespace. Jednak „pod maską” nadal jest to proces hosta, który jądro planuje jak każdy inny.

Dlatego bezpieczeństwo kontenerów to w praktyce analiza tego, jak ta iluzja jest zbudowana i gdzie zawodzi. Jeśli mount namespace jest słaby, proces może zobaczyć host filesystem. Jeśli user namespace jest nieobecny lub wyłączony, root w kontenerze może mapować się zbyt blisko do roota na hoście. Jeśli seccomp nie jest skonfigurowany, a zestaw capabilities jest zbyt szeroki, proces może uzyskać dostęp do syscalli i uprzywilejowanych funkcji jądra, które powinny pozostawać poza zasięgiem. Jeśli socket runtime jest zamontowany wewnątrz kontenera, kontener może wcale nie potrzebować ucieczki z jądra, ponieważ może po prostu poprosić runtime o uruchomienie potężniejszego kontenera‑rodzeństwa lub zamontowanie root filesystem hosta bezpośrednio.

## Czym kontenery różnią się od maszyn wirtualnych

VM zwykle ma własne jądro i granicę abstrakcji sprzętowej. Oznacza to, że kernel gościa może się zawiesić, panicować lub zostać wykorzystany bez automatycznego przejęcia kontroli nad jądrem hosta. W kontenerach workload nie otrzymuje osobnego jądra — zamiast tego dostaje starannie filtrowany i namespaced widok tego samego jądra, którego używa host. W rezultacie kontenery są zwykle lżejsze, szybsze w uruchamianiu, łatwiejsze do zagęszczenia na maszynie i lepiej nadają się do krótkotrwałego uruchamiania aplikacji. Ceną jest to, że granica izolacji zależy dużo bardziej bezpośrednio od poprawnej konfiguracji hosta i runtime.

To nie znaczy, że kontenery są „niebezpieczne”, a VM „bezpieczne”. Oznacza to, że model bezpieczeństwa jest inny. Dobrze skonfigurowany stack kontenerowy z rootless execution, user namespaces, domyślnym seccomp, restrykcyjnym zestawem capabilities, brakiem dzielenia namespace z hostem oraz silnym wymuszaniem SELinux lub AppArmor może być bardzo odporny. Z drugiej strony kontener uruchomiony z `--privileged`, z dzieleniem PID/network z hostem, socketem Docker zamontowanym wewnątrz oraz zapisem bind mountu `/` jest funkcjonalnie znacznie bliżej do dostępu do roota hosta niż do bezpiecznego sandboxu aplikacji. Różnica wynika z warstw, które zostały włączone lub wyłączone.

Istnieje też środkowa droga, którą warto znać, bo pojawia się coraz częściej w realnych środowiskach. Sandboxed container runtimes takie jak gVisor i Kata Containers celowo utwardzają granicę ponad klasyczny `runc` kontener. gVisor wstawia warstwę userspace kernel pomiędzy workload a wieloma interfejsami jądra hosta, podczas gdy Kata uruchamia workload wewnątrz lekkiej maszyny wirtualnej. Nadal używa się ich przez ekosystemy kontenerowe i orkiestrację, ale ich właściwości bezpieczeństwa różnią się od zwykłych OCI runtime i nie powinny być mentalnie grupowane z „normalnymi Docker containers”, jakby wszystko zachowywało się identycznie.

## Stos kontenera: kilka warstw, a nie jedna

Gdy ktoś mówi „ten kontener jest niebezpieczny”, przydatne pytanie brzmi: które warstwa go uczyniła niebezpiecznym? Workload w kontenerze zwykle jest wynikiem współdziałania kilku komponentów.

Na górze często znajduje się warstwa budowy obrazu, taka jak BuildKit, Buildah lub Kaniko, która tworzy obraz OCI i metadane. Nad niskopoziomowym runtime może być engine lub manager taki jak Docker Engine, Podman, containerd, CRI-O, Incus lub systemd-nspawn. W środowiskach klastrowych może też być orchestrator, np. Kubernetes, który ustala żądany postawę bezpieczeństwa przez konfigurację workloadu. W końcu to jądro rzeczywiście egzekwuje namespaces, cgroups, seccomp i politykę MAC.

Ten model warstwowy jest ważny dla zrozumienia domyślnych ustawień. Ograniczenie może być zażądane przez Kubernetes, przetłumaczone przez CRI przez containerd lub CRI‑O, przekształcone w spec OCI przez wrapper runtime, a dopiero potem egzekwowane przez `runc`, `crun`, `runsc` lub inny runtime przeciwko jądru. Kiedy domyślne ustawienia różnią się między środowiskami, często dlatego, że jedna z tych warstw zmieniła finalną konfigurację. Ten sam mechanizm może więc pojawić się w Docker lub Podman jako flaga CLI, w Kubernetes jako pole Pod lub `securityContext`, oraz w niższych warstwach runtime jako wygenerowana konfiguracja OCI dla workloadu. Z tego powodu przykłady CLI w tej sekcji należy czytać jako runtime‑specyficzną składnię dla ogólnej koncepcji kontenera, a nie jako uniwersalne flagi wspierane przez każde narzędzie.

## Rzeczywista granica bezpieczeństwa kontenera

W praktyce bezpieczeństwo kontenera wynika z nakładających się kontroli, a nie z jednej idealnej kontroli. Namespaces izolują widoczność. cgroups zarządzają i ograniczają użycie zasobów. Capabilities redukują to, co proces wyglądający na uprzywilejowany może faktycznie zrobić. seccomp blokuje niebezpieczne syscally zanim dotrą do jądra. AppArmor i SELinux dodają Mandatory Access Control ponad normalne sprawdzenia DAC. `no_new_privs`, masked procfs paths i read-only system paths utrudniają typowe łańcuchy nadużyć uprawnień i proc/sys. Sam runtime też ma znaczenie, ponieważ decyduje, jak są tworzone mounty, sockety, labelki i dołączenia do namespaces.

Dlatego wiele dokumentacji dotyczącej bezpieczeństwa kontenerów wydaje się powtarzalne. Ten sam łańcuch ucieczki często zależy od kilku mechanizmów jednocześnie. Na przykład zapisywalny host bind mount jest zły sam w sobie, ale staje się dużo gorszy, jeśli kontener działa także jako realny root na hoście, ma `CAP_SYS_ADMIN`, nie jest ograniczony przez seccomp i nie jest chroniony przez SELinux lub AppArmor. Podobnie dzielenie PID hosta to poważne ryzyko, ale staje się dramatycznie bardziej użyteczne dla atakującego, gdy jest połączone z `CAP_SYS_PTRACE`, słabą ochroną procfs lub narzędziami do wejścia do namespace, takimi jak `nsenter`. Prawidłowy sposób dokumentowania tematu to więc nie powtarzanie tego samego ataku na każdej stronie, lecz wyjaśnianie, co każda warstwa wnosi do końcowej granicy.

## Jak czytać tę sekcję

Sekcja jest zorganizowana od najbardziej ogólnych koncepcji do najbardziej szczegółowych.

Zacznij od przeglądu runtime i ekosystemu:

{{#ref}}
runtimes-and-engines.md
{{#endref}}

Potem przejrzyj control planes i supply‑chain surfaces, które często decydują, czy atakujący w ogóle będzie potrzebował ucieczki z jądra:

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

Następnie przejdź do modelu ochrony:

{{#ref}}
protections/
{{#endref}}

Strony o namespaces wyjaśniają poszczególne prymitywy izolacji jądra:

{{#ref}}
protections/namespaces/
{{#endref}}

Strony o cgroups, capabilities, seccomp, AppArmor, SELinux, `no_new_privs`, masked paths i read-only paths wyjaśniają mechanizmy zwykle nakładane na namespaces:

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

## Dobry pierwszy sposób myślenia przy enumeracji

Przy ocenie celu w kontenerze znacznie bardziej użyteczne jest zadanie małej liczby precyzyjnych pytań technicznych niż natychmiastowe skakanie do znanych PoC ucieczek. Najpierw zidentyfikuj stack: Docker, Podman, containerd, CRI‑O, Incus/LXC, systemd‑nspawn, Apptainer lub coś bardziej wyspecjalizowanego. Potem zidentyfikuj runtime: `runc`, `crun`, `runsc`, `kata-runtime` lub inną implementację zgodną z OCI. Następnie sprawdź, czy środowisko jest rootful czy rootless, czy user namespaces są aktywne, czy jakiekolwiek host namespaces są współdzielone, jakie capabilities pozostały, czy seccomp jest włączony, czy polityka MAC rzeczywiście egzekwuje, czy występują niebezpieczne mounty lub sockety oraz czy proces może komunikować się z API runtime.

Te odpowiedzi mówią znacznie więcej o rzeczywistej postawie bezpieczeństwa niż sama nazwa obrazu. W wielu ocenach możesz przewidzieć prawdopodobną rodzinę breakoutów zanim przeczytasz pojedynczy plik aplikacji, rozumiejąc finalną konfigurację kontenera.

## Zakres

Ta sekcja obejmuje starszy, skupiony na Dockerze materiał uporządkowany wokół kontenerów: exposure runtime i daemonów, authorization plugins, zaufanie do obrazów i build secrets, wrażliwe host mounty, distroless workloads, privileged containers oraz zabezpieczenia jądra zwykle nakładane na wykonanie kontenera.

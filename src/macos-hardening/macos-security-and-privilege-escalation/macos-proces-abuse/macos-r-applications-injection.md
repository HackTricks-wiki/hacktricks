# macOS R Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `R_PROFILE_USER` / `R_PROFILE`

R은 시작할 때 R code가 포함된 site 및 user profile 파일을 source합니다. `R_PROFILE`은 site profile을 선택하고 `R_PROFILE_USER`는 user profile을 선택하므로, 상속된 환경에서 두 조회 중 하나를 attacker가 읽을 수 있는 파일로 리디렉션할 수 있습니다.<sup>[[1]](#references)</sup>
```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```
`--no-init-file`은 사용자 프로필을 건너뛰고, `--no-site-file`은 site 프로필을 건너뛰며, `--vanilla`는 두 보호 기능을 모두 포함합니다. R은 먼저 `R_ENVIRON` 및 `R_ENVIRON_USER`로 선택된 environment 파일을 처리하지만, 해당 파일은 변수만 설정합니다. 프로필 변수는 임의 코드 실행을 직접 가능하게 하는 primitive입니다.

## `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` 및 library paths

R은 startup 중 `R_DEFAULT_PACKAGES`에 쉼표로 구분된 packages를 attach합니다. `Rscript`는 `R_SCRIPT_DEFAULT_PACKAGES`에 우선권을 부여합니다. 두 변수 중 하나를 `R_LIBS`, `R_LIBS_USER` 또는 `R_LIBS_SITE`와 결합하면 R이 attacker-controlled 상태로 설치된 package를 찾아 load할 수 있으며, 해당 package의 `.onLoad` 또는 `.onAttach` hook이 자동으로 실행됩니다.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```
이는 단순히 느슨한 `.R` 파일이 아니라, 구조적으로 유효하게 설치된 R package를 필요로 합니다. `--vanilla`는 직접 상속된 변수를 지우지 않으므로, 신뢰할 수 있는 wrapper는 profile 파일을 비활성화하는 것뿐만 아니라 기본 package 및 library-path 변수도 unset하거나 대체해야 합니다.

## References

- [1] [R 세션 시작 시 초기화](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [2] [R 설치 및 관리: Add-on packages](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
{{#include ../../../banners/hacktricks-training.md}}

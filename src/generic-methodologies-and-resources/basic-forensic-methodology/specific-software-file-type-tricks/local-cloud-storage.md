# 로컬 클라우드 저장소

{{#include ../../../banners/hacktricks-training.md}}

## 로컬 저장소 에뮬레이터와 계정 키

컨테이너에서 실행되는 Azure 호환 Blob 에뮬레이터는 저장소 서비스가 외부에 노출되지 않더라도 호스트 또는 브리지 네트워크에서 접근할 수 있습니다. 읽을 수 있는 로컬 설정 파일과 백업 파일 메타데이터를 검토해 계정 이름과 키를 찾되, 일반적인 열거 과정에서 키를 출력하지 마세요. [Azurite는 사용자 지정 로컬 계정 키를 지원합니다](https://learn.microsoft.com/en-us/azure/storage/common/storage-use-azurite); [Shared Key 인증](https://learn.microsoft.com/en-us/azure/storage/common/authorize-data-access)은 해당 계정의 데이터에 폭넓은 접근 권한을 부여할 수 있습니다. 키 파일만으로 권한 상승이 입증되는 것은 아닙니다. 엔드포인트에 접근할 수 있는지, 계정과 키가 승인되는지, 그리고 해당 blob에 더 높은 권한을 가진 ID에 사용할 수 있는 자격 증명이 실제로 포함되어 있는지 확인하세요. SSH 개인 키가 들어 있다면, 해당 공개 키도 그 ID에 대해 승인되어 있어야 하고 SSH 접근이 허용되어야 합니다. 키 노출이 확인되면 안전하게 보호하고 교체하세요.

## OneDrive

Windows에서는 OneDrive 폴더를 `\Users\<username>\AppData\Local\Microsoft\OneDrive`에서 찾을 수 있습니다. `logs\Personal` 내부에는 동기화된 파일에 관한 흥미로운 데이터가 포함된 `SyncDiagnostics.log` 파일이 있을 수 있습니다:<sup>[[3]](#references)</sup>

- 바이트 단위 크기
- 생성 날짜
- 수정 날짜
- 클라우드에 있는 파일 수
- 폴더에 있는 파일 수
- **CID**: OneDrive 사용자의 고유 ID
- 보고서 생성 시간
- OS가 설치된 HD의 크기

CID를 찾았다면 **이 ID가 포함된 파일을 검색하는 것**이 좋습니다. _**\<CID>.ini**_ 및 _**\<CID>.dat**_라는 이름의 파일을 찾을 수 있으며, 여기에 OneDrive와 동기화된 파일의 이름 같은 흥미로운 정보가 포함되어 있을 수 있습니다.<sup>[[3]](#references)</sup>

## Google Drive

Windows에서는 Google Drive 기본 폴더를 `\Users\<username>\AppData\Local\Google\Drive\user_default`에서 찾을 수 있습니다.\
이 폴더에는 Google Drive 클라이언트의 동기화 세션과 파일 생성, 수정, 삭제 이벤트를 기록하는 Sync_log.log 파일이 있습니다.<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** 파일은 sqlite 데이터베이스입니다.<sup>[[6]](#references)</sup> 여기에는 **`cloud_graph_entry`** 테이블이 있습니다. 이 테이블에서 **동기화된** **파일**의 **이름**, 수정 시간, 크기, MD5 체크섬을 확인할 수 있습니다.

관련 **`snapshot.db`** 데이터베이스의 **`cloud_entry`** 테이블에는 파일 이름, 타임스탬프, 크기, 체크섬이 포함된 삭제된 레코드가 남아 있을 수 있습니다.<sup>[[4]](#references)</sup>

**`Sync_config.db`** 데이터베이스의 테이블 데이터에는 계정의 이메일 주소, 공유 폴더 경로, Google Drive 버전이 포함되어 있습니다.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox는 파일을 관리하기 위해 **SQLite 데이터베이스**를 사용합니다.<sup>[[2]](#references)</sup> 이때\
다음 폴더에서 데이터베이스를 찾을 수 있습니다.

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

주요 데이터베이스는 다음과 같습니다.

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" 확장자는 **데이터베이스가** **암호화되어 있다**는 뜻입니다. Dropbox는 **DPAPI**를 사용합니다([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>)).<sup>[[1]](#references)</sup>

Dropbox에서 사용하는 암호화를 더 자세히 알아보려면 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)을 읽어보세요.<sup>[[1]](#references)[[2]](#references)</sup>

다만 핵심 정보는 다음과 같습니다.<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

이 정보 외에도 데이터베이스를 복호화하려면 다음이 필요합니다.<sup>[[2]](#references)</sup>

- **암호화된 DPAPI 키**: 레지스트리의 `NTUSER.DAT\Software\Dropbox\ks\client`에서 찾을 수 있습니다(이 데이터를 바이너리로 내보내세요).
- **`SYSTEM`** 및 **`SECURITY`** 하이브
- **DPAPI 마스터 키**: `\Users\<username>\AppData\Roaming\Microsoft\Protect`에서 찾을 수 있습니다.
- Windows 사용자의 **사용자 이름**과 **비밀번호**

그런 다음 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)** 도구를 사용할 수 있습니다.**

![Google Drive - Dropbox: 그런 다음 DataProtectionDecryptor 도구를 사용할 수 있습니다](<../../../images/image (443).png>)

모든 과정이 예상대로 진행되면, 도구가 **원래 키를 복구하는 데 사용해야 하는 기본 키**를 표시합니다. 원래 키를 복구하려면 이 [cyber_chef 레시피](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)를 사용하고, 기본 키를 레시피의 "passphrase"로 입력하세요.

그 결과로 나오는 hex가 데이터베이스 암호화에 사용된 최종 키이며, 다음 방법으로 복호화할 수 있습니다.<sup>[[2]](#references)</sup>

```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```

**`config.dbx`** 데이터베이스에는 다음 정보가 포함됩니다.

- **이메일**: 사용자의 이메일
- **usernamedisplayname**: 사용자의 이름
- **dropbox_path**: dropbox 폴더가 있는 경로
- **Host_id: Hash**: 클라우드 인증에 사용되는 해시입니다. 웹에서만 폐기할 수 있습니다.
- **Root_ns**: 사용자 식별자

**`filecache.db`** 데이터베이스에는 Dropbox와 동기화된 모든 파일과 폴더에 대한 정보가 포함됩니다. `File_journal` 테이블에 가장 유용한 정보가 있습니다.<sup>[[5]](#references)</sup>

- **Server_path**: 서버 내에서 파일이 있는 경로입니다(이 경로 앞에 클라이언트의 `host_id`가 붙습니다).
- **local_sjid**: 파일 버전
- **local_mtime**: 수정 날짜
- **local_ctime**: 생성 날짜

이 데이터베이스의 다른 테이블에는 다음과 같은 흥미로운 정보가 포함됩니다.

- **block_cache**: Dropbox의 모든 파일과 폴더의 해시
- **block_ref**: `block_cache` 테이블의 해시 ID와 `file_journal` 테이블의 파일 ID 연결
- **mount_table**: Dropbox의 공유 폴더
- **deleted_fields**: Dropbox에서 삭제된 파일
- **date_added**

## References

- [1] [Dropbox 소프트웨어 보안에 대한 비판적 분석 (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX 복호화 다시 살펴보기](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [클라우드 스토리지 포렌식 분석 (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS 데이터 Leakage 사례: Leakage 답변](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox 포렌식](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Windows에서 Google Drive 사용 흔적](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}

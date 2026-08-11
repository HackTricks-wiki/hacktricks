# Local Cloud Storage

{{#include ../../../banners/hacktricks-training.md}}

## OneDrive

Windows에서는 OneDrive 폴더를 `\Users\<username>\AppData\Local\Microsoft\OneDrive`에서 찾을 수 있습니다. 또한 `logs\Personal` 내부에는 동기화된 파일과 관련된 일부 흥미로운 데이터를 포함하는 `SyncDiagnostics.log` 파일이 있습니다:<sup>[[3]](#references)</sup>

- 바이트 단위 크기
- 생성 날짜
- 수정 날짜
- cloud 내 파일 수
- 폴더 내 파일 수
- **CID**: OneDrive 사용자의 고유 ID
- 보고서 생성 시간
- OS의 HD 크기

CID를 찾았다면 **이 ID가 포함된 파일을 검색하는 것**이 좋습니다. _**\<CID>.ini**_ 및 _**\<CID>.dat**_라는 이름의 파일을 찾을 수 있으며, 여기에 OneDrive와 동기화된 파일의 이름과 같은 흥미로운 정보가 포함되어 있을 수 있습니다.<sup>[[3]](#references)</sup>

## Google Drive

Windows에서는 기본 Google Drive 폴더를 `\Users\<username>\AppData\Local\Google\Drive\user_default`에서 찾을 수 있습니다.\
이 폴더에는 Google Drive client 동기화 세션과 파일 생성, 수정 및 삭제 이벤트를 기록하는 Sync_log.log 파일이 있습니다.<sup>[[4]](#references)[[6]](#references)</sup>

**`Cloud_graph\Cloud_graph.db`** 파일은 sqlite database입니다.<sup>[[6]](#references)</sup> 여기에는 **`cloud_graph_entry`** table이 포함되어 있습니다. 이 table에서는 **동기화된** **파일**의 **이름**, 수정 시간, 크기 및 파일의 MD5 checksum을 확인할 수 있습니다.

관련된 **`snapshot.db`** database의 **`cloud_entry`** table에는 파일 이름, timestamp, 크기 및 checksum이 포함된 삭제된 record가 남아 있을 수 있습니다.<sup>[[4]](#references)</sup>

**`Sync_config.db`** database의 table 데이터에는 account의 email address, shared folder의 path 및 Google Drive version이 포함되어 있습니다.<sup>[[3]](#references)[[6]](#references)</sup>

## Dropbox

Dropbox는 파일을 관리하기 위해 **SQLite databases**를 사용합니다.<sup>[[2]](#references)</sup> 이\
database는 다음 폴더에서 찾을 수 있습니다:

- `\Users\<username>\AppData\Local\Dropbox`
- `\Users\<username>\AppData\Local\Dropbox\Instance1`
- `\Users\<username>\AppData\Roaming\Dropbox`

주요 database는 다음과 같습니다:

- Sigstore.dbx
- Filecache.dbx
- Deleted.dbx
- Config.dbx

".dbx" extension은 **database**가 **암호화**되어 있음을 의미합니다. Dropbox는 **DPAPI** ([https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN](<https://docs.microsoft.com/en-us/previous-versions/ms995355(v=msdn.10)?redirectedfrom=MSDN>))를 사용합니다.<sup>[[1]](#references)</sup>

Dropbox가 사용하는 암호화를 더 잘 이해하려면 [https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)을 읽어볼 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

그러나 핵심 정보는 다음과 같습니다:<sup>[[1]](#references)</sup>

- **Entropy**: d114a55212655f74bd772e37e64aee9b
- **Salt**: 0D638C092E8B82FC452883F95F355B8E
- **Algorithm**: PBKDF2
- **Iterations**: 1066

이 정보 외에도 database를 복호화하려면 다음이 필요합니다:<sup>[[2]](#references)</sup>

- **암호화된 DPAPI key**: registry의 `NTUSER.DAT\Software\Dropbox\ks\client` 내부에서 찾을 수 있습니다(이 데이터를 binary로 export).
- **`SYSTEM`** 및 **`SECURITY`** hive
- **DPAPI master keys**: `\Users\<username>\AppData\Roaming\Microsoft\Protect`에서 찾을 수 있습니다.
- Windows 사용자의 **username** 및 **password**

그런 다음 [**DataProtectionDecryptor**](https://nirsoft.net/utils/dpapi_data_decryptor.html)**:** 도구를 사용할 수 있습니다.

![Google Drive - Dropbox: 그런 다음 DataProtectionDecryptor 도구를 사용할 수 있습니다](<../../../images/image (443).png>)

모든 과정이 예상대로 진행되면 도구에서 **원래 key를 복구하는 데 사용해야 하는** **primary key**를 표시합니다. 원래 key를 복구하려면 이 [cyber_chef receipt](<https://gchq.github.io/CyberChef/index.html#recipe=Derive_PBKDF2_key(%7B'option':'Hex','string':'98FD6A76ECB87DE8DAB4623123402167'%7D,128,1066,'SHA1',%7B'option':'Hex','string':'0D638C092E8B82FC452883F95F355B8E'%7D)>)를 사용하고, receipt 내부에서 primary key를 "passphrase"로 입력하면 됩니다.

결과로 생성된 hex가 database를 암호화하는 데 사용된 최종 key이며, 다음을 사용하여 복호화할 수 있습니다:<sup>[[2]](#references)</sup>
```bash
sqlite -k <Obtained Key> config.dbx ".backup config.db" #This decompress the config.dbx and creates a clear text backup in config.db
```
**`config.dbx`** database에는 다음 정보가 포함됩니다:

- **Email**: 사용자의 이메일
- **usernamedisplayname**: 사용자의 이름
- **dropbox_path**: Dropbox 폴더가 위치한 경로
- **Host_id: Hash**: cloud 인증에 사용되는 **Hash**입니다. 이 값은 웹에서만 revoke할 수 있습니다.
- **Root_ns**: 사용자 식별자

**`filecache.db`** database에는 Dropbox와 동기화된 모든 파일 및 폴더에 대한 정보가 포함됩니다. `File_journal` table이 가장 유용한 정보를 포함합니다:<sup>[[5]](#references)</sup>

- **Server_path**: server 내부에서 파일이 위치한 경로입니다(이 경로 앞에는 client의 `host_id`가 추가됩니다).
- **local_sjid**: 파일 버전
- **local_mtime**: 수정 날짜
- **local_ctime**: 생성 날짜

이 database 내부의 다른 table에는 더 흥미로운 정보가 포함되어 있습니다:

- **block_cache**: Dropbox의 모든 파일 및 폴더의 hash
- **block_ref**: `block_cache` table의 hash ID와 `file_journal` table의 파일 ID를 연결
- **mount_table**: Dropbox의 공유 폴더
- **deleted_fields**: Dropbox에서 삭제된 파일
- **date_added**

## References

- [1] [Dropbox software security에 대한 비판적 분석 (hack.lu 2012)](http://archive.hack.lu/2012/Dropbox%20security.pdf)
- [2] [Dropbox DBX 복호화 복습](https://blog.digital-forensics.it/2017/04/brush-up-on-dropbox-dbx-decryption.html)
- [3] [Cloud Storage Forensic Analysis (Darren Quick, 2012)](https://studylib.net/doc/9417205/cloud-storage-forensic-analysis)
- [4] [NIST CFReDS Data Leakage Case: Leakage Answers](https://cfreds-archive.nist.gov/data_leakage_case/leakage-answers.pdf)
- [5] [Dropbox Forensics](https://www.forensicfocus.com/articles/dropbox-forensics/)
- [6] [Artifacts of Google Drive Usage in Windows](https://digitalinvestigator.blogspot.com/2021/03/artifacts-of-google-drive-usage-on.html)
{{#include ../../../banners/hacktricks-training.md}}

# Người dùng macOS & Tài khoản bên ngoài

{{#include ../../banners/hacktricks-training.md}}

## Người dùng phổ biến

- **Tài khoản daemon**: Dành riêng cho các daemon hệ thống. Tên ngắn của chúng thường bắt đầu bằng dấu gạch dưới (`_`):

  ```bash
  _amavisd, _analyticsd, _appinstalld, _appleevents, _applepay, _appowner, _appserver, _appstore, _ard, _assetcache, _astris, _atsserver, _avbdeviced, _calendar, _captiveagent, _ces, _clamav, _cmiodalassistants, _coreaudiod, _coremediaiod, _coreml, _ctkd, _cvmsroot, _cvs, _cyrus, _datadetectors, _demod, _devdocs, _devicemgr, _diskimagesiod, _displaypolicyd, _distnote, _dovecot, _dovenull, _dpaudio, _driverkit, _eppc, _findmydevice, _fpsd, _ftp, _fud, _gamecontrollerd, _geod, _hidd, _iconservices, _installassistant, _installcoordinationd, _installer, _jabber, _kadmin_admin, _kadmin_changepw, _knowledgegraphd, _krb_anonymous, _krb_changepw, _krb_kadmin, _krb_kerberos, _krb_krbtgt, _krbfast, _krbtgt, _launchservicesd, _lda, _locationd, _logd, _lp, _mailman, _mbsetupuser, _mcxalr, _mdnsresponder, _mobileasset, _mysql, _nearbyd, _netbios, _netstatistics, _networkd, _nsurlsessiond, _nsurlstoraged, _oahd, _ondemand, _postfix, _postgres, _qtss, _reportmemoryexception, _rmd, _sandbox, _screensaver, _scsd, _securityagent, _softwareupdate, _spotlight, _sshd, _svn, _taskgated, _teamsserver, _timed, _timezone, _tokend, _trustd, _trustevaluationagent, _unknown, _update_sharing, _usbmuxd, _uucp, _warmd, _webauthserver, _windowserver, _www, _wwwproxy, _xserverdocs
  ```

- **Khách**: Tài khoản tạm thời bị giới hạn, có thể được bật hoặc tắt cục bộ hoặc thông qua payload Accounts của MDM.<sup>[[1]](#references)</sup>

```bash
state=("automaticTime" "afpGuestAccess" "filesystem" "guestAccount" "smbGuestAccess")
for i in "${state[@]}"; do sysadminctl -"${i}" status; done;
```

- **Nobody**: Một danh tính không có đặc quyền, được cố ý dùng cho các dịch vụ cần quyền truy cập hệ thống tệp tối thiểu.
- **Root**: Người dùng siêu cấp. Đăng nhập root tương tác bị tắt theo mặc định, dù quản trị viên có thể thực hiện các thao tác có đặc quyền thông qua authorization và `sudo`.<sup>[[2]](#references)</sup>

Thông tin xác minh mật khẩu tài khoản cục bộ và quy trình trích xuất được đề cập trong [Shadow Passwords](macos-files-folders-and-binaries/macos-sensitive-locations.md#shadow-passwords).

## User Privileges

- **Standard user:** Loại tài khoản thông thường, không có quyền quản trị. Các thay đổi mang tính quản trị cần được quản trị viên cấp quyền.
- **Admin user**: Thành viên của nhóm `admin` cục bộ. Admin user vẫn chạy các tiến trình thông thường bằng danh tính người dùng của mình, nhưng có thể cấp quyền cho các thao tác có đặc quyền. Đừng cho rằng chỉ cần là thành viên nhóm thì mọi lệnh đều chạy với quyền root; `sudo`, Authorization Services, chính sách và các bước kiểm tra riêng của ứng dụng vẫn được áp dụng.<sup>[[2]](#references)</sup>
- **Root**: Root là người dùng được phép thực hiện gần như mọi hành động (các biện pháp bảo vệ như System Integrity Protection vẫn áp đặt một số giới hạn).
  - Ví dụ, System Integrity Protection và signed system volume ngăn cả root sửa đổi lâu dài nội dung `/System` được bảo vệ trong quá trình hoạt động bình thường.

## External Accounts

macOS cũng hỗ trợ các tài khoản ứng dụng từ nhà cung cấp bên ngoài. Daemon `accountsd` (`/System/Library/Frameworks/Accounts.framework/Versions/A/Support/accountsd`) làm trung gian cho dữ liệu của Accounts framework; có thể tìm thấy các authentication plug-in trong `/System/Library/Accounts/Authentication/`. Đây là các tài khoản ứng dụng/dịch vụ, không nhất thiết là các danh tính có thể đăng nhập tại cửa sổ đăng nhập macOS. `accountsd` cũng đọc các loại tài khoản đã biết từ `/Library/Preferences/SystemConfiguration/com.apple.accounts.exists.plist`.

## References

- [1] [Apple Developer — Payload quản lý thiết bị Accounts](https://developer.apple.com/documentation/devicemanagement/accounts)
- [2] [Apple — Quyền và quyền sở hữu BSD: tài khoản quản trị và root](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPFileSystem/Articles/BSDInfluences.html)
{{#include ../../banners/hacktricks-training.md}}

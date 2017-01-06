LineCross
====


## Description

Line Unofficial Library For PHP

## Usage
0. Make Authinfo(optional)
	- Token Only
	```php
	$Auth= new AuthInfo("TOKEN");
	```
	- Mail And Pass (and CERT)
	```php
	$Auth= new AuthInfo(NULL,"MAIL","PASS","CERT(optional)");
	```
1. Login
	- Use QR Code
	```php
	$Line = new LineCross();
	```
	- Other
	```php
	$Line = new LineCross($Auth);
	```


## Author

[x9119x](https://twitter.com/_x9119x_)

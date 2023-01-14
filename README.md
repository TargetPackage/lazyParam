# What is lazyParam?
lazyParam is a simple automation tool with the implementation of multi-threading to check for hidden parameters. This tool is still in testing phase and more implementations are soon to be made. _note: Works with python3_

# Features

* Fuzz parameters for both GET and POST method
* Multi-threaded _(Default: 4)_
* Use intensive mode with character bypassing techniques
* Check for LFI, RCE and SSTI

# Todo

* XSS checking
* Add examples to prove effectiveness

# Usage

Fuzz parameters with build-in wordlists:

```shell
python3 lazyparam.py -u http://example.com/file.php
```

Specify custom wordlists:

```shell
python3 lazyparam.py -u http://example.com/file.php -w wordlists.lst
```

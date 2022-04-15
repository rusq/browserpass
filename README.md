# Browser Password Stealer #

Universal tool aimed at obtaining and decrypting browser passwords, combined
from different articles and sources (listed below).

This is a research into browser password encryption and CGO interfacing.

Educational use only: this tool must not be used for illegal activities.

Releasing in hope that someone might find this interesting.

# Usage

## Compiling

```shell
go build
```

## Running

### Chrome
Get all Chrome passwords:
```shell
./browserpass -b c
```

Once started, on MacOS, you will be prompted to enter your keychain password.
The keychain password is needed to get the Chrome keychain decryption key, that
is used to decrypt your passwords.


### Firefox

Get all Firefox passwords:
```shell
./browserpass -b f
```

Passwords are printed in the following way:
```
https://example.com
        login:          "you"
        password:       "your_password"
```

# Reference
1. https://github.com/unode/firefox_decrypt/blob/master/firefox_decrypt.py
2. https://cs.chromium.org/chromium/src/components/os_crypt/os_crypt_mac.mm?g=0
3. https://medium.com/learning-the-go-programming-language/writing-modular-go-programs-with-plugins-ec46381ee1a9
4. https://github.com/kholia/mozilla_password_dump/blob/master/mozilla_password_dump.c
5. https://github.com/lacostej/firefox_password_dump/blob/master/ff_key3db_dump.c
6. https://github.com/unode/firefox_decrypt
7. https://github.com/lclevy/firepwd/blob/master/firepwd.py
8. [Chrome password decryption (RUS)](./reference/article.txt)

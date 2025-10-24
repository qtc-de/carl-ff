### carl-ff

----

*carl-ff* is a small python utility and library to parse and modify Firefox's
*ClientAuthenticationRememberList*. The *ClientAuthenticationRememberList* is
a binary file used by Firefox to make authentication decisions regarding whether
to send a client certificate to a particular server.


### Installation

----

*carl-ff* can be build and installed as a pip package. The recommended way of installing is via pipx:

```console
[user@host ~]$ pipx install carl-ff
```

You can also build *carl-ff* from source by running the following commands:

```console
[user@host ~]$ git clone https://github.com/qtc-de/carl-ff
[user@host ~]$ cd carl-ff
[user@host ~/carl-ff]$ pipx install .
```


### Usage

----

*carl-ff* attempts to find the `ClientAuthRememberList.bin` file within your Firefox
profile automatically. Invoking `carl-ff` without any options just lists your current
authentication decisions:

```console
user@host:~$ carl-ff
[+] ClientAuthRememberList:
[+]
[+]	Allowed Entries:
[+]		0.) https://trusted.internal.local
[+]
[+]	Blocked Entries:
[+]		1.) https://untrusted.external.web
```

To add a new entry, use the `add` subcommand. The `add` subcommand requires either
the `--cert` or `--blocked` arguments to be specified. With `--cert` you can select
the certificate to use for authentication. With `--block` you decide to not send a
certificate. Moreover, the `--host` or `--from-file` arguments are required. With
`--host` you can specify the desired host. With `--from-file` you can specify a file
that contains hostnames:

```console
user@host:~$ carl-ff add --cert cert.pem --host auth.internal.local
[+] ClientAuthRememberList:
[+]
[+]	Allowed Entries:
[+]		0.) https://trusted.internal.local
[+]		1.) https://auth.internal.local
[+]
[+]	Blocked Entries:
[+]		2.) https://untrusted.external.web

user@host:~$ carl-ff add --block --host third-party.internal.local
[+] ClientAuthRememberList:
[+]
[+]	Allowed Entries:
[+]		0.) https://trusted.internal.local
[+]		1.) https://auth.internal.local
[+]
[+]	Blocked Entries:
[+]		2.) https://untrusted.external.web
[+]		3.) https://third-party.internal.local
```

To remove an entry from the list, use the `del` subcommand. The `del` subcommand
requires an additional integer parameter that specifies the entry you want to delete.
Be careful when using this while Firefox is open, as new authentication decisions
may change an index.

```console
user@host:~$ carl-ff del 1
[+] ClientAuthRememberList:
[+]
[+]	Allowed Entries:
[+]		0.) https://trusted.internal.local
[+]
[+]	Blocked Entries:
[+]		1.) https://untrusted.external.web
[+]		2.) https://third-party.internal.local
```


### Acknowledgements

----

*carl-ff* was inspired by [ff-carl](https://github.com/andrewoswald/ff-carl),
a Rust library for modifying `ClientAuthRememberList.bin`.


### Disclaimer

----

*ClientAuthenticationRememberList.bin* uses a proprietary format that may change
in future or has not been implemented correctly by this library. This tool and
the associated library come with absolutely no warranty that they will work
correctly. Always verify the results within the Firefox settings and use the
tool / library on your own risk.

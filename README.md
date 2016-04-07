# policyd

This is a simple Flash socket policy server, written with
[libuv](https://github.com/libuv/libuv).

Before an SWF opens a TCP socket connection, the Flash runtime first
attempts to connect to that host, typically on port 843, and requests
a socket policy. This is a small XML document that indicates to which
ports the SWF is allowed to connect. This is a security measure to
prevent SWFs from connecting to internal hosts or arbitrary ports.

See
[Adobe's page](http://www.adobe.com/devnet/flashplayer/articles/socket_policy_files.html)
on socket policy servers for more information.

A port other than 843 can be used for the socket policy server, with
the caveat that if another socket policy server is available on port
843, the one on port 843 is considered authoritative. Also, a
non-standard port requires an explicit socket policy request in AS3:

```as3
Security.loadPolicyFile("xmlsocket://example.com:3000");
```

See the
[Security.loadPolicyFile](http://help.adobe.com/en_US/FlashPlatform/reference/actionscript/3/flash/system/Security.html#loadPolicyFile%28%29)
documentation for more details.

## Requirements

`policyd` requires [libuv](https://github.com/libuv/libuv).

## Building

Install the development package for libuv, and compile with `make`.

## Usage

The `policyd` server supports these options:

* -l IP, --listen=IP : The IP to listen on; defaults to 0.0.0.0
* -p PORT, --port=PORT : The port to listen on; defaults to 843
* -c FILE, --config=FILE : The socket policy configuration file

To have `policyd` listen on all IPs, on port 3000, and use the socket
policy file named `policy.xml` in the current directory:

```
./policyd -l 0.0.0.0 -p 3000 -c policy.xml
```

This can be tested with:

```bash
printf "<policy-file-request/>\0" | nc localhost 3000
```

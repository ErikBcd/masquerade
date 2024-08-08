Masquerade is an implementation of [MASQUE]([https://ietf-wg-masque.github.io/](https://datatracker.ietf.org/wg/masque/about/)). For UDP, it implements the `connect-udp` extended HTTP/3 CONNECT method as defined in [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html) using HTTP datagrams defined in [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html). For TCP, it implements the HTTP/3 CONNECT method as defined in [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html#name-the-connect-method).

For client, it exposes a HTTP/1.1 or SOCKS5 interface for easy connection.

It is built on HTTP/3 and QUIC provided by the library [quiche](https://github.com/cloudflare/quiche).

Very early prototype with no thorough testing, missing a lot of features, poorly documented, and very poor error and edge case handling.

This fork aims to build up on the original masquerade implementation for the sake of improvement and evaluation.

### Todo:
 * ~~Fix socks-udp (Broke when updating to the latest quiche version)~~ Done!
 * Fix cases where connections aren't shut down properly
 * Refactor some things (Code is hard to read in some places, Error handling is missing)

# Connect-IP branch

This branch is for implementing the CONNECT-IP method as defined in [RFC 9484](https://datatracker.ietf.org/doc/rfc9484/).
For now this is a very early, simple design.

**Note**: This is being developed on a Linux machine, no special support for other operating systems.
Also this is still in early development. Right now it's just loose code samples that don't do anything. We're getting there tho.

## Basic inner workings
 * The user can connect to the masquerade server via the ip_connect_client (new binary)
 * The ip_connect_client creates a virtual Interface (TUN), and the user can route traffic to that TUN
 * Internally, the client will ask for an IP address from the server and change the source address of all outgoing packets to that address (and vice versa change the destination address from all incoming packets)
 * Client and server can work with all capsule types defined in RFC 9484

## Limitations
 * Right now there can only be one user per client (this should be easy to change in the future)
 * The way packets are sent is very basic, no special congestion options or anything

## Examples

Server:
```
# host server on interface with IP 192.168.1.2 port 4433
$ cargo run --bin server -- 192.168.1.2:4433
```

Client: 
```
# connect to server at 192.168.1.2:4433 and host HTTP/1.1 server on localhost port 8989
$ cargo run --bin client -- 192.168.1.2:4433 127.0.0.1:8989 http

# or host a socks server
$ cargo run --bin client -- 192.168.1.2:4433 127.0.0.1:8989 socks
```


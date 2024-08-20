Masquerade is an implementation of [MASQUE]([https://ietf-wg-masque.github.io/](https://datatracker.ietf.org/wg/masque/about/)). For UDP, it implements the `connect-udp` extended HTTP/3 CONNECT method as defined in [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html) using HTTP datagrams defined in [RFC 9297](https://www.rfc-editor.org/rfc/rfc9297.html). For TCP, it implements the HTTP/3 CONNECT method as defined in [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114.html#name-the-connect-method).

For client, it exposes a HTTP/1.1 or SOCKS5 interface for easy connection.

It is built on HTTP/3 and QUIC provided by the library [quiche](https://github.com/cloudflare/quiche).

Very early prototype with no thorough testing, missing a lot of features, poorly documented, and very poor error and edge case handling.

This fork aims to build up on the original masquerade implementation for the sake of improvement and evaluation.

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

## Running

You might need to add rules in the ip table first to get the CONNECT-IP method to work.
In the server you have to allow forwarding on your outgoing interface, for example eth0:
```
$ sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

And for the client you have to do that for the client TUN interface, for example tunMasqClient:
```
$ sudo iptables -t nat -A POSTROUTING -o tunMasqClient -j MASQUERADE
```

### Server
```
# Start the server on host IP 0.0.0.0, port 4433
# The TUN will be called tunMasqServer with the ip/range 10.8.0.1
# local_ip and link_dev are the interface via which the traffic from the TUN will be routed.
$ cargo build --release && sudo ./target/release/server --bind_addr 0.0.0.0:4433 --tun_addr 10.8.0.1/24 --tun_name tunMasqServer --local_ip 192.168.0.71 --link_dev eth0
```
### CONNECT-IP Client
```
# Start the client and connect it to the masquerade server located at 192.168.0.71:4433
# TUN device will be called tunMasqClient at 10.9.0.1, address range 10.9.0.2/24 
$ cargo build --release && sudo ./target/release/ip-connect-client --server_name 192.168.0.71:4433 --tun_addr 10.9.0.2/24 --tun_gateway 10.9.0.1 --tun_name tunMasqClient
```

### TCP/UDP Client: 
```
# connect to server at 192.168.1.2:4433 and host HTTP/1.1 server on localhost port 8989
$ cargo run --bin client -- 192.168.1.2:4433 127.0.0.1:8989 http

# or host a socks server
$ cargo run --bin client -- 192.168.1.2:4433 127.0.0.1:8989 socks
```


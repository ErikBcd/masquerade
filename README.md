# Masquerade - CONNECT-IP Fork

## This project is heavily based on the original Masquerade implementation

The original repository that was used as a basic template for this lies at [https://github.com/jromwu/masquerade](https://github.com/jromwu/masquerade).

## Why?

This is part of a thesis I am writing on evaluating the usability and speed of MASQUE based proxies, specifically the CONNECT-IP protocol.
It started out as a more general "let's take a look at available solutions and maybe enhance one" thing, but we later realized that the CONNECT-IP protocol would probably yield the best results, so I decided to implement this on top of an existing codebase.
The original Masquerade implementation was already pretty stable, which is why this project exists now.

## What?

Masquerade is an implementation of [MASQUE]([https://ietf-wg-masque.github.io/](https://datatracker.ietf.org/wg/masque/about/)). For IP traffic the connect_ip_client implements the `CONNECT-IP` method defined in [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484.html) with a specialised capsule protocol.

If you need an implementation for the CONNECT or CONNECT-UDP methods you can look into the original repository or into the `connect-udp-included` branch in this repository, this includes a few small fixes.

It is built on HTTP/3 and QUIC provided by the library [quiche](https://github.com/cloudflare/quiche).

Very early prototype with no thorough testing, missing a lot of features, poorly documented, and very poor error and edge case handling.

This fork aims to build up on the original masquerade implementation for the sake of improvement and evaluation.

**Note**: This is being developed on a Linux machine, no special support for other operating systems.
Still a very early version that only has some base functionality.

## Basic inner workings

### Server

The server creates a virtual network interface ([TUN](https://de.wikipedia.org/wiki/TUN/TAP)) and a QUIC server. It will then wait for clients to connect and choose a protocol.

For CONNECT-IP the server will then assign an IP to the client and route all incoming traffic via that TUN interface. The data traffic is purely transmitted via datagrams.

### CONNECT-IP Client

First, the client will attempt to connect to the server and get the basic connection going.
Afterwards another virtual network interface is created, and the system is set up to route all traffic via that interface. If this succeeds the client will attempt to establish an HTTP/3 CONNECT-IP session and send all traffic on the TUN interface to the server via HTTP/3 datagrams, and all traffic received as datagrams from the server to the TUN interface.

## Running

The server and the connect-ip client both have default configuration files prepared in `config/default_*_config.toml`. You can set all configuration in there and then save them as `client_config.toml` or `server_config.toml`, or provide the path to the config via `--client_config <path-to-file>`.

The default configuration files also have explanation for the parameters, you can also access hints via `--help` for the connect-ip client and server.

Arguments given via the command line instead of the configuration file take precedence.

This was tested and written on arch linux and should work on most other distributions as well. 
The software does not work on Windows, and I can't test it on MacOS.

### Server
```
# Build & start the server with the options set in the config file, but overwrite the local_uplink_device_name
$ cargo build --release && sudo ./target/release/server --local_uplink_device_name eth0
```

### CONNECT-IP Client
```
# Build & Start the client and connect it to the masquerade server located at 192.168.0.71:4433
$ cargo build --release && sudo ./target/release/connect_ip_client  --server_address 192.168.0.71:4433 
```

## State of the CONNECT-IP method

Generally performs okay-ish. Speedtests (iperf3 between clients, regular speedtests via cloudflare) reach up to 350mbit/s on my systems. However, flooding the client with datagrams will result in very poor performance or crashes. Bidirectional UDP tests in iperf3 do this, so.. avoid these I guess. Will be tackled later.

## TODOs

 * Create a proper documentation
 * Implement security features (authorization of clients, ..)
 * Tackle stability problems under datagram flood situations in connect-ip client
 * Benchmarks

# rust ebpf IP loopback
An example of IP loopback implementation using aya-rust ebpf library.
This example demonstrates how a packet modification and respective
checksum update is handled for an IPv4 packet.

## Prerequisites

1. Setup dev environment for aya-rust:
    ```
    $ rustup install stable
    $ rustup toolchain install nightly --component rust-src
    $ cargo install bpf-linker
    $ cargo install cargo-generate
    ```
    NOTE: For details follow instructions provided here: https://aya-rs.dev/book/start/development/

## Building and running

1. Build ebpf component:
    ```
    $ cargo xtask build-ebpf
    ```

    To perform a release build you can use the `--release` flag.
    You may also change the target architecture with the `--target` flag.

2. Build the user-space component:

    ```
    $ cargo build
    ```

3. Run the program:

    ```
    $ RUST_LOG=info cargo xtask run -- --iface <network-interface-name>
    ```

## Verify

Lets consider two hosts in your LAN:
- **192.168.1.22**: Where the ip-loopback ebpf program will be run.
- **192.168.1.33**: Another host that wants its UDP packets loopback'ed.

1. Run the ip-loopback ebpf program:
    ```
    $ RUST_LOG=info cargo xtask run -- --iface eth0
    ```

2. On the remote host(192.168.1.33) run a netcat UDP listener on the at some port(eg: 15000):
   ```
   $ nc -ul 0.0.0.0 15000
   ```

3. On that same remote host run a netcat UDP client with the destination IP as this host(where the ip-loopback ebpf program is running):
   ```
   $ echo "hello world..." | nc -u 192.168.1.22 15000
   ```

4. After the UDP message is sent you will see that it comes back to the netcat listener in the same host, although it was to another host:
   ```
   $ echo "hello world..." | nc -u 192.168.1.22 15000
   hello world...
   ```

You can also use tcpdump on the remote host to verify that the packet has been reversed.
 
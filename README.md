# PS-004: Gateway-Assisted DNSSEC for ESP8266

## Overview

This project explores gateway-assisted DNSSEC validation using an ESP8266 Client -> DNS-over-TLS Gateway -> Unbound DNS Resolver -> NSD Authoritative DNS Server

The ESP8266 sends DNS queries to the gateway over an intended DNS-over-TLS connection. The gateway uses Unbound for DNS resolution and DNSSEC validation, with NSD hosting the lab's test zones.

## Architecture

ESP8266 Client -> DNS-over-TLS Gateway -> Unbound DNS Resolver -> NSD Authoritative DNS Server

## Technologies

- ESP8266 / NodeMCU
- PlatformIO and Arduino framework
- BearSSL
- Ubuntu WSL2
- Unbound
- NSD
- Python

## Test Domains

| Domain | Expected result |
|---|---|
| `secure.lab.test` | DNSSEC-valid response |
| `insecure.lab.test` | Unsigned DNS response |
| `www.bogus.lab.test` | DNSSEC validation failure |

## Current Progress

- ESP8266 board setup and firmware upload tested.
- Wi-Fi and gateway TCP connectivity tested.
- DNS query construction and verdict parsing tested.
- Gateway DNSSEC test zones configured and validated.
- ESP8266-to-gateway TLS handshake currently under investigation.
- Public-key pinning, HMAC channel-binding verification and complete end-to-end testing remain pending.

## Security

Do not commit private keys, shared secrets, passwords or generated credential files. Keep gateway credentials outside version control.

## Status

Work in progress for the AIORI3 PS-004 hackathon.

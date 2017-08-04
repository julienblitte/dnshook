# dnshook
Linux DNS server to redirect all trafic to specific server.
Can be used for security audits or to make a captive portal.

## Operating Systems
Designed for **Linux**, especially for Debian based distribution.

## Hardware architecture
Compiled and tested over **X86** and **ARMHF** architectures.

## Service
* DNS A type query (standard request): redirect all name resolution to local or defined IP address
* DNS PTR type query (reverse resolution): if compiled with option EASY_REMOTE define new IP address target for all name resolution
* DNS 0xFF0C type : if compiled without option EASY_REMOTE define new IP address target for all name resolution

## Protocol
DNS over UDP, port 53

## Language
Programmed in **C**.

## Limitation
Start-up dased on SystemV scripts.

## Releases
* Version 0.2: https://github.com/julienblitte/dnshook/releases/tag/0.2


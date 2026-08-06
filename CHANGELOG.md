# Changelog

## 0.2.1

- changed the project license from MIT to GNU AGPL v3 or later;
- declared Daniele Stefano Continenza as creator and original copyright holder;
- added AUTHORS.md, NOTICE and SPDX copyright headers;
- updated Italian and English licensing documentation.

## 0.2.0

- replaced the simplified watcher with the production-aligned 1,400-line engine;
- added local nftables bridge metrics and automatic bridge removal after OpenWrt confirmation;
- added exact `ss -K` auto-family behaviour for IPv4-mapped Apache sockets;
- aligned the banIP backend with direct runtime insertion, verification, conntrack deletion and persistence without reload;
- added OpenWrt `apk` and `opkg` prerequisite handling;
- corrected the restricted SSH command grammar to match the real watcher;
- added standalone detector code independent of CSF/LFD;
- excluded all site-specific Apache VirtualHosts and production addresses;
- expanded Italian and English documentation.

## 0.1.0

Initial prototype release.

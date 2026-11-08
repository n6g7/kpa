# Changelog

## [0.2.0](https://github.com/n6g7/kpa/compare/v0.1.0...v0.2.0) (2026-11-08)


### Features

* copy and list totp codes ([#33](https://github.com/n6g7/kpa/issues/33)) ([df7ed4c](https://github.com/n6g7/kpa/commit/df7ed4ce4249a0777d16bec15eee457119a6e286))
* let copy address custom fields ([#35](https://github.com/n6g7/kpa/issues/35)) ([108888e](https://github.com/n6g7/kpa/commit/108888e100d3f92a5834dfd0e2f795600467b565))
* list reports each entry's copyable field names ([#32](https://github.com/n6g7/kpa/issues/32)) ([844c5d8](https://github.com/n6g7/kpa/commit/844c5d883e322b81a4a2bd9e0bf8ae0ec48e27fb))


### Bug Fixes

* log an operation before sending its reply ([#37](https://github.com/n6g7/kpa/issues/37)) ([464cbb0](https://github.com/n6g7/kpa/commit/464cbb07793ce2ce50cca342eca7f57c954174cf))
* register the tray whenever a watcher is or becomes available ([#31](https://github.com/n6g7/kpa/issues/31)) ([78ac3af](https://github.com/n6g7/kpa/commit/78ac3afca89b5f5c7c1b0b160b126e120f8e1ebf))
* report the commit in kpa version on release builds too ([#28](https://github.com/n6g7/kpa/issues/28)) ([51f4204](https://github.com/n6g7/kpa/commit/51f42041bfb1352f1c8ca1c34074a67183d33a69))

## 0.1.0 (2026-11-07)


### Features

* add a ksni-based tray (StatusNotifierItem) ([#15](https://github.com/n6g7/kpa/issues/15)) ([7c8ca6b](https://github.com/n6g7/kpa/commit/7c8ca6bea5c3bb3c9f03d6ecdd3b4d728626b772))
* Add a Nix package output and a home-manager module ([#14](https://github.com/n6g7/kpa/issues/14)) ([3420966](https://github.com/n6g7/kpa/commit/3420966cdabcdadd81d155c9f9453180c615407f))
* add a version command reporting the build's git ref ([#10](https://github.com/n6g7/kpa/issues/10)) ([bc28c6d](https://github.com/n6g7/kpa/commit/bc28c6d63583666b926a6bf2ab026b32019bb243))
* **fuzz:** add a cargo-fuzz harness for request decoding ([#16](https://github.com/n6g7/kpa/issues/16)) ([5eb07bb](https://github.com/n6g7/kpa/commit/5eb07bb3d47a717dbb84f5fb8bd1b35c60e9e092))
* have kpa version report the daemon's version too ([#25](https://github.com/n6g7/kpa/issues/25)) ([95c640f](https://github.com/n6g7/kpa/commit/95c640ff4376b073f5e7b353bc3cbe02da2466fa))
* log at four levels to stderr, with journald priorities ([#20](https://github.com/n6g7/kpa/issues/20)) ([b4307cc](https://github.com/n6g7/kpa/commit/b4307cc031e21f71395dcaba6d790e17007f387b))
* **nix:** sandbox the home-manager module's systemd service by default ([#19](https://github.com/n6g7/kpa/issues/19)) ([2a65d66](https://github.com/n6g7/kpa/commit/2a65d6679ca08b39245a919ea413456834ff0774))
* show the built commit in kpa version for untagged/Nix builds ([#21](https://github.com/n6g7/kpa/issues/21)) ([93174f1](https://github.com/n6g7/kpa/commit/93174f1e6aa30f2405da7f065c70ef836a2873bc))


### Bug Fixes

* **ci:** drop the "kpa-" component prefix from release-please tags ([#13](https://github.com/n6g7/kpa/issues/13)) ([cbc5965](https://github.com/n6g7/kpa/commit/cbc59652ecd4c58cfa05f5fdca75754177d2bfcc))
* **clip:** end a clipboard offer when its database locks ([#18](https://github.com/n6g7/kpa/issues/18)) ([6c0b0ca](https://github.com/n6g7/kpa/commit/6c0b0caa0a96d15d2337356f2011927086320ffb))
* end a database's clipboard offer when the freshness guard drops it ([#24](https://github.com/n6g7/kpa/issues/24)) ([779aad1](https://github.com/n6g7/kpa/commit/779aad181a5b61fe305e70b5488c3160a5d38f13))
* give the unlock prompt its own stderr ([#23](https://github.com/n6g7/kpa/issues/23)) ([79df079](https://github.com/n6g7/kpa/commit/79df079b219d71f91574ce4bf429ac1189414016))

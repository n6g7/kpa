# Changelog

## [0.4.0](https://github.com/n6g7/kpa/compare/v0.3.0...v0.4.0) (2026-11-28)


### ⚠ BREAKING CHANGES

* protocol version 2. A client or daemon of version 1 gets `version_mismatch`.

### Features

* add SSH agent approval and signing policy ([#59](https://github.com/n6g7/kpa/issues/59)) ([331b441](https://github.com/n6g7/kpa/commit/331b4417953458667cb32263a90acd018083fe31))
* add the SSH agent protocol layer ([#58](https://github.com/n6g7/kpa/issues/58)) ([58957d5](https://github.com/n6g7/kpa/commit/58957d56f2923ca356b97be2c66abf5e847bd45b))
* ask for the unlock password on a terminal the requester passes ([#90](https://github.com/n6g7/kpa/issues/90)) ([eaa0545](https://github.com/n6g7/kpa/commit/eaa0545c0d6a60d6cc107f96cc865397f7b19440))
* **auto_lock:** the front end that locks without a request ([#100](https://github.com/n6g7/kpa/issues/100)) ([c2183f1](https://github.com/n6g7/kpa/commit/c2183f1038e77fddad570f50dbb77c0591059231))
* **cli:** kpa pick ([#129](https://github.com/n6g7/kpa/issues/129)) ([efc66d4](https://github.com/n6g7/kpa/commit/efc66d4f188b35cf97e59baae91b5d08fe575dd0))
* **control:** kpa's own socket and the daemon's wiring on the core ([#103](https://github.com/n6g7/kpa/issues/103)) ([b5046bf](https://github.com/n6g7/kpa/commit/b5046bf21d3bfeeeff45f4529a4c9d71a63086f2))
* **control:** status reports whether a copy would land ([#127](https://github.com/n6g7/kpa/issues/127)) ([fe7a48b](https://github.com/n6g7/kpa/commit/fe7a48bade8e8d151c564d216a19296f273594ea))
* **databases:** the core that holds every database and what locks it ([#99](https://github.com/n6g7/kpa/issues/99)) ([2a526dc](https://github.com/n6g7/kpa/commit/2a526dc8208090eea01af64b645095085483471c))
* discover and serve SSH keys from vault attachments ([#57](https://github.com/n6g7/kpa/issues/57)) ([cee7525](https://github.com/n6g7/kpa/commit/cee7525ae40ebef049a4d9d21afb191e9407fbed))
* **hm-module:** wire services.kpa.sshAgent.enable ([#54](https://github.com/n6g7/kpa/issues/54)) ([44ef9dc](https://github.com/n6g7/kpa/commit/44ef9dc0d0c851a3a182069eaae8f06f09664d7e))
* **nix:** put kpa on PATH and bind a shell key to kpa pick ([#130](https://github.com/n6g7/kpa/issues/130)) ([d3fd5c7](https://github.com/n6g7/kpa/commit/d3fd5c7c6018448e7874df36c7dc1a524179c50c))
* **output:** a Table that escapes its cells ([#81](https://github.com/n6g7/kpa/issues/81)) ([73628ae](https://github.com/n6g7/kpa/commit/73628ae1f8dd9a31e72b71337a18023fc84fd4ca))
* pass the unlock prompt's message via KPA_PROMPT_MESSAGE ([#56](https://github.com/n6g7/kpa/issues/56)) ([68fb3f4](https://github.com/n6g7/kpa/commit/68fb3f490b969a6f54c4d2adead2fe0bbac2e588))
* **prompt:** prompt programs get the data behind the message in KPA_PROMPT_DATA ([#118](https://github.com/n6g7/kpa/issues/118)) ([038ad46](https://github.com/n6g7/kpa/commit/038ad463434487e8f47719971e3189c18809a5e9))
* serve the SSH agent from the daemon ([#71](https://github.com/n6g7/kpa/issues/71)) ([c66c48f](https://github.com/n6g7/kpa/commit/c66c48f3a6c86b279ca53ae622df293b6fe075be))
* **ssh_agent:** agent socket loop ([#68](https://github.com/n6g7/kpa/issues/68)) ([c6595db](https://github.com/n6g7/kpa/commit/c6595db79f6ec4fcd3667bf1cdf562f426259c80))
* **ssh_agent:** key state and identity listing ([#69](https://github.com/n6g7/kpa/issues/69)) ([e26e61f](https://github.com/n6g7/kpa/commit/e26e61f1757a79d4346b45f6bbf90990fd773faa))
* **ssh_agent:** kpa ssh keys ([#77](https://github.com/n6g7/kpa/issues/77)) ([e27c750](https://github.com/n6g7/kpa/commit/e27c7508fd9869f885d48c94d6e3126fcf5a5fd9))
* **ssh_agent:** kpa ssh pending and kpa ssh approve ([#85](https://github.com/n6g7/kpa/issues/85)) ([db0d31c](https://github.com/n6g7/kpa/commit/db0d31cfb324e58606d3aa479fab04d0e1435094))
* **ssh_agent:** name the key in the sign log line, from config only ([#76](https://github.com/n6g7/kpa/issues/76)) ([aff6b73](https://github.com/n6g7/kpa/commit/aff6b73cf7c93daeaa89c917267c1afd40b5d113))
* **ssh_agent:** pending requests and approvals ([#78](https://github.com/n6g7/kpa/issues/78)) ([993a50e](https://github.com/n6g7/kpa/commit/993a50ecb1aebf3abd2ef93f610d713c3cf27931))
* **ssh_agent:** sign flow and approval ([#70](https://github.com/n6g7/kpa/issues/70)) ([e453d20](https://github.com/n6g7/kpa/commit/e453d20fc062dcb799bac0f8a62dae181605feb1))
* **ssh_agent:** tell a requester outside the desktop what to run ([#86](https://github.com/n6g7/kpa/issues/86)) ([45fd2b9](https://github.com/n6g7/kpa/commit/45fd2b974d8c22b05d1cdef7a07e973cd0593d09))
* **ssh_agent:** the agent on the core ([#105](https://github.com/n6g7/kpa/issues/105)) ([18922a0](https://github.com/n6g7/kpa/commit/18922a06991c895b6a24634d34e92afc8a5c4e62))
* **ssh_agent:** unlock on demand ([#79](https://github.com/n6g7/kpa/issues/79)) ([4efd450](https://github.com/n6g7/kpa/commit/4efd45052431f2d9b2a307167dd2f8336f0297e0))
* **ssh-agent:** a host a trusted CA certified is named by its certificate's principal ([#122](https://github.com/n6g7/kpa/issues/122)) ([28bdeb1](https://github.com/n6g7/kpa/commit/28bdeb11f364f4f8130dd888b8ec2dce9cfd35ce))
* **ssh-agent:** forwarded logins are approved per forwarding session ([#111](https://github.com/n6g7/kpa/issues/111)) ([285b668](https://github.com/n6g7/kpa/commit/285b668bd03ec930fd9c2d9a4624b4a6c8fe8073))
* **ssh-agent:** kpa ssh grants lists the signature approvals in force ([#114](https://github.com/n6g7/kpa/issues/114)) ([be9eecd](https://github.com/n6g7/kpa/commit/be9eecdb28e02bd40d9b9ee6d2926b839900b0f1))
* **ssh-agent:** kpa ssh grants shows host names, and --full shows every column ([#115](https://github.com/n6g7/kpa/issues/115)) ([0df001a](https://github.com/n6g7/kpa/commit/0df001add79473754a71bc243d62e2295398e6cc))
* **ssh-agent:** kpa ssh keys shows the name each key is served under ([#121](https://github.com/n6g7/kpa/issues/121)) ([2cd0779](https://github.com/n6g7/kpa/commit/2cd077934a37039effc61f9476a3f70d92c5b826))
* **ssh-agent:** the known_hosts files that name hosts are a setting ([#124](https://github.com/n6g7/kpa/issues/124)) ([1b79741](https://github.com/n6g7/kpa/commit/1b797419f9a9f2b259c2adf2150d3fb13d207a6b))
* **ssh-agent:** the prompt shows every host a forwarded login came through ([#125](https://github.com/n6g7/kpa/issues/125)) ([d7a8b3a](https://github.com/n6g7/kpa/commit/d7a8b3a308e23dce73525b30ac161531ddb815c0))
* **ssh-agent:** the sign log line names hosts as known_hosts does ([#120](https://github.com/n6g7/kpa/issues/120)) ([672e93c](https://github.com/n6g7/kpa/commit/672e93c428a5c182751cfcb68f2d8d235891c0d9))
* **ssh:** approvals and pending requests held per database and unlock ([#102](https://github.com/n6g7/kpa/issues/102)) ([a80f0f3](https://github.com/n6g7/kpa/commit/a80f0f3429f6135d5049f3a77d197e62b51d3e3c))
* the daemon asks for the unlock password on the CLI's terminal ([#91](https://github.com/n6g7/kpa/issues/91)) ([eab38ae](https://github.com/n6g7/kpa/commit/eab38ae50e3e1b83d65b8e4656e49dc62cf586b0))
* **tray:** the tray on the core ([#104](https://github.com/n6g7/kpa/issues/104)) ([c939420](https://github.com/n6g7/kpa/commit/c939420dfe8ba2c79d08834e587120824fe7f13d))


### Bug Fixes

* **auto_lock:** accept logind's messages only from the connection that owns its name ([#107](https://github.com/n6g7/kpa/issues/107)) ([410c2a2](https://github.com/n6g7/kpa/commit/410c2a2a06e30f4126e359676d923c8fa108e5a4))
* **auto-lock:** hold the sleep inhibitor again after a watch lost mid-suspend ([#151](https://github.com/n6g7/kpa/issues/151)) ([e3aeab5](https://github.com/n6g7/kpa/commit/e3aeab559edbaa09e55cd3456a35644d3def389c))
* **auto-lock:** keep reading logind's connection while it is called ([#142](https://github.com/n6g7/kpa/issues/142)) ([cba4f09](https://github.com/n6g7/kpa/commit/cba4f09de16412ca9ead99af96a9823074fc57d6))
* **clipboard:** answer no paste once the unlock behind a copy is locked ([#148](https://github.com/n6g7/kpa/issues/148)) ([cd55ff3](https://github.com/n6g7/kpa/commit/cd55ff3a3cc31c41d493cda3ff97425cbe779c85))
* **control:** make the socket's I/O deadlines total ([#154](https://github.com/n6g7/kpa/issues/154)) ([43afd1b](https://github.com/n6g7/kpa/commit/43afd1b98facc13e6de0cebe99ffb98e08d8683f))
* **copy:** never offer the entry's otp field, only the code made from it ([#143](https://github.com/n6g7/kpa/issues/143)) ([1f17791](https://github.com/n6g7/kpa/commit/1f17791ce4e996371870b736e2faef435724de4d))
* **databases:** count the time the machine sleeps toward the idle timeout ([#153](https://github.com/n6g7/kpa/issues/153)) ([039dd84](https://github.com/n6g7/kpa/commit/039dd846eabb3bddc0a7ccf2c65730b543419d32))
* **databases:** read KDBX3 and KDBX4 files only ([#144](https://github.com/n6g7/kpa/issues/144)) ([2a450de](https://github.com/n6g7/kpa/commit/2a450dee7c67438f43ca205dac276d1bdd4799f6))
* **databases:** read only regular files under a size ceiling ([#157](https://github.com/n6g7/kpa/issues/157)) ([95ceda0](https://github.com/n6g7/kpa/commit/95ceda0dd90e1d877477f6c61e02b7b9b628c985))
* **databases:** refuse key derivation above ceilings before it runs ([#158](https://github.com/n6g7/kpa/issues/158)) ([c83fd83](https://github.com/n6g7/kpa/commit/c83fd83500b4d4b9a5be7c14e0aa92a47c73c7f4))
* **databases:** stat a vault's file without the core's lock ([#108](https://github.com/n6g7/kpa/issues/108)) ([678abea](https://github.com/n6g7/kpa/commit/678abea36d60e676ef3160fc3389947e023caa21))
* find the compositor on each copy, with kpa's own clipboard client ([#62](https://github.com/n6g7/kpa/issues/62)) ([e0657dc](https://github.com/n6g7/kpa/commit/e0657dc579ca8f45b78da17dd921f757ea989a6a))
* give the default unlock prompt its message ([#72](https://github.com/n6g7/kpa/issues/72)) ([79663ed](https://github.com/n6g7/kpa/commit/79663edd56af980aa42d3f7ddc849571f026de43))
* **pick:** keep an entry's title off the field chooser's command line ([#146](https://github.com/n6g7/kpa/issues/146)) ([1d864d3](https://github.com/n6g7/kpa/commit/1d864d3baded826c84a09d23c618114c18691f61))
* **pick:** write the copied field's name quoted and escaped like the title ([#150](https://github.com/n6g7/kpa/issues/150)) ([4758fe2](https://github.com/n6g7/kpa/commit/4758fe2cdac1885db43731bba171e90b519cb034))
* **ssh-agent:** a host that presents a certificate binds by the key it certifies ([#119](https://github.com/n6g7/kpa/issues/119)) ([593e7e3](https://github.com/n6g7/kpa/commit/593e7e3b9a96fc9d912b6bc65bc7adff15afc4bd))
* **ssh-agent:** keep a connection forwarded once its first bind claims it ([#141](https://github.com/n6g7/kpa/issues/141)) ([14e79c1](https://github.com/n6g7/kpa/commit/14e79c1d8862935b008da6612096b78ab43f9d6e))
* **ssh-agent:** name a key as the unlocked database does once it is unlocked ([#116](https://github.com/n6g7/kpa/issues/116)) ([103d764](https://github.com/n6g7/kpa/commit/103d7647b98a0b67a1012125eaf5f8f19b362c32))
* **ssh-agent:** quote a prompt's key name and namespace and escape what a login's user can carry ([#145](https://github.com/n6g7/kpa/issues/145)) ([f599d27](https://github.com/n6g7/kpa/commit/f599d27a5f9fd997f7973c5280ab20b0655f0d3c))
* **totp:** make no code for a period or digit count the code library can't take ([#152](https://github.com/n6g7/kpa/issues/152)) ([e6bbf47](https://github.com/n6g7/kpa/commit/e6bbf476a170288feb7009058000dbcd5cf31a39))

## [0.3.0](https://github.com/n6g7/kpa/compare/v0.2.0...v0.3.0) (2026-11-12)


### Features

* accept the master password in an unlock request ([#40](https://github.com/n6g7/kpa/issues/40)) ([4e47bbb](https://github.com/n6g7/kpa/commit/4e47bbb6218dd3aa97759cd09a494f815ac1eebc))
* bound password prompts with a timeout and locks ([#39](https://github.com/n6g7/kpa/issues/39)) ([ad5872e](https://github.com/n6g7/kpa/commit/ad5872eb2c6e1324cd1f508778b0857338a4b13b))
* gate copy on origin and the desk's active, unlocked state ([#47](https://github.com/n6g7/kpa/issues/47)) ([25adbae](https://github.com/n6g7/kpa/commit/25adbaeb913ef06c69f8abca32319195893f25d9))
* read the master password from the terminal when there's no display ([#48](https://github.com/n6g7/kpa/issues/48)) ([29dfff5](https://github.com/n6g7/kpa/commit/29dfff55729207cdbee60b2d367406dfe81ad771))
* refuse on-screen prompts for unlocks from outside the desktop ([#41](https://github.com/n6g7/kpa/issues/41)) ([bc17bcb](https://github.com/n6g7/kpa/commit/bc17bcb5df628ae13fc97ede9e0a10e4454b448a))


### Bug Fixes

* don't log "unlocked" when the database was already unlocked ([#43](https://github.com/n6g7/kpa/issues/43)) ([7c6f81c](https://github.com/n6g7/kpa/commit/7c6f81c1c1223c7ca5a1fd83ae6c88ee36b7bc2d))
* mark every kpa process non-dumpable before dispatch ([#52](https://github.com/n6g7/kpa/issues/52)) ([ff9f38d](https://github.com/n6g7/kpa/commit/ff9f38d48b76bb8b324c7f96999589e67deea9d7))
* stop build.rs rerunning on every build in git worktrees ([#50](https://github.com/n6g7/kpa/issues/50)) ([4ff296b](https://github.com/n6g7/kpa/commit/4ff296be60d95e9f34aae0d400d6564e55874655))
* zeroize the CLI's outbound request buffer ([#53](https://github.com/n6g7/kpa/issues/53)) ([118a1cb](https://github.com/n6g7/kpa/commit/118a1cbdee72b4fdf282afe5ed51a4419d75eb74))

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

# kpa — browser autofill

kpa fills usernames, passwords and TOTP codes into websites' login forms,
through its own extension for Chromium-based browsers and Firefox. The
user opens the extension from the browser's toolbar, which lists the
logins whose URL matches the page; picking one fills it. The extension
reaches `kpa serve` through a native messaging host: a small program the
browser starts, which relays each request to kpa's browser socket.

**Not built yet.** This doc is the design the implementation follows.
Nothing in `src/` implements it, the extension doesn't exist yet, and the
other docs don't describe it: [`design.md`](./design.md) § Scope still
lists a browser backend under *Is not*. The steps are in
[`TODO.md`](../TODO.md).

It follows `copy`'s rules ([`headless.md`](./headless.md) § 5): a secret
leaves only for a requester on the desktop, while the display session is
active and unlocked, and a fill asks nothing more of the user than a
`copy` does. A locked database is unlocked on demand, on screen.

## 1. Overview

- **The browser's own UI starts every fill.** The extension's toolbar
  button, or the shortcut the browser lets its user give it, opens a popup
  listing the page's logins. Nothing of the extension runs in a page until
  the user opens the popup on its tab, so a page can't trigger it or tell
  it is installed before then, and has no menu of the extension's to draw
  over (§ 3).
- **It shows what it will fill.** The fields a pick would fill are
  outlined in the page, and each login in the popup says which of them it
  fills, so a page kpa reads wrong is seen before the pick (§ 5.2, § 5.3).
- **Entries match by host.** An entry's URL, and the extra URLs some
  clients store beside it, match a page on the same host or a subdomain
  of it, over the same scheme or an upgrade from `http` to `https` (§ 4).
- **One pick fills what the page shows**: the username, the password and
  a one-time code, whichever of the three the page has a field for. It
  never submits the form. A login spread over several pages is one pick
  per page (§ 5.4).
- **No prompt for a fill.** Picking the login is the request, as running
  `kpa copy` is. The log names the entry and fields, as for a copy (§ 5.5).
- **Locked databases are offered for unlock.** Under the matches from the
  unlocked databases, the popup lists each locked database, and picking
  one raises kpa's unlock prompt on screen (§ 5.6).
- **Every database serves logins unless it opts out** with
  `serve_logins = false` (§ 8).
- **kpa decides what matches.** The extension sends the page's origin, as
  the browser reports it, and kpa answers with the matching logins and,
  for a fill, with only the fields asked for, of an entry that matches.
- **Its own socket**, `$XDG_RUNTIME_DIR/kpa/browser`, which speaks only
  what the extension needs, with a version of its own: the one socket
  whose responses carry a secret (§ 7).
- **No store listings.** Chromium-based browsers load the extension
  unpacked. Firefox installs a package Mozilla has signed without listing
  it, attached to each kpa release (§ 9).

## 2. Use cases

**Served**

- Signing in to a site from Chromium, Google Chrome, Brave, Vivaldi or
  another Chromium-based browser, or from Firefox, with the extension
  installed: a username and password form, a username page followed by a
  password page, and a code page after either.
- A login form in a frame of the page's own origin.
- Several logins for one site, each listed with its title, username and
  database.

**Not served**

- **Saving or updating a login.** kpa is read-only ([`design.md`](./design.md)
  § Scope). The extension never offers to save what a form submits.
- **A form in a frame of another origin**, such as a sign-in frame a page
  embeds from its identity provider. The extension can't reach it (§ 6.2).
- **HTTP authentication dialogs**, which the browser draws, not the page.
- **A browser outside the desktop**, such as one in a remote desktop
  session, and any request while the screen is locked
  ([`headless.md`](./headless.md) § 3).
- **Flatpak and Snap browsers** (§ 9.5).
- **Pages other than `http` and `https`**: `file:`, a browser's own pages,
  another extension's.
- **Passkeys**, which come with an emulated security key
  ([`ROADMAP.md`](../ROADMAP.md) 0.6.0).

## 3. Why an extension, and why only through the toolbar

Desktop browsers on Linux take no outside password provider. Their own
password managers keep their own stores, and the routes below the browser
(an emulated security key, `credentialsd`) carry passkeys, never
passwords. So kpa reaches the page through an extension.

An extension can't open a Unix socket. It reaches a local program either
over HTTP or a WebSocket to `localhost`, or through native messaging,
where the browser starts the program and talks to it over its stdin and
stdout. kpa has no network surface and gains none
([`threat-model.md`](./threat-model.md) ACT-2), so it takes native
messaging.

**Not a KeePass client's extension.** kpa could speak the native messaging
protocol of a KeePass client's existing extension and need no extension of
its own. That extension asks for a page's logins as each page loads, draws
its menus inside pages, offers to save logins, and keeps the key it pairs
with in the database, which kpa never writes. Its protocol and behaviour
belong to another project, so every rule below would be that project's.

**Not a menu in the page.** Most extensions put a menu under a page's
login fields, which needs a script in every page and permission to read
and change every site. A menu drawn inside a page can be clickjacked: the
page hides it, or covers it with bait of its own, and the user's click on
the bait lands on the menu's fill. That works against inline menus of most
password managers (Tóth, DEF CON 33, 2025), and the fixes vendors shipped
are partial. A popup is drawn by the browser, outside the page, so a page
can neither hide nor cover it. The toolbar route costs the suggestions
under the field, and forms in frames of another origin (§ 6.2). In return:

- the extension asks for no permission to read or change sites, only
  `activeTab` for the tab the user opened it on;
- nothing of the extension runs in a page until the user opens the popup
  on its tab, so pages can't detect it before then, and a hostile page
  can't start a fill.

## 4. Which entries match a page

### 4.1 The page's origin

A tab shows one page, which can embed other pages in frames
(`<iframe>`), each with an origin of its own. The extension takes the
origin of the page the tab shows from the browser (the tab's URL, which
`activeTab` grants), never from the page's own scripts, and sends it to
kpa. kpa serves `http` and `https` origins only: a scheme, a host and a
port, the port being the scheme's default when the URL names none. The
host comes in its ASCII form, IDN hosts as punycode.

### 4.2 An entry's URLs

An entry's URLs are its `URL` field and every custom field whose name
starts with `KP2A_URL` (`KP2A_URL`, `KP2A_URL_1`, …), the extra URLs
Android KeePass clients write and desktop clients read. Protected values
count: matching reads them inside kpa, and only the fact of a match
leaves.

Each value is read as a URL:

- A value without a scheme is an `https` URL: `example.com/login` is
  `https://example.com/login`.
- A scheme other than `http` and `https` (`androidapp://`, `ssh://`) is
  ignored.
- The host is lowercased, put in its ASCII form and stripped of a trailing
  dot. The path, query, fragment and user info are ignored.
- A value that doesn't parse as a URL with a host, such as a pattern with
  `*` in it, is ignored.

### 4.3 The rule

An entry's URL matches a page when all three hold:

- **Host:** the page's host is the URL's host, or a subdomain of it on a
  label boundary. An IP address matches only itself.
- **Scheme:** an `https` page takes `https` and `http` URLs; an `http`
  page takes only `http` URLs. A secret saved for a site's `https` pages
  never goes to an unencrypted one.
- **Port:** if the URL names a port, the page's port is that port.

| Entry URL | Matches | Doesn't match |
| --- | --- | --- |
| `example.com` | `https://example.com`, `https://login.example.com`, `https://example.com:8443` | `http://example.com`, `https://notexample.com`, `https://example.org` |
| `https://login.example.com/sso` | `https://login.example.com`, `https://eu.login.example.com` | `https://example.com`, `https://www.example.com` |
| `http://router.lan` | `http://router.lan`, `https://router.lan` | |
| `https://192.168.1.1:8443` | `https://192.168.1.1:8443` | `https://192.168.1.1`, `https://192.168.1.10:8443` |

No public suffix list: an entry is the user's own statement of where it
belongs, and the rule never widens it beyond the host it names. An entry
whose URL is a public suffix (`com`, `github.io`) matches every site under
it; § 10 says what that gives its author.

An entry matches if any of its URLs matches.

### 4.4 Which entries are offered

An entry is offered when one of its URLs matches and:

- its database is unlocked and doesn't set `serve_logins = false`;
- it isn't in the recycle bin;
- neither it nor a group above it carries the custom data
  `BrowserHideEntry` set to `true`, a KeePass client's mark for an entry
  kept out of browsers;
- it has a username, a password or a TOTP seed.

kpa doesn't read the per-site allow and deny lists a KeePass client keeps
in an entry's custom data: they record that client's own prompts, and kpa
has none. Expired entries are offered, as `list` and `copy` serve them.

### 4.5 Order

The matches come in this order: an entry whose URL's host is the page's
own before one that matches through a parent domain, the closer parent
first; then by title; then by the databases' order in the config.

## 5. Filling

### 5.1 The popup

Opening the popup sends kpa a `logins` request for the tab's origin
(§ 7.4). The popup shows:

- one line per match: its title, its username and its database. As in
  `list`, a protected title or username is left out, and every string is
  shown as text, never as markup;
- under them, one `Unlock <database>` line per locked database that serves
  logins, whether or not anything matched;
- a line saying why there is nothing, when that is so: no login for the
  site, a page that isn't `http` or `https`, a browser outside the desktop
  or a locked screen (`no_display`), `kpa serve` not reachable or the host
  not installed, or a kpa that speaks another version of the protocol.

### 5.2 Finding the fields

When the popup lists a login, the extension runs a script in the page the
tab shows to find the fields a pick would fill. It looks through the page,
its frames of the same origin, and the shadow roots in both, closed ones
included (the subtrees a web component keeps out of the page's own
queries).

A field counts only if the user can see it and type into it: enabled, not
read-only, at least 10 pixels wide and high, not hidden by `display`,
`visibility` or an opacity under 0.7 on it or a parent, and the topmost
element at its centre is the field or its label. A form a page keeps out
of sight gets nothing.

The fields come from one form: the one holding the field the user last
focused, if it has one of the fields below, else the first in the page
that has one. The inputs outside any `<form>` count as one form. In it:

- **Password**: an `<input type="password">` not marked
  `autocomplete="new-password"`, which marks a sign-up or change form's new
  password. Of several, the one marked `current-password`, else the first.
- **Username**: the field marked `autocomplete="username"`, else one
  marked `email`, else the nearest text, email or tel field before the
  password.
- **Code**: the field marked `autocomplete="one-time-code"`, else a text,
  number or tel field whose name, id, label or placeholder reads as a
  one-time code (`otp`, `2fa`, `verification code`, …) and not as a postal,
  promo or recovery code. Or a row of four to eight single-character
  fields, which take one digit each when there are as many as the code has
  digits.

A form without a password field can still ask for a username alone, the
first step of a sign-in split across pages. It is the field marked
`autocomplete="username"` or `email`, else the one text or email field
whose name, id, label or placeholder reads as a login (`user`, `login`,
`email`, …), in a form that doesn't read as a search, a newsletter or a
subscription. Words are matched in English only.

What larger password managers add on top, kpa leaves out: predictions
from a server or a trained model, tables of per-site exceptions, and word
lists in many languages. They find the fields on more pages. kpa shows
what it found instead (§ 5.3), and a page it reads wrong is left to
`kpa pick` or `kpa copy`.

### 5.3 Showing the fields

Each field found gets an outline in its kind's colour, and the popup
shows which colour is which. Each login's line says which of username,
password and code a pick fills: those the page has a field for and the
entry has a value for. A login with none can't be picked. The outlines go when the
popup closes or the fill is done.

An outline is a style on the field itself, set `!important`, drawn inside
its border so a parent that clips its content doesn't hide it, and put
back as it was afterwards. The page can see the outlines, and so tell the
popup is open on its tab, and it can remove them. That gains it nothing: a
fill gives a page only a login matched to its own origin, and the page can
read every field it is given, whichever kpa chose. The outlines are there
to catch kpa's mistakes on an honest page.

### 5.4 What a pick fills

1. **It asks kpa for the fields shown**, among those the entry has
   (§ 7.4). The tab's origin is read again for the request; if it changed
   since the popup listed the logins, the popup lists again instead of
   filling.
2. **It fills them.** A second script writes each value into the field
   shown for it, after checking that the field is still in the page, still
   counts (§ 5.2), and that its frame's origin is still the one kpa
   matched. A field whose `maxlength` is shorter than its value is left
   as it is, and the popup stays open to say so.
3. **It acts as typing would.** Each write raises the events a page's own
   code listens for: `focus`, the value, `input` and `change`, then
   `blur`. The script runs in the extension's isolated world (§ 6.1),
   where setting a field's value reaches the browser's own setter, below
   the one frameworks such as React put on their fields, so they see the
   change.

It never submits the form, never fills a field it didn't show, and keeps
nothing. The TOTP code is generated when kpa answers the fill, so it is
current. A username page followed by a password page, or a code page after
the password, is another pick from the popup on each page.

The values go straight into their fields, not through the clipboard. A
copy reaches every program that reads the clipboard while it is offered
([`threat-model.md`](./threat-model.md) T-6), and can be pasted anywhere;
a fill reaches only the fields of the origin kpa matched.

### 5.5 Who may fill, and why there is no prompt

The browser socket answers only a requester on the desktop while the
display session is active and unlocked: `copy`'s gate
([`headless.md`](./headless.md) § 5), for the same reason, since a secret
must reach only the desk. Anything else is `no_display`, a `logins`
request included, so the popup says kpa can't fill here before it lists
anything. The host the browser starts runs in the browser's cgroup, so a
browser on the desktop passes the gate.

A fill raises no prompt. Any process of the user can already `copy` any
secret of an unlocked database ([`threat-model.md`](./threat-model.md)
T-18), so a prompt would cost every fill a second step without keeping
anything from a process that skips the extension. What URL matching adds
is for the user's own clicks: a login goes only to a page on the host its
entry names, so a look-alike domain gets nothing.

### 5.6 Unlocking from the popup

Picking `Unlock <database>` sends an `unlock` request. The popup closes as
the prompt takes the focus, and the extension's background keeps the
request open until kpa answers. kpa runs the unlock's four steps
([`design.md`](./design.md) § Unlocking) with the fill's gate read after
the unlock's token is taken, and asks on screen:
`Unlock database work to find a login for example.com?`. Its prompt data
is `{"v":1,"database":"work","site":"example.com"}`, `site` being the
page's host, escaped as every string of the prompt data is. Opening the
popup again lists that database's matches.

The prompt ends as any unlock prompt does: answered, after
`prompt_timeout`, or by a lock. `unlock_in_progress` comes before the gate,
as for `control`'s `unlock`.

### 5.7 Activity, lock and the log

- A fill counts as activity for its database once answered, as `copy`
  does. A `logins` request doesn't, so opening the popup on page after
  page keeps no database unlocked.
- kpa keeps nothing per fill, so a lock has nothing of the browser front
  end's to end but an unlock prompt.
- A fill is logged at `info` as a copy is: the fields, the entry's title
  and the database. The site isn't logged, since it would put the entry's
  URL in the log ([`design.md`](./design.md) § Secrets). `logins` is a read
  and isn't logged; an unlock is logged as every unlock is.

## 6. The extension

### 6.1 What runs where

An extension is several parts, each run by the browser in a place of its
own, which talk to each other by messages:

```
toolbar button ─▶ popup
                    │ extension messages
                  background ─── scripting.executeScript ──▶ find and fill scripts
                    │ native messaging: stdin and stdout     (in the tab's page,
                  kpa-browser-host                            isolated world)
                    │ $XDG_RUNTIME_DIR/kpa/browser
                  kpa serve: frontends::browser
```

- **The popup** is the small window the browser opens under the
  extension's toolbar button: a page of the extension's own, drawn by the
  browser over the tab and out of the page's reach. It lists the logins
  and takes the pick, and it closes as soon as it loses the focus.
- **The background** is the extension's script with no window (a service
  worker in Chromium, an event page in Firefox), which the browser starts
  when the popup sends it a message and stops once it is idle. It is the
  one part that talks to kpa: it reads the tab's origin from the browser,
  opens a native messaging connection for each request, which starts the
  host, and closes it once answered. It also injects the scripts. A
  request outlives the popup there, as an unlock must once kpa's prompt
  takes the focus.
- **The find and fill scripts** run in the page the tab shows, in the
  extension's isolated world: they see and change the page's document,
  its fields included, but their JavaScript is apart from the page's, so
  the page's scripts can't see or call them, or read the values the fill
  script is handed before it writes them. Both share the page's isolated
  world, so the fill script finds the fields the find script outlined.
  They reach the frames of the same origin through the page's document;
  they aren't injected into every frame, since Chromium fails the whole
  injection when one frame is of an origin the extension can't reach.
- **`kpa-browser-host`** is the native messaging host: the program the
  browser starts for the extension and talks to over its stdin and
  stdout, which relays each request to the browser socket (§ 7).

One fill, from end to end:

1. The user clicks the toolbar button. The browser opens the popup and
   grants the extension the tab (§ 6.2).
2. The popup asks the background for the tab's logins. The background
   reads the tab's URL from the browser, sends kpa a `logins` request for
   its origin, and the popup lists what kpa answers.
3. If kpa matched a login, the background injects the find script, which
   outlines the fields it finds (§ 5.2, § 5.3) and returns their kinds.
   The popup says what each login fills.
4. The user picks a login. The background sends kpa a `fill` request for
   that entry and those kinds, and injects the fill script with kpa's
   answer, which writes each value into its field (§ 5.4). The popup
   closes once every value is written.

The extension stores nothing: no settings, no cache, no logins.

### 6.2 Permissions

`activeTab`, `scripting` and `nativeMessaging`, and no host permissions.
`activeTab` grants the tab the user opened the popup on: the page it shows
and that page's frames of the same origin, until the tab moves to another
page. Frames of another origin would need a host permission for each
site, which kpa doesn't ask for. Of the three, only `nativeMessaging`
shows a warning when installing.

### 6.3 Browser versions

Chromium 121 and Firefox 140. Chromium 121 is the first in which every
asynchronous extension API returns a promise, as Firefox's do, so one
script calls the same `chrome.*` APIs in both. Firefox 140 is the
first to show an extension's data collection declaration
(`data_collection_permissions`, declared as none), which
addons.mozilla.org asks of every new extension.

### 6.4 The code

One source tree serves both browsers: the same scripts and popup, calling
APIs both browsers have. Only the manifest differs, in the keys one
browser reads and the other warns about. Chromium's names the background
as a service worker and carries the `key` that fixes its id; Firefox's
names the background's script and carries `browser_specific_settings`
(its id, its oldest version and its data collection, none).
`extension/manifest.json` holds the rest, and packaging adds each
browser's keys (§ 9.2).

Plain JavaScript, with no libraries, no bundler and no minification: what
is reviewed is what ships, and a Firefox package needs no source archive
to be signed.

## 7. The host and the browser socket

### 7.1 Starting the host

The browser starts the program a host manifest names, only for the
extension the manifest allows (§ 9.1), with arguments of its own: the
extension's origin in Chromium, the manifest's path and the extension's
id in Firefox. A manifest can't add arguments of its own, so the host
can't be a `kpa` subcommand, whose parser would refuse the browser's. It
is a second binary of kpa's one Cargo package, `kpa-browser-host`:
`src/bin/kpa-browser-host.rs` beside `src/main.rs`, both built on the
`kpa` library, so one build and one package carry both. It takes no
arguments of its own and ignores the browser's, since any process of the
user could start it with any.

Like every kpa process, it forbids its own core dumps before anything
else. It exits when the browser closes its stdin.

### 7.2 Relaying

Native messaging frames are a 32-bit length in the machine's byte order
and that many bytes of UTF-8 JSON. The host relays without reading the
JSON:

- each frame from the browser goes as one line on a new connection to the
  browser socket, and the line kpa answers goes back as one frame;
- a frame over 64 KiB, the socket's request cap, is refused without a
  connection;
- with no socket to connect to, the host answers itself, with
  `daemon_unreachable`, so the extension can tell a missing daemon from a
  missing host;
- the buffers that held an answer are zeroized.

### 7.3 The socket

`$XDG_RUNTIME_DIR/kpa/browser`, bound and checked like the control socket
([`protocol.md`](./protocol.md) § Connections): mode 0600, only the
daemon's uid, line-delimited JSON, one request and one response per
connection, a request line capped at 64 KiB. Its path is fixed, so the
host finds it with no config. It exists unless every database sets
`serve_logins = false`, and failing to bind it stops `kpa serve`, as the
agent's socket does.

It is a socket and a front end of its own, not more `control` ops, for two
reasons:

- **It is all the extension can reach.** The host relays without reading
  (§ 7.2), so whatever the socket answers, the extension can ask: on the
  browser socket, a site's logins, a fill and an unlock. On `control` it
  could also ask for `list`, every entry's title and username, those of
  databases that opt out included, and `ssh_approve`. The extension can't
  open a socket itself, so what this socket speaks bounds what the
  extension can do, even one a page has taken over. On one socket the
  daemon couldn't bound it, since kpa can't tell the host's connections
  from the CLI's ([`threat-model.md`](./threat-model.md) NG-1).
- **It has a version of its own.** `control` refuses a request of another
  version ([`protocol.md`](./protocol.md) § Version), which suits a CLI
  installed with its daemon. The extension updates apart from kpa
  (§ 9.2), in a browser that stays open for days, so on `control` every
  change to that protocol would stop filling until the extension caught
  up.

### 7.4 The protocol

Every request carries `v` and `op`, and every answer `v` and `ok`, as on
the control socket.

| Request | Carries | Answer |
| --- | --- | --- |
| `logins` | `origin` | `logins`: per match its `db`, `uuid`, `title` and `username` (each left out when protected or empty) and `has`, which of `username`, `password` and `totp` it has; `locked`: the locked databases that serve logins |
| `fill` | `origin`, `db`, `uuid`, `fields`: some of `username`, `password`, `totp` | `values`: each asked field's value, `totp` being the current code |
| `unlock` | `origin`, `db` | once the database is unlocked |

`fill` checks again that the entry is offered for the origin (§ 4.4). Its
answer is serialized into a zeroizing buffer of exactly its size, as the
control socket's are. A database whose file changed since its unlock is
locked by the read, as everywhere ([`design.md`](./design.md) § Files and
freshness): `logins` lists it under `locked`, and `fill` answers `stale`.

Errors use `protocol.md`'s codes: `version_mismatch`, `malformed_request`
(an origin that isn't `http` or `https` included), `no_display`,
`unknown_db` (a database that opts out included), `locked`, `stale`,
`not_found` (no such entry, or it isn't offered for the origin),
`field_empty`, `unlock_in_progress`, `prompt_cancelled` and
`wrong_credentials`, and two of their own: `too_large`, an answer over the
1 MiB a browser takes from a host, and the host's `daemon_unreachable`
(§ 7.2).

**The version.** `v` is this protocol's own, starting at 1. The extension
and kpa update separately, so a request with another `v` is answered with
the one kpa speaks, and the popup says which side to update.

## 8. Configuration

| Setting | Where | Default | Meaning |
| --- | --- | --- | --- |
| `serve_logins` | `[[database]]` | `true` | Offer and fill this database's logins in the browser |

```toml
[[database]]
name = "personal"
path = "~/vaults/personal.kdbx"

[[database]]
name = "work"
path = "~/vaults/work.kdbx"
serve_logins = false        # never offered or filled in a browser
```

An unknown key in `[[database]]` is a config error naming it: a misspelt
`serve_logins` would otherwise serve the database it was meant to keep
out.

## 9. Installing

### 9.1 What is installed

Per user:

1. **The extension**, in each browser profile (§ 9.2).
2. **A host manifest**, `kpa.json`, in each browser's directory for them:
   `~/.mozilla/native-messaging-hosts/` for Firefox,
   `~/.config/chromium/NativeMessagingHosts/` for Chromium, and each
   other Chromium-based browser's own (`~/.config/google-chrome/`,
   `~/.config/BraveSoftware/Brave-Browser/`, …). It names
   `kpa-browser-host` by absolute path and the extension that may start
   it, by id:

```json
{"name": "kpa", "description": "kpa", "type": "stdio",
 "path": "/path/to/kpa-browser-host",
 "allowed_origins": ["chrome-extension://<id>/"]}
```

   Firefox's has `allowed_extensions` with the extension's id instead of
   `allowed_origins`.

The user doesn't write the manifests: the home-manager module does
(§ 9.3), `kpa browser register` does without it (§ 9.4), and a browser
package that takes a list of native messaging hosts finds them in kpa's
package (§ 9.3).

### 9.2 The extension's packages

The extension's version is kpa's, and each release builds two packages:

- **Chromium-based browsers** load the extension unpacked, with the
  browser's developer mode on. Its manifest carries a fixed public `key`,
  which fixes its id, so the host manifest can name it. The release
  attaches the directory as a zip.
- **Firefox** keeps only extensions Mozilla has signed. The release
  workflow has each version signed through addons.mozilla.org's unlisted
  channel, which signs without listing or review, and attaches the
  signed `.xpi`. Its manifest carries a fixed `gecko.id`. A build between
  releases is unsigned: Firefox loads it as a temporary add-on, or keeps
  it in the Developer Edition, Nightly and ESR builds with signature
  checks turned off.

The extension doesn't update itself: a new kpa release comes with new
packages to install, and until then the popup reports a version mismatch
if the protocol changed. A Firefox package that fetched each release's
update on its own would run ahead of a kpa its user has pinned.

### 9.3 The home-manager module

`services.kpa.browsers` lists the browsers to write host manifests for
(`"firefox"`, `"chromium"`, `"google-chrome"`, `"brave"`, `"vivaldi"`),
none by default. The module also puts the unpacked Chromium extension in a
directory at a stable path, `$XDG_DATA_HOME/kpa/browser-extension`, the
one to load, so an upgrade reaches the browser at its next start.
Installing the extension in a profile is the user's step.

The package also carries the manifests at `etc/chromium/native-messaging-hosts/`
and `lib/mozilla/native-messaging-hosts/`, where browser packages that
take a list of native messaging hosts look for them.

### 9.4 Without home-manager

`kpa browser register` writes `kpa.json` into the manifest directory of
each browser § 9.3 lists whose own configuration directory exists, and
says which it wrote. It names `kpa-browser-host` by the path it is found
at on `PATH`, without following links: a Nix profile's
`bin/kpa-browser-host` is a link that outlives an upgrade, while the store
path behind it can go at the next garbage collection. A manifest already
as it would write it is left alone, so it can run again after kpa moves.

### 9.5 Sandboxed browsers

A Flatpak or Snap browser can start a native host only inside its sandbox,
where kpa's socket isn't reachable, so its extension reports kpa as not
installed. kpa doesn't support them.

### 9.6 Day to day

| Action | What happens |
| --- | --- |
| Opening the popup on a site's login page | It lists the site's logins from the unlocked databases, and an `Unlock` line per locked one. The fields a pick would fill are outlined, and each login says which it fills |
| Opening the popup on a page kpa reads wrong | The outlines are on the wrong fields, or missing: the user closes the popup and uses `kpa pick` instead |
| Picking a login | Its username and password are filled. The user submits the form |
| Picking a login on a username-only page | The username is filled; on the password page, a second pick fills the password |
| Picking a login on a page asking for a code | The current TOTP code is filled |
| Picking `Unlock work` | kpa asks `Unlock database work to find a login for example.com?`; opening the popup again lists its logins |
| A site with no login in kpa | The popup says so |
| An `http` page of a site saved as `https` | No login is offered |
| Screen locked, or the browser outside the desktop | The popup says kpa can't fill here |

## 10. Claims

What this design claims and what it accepts, in the terms of
[`threat-model.md`](./threat-model.md), which doesn't carry them yet.

**The boundaries.** kpa's browser socket, whose untrusted side is every
process of the user: the host a browser starts, and anything else running
as the user. And the page, whose untrusted side is everything it can do to
the fields the extension reads and fills.

**Claims**

- **Read-only holds** (G-1). No request writes a database, and kpa writes
  no file for the browser.
- **Secrets leave by a second route** (G-3): a `fill` answer on the
  browser socket, carrying only the fields the request names (username,
  password, the current TOTP code; never notes, other fields, attachments
  or the TOTP seed), of an entry offered for the origin the request
  claims, in a database that doesn't opt out, for a requester on the
  desktop while the display session is active and unlocked. No other
  response on any socket carries a secret.
- **A page gets only what is filled into it**, after a pick on its own tab.
  It can't start a fill or list logins, and can't tell the extension is
  installed before the popup is opened on its tab. A login is filled only
  into the fields outlined before the pick, in a frame of the origin kpa
  matched, never into a field the user can't see, and never submitted.
- **A login goes only to the hosts its entry names**, for fills the
  extension makes (§ 4.3): a look-alike domain, a parent domain and an
  `http` page of an `https` site get nothing.
- **No prompt where nobody can see it** (G-12). An unlock from the popup is
  asked on screen only, for a requester on the desktop while the display
  session is active and unlocked.
- **A lock ends it** (G-5, G-6). kpa keeps nothing per fill; a lock ends an
  unlock prompt in flight. The answer's buffers in kpa and in the host are
  zeroized.
- **Nothing persisted** (G-4). The extension stores nothing, and a fill's
  log line names the entry and fields, never the site.
- **The socket's input is only data** (G-11). Requests are bounded, a
  malformed or flooding client is refused without crashing the daemon, and
  the decoder and the host's frame reader are fuzzed.
- **Entry content is only data** (G-10). Titles and usernames are shown as
  text in the popup, and entry URLs are parsed for matching, never fetched
  or shown.

**Accepted**

- **Any process of the user can reach the socket and fill any login, for
  any origin it claims** (NG-1, T-18), as it can `copy` it. Matching keeps
  the user's own clicks from filling the wrong site; it is not a boundary
  inside the uid.
- **The origin is the browser's word**, passed on by the extension. The
  popup shows the logins kpa matched for it.
- **The extension is trusted inside the browser.** It sees the logins it
  lists and the values it fills. A compromised extension gets those for
  the tabs it is opened on.
- **What the page does with a filled value** (NG-5). A page on a host an
  entry covers gets that entry's values when the user picks it there:
  through a flaw in the site, or content of someone else's on a subdomain
  the entry's URL covers.
- **Whoever writes entries in a served database can add a login** (ACT-4).
  An entry planted with a site's URL, or with a public suffix as its URL,
  shows up under the title its author chose. Filling it gives the page
  its author's values, nothing of the user's.
- **The browser holds what it is given.** The values pass through the
  extension's JavaScript, which can't zeroize them, and the page's fields.

## 11. Code

One new front end, a read on the core, a second binary and the extension.

| Subsystem | Is | Uses |
| --- | --- | --- |
| `frontends::browser` | the browser socket and its protocol, matching entries to an origin, the listing, the fill and the unlock from the popup, the host's relay, and `kpa browser register` | `databases`, `authn`, `authz`, `prompt`, `display_session`, `socket`, `config`, `paths` |

```
src/
  bin/kpa-browser-host.rs   hardening, then the host's relay
  frontends/browser/
    mod.rs              the socket: one connection, one request; its path
    proto.rs            requests and answers
    origin.rs           the page's origin
    matching.rs         an entry's URLs against an origin, and their order
    logins.rs           the listing
    fill.rs             the fill, and its gate
    unlock.rs           the unlock from the popup, and its message
    host.rs             kpa-browser-host: frames in and out, one connection each
    register.rs         kpa browser register: the manifests and their directories
extension/
  manifest.json         what both browsers read
  manifest.chromium.json, manifest.firefox.json
                        the keys one browser reads alone, added at packaging
  background.js         native ports, the tab's origin, injecting the scripts
  popup.html, popup.js  the list of logins
  find.js, fill.js      finding and outlining the fields, and filling them
```

- **`databases`** gains one read on `Open`: the entries offered to a
  browser (outside the recycle bin, not marked `BrowserHideEntry`), each
  with its URLs, title, username and which of username, password and TOTP
  it has. The recycle bin and custom data are the core's to know, as no
  `keepass` type leaves it.
- **`config`** gains `serve_logins`, and `[[database]]` refuses unknown
  keys.
- **The hardening call** moves from `main.rs` into the library, so both
  binaries make it first.
- **`prompt`'s data** gains `site`.
- **Portability.** The socket, the host and the extension are OS-neutral.
  Who is asking goes through the request-origin seam
  ([`portability.md`](./portability.md)); the socket's path comes from
  `paths`. On macOS, host manifests have other directories and the same
  code serves Chromium and Firefox there.
- **Dependencies.** `url`, for parsing entry URLs and putting hosts in
  their ASCII form. The extension has none.

**Testing**

- **Matching** alone: the rule's table (§ 4.3), scheme-less values,
  ignored schemes, IP addresses, IDN hosts, `KP2A_URL` fields, the hide
  mark on an entry and on a group, the recycle bin, and the order.
- **The front end** against a real `Databases`, with scripted prompts,
  through its socket: the gate, a database that opts out, a fill asking
  for a field the entry lacks, an entry that stops matching, a changed
  file, a version mismatch. The races are tests: a lock while the unlock
  prompt is up, the display session locking mid-request.
- **The host**: frames in and out against a socket, an oversized frame,
  no daemon, stdin closed mid-request.
- **Registering**: against a scratch home with some browsers' directories,
  the manifests written, a link on `PATH` kept as a link, and a second run
  that changes nothing.
- **Fuzzing**: the socket's requests and the host's frame reader.
- **The extension**: Node's own test runner for the background's protocol
  and the popup's states.
- **Finding the fields**, in the end-to-end test's browsers, which lay
  pages out as a user's would: a set of test pages, each a form of a shape
  § 5.2 names or turns down (a sign-up form beside a login form, a
  change-password form, a search box, a newsletter box, a hidden form, a
  field covered by another element, fields in a shadow root, a postal code
  field on a code page), with the fields each must find.
- **End to end**: a NixOS VM test in the flake's `checks` runs Chromium
  and Firefox with the extension against test pages served in the VM (a
  login form, a username page then a password page, a code page with one
  field and with a row of digit fields, a same-origin frame, a frame of
  another origin, an `http` page for an `https` entry) and a real
  `kpa serve`, and checks what each field holds. A toolbar click can't be
  scripted, so the test grants the tab's access itself and drives the
  background's pick from there.

## Sources

- [Native messaging (MDN)](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
- [Native messaging (Chrome)](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
- [`activeTab` (Chrome)](https://developer.chrome.com/docs/extensions/develop/concepts/activeTab)
- [Signing and distributing an add-on (Firefox Extension Workshop)](https://extensionworkshop.com/documentation/publish/signing-and-distribution-overview/)
- [DOM-based extension clickjacking (Marek Tóth, 2025)](https://marektoth.com/blog/dom-based-extension-clickjacking/)

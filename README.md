# Rd — Remote Desktop (RDP) client for Plan 9

**Rd** is a remote desktop client for the **Plan 9** operating system family. It implements **Microsoft Remote Desktop Protocol (RDP)** and lets you interact with a remote graphical desktop by:

- decoding server “update” PDUs (screen drawing operations) and rendering them locally
- capturing local input (keyboard/mouse) and forwarding it to the server

Rd is written in C and is packaged as a single executable (`rd`) built from a set of small protocol/UI modules.

![Screenshot](https://repository-images.githubusercontent.com/1048642731/0b819f74-9069-4ece-b70a-1f88e288a6a9)

---

## Supported Plan 9 systems

Rd targets both:

- **Plan 9 from Bell Labs, 4th Edition** (the “9legacy” line), and
- **9front**

The build system resolves platform distinctions automatically in the `mkfile` based on the build host environment.

---

## Protocol and security notes

- Rd targets **RDP5-era and newer** servers and does **not** support pre‑RDP5 versions.
- The server must support an upgrade equivalent to **STARTTLS** (Windows XP SP2 / Windows Server 2003 and newer).
- Server X.509 certificates are verified by `okThumbprint` against the thumbprint list in:

  - `/sys/lib/tls/rdp`

---

## Building and installing

Rd follows the conventional Plan 9 build workflow:

- Build (for the current host architecture):

  ```
  mk
  ```

- Install (for the current host architecture):

  ```
  mk install
  ```

- Build and install for all supported architectures:

  ```
  mk installall
  ```

---

## Usage

```
rd [-0A] [-T title] [-a depth] [-c wdir] [-d dom] [-k keyspec] [-s shell] [net!]server[!port]
```

Rd takes exactly **one non-optional argument**: a **server connection string**.

### Connection string format

The simplest form is just a server name:

- `server`

The connection string can also include a specific Plan 9 network stack (instead of the default `/net/tcp`) and an explicit port:

- `[net!]server[!port]`

Examples:

- `windows.example.com`
- `tcp!windows.example.com!3389`

### Options

- `-k keyspec`  
  Adds extra attributes to the **factotum** key query used to obtain credentials (the attributes are appended to the query passed to `auth_getuserpasswd`).

- `-d dom`  
  Specifies a **Windows domain name** to authenticate against (for domain logons).

- `-A`  
  Disables factotum-based “auto logon”. With `-A`, Rd requests the server to present an interactive **logon screen** instead, and credentials are entered and validated inside the remote GUI session. At that stage, credential submission occurs over an **encrypted channel**.

- `-T title`  
  Customizes the local window label. By default it is:

  - `rd <hostname>`

- `-a depth`  
  Select an alternative **image depth** (bits per pixel). The default is **24** (“full color”).

- `-s shell`  
  Requests a specific **logon shell** (remote session startup program).

- `-c wdir`  
  Requests a specific remote **working directory**.

- `-0`  
  Requests attaching to the server’s **console session** (if supported by the server/negotiation).

---

## High-level architecture (for readers of the code)

A quick overview of the runtime flow and the major modules.

### 1) Entry point and session state

- The program starts in `rd.c` (`main()`).
- A single `Rdp` struct (declared in `dat.h`) represents the session: network fd, negotiated protocol state, screen parameters, authentication fields, and extension/virtual-channel state.

### 2) Connection and handshake pipeline

Connection setup follows a staged pipeline:

1. Parse command-line options (title, depth, domain, shell override, working directory, console attach).
2. Optionally obtain credentials from factotum.
3. `dial()` the server (default TCP port 3389).
4. Perform **X.224** transport/session handshake.
5. Initialize the local screen/window.
6. Perform the main **RDP handshake** (negotiation/capabilities/licensing/activation).

### 3) Concurrency model: network loop + local input helpers

After handshaking, Rd runs:

- A **main network loop** that repeatedly:
  - reads and parses protocol messages (`readmsg`)
  - dispatches them through a session state machine (`apply`)
- Helper processes created with `rfork(RFPROC|RFMEM)` to read local devices:
  - mouse input (`/dev/mouse`)
  - keyboard input (`/dev/cons`, raw mode via `/dev/consctl`)
  - clipboard/snarf integration (“snarf” polling)

The helpers forward local events to the server while the main process handles incoming updates and rendering.

### 4) Message parsing, updates, and rendering

Incoming data is modeled as `Msg` structures (`dat.h`) covering:
- X.224 and MCS control PDUs for setup/activation
- licensing messages
- input events
- server “update” PDUs (screen updates)
- virtual channel traffic

Server updates are decoded into higher-level update structures (image updates, palette/colormap updates, pointer warp, etc.) and then rendered via the Plan 9 drawing subsystem.

### 5) Virtual channels (extensions)

Rd includes a virtual-channel abstraction (`Vchan`) that:
- maps named channels to handler callbacks
- buffers/defragments channel fragments
- supports features such as clipboard/snarf synchronization
- provides hooks for extensions such as audio and device-redirection-style messages

---

## Repository layout (selected files)

**Start here:**

- `rd.c` — program entry point, handshake pipeline, network loop, local input helpers
- `dat.h` — session (`Rdp`) and protocol/message model (`Msg`, update structures, virtual channels)
- `mkfile` — build rules and object list

**Protocol and transport:**

- `x224.c` — X.224 connection setup/teardown and TPDU framing (transport/session layer)
- `mcs.c` — MCS (T.12x) connection/channel management helpers
- `mpas.c` — core RDP “share control/data” PDU helpers (control flow, security header sizing, transmit prep)
- `msg.c` — message encode/decode (`readmsg`/`writemsg`) and typed `Msg` marshalling
- `cap.c` — capability parsing/serialization used during negotiation

**Security:**

- `tls.c` / `tls9f.c` — TLS support and certificate/thumbprint verification glue (build selects the appropriate file)

**Rendering and graphics updates:**

- `draw.c` — apply server drawing orders/bitmap updates to the local Plan 9 window
- `load.c` — bitmap/cache loading helpers used by update decoding
- `rle.c` — RLE decompression used for bitmap/update payloads
- `mppc.c` — MPPC decompression used for compressed update payloads
- `eclip.c` — clipping/region helpers for drawing operations

**Input and window integration:**

- `mouse.c` — mouse event encoding and client-to-server forwarding (and pointer warp support)
- `kbd.c` — keyboard event encoding and client-to-server forwarding
- `wsys.c` — window-system integration helpers (resizes, window events, etc.)

**Virtual channels and extensions:**

- `vchan.c` — virtual channel table setup, fragmentation/defragmentation, and send/dispatch support
- `rpc.c` — higher-level request/response helpers used by some channel-style interactions
- `audio.c` — audio virtual channel handling and client-side playback hooks
- `efs.c` — extension/virtual channel support for device-redirection-style messages (see `Efsmsg` in `dat.h`)

**Utilities and tests:**

- `alloc.c` — allocation helpers (`emalloc`/`erealloc`)
- `utf16.c` — UTF‑16 conversion helpers used by several protocol fields
- `aud_test.c` — audio-related tests
- `efs_test.c` — tests for EFS/extension encoding/decoding
- `msg_test.c` — message parsing/encoding tests

**Headers:**

- `fns.h` — shared internal function declarations across modules

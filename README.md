# AppleUtils

Terminal toolkit for Apple device recovery and APFS work.

Recovery waits for a device and restores it. Explorer browses APFS volumes.
Repair analyses and applies fixes. Asahi creates, installs, and updates
[Asahi Linux](https://asahilinux.org/) discs.

## Requirements

Latest stable Rust. The toolkit is Unix: it builds and runs on macOS and Linux.
Recovery talks to a local Unix-domain restore bridge. Asahi `--latest` /
`--package` downloads use `curl`, and extracting the official installer archive
uses `tar`.

Optional: the [`ipsw`](https://github.com/blacktop/ipsw) command (for example
`brew install blacktop/tap/ipsw`). With it installed, Recovery accepts an `.ipsw`
wherever it asks for a restore folder. The archive's file tree is indexed in
memory and only the files a restore needs are written to a private temp
directory, when the manifest asks for them. macOS `.aea` images are decrypted
there with `ipsw fw aea`, and the directory is removed when the session ends.
Without `ipsw`, extract the IPSW and hand over the folder as before.

Apple's `fsck_apfs` is used only in CI on macOS. It is not required to build or
run the toolkit. APFS and FAT image work is done in-process.

## TUI

```
cargo run
```

Starts the picker. From there: Recovery, APFS Explorer, APFS Repair, Asahi
Linux tooling, or IPSW Export.

IPSW Export appears only when the optional `ipsw` command is installed (see
Requirements). Pick an `.ipsw`, then browse its file tree: space selects a file
or a whole folder, `/` filters, and the options pane picks what happens on the
way out. `.aea` images are decrypted (with your own AEA key, or the one `ipsw`
fetches from Apple), IM4P payloads are decompressed, and `ipsw extract`
components such as the kernelcache or dyld shared cache can be added to the
export. Press `e` and choose an output folder (the default is `<archive>-export`
next to the archive); files are streamed out of the archive with their
checksums verified. Everything temporary is cleaned up
automatically, including when you cancel or quit mid-export.

## CLI

Use `cargo run -- <command>` while developing.

### Asahi

Create, install, update, and validate [Asahi Linux](https://asahilinux.org/) discs.

Flavour metadata comes from the upstream
[asahi-installer-data](https://github.com/AsahiLinux/asahi-installer-data) feed and
artefacts are downloaded from `cdn.asahilinux.org`. AppleUtils is an independent
tool and is not affiliated with or endorsed by the
[Asahi Linux project](https://asahilinux.org/).

Generated discs use 4096-byte GPT logical blocks and a matching FAT32 EFI
partition for Apple ANS storage. The minimum image size is 8 GiB. APFS and FAT
are written and checked in-process; validation does not call host filesystem
tools.

`--m1n1` is the EFI stage-two image. Stage one comes from the official Asahi installer archive, which builds m1n1 with chainloading support. Use `--stage1 FILE` to supply that raw image offline. OS packages retain all `esp/` files and their separate boot image. Updates preserve the installed root filesystem unless a root payload is requested, and regular image files are replaced only after the staged update validates.

```
apple-utils asahi flavors [--metadata FILE]
apple-utils asahi create --output DISC.qcow2 --latest [--os FLAVOR] [--size 32G] [--workdir DIR]
apple-utils asahi create --output DISC.qcow2 --package ZIP [--os FLAVOR] [--size 32G] [--workdir DIR]
apple-utils asahi create --output DISC.qcow2 --kernel FILE --m1n1 FILE --root FILE [--size 8G]
apple-utils asahi install --output DEST --latest [--os FLAVOR] [--size 32G]
apple-utils asahi install --output DEST --kernel FILE --m1n1 FILE --root FILE [--size 8G]
apple-utils asahi update DISC.qcow2 --kernel FILE --m1n1 FILE [--root FILE]
apple-utils asahi validate DISC.qcow2
```

### Explorer

Open an APFS image, then list, stat, extract, or insert files.

```
apple-utils explorer IMAGE
apple-utils explorer IMAGE --list PATH
apple-utils explorer IMAGE --stat PATH
apple-utils explorer IMAGE --extract PATH [--out DEST]
apple-utils explorer IMAGE --insert HOST [--at DIR] [--volume NAME]
```

### Repair

Sweep an APFS image for problems, then apply repairs by id or interactively.

```
apple-utils repair IMAGE
apple-utils repair IMAGE --dump
apple-utils repair IMAGE --apply ID
apple-utils repair IMAGE --apply all
apple-utils repair IMAGE --interactive
```

Licensed under [MIT](LICENSE).

<div align="center">

<a href="https://www.buymeacoffee.com/seggy116"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-violet.png" alt="Buy me a coffee" height="50" /></a>

</div>

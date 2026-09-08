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

Apple's `fsck_apfs` is used only in CI on macOS. It is not required to build or
run the toolkit. APFS and FAT image work is done in-process.

## TUI

```
cargo run
```

Starts the picker. From there: Recovery, APFS Explorer, APFS Repair, or Asahi
Linux tooling.

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

Images with 512-byte GPT logical blocks must be regenerated; inspection can still read them, but validation and updates reject them before mutation. Images made by the former synthetic APFS writer must also be regenerated. Repair now reports their container-structure failure; changing header fields alone cannot reconstruct missing allocation and checkpoint metadata.

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

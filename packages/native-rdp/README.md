# Native ARM RDP package inputs

Prepared on 2026-09-05. These are reviewed AUR recipes. The xrdp recipe disables optional imlib2 login-screen artwork after four image-scaling checks failed against the installed library; all 213 upstream checks passed with built-in BMP support. H.264 and RemoteFX remain enabled. The xorgxrdp recipe is unmodified. Build as an unprivileged user with `makepkg`; never use
`make install` against the live root. Review the installation transaction before
using pacman. The migration handoff defines the approval and acceptance gates.

- xrdp recipe: https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=xrdp
- xrdp patch: https://aur.archlinux.org/cgit/aur.git/plain/arch-config.diff?h=xrdp
- xrdp install hook: https://aur.archlinux.org/cgit/aur.git/plain/xrdp.install?h=xrdp
- xorgxrdp recipe: https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=xorgxrdp

The xrdp 0.10.6.1 source SHA-256 is
`2f7beb5a3b2529c8d72dc0df9b8cdca31ab0e0c14d1e3421210f5e6ec0ab3b75`.
The xorgxrdp 0.10.5 source SHA-256 is
`a5d03435f0ef48bf3d5010e63d9264f2334e7063cba3ecd8d4c0a15616a4f712`.
Both downloaded archives match the recipe checksums. The xorgxrdp detached
signature verifies against the recipe's pinned primary key
`61ECEABBF2BB40E3A35DF30A9F72CDBC01BF10EB`, signing subkey
`18AB838A907167745914871903993B4065E7193B`.

The recipes enable software x264 in xrdp and leave xorgxrdp glamor disabled.
Native ARM builds and package inspection completed. The configured xrdp suite
passed 213 tests; xorgxrdp loaded in a real Xorg session. Windows App negotiated
software H.264. Package outputs, logs and `.BUILDINFO` are preserved in the
private evidence locations listed in the migration handoff. Full client and
migration acceptance remains incomplete.

#!/bin/sh
# Install a published XCertM release on Linux or Synology DSM.
set -eu
umask 077

die() { printf 'xcertm installer: %s\n' "$*" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage: install.sh [--version vMAJOR.MINOR.PATCH] [--bin-dir DIRECTORY]'
}

version=
bin_dir=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --version|--bin-dir)
            option=$1
            if [ "$#" -lt 2 ]; then die "missing value for $option"; fi
            [ -n "$2" ] || die "missing value for $option"
            case "$option" in
                --version) version=$2 ;;
                --bin-dir) bin_dir=$2 ;;
            esac
            shift 2
            ;;
        --help|-h) usage; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

for tool in curl uname id tar sha256sum mktemp mkdir chmod mv rm rmdir cat awk grep stat; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done
[ "$(uname -s)" = Linux ] || die 'only Linux and Synology DSM are supported'
case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    i386|i486|i586|i686) arch=386 ;;
    aarch64|arm64) arch=arm64 ;;
    armv7l|armv7hl|armv8l) arch=armv7 ;;
    *) die "unsupported architecture: $(uname -m)" ;;
esac
environment=Linux
if [ -f /etc.defaults/VERSION ] && [ -f /etc/synoinfo.conf ]; then
    environment='Synology DSM'
fi
uid=$(id -u)
root_uid=$(stat -c '%u' /)
if [ -z "$bin_dir" ]; then
    if [ "$uid" = 0 ]; then
        bin_dir=/usr/local/bin
    else
        [ -n "${HOME:-}" ] || die 'HOME is unset; specify --bin-dir'
        bin_dir=$HOME/.local/bin
    fi
fi
case "$bin_dir" in /*) ;; *) die '--bin-dir must be an absolute path' ;; esac

download() {
    curl --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 \
        --max-filesize 67108864 --fail --location --silent --show-error "$@"
}
repository=https://github.com/kernaxis/xcertm
if [ -z "$version" ]; then
    latest=$(download --head --output /dev/null --write-out '%{url_effective}' "$repository/releases/latest") ||
        die 'no published stable release could be found'
    case "$latest" in
        "$repository"/releases/tag/*) version=${latest##*/} ;;
        *) die 'no published stable release could be found' ;;
    esac
fi
printf '%s\n' "$version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' ||
    die 'expected a stable version such as v0.1.0'

# Reject unsafe existing ancestors before creating directories through them.
check_directory() {
    directory=$1
    while :; do
        [ ! -L "$directory" ] || die "symlink in installation path: $directory"
        if [ -e "$directory" ]; then
            [ -d "$directory" ] || die "not a directory: $directory"
            owner=$(stat -c '%u' "$directory")
            mode=$(stat -c '%a' "$directory")
            [ "$owner" = "$root_uid" ] || [ "$owner" = "$uid" ] || die "unsafe directory owner: $directory"
            # A sticky ancestor such as /tmp protects owned child directories.
            [ "$((0$mode & 0022))" -eq 0 ] || [ "$((0$mode & 01000))" -ne 0 ] ||
                die "group/world writable directory: $directory"
        fi
        [ "$directory" != / ] || break
        directory=${directory%/*}
        [ -n "$directory" ] || directory=/
    done
}
case "$bin_dir/" in */../*|*/./*|*//* ) die '--bin-dir must not contain dot or empty path components' ;; esac
check_directory "$bin_dir"
if [ ! -d "$bin_dir" ]; then
    (umask 022; mkdir -p "$bin_dir")
fi
bin_dir=$(cd "$bin_dir" && pwd -P)
[ "$(stat -c '%u' "$bin_dir")" = "$uid" ] || die 'installation directory must be owned by the executing user; use sudo for a system installation'
binary=$bin_dir/xcertm
if [ -e "$binary" ] || [ -L "$binary" ]; then
    die "already installed at $binary; use '$binary update' (with sudo for a system installation)"
fi
lock=$bin_dir/.xcertm-install.lock
mkdir "$lock" 2>/dev/null || die "another installation may be running ($lock); inspect it before removing a stale lock"
stage=
doc_stage=
cleanup() {
    [ -z "$stage" ] || rm -rf "$stage"
    [ -z "$doc_stage" ] || rm -rf "$doc_stage"
    rmdir "$lock" 2>/dev/null || :
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
stage=$(mktemp -d "$bin_dir/.xcertm-install.XXXXXX")
archive=xcertm_${version#v}_linux_${arch}.tar.gz
printf 'Installing xcertm %s for %s (%s) at %s\n' "$version" "$environment" "$arch" "$binary"
download --output "$stage/$archive" "$repository/releases/download/$version/$archive"
download --output "$stage/SHA256SUMS" "$repository/releases/download/$version/SHA256SUMS"
[ "$(stat -c '%s' "$stage/SHA256SUMS")" -le 65536 ] || die 'checksum manifest is too large'
checksum=$(awk -v name="$archive" '
    NF == 2 && ($2 == name || $2 == "*" name) { count++; hash=$1 }
    END { if (count != 1 || length(hash) != 64) exit 1; print hash }
' "$stage/SHA256SUMS") || die 'missing, invalid or duplicate archive checksum'
case "$checksum" in *[!0123456789abcdefABCDEF]*) die 'invalid SHA-256 checksum' ;; esac
(cd "$stage" && printf '%s  %s\n' "$checksum" "$archive" | sha256sum -c -) || die 'archive SHA-256 verification failed'

# Stream only exact members into private regular files; never unpack archive paths.
tar -tzf "$stage/$archive" > "$stage/members"
for name in xcertm LICENSE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.txt; do
    awk -v name="$name" '$0 == name { count++ } END { exit count != 1 }' "$stage/members" ||
        die "missing or duplicate archive member: $name"
    tar -xOzf "$stage/$archive" "$name" > "$stage/$name"
    [ -s "$stage/$name" ] || die "empty archive member: $name"
done
chmod 0755 "$stage/xcertm"
[ "$("$stage/xcertm" --version)" = "xcertm version $version" ] || die 'replacement binary cannot run or reports an unexpected version'

doc_root=${bin_dir%/*}/share/doc/xcertm
check_directory "$doc_root"
(umask 022; mkdir -p "$doc_root")
doc_dir=$doc_root/$version
if [ -e "$doc_dir" ] || [ -L "$doc_dir" ]; then
    check_directory "$doc_dir"
    for name in LICENSE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.txt; do
        if [ ! -f "$doc_dir/$name" ] || [ -L "$doc_dir/$name" ]; then
            die 'invalid existing release notices'
        fi
        [ "$(sha256sum < "$doc_dir/$name")" = "$(sha256sum < "$stage/$name")" ] || die 'existing release notices differ'
    done
else
    # Documentation can reside on a different filesystem from the binary.
    doc_stage=$(mktemp -d "$doc_root/.notices.XXXXXX")
    for name in LICENSE THIRD_PARTY_NOTICES.md THIRD_PARTY_LICENSES.txt; do
        cat "$stage/$name" > "$doc_stage/$name"
        chmod 0644 "$doc_stage/$name"
    done
    chmod 0755 "$doc_stage"
    mv "$doc_stage" "$doc_dir"
fi
if [ -e "$binary" ] || [ -L "$binary" ]; then
    die 'installation target appeared during installation; refusing to overwrite it'
fi
mv "$stage/xcertm" "$binary"
printf 'Installed xcertm %s.\n' "$version"
case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) printf 'Add %s to your PATH, or run %s directly.\n' "$bin_dir" "$binary" ;;
esac

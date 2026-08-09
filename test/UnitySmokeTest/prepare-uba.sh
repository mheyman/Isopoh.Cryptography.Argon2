#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
sdk_dir="$repo_root/.uba-work/dotnet-argon2"
installer="$sdk_dir/dotnet-install.sh"
plugins="$script_dir/Assets/Plugins"
dotnet_cmd="$sdk_dir/dotnet"

if [[ "${OSTYPE:-}" == cygwin* || "${OSTYPE:-}" == msys* ]]; then
  dotnet_cmd="$sdk_dir/dotnet.exe"
fi

mkdir -p "$sdk_dir" "$plugins"

if [[ ! -x "$dotnet_cmd" ]]; then
  curl --fail --location --silent --show-error \
    https://dot.net/v1/dotnet-install.sh \
    --output "$installer"
  bash "$installer" --channel 10.0 --install-dir "$sdk_dir"
fi

"$dotnet_cmd" build \
  "$repo_root/lib/Isopoh.Cryptography.Argon2/Isopoh.Cryptography.Argon2.csproj" \
  --configuration Release \
  --framework netstandard2.0 \
  -p:GeneratePackageOnBuild=false

cp "$repo_root/lib/Isopoh.Cryptography.Argon2/bin/Release/netstandard2.0/Isopoh.Cryptography.Argon2.dll" "$plugins/"
cp "$repo_root/lib/Isopoh.Cryptography.Blake2b/bin/Release/netstandard2.0/Isopoh.Cryptography.Blake2b.dll" "$plugins/"
cp "$repo_root/lib/Isopoh.Cryptography.SecureArray/bin/Release/netstandard2.0/Isopoh.Cryptography.SecureArray.dll" "$plugins/"

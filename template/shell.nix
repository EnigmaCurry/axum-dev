{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    rustup
    nodejs
    pnpm
    just
    gettext  # provides GNU envsubst (not the Go a8m/envsubst which ignores SHELL-FORMAT)
    cargo-binstall
    pkg-config
    openssl
    openssl.dev
    sqlite
  ];

  shellHook = ''
    export OPENSSL_DIR=${pkgs.openssl.dev}
    export OPENSSL_LIB_DIR=${pkgs.openssl.out}/lib

    # Ensure a default Rust toolchain is available
    if ! rustup show active-toolchain &>/dev/null; then
      echo "Setting up stable Rust toolchain..."
      rustup default stable
    fi
  '';
}

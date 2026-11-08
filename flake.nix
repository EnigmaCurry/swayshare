{
  description = "swayshare - temporary, peer-scoped remote desktop access for Sway";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        swayshare = pkgs.rustPlatform.buildRustPackage {
          pname = "swayshare";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          # swayshare execs wayvnc by name; keep it on PATH so the binary
          # works without the user arranging that themselves.
          postInstall = ''
            wrapProgram $out/bin/swayshare \
              --prefix PATH : ${pkgs.wayvnc}/bin
          '';

          meta = with pkgs.lib; {
            description = "Temporary, peer-scoped remote desktop access for Sway";
            mainProgram = "swayshare";
            platforms = platforms.linux;
            license = licenses.mit;
          };
        };
        default = swayshare;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            # The runtime dependency, plus what ./scripts/e2e-smoke.sh needs.
            wayvnc
            sway
            tigervnc
          ];
          RUST_BACKTRACE = "1";
        };
      });

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = "${self.packages.${pkgs.system}.swayshare}/bin/swayshare";
        };
      });
    };
}

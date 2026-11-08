{
  description = "swayshare - temporary, peer-scoped remote desktop access for Sway";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # swayshare execs these by name; keeping them on PATH means the binary
      # works without the user arranging that themselves.
      runtimeDeps = pkgs: [ pkgs.wayvnc pkgs.wl-clipboard ];

      # `withGui` controls the optional GTK4 configuration window. Without it
      # the build needs no GTK development libraries at all.
      mkSwayshare = pkgs: { withGui }:
        pkgs.rustPlatform.buildRustPackage {
          pname = if withGui then "swayshare" else "swayshare-cli";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          buildNoDefaultFeatures = !withGui;

          nativeBuildInputs =
            pkgs.lib.optionals withGui [
              pkgs.pkg-config
              # Sets up the GSettings schemas and icon theme path GTK needs.
              pkgs.wrapGAppsHook4
            ]
            ++ pkgs.lib.optionals (!withGui) [ pkgs.makeWrapper ];

          buildInputs = pkgs.lib.optionals withGui [ pkgs.glib pkgs.gtk4 ];

          # With wrapGAppsHook4 the wrapper is built for us, so the runtime
          # PATH is contributed through its argument list rather than by
          # wrapping a second time.
          preFixup = pkgs.lib.optionalString withGui ''
            gappsWrapperArgs+=(
              --prefix PATH : ${pkgs.lib.makeBinPath (runtimeDeps pkgs)}
            )
          '';
          postInstall = pkgs.lib.optionalString (!withGui) ''
            wrapProgram $out/bin/swayshare \
              --prefix PATH : ${pkgs.lib.makeBinPath (runtimeDeps pkgs)}
          '';

          meta = with pkgs.lib; {
            description =
              "Temporary, peer-scoped remote desktop access for Sway"
              + optionalString (!withGui) " (without the GTK window)";
            mainProgram = "swayshare";
            platforms = platforms.linux;
            license = licenses.mit;
          };
        };
    in
    {
      packages = forAllSystems (pkgs: rec {
        swayshare = mkSwayshare pkgs { withGui = true; };
        swayshare-cli = mkSwayshare pkgs { withGui = false; };
        default = swayshare;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = with pkgs; [ glib gtk4 ];
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            # Runtime dependencies, plus what the smoke-test scripts need.
            wayvnc
            wl-clipboard
            sway
            tigervnc
            grim
            dbus
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

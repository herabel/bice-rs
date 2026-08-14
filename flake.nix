{
  description = "Bice-rs - a open-source password manager with XChaCha20-poly1305, own binary format and self-hosted post-quantum cloud sync.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = inputs:
       let
           systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
       in
       {
        devShells = builtins.listToAttrs (map (system: {
          name = system;
          value = {
            default = (let
              pkgs = inputs.nixpkgs.legacyPackages.${system};
            in pkgs.mkShell {
              nativeBuildInputs = [ pkgs.pkg-config ];
              buildInputs = [ ] ++ (if pkgs.stdenv.hostPlatform.isLinux then [
                pkgs.udev
              ] else [ ]);
            });
          };
        }) systems);
    };
}

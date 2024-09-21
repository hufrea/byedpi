{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
      in
      {
        packages = rec {
          byedpi = pkgs.stdenv.mkDerivation {
            name = "ciadpi";
            src = ./.;
            buildInputs = with pkgs; [ gcc gnumake ];
            buildPhase = "make";
            installPhase = ''
              mkdir -p $out/bin 
              cp ciadpi $out/bin/ 
            '';
          };
          default = byedpi;
        };
      }
    );
}


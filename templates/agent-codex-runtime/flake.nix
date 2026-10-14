{
  description = "Codex policy runtime scaffold (no agent client)";
  inputs = {
    mvm.url = "github:tinylabscom/mvm/76809dcc5a0ccfaae5390967b8f9b464f84e47a8?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/b6018f87da91d19d0ab4cf979885689b469cdd41";
  };
  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };
      appSrc = pkgs.runCommand "codex-runtime-app" { } ''
        mkdir -p "$out"
        cp -r ${./app}/. "$out/"
      '';
    in {
      packages.${system}.default = mvm.lib.${system}.mkGuest {
        name = "codex-runtime";
        packages = [ pkgs.nodejs_22 pkgs.git pkgs.curl pkgs.ripgrep pkgs.jq ];
        entrypoint.command = [
          "${pkgs.bash}/bin/bash" "${appSrc}/check-runtime.sh"
          "${pkgs.nodejs_22}/bin/node"
        ];
      };
    };
}

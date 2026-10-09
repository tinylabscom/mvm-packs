{
  description = "Pinned CPython closure for the runtime/python workload image";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/8fd9daa3db09ced9700431c5b7ad0e8ba199b575";

  outputs = { nixpkgs, ... }: {
    packages.aarch64-linux.default =
      (import nixpkgs { system = "aarch64-linux"; }).python312;
  };
}

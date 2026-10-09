{
  description = "mvm microVM — single-node Kubernetes (k3s, rootless)";

  # EXPERIMENTAL scaffold: the image builds, but rootless k3s bring-up and its
  # boot-image capability contract are tracked by this repository's issue #1.
  # See README.md in this directory for the constraints and open items.
  #
  # The template deliberately does not select a boot kernel. `mkGuest`'s
  # `kernel` argument only supplies modules to the rootfs; the host boots the
  # workload kernel from its generated image set. Kubernetes-specific image
  # work and kernel variants do not belong outside this template repository.
  inputs = {
    mvm.url = "github:tinylabscom/mvm?dir=nix";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
  };

  outputs = { mvm, nixpkgs, ... }:
    let
      system = "aarch64-linux";
      pkgs = import nixpkgs { inherit system; };

      # Single-node k3s, rootless under the mvm workload uid.
      #
      # Networking contract of the guest (see README.md): there is no guest
      # NIC and no TAP/TUN. PID 1 exports ALL_PROXY / HTTP_PROXY /
      # HTTPS_PROXY pointing at the vsock egress proxy on loopback
      # (socks5h://127.0.0.1:1080), and only admitted host:port flows tunnel
      # to the host. Cluster-internal traffic (apiserver, pods, services) is
      # ordinary in-guest netns/bridge traffic and needs no NIC. RootlessKit
      # therefore runs with --net=host: there is no upstream interface for a
      # slirp4netns-style userspace stack to speak to.
      startScript = pkgs.writeShellScript "k3s-rootless-start" ''
        set -eu

        DATA_DIR=/data/k3s
        KUBECONFIG_OUT=''${KUBECONFIG_OUT:-/data/k3s/k3s.yaml}

        if ! grep -q " /data " /proc/mounts; then
          echo "k3s-rootless-start: /data is not mounted; attach a :rw disk" >&2
          echo "  volume, e.g. --mount ./k3s-data:/data:20G:rw" >&2
          exit 1
        fi
        mkdir -p "$DATA_DIR" "$DATA_DIR/home"

        # The k3s multicall binary extracts its asset data under HOME on every
        # invocation (even `kubectl`); uid 1000's default HOME here is /, which
        # is read-only. Point HOME at the writable data volume.
        export HOME="$DATA_DIR/home"

        # Proxy env (ALL_PROXY/HTTP_PROXY/HTTPS_PROXY) is inherited from PID 1:
        # container image pulls and other outbound HTTPS ride the vsock egress
        # proxy, and only allow_hosts-admitted destinations are tunneled.
        #
        # Rootless single-node server. --disable keeps the control plane lean
        # for the dev/test tier this targets; add traefik/servicelb back when
        # ingress is needed (host reachability then goes through a declared
        # --port ingress forward, not a NodePort on a NIC).
        # RootlessKit v2 dropped the --ipc/--uts flags (the namespaces are
        # implied); passing them kills the whole bring-up with a usage error
        # before k3s ever runs. --net=host is the load-bearing one: there is
        # no upstream interface for a slirp4netns-style stack to speak to.
        # Bring-up shape, from live smoke findings: RootlessKit is out - v2
        # still demands /etc/subuid plus a setuid newuidmap, and a sealed
        # image can carry neither. Instead this is plain rootful k3s inside
        # a user namespace (unshare -Urmpf, the same primitive the generic
        # rootless tenant probe exercises). --fork is load-bearing: without
        # it unshare execs k3s in the parent PID namespace, the first child
        # becomes the new namespace's init and every later fork fails ENOMEM
        # once it exits, and Go cannot create threads at all (clone with
        # CLONE_THREAD returns EINVAL). Inside the namespace we are uid 0 with
        # NET_ADMIN in the owned namespace, on the guest's single network
        # (the NIC-less contract: no upstream exists for a slirp4netns-style
        # stack). The kubelet hard-requires /dev/kmsg, which root-in-userns
        # cannot read, so bind /dev/null over it inside the owned mount
        # namespace - OOM events simply go unobserved.
        exec unshare -Urmpf sh -c '
          mount --bind /dev/null /dev/kmsg 2>/dev/null || true
          exec ${pkgs.k3s}/bin/k3s server \
            --data-dir="$DATA_DIR" \
            --write-kubeconfig="$KUBECONFIG_OUT" \
            --write-kubeconfig-mode=600 \
            --disable=traefik,servicelb
        '
      '';

      kubectlWithConfig = pkgs.writeShellScriptBin "kubectl" ''
        exec ${pkgs.k3s}/bin/k3s kubectl --kubeconfig /data/k3s/k3s.yaml "$@"
      '';
    in
    {
      # Wrapped in the builder-VM image contract (the shape mvm-images uses for
      # every image): the runCommand output carries the rootfs + an in-nix
      # serialized mvm-meta.json sidecar, and exposes the inner mkGuest rootfs
      # as passthru.rootfs. A bare mkGuest output builds fine but leaves the
      # runtime sidecar to a `nix eval` against a host path the builder VM
      # cannot read — the build then refuses to boot its own output.
      packages.${system}.default =
        let
          rootfsPkg = mvm.lib.${system}.mkGuest {
            name = "kubernetes-vm";

            # Dev console for the smoke test (exec/console drive the cluster),
            # while the entrypoint keeps its rootless uid — mkGuest would
            # otherwise run a dev image's entrypoint as root.
            dev = true;
            uids.entrypoint = 1000;

            # Sized for a control plane: 4 vCPU / 4 GiB. Container image
            # storage consumes the /data disk volume, not the read-only rootfs.
            vcpus = 4;
            memory_mib = 4096;

            packages = [
              pkgs.k3s
              pkgs.rootlesskit
              kubectlWithConfig
            ];

            extraFiles."/usr/local/bin/k3s-rootless-start" = {
              source = startScript;
              mode = "0755";
            };
            # The universal-initramfs path runs the workload as uid 901
            # (mvm-agentd's WORKLOAD_UID), but mkGuest bakes accounts only
            # for its own uids (989/990/1000). RootlessKit resolves the
            # current uid to a username to compute the uid/gid map, and
            # without an account the bring-up dies with "unknown userid
            # 901". Bake the identity the universal path actually uses.
            # NB: mkGuest re-indents `content` when it embeds the file, so a
            # whitespace-sensitive file like /etc/passwd must be a plain
            # escaped string - an indented '' string leaks leading spaces
            # into every line and breaks parsers.
            extraFiles."/etc/passwd" = {
              mode = "0644";
              content = "root:x:0:0:root:/root:/bin/sh\nmvm-egress:x:989:989:mvm FlowMux egress:/var/empty:/bin/false\nmvm-agent:x:990:990:mvm guest agent:/var/empty:/bin/false\nmvm-worker:x:1000:1000:mvm workload:/home/mvm-worker:/bin/sh\nmvm-workload:x:901:901:mvm workload (universal path):/home/mvm-worker:/bin/sh\n";
            };
            extraFiles."/etc/group" = {
              mode = "0644";
              content = "root:x:0:\nmvm-egress:x:989:\nmvm-agent:x:990:\nmvm-worker:x:1000:\nmvm-workload:x:901:\n";
            };

            entrypoint.command = [ "/usr/local/bin/k3s-rootless-start" ];

            # Declared to the guest agent's probe loop; the agent runs the
            # drop-in and serves ProbeStatus over vsock. Readiness = this node
            # is Ready.
            healthChecks.node-ready = {
              # k3s is a multicall binary: even `kubectl` extracts its data
              # dir on start, and as uid 1000 with HOME=/ that dies on the
              # read-only root. Give it the writable data home the entrypoint
              # provisions.
              healthCmd = "env HOME=/data/k3s/home ${pkgs.k3s}/bin/k3s kubectl --kubeconfig /data/k3s/k3s.yaml get nodes --no-headers | grep -q Ready";
              healthIntervalSecs = 10;
              healthTimeoutSecs = 15;
            };
          };
          meta = rootfsPkg.passthru.mvm;
          # Serialize the sidecar in-nix (the rootless-tenant contract): the
          # builder-VM runtime reads $out/mvm-meta.json without evaluating
          # anything. Protocol version is locked to
          # PROTOCOL_VERSION_AUTHENTICATED in mvm-contract.
          sidecarJson = builtins.toJSON {
            inherit (meta)
              name accessible sealed entrypointKind initSystem
              expectedBootMs agentBinary rootlessEntrypoint hypervisor
              overlayAware runtimeLean;
            imageTag = "";
            source = "built-local";
            builtAt = "";
            protocolVersion = 2;
            generatorRev = "";
          };
        in
        pkgs.runCommand "kubernetes-vm-image"
          { passthru = { rootfs = rootfsPkg; }; }
          ''
            set -euo pipefail
            mkdir -p $out
            if [ -f ${rootfsPkg} ]; then
              cp ${rootfsPkg} $out/rootfs.ext4
            else
              img=$(find ${rootfsPkg} -maxdepth 1 \( -name '*.img' -o -name '*.ext4' \) | head -1)
              [ -n "$img" ] || { echo "mkGuest output ${rootfsPkg} has no .img/.ext4" >&2; exit 1; }
              cp "$img" $out/rootfs.ext4
            fi
            cat > $out/mvm-meta.json <<'META'
            ${sidecarJson}
            META
            chmod 0644 $out/rootfs.ext4 $out/mvm-meta.json
          '';
    };
}

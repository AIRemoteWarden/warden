# AI Warden

AI Warden is an AI-assisted remote shell product that helps teams share a real terminal with a customer without asking them to give up control.

It is a local-first remote shell product for support, operations, and debugging, with approvals and output protection built into the host side.

The goal is simple: let a customer share a real terminal session with an operator, while keeping control on the customer machine.

## Why this exists

Most remote support tools are built for screens, not shells.

Terminal access is different:

- commands can be destructive
- credentials and secrets can appear in output
- support sessions need to feel native, not like a broken terminal emulator
- customers need clear local control before they trust the tool

Warden is being built around those constraints from day one.

## What Warden is trying to do

- run a real shell on the host machine
- let a remote guest join through the browser
- keep policy enforcement on the host side
- require local approval for risky commands
- support masking of sensitive output before it reaches the guest
- make the security model understandable enough that a customer can actually say yes to using it

## Current direction

This repository is still early, but the main shape is already here:

- `warden-client/`
  - Rust host client
  - terminal runtime, policy enforcement, approvals, redaction, transport
- `server/`
  - Go control and relay backend
  - browser guest session entry
  - default policy distribution endpoint

Current work includes:

- host-side approvals for commands like `sudo` and other risky operations
- sensitive file handling for things like `/etc/shadow`
- early output redaction flows
- policy distribution from the backend
- experiments around database-aware masking for `psql`

## Run the server with Podman

The early deployment target is a single container for the backend and a downloadable host client binary.

Pull and run the published server image:

```bash
podman pull ghcr.io/ai-remote-warden/warden-server:latest
podman run --replace -it \
  --name ai-warden-server \
  -p 8080:8080 \
  -e WARDEN_CONTROL_ADDR=:8080 \
  -e WARDEN_PUBLIC_HOST=http://YOUR_PUBLIC_IP:8080 \
  ghcr.io/ai-remote-warden/warden-server:latest
```

Replace `YOUR_PUBLIC_IP` with the public IP address or domain that your users will reach.

Important:

- Warden does not yet provide end-to-end encryption for terminal traffic.
- If you deploy it on the public internet today, assume the server can see session content and deploy carefully.
- End-to-end encryption is planned, but it is not in place yet.

Build and run the server locally:

```bash
podman build --isolation=chroot -t ghcr.io/ai-remote-warden/warden-server:local ./server
podman run --replace -it \
  --name ai-warden-server \
  -p 8080:8080 \
  -e WARDEN_CONTROL_ADDR=:8080 \
  -e WARDEN_PUBLIC_HOST=http://localhost:8080 \
  ghcr.io/ai-remote-warden/warden-server:local
```

Or use Compose:

```bash
podman compose up --build
```

Notes:

- `8080` serves control APIs, the guest page, static assets, websocket relay endpoints, and `/healthz`
- default policy is embedded into the server binary
- you can override the policy file with `WARDEN_POLICY_PATH=/path/to/policy.json`

## Run the client

Build and start the host client:

```bash
cd warden-client
cargo run -- start --server YOUR_SERVER_HOST
```

If you want `ask ai` to use an OpenAI-compatible local model server such as `llama.cpp`, pass `--llm`:

```bash
cd warden-client
cargo run -- start --server YOUR_SERVER_HOST --llm localhost:9001
```

`--llm localhost:9001` is normalized to `http://localhost:9001/v1`.

## Building in public

We are developing this in public because the hard parts matter:

- terminal fidelity
- local-first trust boundaries
- explainable approvals
- practical DLP for shell and database workflows

If that problem space is familiar to you, this project will probably make sense quickly.

## Status

This is not a polished product release yet.

It is an active working repository for the client, backend, policy model, and interaction design. Expect rapid iteration.

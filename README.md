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

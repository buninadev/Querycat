import { readFileSync } from "node:fs";
import { createServer, type AddressInfo, type Socket } from "node:net";
import { Client as SshClient, type ConnectConfig } from "ssh2";
import { SSH_READY_TIMEOUT_MS } from "./limits.js";
import type { Secrets, SshConfig } from "./store.js";

export interface Tunnel {
  localPort: number;
  /** Why the SSH host last refused to open a channel to the database, if it did. */
  forwardError(): string | undefined;
  close(): void;
}

interface Target {
  host: string;
  port: number;
}

function sshAuthOptions(ssh: SshConfig, secrets: Secrets): Partial<ConnectConfig> {
  switch (ssh.auth.method) {
    case "agent": {
      const agent = process.env.SSH_AUTH_SOCK;
      if (!agent) {
        throw new Error("SSH agent auth selected but SSH_AUTH_SOCK is not set.");
      }
      return { agent };
    }
    case "key":
      return { privateKey: readFileSync(ssh.auth.privateKeyPath), passphrase: secrets.sshPassphrase };
    case "password":
      return { password: secrets.sshPassword };
  }
}

function connectSsh(ssh: SshConfig, secrets: Secrets): Promise<SshClient> {
  const client = new SshClient();
  return new Promise((resolve, reject) => {
    client
      .once("ready", () => resolve(client))
      .once("error", reject)
      .connect({
        host: ssh.host,
        port: ssh.port,
        username: ssh.username,
        readyTimeout: SSH_READY_TIMEOUT_MS,
        ...sshAuthOptions(ssh, secrets),
      });
  });
}

/**
 * Opens an SSH connection and a local port on 127.0.0.1 that forwards to the
 * database as seen from the SSH host. Postgres then connects to that local port.
 */
export async function openTunnel(ssh: SshConfig, secrets: Secrets, target: Target): Promise<Tunnel> {
  const client = await connectSsh(ssh, secrets);
  let lastForwardError: string | undefined;

  const forward = (socket: Socket) => {
    socket.on("error", () => socket.destroy());
    client.forwardOut("127.0.0.1", socket.remotePort ?? 0, target.host, target.port, (error, channel) => {
      if (error) {
        lastForwardError = error.message;
        socket.destroy();
        return;
      }
      channel.on("error", () => socket.destroy());
      socket.pipe(channel).pipe(socket);
    });
  };

  const server = createServer(forward);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));

  return {
    localPort: (server.address() as AddressInfo).port,
    forwardError: () => lastForwardError,
    close() {
      server.close();
      client.end();
    },
  };
}

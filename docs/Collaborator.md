Collaborator Endpoint (HTTP OOB) — Setup Guide

Goal
- Host your own simple HTTP endpoint to receive out‑of‑band callbacks from SSRF/XXE/Blind‑XSS payloads. Avoids public services that are often blocked.

What you need
- A domain you control (e.g., yourdomain.com)
- A server/VPS with a public IP and port 80 open

Step 1 — DNS
- Create an A record: collab.yourdomain.com -> <your_server_ip>
- (Optional) Wildcard A: *.collab.yourdomain.com -> <your_server_ip>

Step 2 — Run the receiver (fast path)
- SSH to your server, then run:

  python3 recon-platform/modscan/tools/collaborator_receiver.py --host 0.0.0.0 --port 80 --log-file ~/collaborator.log

- Verify:

  curl http://collab.yourdomain.com/health
  curl http://collab.yourdomain.com/test123

- Watch logs in the terminal (JSON lines) or tail the log file:

  tail -f ~/collaborator.log

Step 2b — Run unprivileged (reverse proxy)
- If binding 80 requires root, run receiver on 8080 and use Nginx to proxy:

  python3 recon-platform/modscan/tools/collaborator_receiver.py --host 127.0.0.1 --port 8080 --log-file ~/collaborator.log

- Install Nginx and drop tools/collaborator_nginx.conf into /etc/nginx/sites-available/collaborator, then:

  ln -s /etc/nginx/sites-available/collaborator /etc/nginx/sites-enabled/
  systemctl reload nginx

Step 2c — Run as a systemd service
- Copy tools/collaborator_receiver.service to /etc/systemd/system/collaborator_receiver@<user>.service
- Start and enable:

  systemctl daemon-reload
  systemctl enable collaborator_receiver@<your-username>
  systemctl start collaborator_receiver@<your-username>

Step 3 — Wire ModScan to it
- Export environment variable (simplest):

  export COLLABORATOR_DOMAIN="collab.yourdomain.com"

- Or config.json:

  {
    "collaborator": {
      "base_domain": "collab.yourdomain.com",
      "enabled": true,
      "https": false
    }
  }

Step 4 — Use it
- ModScan will embed unique markers in SSRF/XXE payloads and annotate findings with “monitor collaborator logs”.
- You’ll see inbound requests like:

  {"ts":"...Z","host":"collab.yourdomain.com","path":"/ssrf/MODSCAN_172...","method":"GET",...}

Notes
- HTTPS is not required; plain HTTP is fine for beaconing.
- Wildcard DNS improves compatibility when targets require unique subdomains. It’s optional.
- You can reuse the same endpoint for Blind XSS beacons by setting BLIND_XSS_DOMAIN=collab.yourdomain.com.


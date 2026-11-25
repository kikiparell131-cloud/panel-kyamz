# KYAMZ Personal Panel

Personal, single-account web panel for managing Node.js and Python bot processes. UI is inspired by the screenshots: dark dashboard, host resources, server cards, console controls, file manager, startup settings, and responsive mobile layout.

## Railway deployment

1. Create a Railway project and deploy this repository as a Node.js service.
2. Set the service start command to `npm start` (Railway can also detect `package.json`).
3. Add a Railway Volume and mount it at `/data`. This stores server files and metadata across deployments.
4. Add variables:
   - `PANEL_USERNAME=KYAMZ`
   - `PANEL_PASSWORD_HASH` (optional; default login password is `ADMINKYAMZ`)
   - `SESSION_SECRET=<random string at least 32 characters>`
   - `DATA_DIR=/data`
   - `NODE_ENV=production`
5. Login default: username `KYAMZ`, password `ADMINKYAMZ`. Change the password hash before exposing the panel publicly. To generate a new scrypt hash, run this Node snippet locally:

   ```js
   const crypto = require("crypto");
   const salt = crypto.randomBytes(16);
   crypto.scrypt("YOUR_NEW_PASSWORD", salt, 64, (err, key) => console.log("scrypt$" + salt.toString("hex") + "$" + key.toString("hex")));
   ```

   Set the output as `PANEL_PASSWORD_HASH`. Never commit `.env` or secrets.
6. Deploy, then open the Railway public domain. The app listens on `process.env.PORT`.

## Features

- One login account only (username defaults to `KYAMZ`; password is checked against a bcrypt hash).
- Create Node.js or Python server folders with starter file.
- Start, stop, restart, force-kill; live stdout/stderr console over WebSocket; stdin command input.
- File manager: browse directories, create files/folders, edit text files (up to 2 MB), upload files (up to 10 MB), extract ZIP archives (max 10 MB ZIP / 200 MB extracted / 3000 entries), delete files/folders.
- Startup command, auto-restart setting, memory/CPU allocation labels, process memory and uptime display.
- Mobile-responsive interface.

## Important Railway limitations

This is a lightweight personal process panel, **not** a full Pterodactyl-style isolated container manager. Child bot processes run inside the same Railway service/container and share its actual CPU/RAM limits. The memory/CPU selections are currently informational allocation labels; Railway does not enforce them per child process. Deploys/restarts stop child processes; start them again after deployment (or use Railway's service process strategy for production bots). Use a Railway Volume mounted at `/data` for persistence. Railway exposes one public HTTP port per service; bot scripts should use `process.env.PORT` when hosting a web endpoint and use outbound connections for WhatsApp/Telegram.

Only run scripts you trust. The panel allows its authenticated owner to execute configurable startup commands. Keep the Railway domain private and use a strong password hash and session secret.

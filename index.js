const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

function _cookiesArg(opts = {}) {
  const explicit = opts.cookies;
  const envPath = process.env.YTDLP_COOKIES;
  const defaultPath = path.join(process.cwd(), 'cookies.txt');
  const cookiesPath = explicit || envPath || (fs.existsSync(defaultPath) ? defaultPath : null);
  return cookiesPath ? ['--cookies', cookiesPath] : [];
}

function isAvailable() {
  return new Promise((resolve) => {
    const p = spawn('yt-dlp', ['--version']);
    p.on('error', () => resolve(false));
    p.on('close', (code) => resolve(code === 0));
  });
}

function stream(url, opts = {}) {
  const format = opts.format || 'bestaudio[ext=m4a]/bestaudio';
  const args = ['-o', '-', '-f', format, '--no-playlist', '--no-warnings', url];
  const cookies = _cookiesArg(opts);
  if (cookies.length) args.splice(0, 0, ...cookies);

  const proc = spawn('yt-dlp', args, { stdio: ['ignore', 'pipe', 'pipe'] });

  proc.on('error', (e) => {
    // consumer can listen on proc for errors
  });

  return { stream: proc.stdout, proc };
}

async function getInfo(url, opts = {}) {
  return new Promise((resolve) => {
    const args = ['--dump-json', '--no-playlist', '--no-warnings', url];
    const cookies = _cookiesArg(opts);
    if (cookies.length) args.splice(0, 0, ...cookies);

    const proc = spawn('yt-dlp', args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    proc.stdout.on('data', (d) => { out += d.toString(); });
    proc.on('error', () => resolve(null));
    proc.on('close', (code) => {
      if (code === 0 && out) {
        try { resolve(JSON.parse(out)); } catch (e) { resolve(null); }
      } else resolve(null);
    });
  });
}

module.exports = { isAvailable, stream, getInfo };

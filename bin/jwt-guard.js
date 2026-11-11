#!/usr/bin/env node
/**
 * JWT Inspector Guard — Unified CLI & Desktop Workstation Launcher
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const rootDir = path.resolve(__dirname, '..');
const srcDir = path.join(rootDir, 'src');
const args = process.argv.slice(2);
const defaultPort = process.env.PORT || '8124';

const isWeb = args[0] === 'web' || args.includes('--web');
const isAppRequest =
  !isWeb &&
  (args.length === 0 ||
    args.includes('--gui') ||
    args.includes('--app') ||
    args.includes('--desktop') ||
    args[0] === 'app' ||
    args[0] === 'desktop' ||
    args[0] === 'gui');

if (isWeb) {
  console.log(`Launching JWT Inspector Guard Web UI on http://127.0.0.1:${defaultPort} ...`);
  const pyChild = spawn('python3', [path.join(rootDir, 'server.py')], {
    cwd: rootDir,
    stdio: 'inherit',
    env: {
      ...process.env,
      PORT: String(defaultPort),
      HOST: '127.0.0.1',
      PYTHONPATH: process.env.PYTHONPATH ? `${srcDir}:${process.env.PYTHONPATH}` : srcDir,
      ZOTH_ZERO_EGRESS: 'true',
    },
  });
  pyChild.on('error', (pyErr) => {
    console.error('[JWT-Guard] Failed to start web server:', pyErr);
  });
} else if (isAppRequest) {
  console.log('Launching JWT Inspector Guard Desktop Workstation...');

  const candidateElectronPaths = [
    path.join(rootDir, 'node_modules', '.bin', 'electron'),
    '/usr/local/bin/electron',
    '/usr/bin/electron',
  ];

  let electronCmd = 'electron';
  for (const p of candidateElectronPaths) {
    if (fs.existsSync(p)) {
      electronCmd = p;
      break;
    }
  }

  const child = spawn(electronCmd, ['.'], {
    cwd: rootDir,
    stdio: 'inherit',
    env: {
      ...process.env,
      PYTHONPATH: process.env.PYTHONPATH ? `${srcDir}:${process.env.PYTHONPATH}` : srcDir,
      ELECTRON_ENABLE_LOGGING: '1',
      ZOTH_ZERO_EGRESS: 'true',
    },
  });

  child.on('error', (err) => {
    console.warn(`[JWT-Guard] Electron notice: ${err.message}. Starting web UI on 127.0.0.1:${defaultPort}...`);
    const pyChild = spawn('python3', [path.join(rootDir, 'server.py')], {
      cwd: rootDir,
      stdio: 'inherit',
      env: {
        ...process.env,
        PORT: String(defaultPort),
        HOST: '127.0.0.1',
        PYTHONPATH: process.env.PYTHONPATH ? `${srcDir}:${process.env.PYTHONPATH}` : srcDir,
      },
    });
    pyChild.on('error', (pyErr) => {
      console.error('[JWT-Guard] Failed to start backend:', pyErr);
    });
  });
} else {
  const child = spawn('python3', ['-m', 'jwt_inspector_guard.cli', ...args], {
    cwd: rootDir,
    stdio: 'inherit',
    env: {
      ...process.env,
      PYTHONPATH: process.env.PYTHONPATH ? `${srcDir}:${process.env.PYTHONPATH}` : srcDir,
    },
  });

  child.on('exit', (code) => {
    process.exit(code || 0);
  });
}

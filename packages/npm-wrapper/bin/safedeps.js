#!/usr/bin/env node
const { spawnSync } = require('child_process');
const args = process.argv.slice(2);
const cmd = process.platform === 'win32' ? 'python' : 'python3';
let result = spawnSync(cmd, ['-m', 'safedeps.cli', ...args], { stdio: 'inherit' });
if (result.error) {
  console.error('SafeDeps Python core not found. Install with: pip install safedeps');
  process.exit(1);
}
process.exit(result.status ?? 1);

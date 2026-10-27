# Salist Encrypt

A client-side cryptographic and steganographic web application built with Web Crypto API and zero external runtime dependencies.

## Features

- Text Encryption: Cascaded AES-256-GCM with PBKDF2 key derivation and ultra-compact stream cipher with CRC verification.
- File and Archive Encryption: Encrypt any single file with metadata preservation or pack multiple files and folders into an encrypted ZIP container.
- Image Scrambling: Visual pixel permutation with authenticity watermark embedding.
- Steganography: Differential macro-cell modulation designed to survive image compression and LSB fallback extraction.
- Password Generator: Configurable character set selection (uppercase, lowercase, numbers, symbols) and entropy calculation.
- Hash Suite: Real-time calculation of MD5, SHA-1, SHA-256, and SHA-512 digests.
- QR Code Suite: Vector QR code generation and scanner via device camera or file upload.
- Interface: Apple-inspired monochromatic solid layout with dark and light modes.

## Architecture

- Fully static and client-side: all cryptographic operations are executed in the browser sandbox.
- Zero tracking, zero telemetry, and zero third-party network requests.
- No database or backend required.

## Quick Start

### Direct in Browser
Open `index.html` in any modern web browser.

### Using Python Local Server
```bash
python enc.py
```
Navigate to `http://127.0.0.1:6778` in your browser.

## File Structure

- `index.html`: Core markup and embedded offline utilities.
- `style.css`: Monochromatic interface styles for dark and light modes.
- `app.js`: Application logic, cryptographic workflows, and event handlers.
- `enc.py`: Lightweight local HTTP server.

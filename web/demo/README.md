# HyperVerITAS Demo — Chrome Extension + Article Pages

## What's here

```
demo/
├── extension/          # Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── content.js      # Scans pages, injects verify badges
│   ├── badge.css       # Badge styling
│   ├── popup.html      # Extension popup UI
│   └── popup.js
└── articles/
    ├── authentic-article.html   # Tagged with data-hyperveritas-proof="authentic"
    └── fake-article.html        # Tagged with data-hyperveritas-proof="tampered"
```

## Install the extension (one time)

1. Open `chrome://extensions` in Chrome / Edge
2. Toggle **Developer mode** (top-right)
3. Click **Load unpacked**, select the `demo/extension/` folder
4. The "HyperVerITAS Provenance Verifier" extension should appear

*(If Chrome complains about a missing icon, either add an `icon.png` to the extension folder or remove the `icons` block from `manifest.json`.)*

## Run the demo

1. Start the backend (`npm run dev:backend` in `web/`, default: `http://localhost:3006`). It serves the article pages at `/demo/`.
2. Prime the integrity demos once (each runs the prover; takes a minute):
   ```
   curl -X POST http://localhost:3006/api/integrity-demo/setup
   curl -X POST http://localhost:3006/api/audio-integrity-demo/setup
   ```
3. Open an article (must be served from the backend origin, not file://):
   - http://localhost:3006/demo/authentic-article.html
   - http://localhost:3006/demo/fake-article.html

4. Badges appear on the hero image and audio. Click to verify.
   - Authentic article → badges turn **green ✅**
   - Fake article → badges turn **red ❌**

5. Click the extension icon to see the last verification result.

## How it works (demo flow)

Each `<img>` / `<audio>` on the article pages has a `data-hyperveritas-proof="authentic|tampered"` attribute. The extension's content script:

1. Detects the attribute
2. Wraps the element and injects a badge
3. On click → calls `/api/integrity-demo/verify/<kind>` (or `/api/audio-integrity-demo/verify/<kind>` for audio)
4. Backend runs:
   - `verifyCameraAttestation(...)` — ECDSA check on the camera hash
   - `hv_crop_brakedown_verify` — SNARK check on the transformation
5. Badge updates with the combined verdict

## Story for the talk

> "The verifier is already a WASM module — packaging it as a browser extension means
> provenance can travel with the media. Any site serving HyperVerITAS-signed content
> gets verified automatically, regardless of whether the site knows about ZK."

Show the authentic article → all green. Switch to the fake article → all red. Done.

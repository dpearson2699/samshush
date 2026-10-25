# Samshush

Inspect Samsung TV firmware and disable unwanted voice, sensing and background
services with reversible controls. The included profile is verified for the
**Frame Pro QN65LS03FWFXZA, firmware 1301.0**; other builds need their own assessment.

### How it works

Samshush runs Python tools on your computer and temporary helpers on the TV.
Developer Mode provides the entry point; an exploit chain supplies root access.

- **Connect:** Samsung Smart Development Bridge (SDB) connects over the LAN on TCP
  port 26101. Command injection in SDB’s package handling provides shell execution.
- **Get root:** The tools combine excessive Linux capabilities in the TV’s .NET
  runtime with its privileged SDK archive launcher (`sdbd-tarlauncher`) to obtain
  UID 0 inside a private mount namespace, without flashing firmware.
- **Run commands:** A temporary root helper connects back to your computer over
  TCP. Commands and results use per-session HMAC-SHA256 authentication.
- **Apply controls:** The tools check compatibility, save original state, apply
  app blocks, service masks or certificate overlays, and verify the result.

Persistence depends on the control. Native app-disable flags and vendor startup
markers live on persistent storage; the 25 voice-app blocks and eight markers
survived a verified software reboot. Newly blocked optional apps use the same
native mechanism, but have not yet had their own reboot test. Service masks and
certificate overlays live in `/run` and **clear on every reboot**. They must be
reapplied after checking the TV's build and current state; Samshush installs no
automatic startup hook. Ordinary standby can retain this state, but standby and
a full restart are different events.

Automatic firmware updates can be turned off with `auto-update disable`; the tool
saves the previous native setting for `auto-update restore` and leaves manual
updates available. This reduces unexpected firmware changes; it does not guarantee
that every vendor update path is blocked. **Persistence across a firmware update
is not guaranteed:** an update can reset app flags, replace startup logic or trust
stores, and close the temporary-root entry point. After any update, reassess the
build before applying controls. The tools reject an unrecognized build rather
than assume the old controls still work. Power-cycle persistence has not been tested.

## Usage

1. Connect your TV and computer to the same network. On the TV, open **Apps →
   App Settings**, enter **12345**, enable **Developer Mode**, enter your computer’s
   LAN IP address, and reboot. See [Samsung’s setup guide](https://developer.samsung.com/smarttv/develop/getting-started/using-sdk/tv-device.html)
   if your menus differ.
2. Clone the repository, then open it in your coding agent:

   ```sh
   git clone https://github.com/elithrar/samshush.git
   cd samshush
   ```

3. Copy this prompt into your coding agent:

   ```text
   Read AGENTS.md, then find and connect to my Samsung TV on the local network.
   Use this repo’s uv-driven Python tools to verify compatibility and apply its
   supported privacy controls. Follow the README recommendations, preserve normal
   TV functions, verify each change, and explain the results and how to undo them.
   ```

> This was developed using GPT-6 Astra. I expect other frontier models to be
> successful given the prompt and tools in this repo. But your mileage may vary
> if you’re using smaller/quantized or previous-generation models.

Your agent handles dependencies, compatibility checks and recovery using
[AGENTS.md](AGENTS.md). Device commands use temporary root access, including audits.

## Findings & Services

These recommendations target a TV used for HDMI devices and streaming, without
voice assistants or sound-based monitoring.

| Service or feature | Recommendation | What we found and why |
| --- | --- | --- |
| Bixby, Alexa and voice recognition | Disable | Separate apps handle assistants, speech recognition and wake words. Native app blocks prevent these apps from launching. |
| Always-on voice and far-field listening | Disable | Dedicated services support voice activation, including standby paths. Disabling the visible assistant alone does not cover them. |
| Virtual microphones, Bluetooth HFP and soundbar voice passthrough | Disable for microphone privacy | These provide additional microphone routes. Blocking them can remove hands-free features; keep normal Bluetooth and audio output services. |
| SmartThings and SmartThings Find | Disable unused integrations | Seven selected client, plugin, hub and Find apps reject launches; three IoT hub activation units are masked. This disables their integrations without removing the shared sensor mediator. |
| SmartThings Sound Sensor / Pet Care | Turn sound sensing off | SmartThings supports sound-triggered events in standby. Keep the shared sensor mediator: it also provides light-sync integration. |
| Ambient sound and ultrasonic Art presence | Disable for microphone privacy | `ambient-sound` supports sound sensing and microphone-based presence detection. This trades automatic presence detection for privacy; preserve manual Art Mode. |
| Wi-Fi presence | Disable if unused | The separate LAN-presence service and its activation path are masked for this boot. Core Wi-Fi and networking remain enabled. |
| Viewing Information Services | Turn optional collection off | Viewing-data consent is separate from voice settings. Use the supported privacy setting rather than broadly disabling content-analysis services. |
| Content analysis and iACR | Keep enabled | Content-analysis code includes logo recognition and HDMI auto-detection; iACR exposes playback controls. Treating the whole stack as advertising risks useful input features. |
| Screen-based game/app recognition | Disable if unused | The installed model uses INT8 operations with a 64×64 input; capture code requests 960×540 frames at a configured 2.5-second interval. The recognition launcher and UI-image detector are masked for this boot, with their processes absent. |
| Advertising and usage analytics | Disable dedicated components | Adagent, targeted-ad and CoBA ad apps reject launches. The adagent unit and six analytics/diagnostic reporting units are masked for this boot; this does not cover every telemetry path. |
| TV Plus, Gaming Hub and Samsung Health | Disable if unused | Seven selected apps reject launches, and five Health activation units are masked. Shared TV Plus broadcast/channel backends remain available. |
| PISA shared framework | Preserve account-consent integration | PISA also manages account-consent and customization clients. Block the separate adagent app while preserving the framework that schedules those clients. |
| Remote Management | Leave off unless needed for support | The support daemon includes packet-dump capability. That is a reason to limit remote support, not evidence of continuous packet capture. |
| HDMI-CEC / Anynet+ and ARC/eARC | Keep enabled | CEC controls connected-device power and remote commands; ARC/eARC returns audio to the soundbar. Removing either works against normal HDMI use. |
| eMudhra / emSign trust roots | Remove the four selected roots | All 11 targeted certificate files now use verified replacement overlays, preserving unrelated certificates. Removal lasts for this boot; embedded app trust stores and already-cached certificates are outside this coverage. |
| Automatic firmware updates | Turn off; update manually after assessment | The native Auto Update setting is verified Off. Manual updating remains available; a firmware update can reset controls or close the root entry point. |
| Settings, manual Art Mode, playback, browser, Netflix, networking, One Connect and DRM | Keep enabled | These provide the TV’s core functions. Preserve their shared runtimes and unrelated trust certificates. |

The verified deployment blocks **25 voice apps, ambient-sound and 17 optional
apps**, with **eight startup guards, 43 runtime unit masks and 11 certificate
overlays**. The owner confirmed Apple TV picture, sidebar/input selection and
soundbar volume after the main changes. The voice app blocks and guards survived
an earlier reboot; the new optional blocks and Auto Update setting have not yet
had a reboot test. See **How it works** for persistence limits. These controls do
not establish complete microphone isolation or complete advertising/telemetry
suppression, and they disable apps rather than uninstall their files.

## Development

```sh
uv run --project tools ruff check tools
uv run --project tools ruff format --check tools
uv run --project tools python -m unittest discover -s tools/tests -v
```

[Detailed agent prompt](prompts/samsung-tv-privacy.md)

## License

[BSD 3-Clause](LICENSE) for original project code and documentation.
See [NOTICE](NOTICE) for third-party code, device payloads and firmware.

## Credits

I had originally started this mid Oct after seeing [this tweet](https://x.com/lucataco/status/2111846873216553433?s=46) from [@lucataco](https://x.com/lucataco) - getting my Frame TV to boot faster, stop suspending volume and removing all the unnecessary apps sounded great. In parallel I ran across [@log4j’s](https://x.com/log4j) thread on [the spyware, adware and extremely questionable findings](https://x.com/log4j/status/2113014142600953868?s=46) on their Samsung TV. This inspired me to push harder in my rooting activities and to see how far Astra would go in terms of rooting my TV over the network (it turns out: pretty far!).

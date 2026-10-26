# Samshush

Root your Samsung TV and disable unwanted voice, advertising and background
services. Changes are reversible. Verified profiles cover the **Frame Pro
QN65LS03FWFXZA on firmware 1301.0** and **S95C QN55S95CAFXZA on firmware 2220.4**.
Support is limited to the exact internal builds checked by each profile.

## How it works

Samshush runs on your computer and connects to your TV over the local network.
It uses Python tools and temporary helpers on the TV:

- **Connect:** Samsung's Smart Development Bridge (SDB) provides the connection
  on TCP port 26101. A command-injection flaw lets Samshush run shell commands.
- **Get root:** Flaws in the TV's .NET runtime and Samsung's archive launcher
  provide temporary root access. No firmware flashing is needed.
- **Apply changes:** Samshush saves the original state, blocks selected apps and
  services, and filters the certificate files. The helper sends results back over
  an authenticated TCP connection, then exits. Restore commands undo the changes.

App blocks use persistent settings. An optional startup hook reapplies service
masks and certificate changes in the background, without your computer. Remove it
with `startup remove` before restoring those controls. Firmware updates can reset
the changes or patch the root exploit, so check compatibility before updating.

The S95C profile (`--profile s95c-2220`) supports 23 voice app blocks, seven
startup guards, 21 voice units, the separate ambient-sound app and optional
Wi-Fi presence and Samsung home preload masks, and the Art app group. Other
optional controls remain
unsupported on that profile. Its native disable/restore trial, launch-denial checks
and boot-hook reapplication after a physical power cycle passed on one TV.
The default `frame` profile retains its existing controls.

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

These recommendations assume you use HDMI devices and streaming apps, and don’t
need voice assistants or sound monitoring.

| Service or feature | Recommendation | What we found and why |
| --- | --- | --- |
| TV's physical microphone switch | Set to Off | Samsung's [S95C-family manual](https://www.samsung.com/ca/support/model/QN55S95CAFXZC/) places the switch on the bottom edge; location varies. It disables the TV microphone's voice and sound features. The Smart Remote has a separate microphone. |
| Bixby, Alexa and voice recognition | Disable | Separate apps handle assistants, speech recognition and wake words. Native app blocks prevent these apps from launching. |
| Always-on voice and far-field listening | Disable | Dedicated services support voice activation, including standby paths. Disabling the visible assistant alone does not cover them. |
| Virtual microphones, Bluetooth HFP and soundbar voice passthrough | Disable for microphone privacy | These add microphone inputs beyond the TV’s built-in mic. Blocking them can remove hands-free features. Keep normal Bluetooth and audio output services. |
| SmartThings and SmartThings Find | Disable unused integrations | Samshush blocks the selected client, plugin, hub and Find apps and the IoT hub startup paths. The shared sensor service stays enabled for light sync. |
| SmartThings Sound Sensor / Pet Care | Turn sound sensing off | SmartThings can trigger events from sound, including in standby. The shared sensor service also handles light sync, so keep it enabled. |
| Ambient sound and ultrasonic Art presence | Disable for microphone privacy | `ambient-sound` uses the microphone for sound and presence detection. Blocking it removes automatic presence detection. Manual Art Mode still works. |
| Wi-Fi presence | Disable if unused | Samshush blocks the presence service and its startup path separately from radio power. On the Ethernet-connected S95C, Wi-Fi was already off while presence was still running; these masks preserve Ethernet and the existing radio setting. |
| Samsung home preloads (S95C) | Stop them if you use another launcher | At every boot Samsung starts its home preview updater, Multi View and the browser in the background. Samshush masks those three preload units, so each app starts only when you open it, at the cost of a slower first launch. |
| Art app on TVs without Art Mode (S95C) | Disable it | The S95C has no Art Mode, but Samsung still starts its Art app at every boot to sync art from Samsung's server, and the Art app then starts the home screen's Art tab. Samshush disables both. Ambient Mode is a separate app and keeps working. |
| Viewing Information Services | Turn optional collection off | Viewing-data consent is separate from voice settings. Turn it off in the TV’s privacy settings. |
| Content analysis and iACR | Keep enabled | Content analysis handles logo recognition and HDMI auto-detection. iACR provides playback controls. Disabling these can break useful input features. |
| Screen-based game/app recognition | Disable if unused | The detector requests 960×540 frames at a configured 2.5-second interval, then feeds a 64×64 image into an INT8 model. Samshush blocks the recognition launcher and UI-image detector. |
| Advertising and usage analytics | Disable dedicated components | Samshush blocks Adagent, targeted-ad, CoBA ads and the selected analytics and diagnostic-reporting services. Other apps may still send telemetry. |
| TV Plus, Gaming Hub and Samsung Health | Disable if unused | Samshush blocks the selected apps and Health startup paths. Shared TV Plus broadcast and channel services stay enabled. |
| PISA shared framework | Keep enabled | PISA schedules account-consent and customization services as well as ads. Block its separate adagent app to preserve those other functions. |
| Remote Management | Leave off unless needed for support | The support daemon includes packet-dump capability. That is a reason to limit remote support, not evidence of continuous packet capture. |
| HDMI-CEC / Anynet+ and ARC/eARC | Keep enabled | CEC handles device power and remote commands. ARC/eARC sends audio to the soundbar. |
| eMudhra / emSign trust roots | Remove the four selected roots | Samshush filters these roots from 11 certificate files and leaves other certificates intact. Embedded app trust stores and cached certificates are unaffected. |
| Automatic firmware updates | Turn off and update manually | Check compatibility before installing firmware. An update can reset the changes or patch the root exploit. |
| Settings, manual Art Mode, playback, browser, Netflix, networking, One Connect and DRM | Keep enabled | These provide the TV’s core functions. Preserve their shared runtimes and unrelated trust certificates. |

Apps are disabled, not uninstalled. Apple TV playback, the sidebar, input selection
and soundbar volume still work on the tested TV. This doesn’t cover every microphone
input or telemetry source. See [AGENTS.md](AGENTS.md#prove-the-outcome) for test
coverage and remaining gaps.

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

## Contributing

I'm trying a new way of accepting contributions on this repository, because the
variance in pull requests based on people's ability to prompt, review, and even
the model they're using generates a dramatic review burden. Instead.

**If you want to contribute to this, you should open an issue and concisely describe
the problem you're running into, and the feature you want to add or bug you want
to fix that solves it. If you've tested this out on a local copy, include the
concise prompt that you used, including any file changes that resolved this.**

In fact, I recommend simply copying this contributing section, or telling your
agent to follow this contribution guide when opening an issue.

**The goal here is that your problem, feature/bug, and prompt should be an input
into my agent instead, so that I can more carefully curate what gets added here
and ensure that documentation, AGENTS.md, and all tooling are moving in lockstep.**

I simply can't guarantee that a pull request is going to do all these things,
and it's often easier these days to address somebody's challenges from scratch,
or from good inputs rather than trying to review their outputs and fix them.

## Credits

I started this in mid-October after seeing [this tweet](https://x.com/lucataco/status/2111846873216553433?s=46)
from [@lucataco](https://x.com/lucataco). Getting my Frame TV to boot faster, stop
suspending volume and lose the unnecessary apps sounded great.

Then I came across [@log4j’s](https://x.com/log4j) thread on
[the spyware, adware and extremely questionable findings](https://x.com/log4j/status/2113014142600953868?s=46)
on their Samsung TV. That pushed me to see how far Astra could get rooting my TV
over the network. It turns out: pretty far!

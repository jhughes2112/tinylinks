<div align="center">
    <img alt="TinyLinks" title="TinyLinks" width="96" src="assets/logo-rounded.png">
    <h1>TinyLinks</h1>
    <p>Lightweight, OAuth-only gateway with a simple UI for protecting apps.</p>
</div>

<br />

TinyLinks is a minimal service that puts an OAuth login screen in front of your apps. It focuses on OAuth providers (e.g., GitHub, Google, generic OIDC) and intentionally does not support username/password or TOTP.

This project started as a customization of TinyAuth. Credit and thanks to the original author and community:
- Originally based on TinyAuth by steveiliop56 — https://github.com/steveiliop56/tinyauth

![Screenshot](assets/screenshot.png)

## Getting Started

- Configure your OAuth providers (GitHub/Google/Generic) and app settings in the environment or configuration file.
- Start the service and point your reverse proxy at the provided endpoints.

> Note: TinyLinks does not integrate with Docker labels and does not support username/password or TOTP. It is OAuth-only.

## Contributing

Contributions are welcome. Please open an issue or pull request with improvements or fixes.

## Acknowledgements

- TinyLinks owes its origins and much of its design to TinyAuth by steveiliop56.

## License

TinyLinks is licensed under the GNU General Public License v3.0. You may copy, distribute and modify the software as long as you track changes/dates in source files. Any modifications to or software including (via compiler) GPL-licensed code must also be made available under the GPL along with build & install instructions. See the [LICENSE](./LICENSE) file for details.

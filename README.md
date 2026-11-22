# Slipstream

> **This is a fork.** arngory/slipstream carries the server of a [raycontrol](https://github.com/arngory/raycontrol)
> node (branch `server/hardening`) and the client of [Niko](https://github.com/arngory/niko) (branch
> `client/pin-alpn-sni`): what differs and who pins them is in [FORK.md](FORK.md). The rest of this file is upstream's.

![GitHub Release](https://img.shields.io/github/v/release/EndPositive/slipstream?include_prereleases&sort=semver&display_name=tag)
![GitHub License](https://img.shields.io/github/license/EndPositive/slipstream)

A high-performance covert channel over DNS, powered by QUIC multipath.

<p align="center">
  <picture align="center">
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/file_transfer_times_dark.png">
    <source media="(prefers-color-scheme: light)" srcset="docs/assets/file_transfer_times_light.png">
    <img alt="Shows a bar chart with benchmark results." src="docs/assets/file_transfer_times_light.png">
  </picture>
</p>

<p align="center">
  <i>Exfiltrating a 10 MB file over a single DNS resolver.</i>
</p>

## Highlights

* Adaptive congestion control for rate-limited resolvers
* Parallel routing over multiple multiple rate-limited resolvers
* 60% lower header overhead than DNSTT

## Installation

Get the latest binaries [GitHub releases](https://github.com/EndPositive/slipstream/releases/latest) or pull the latest version from the [GitHub Container Registry](https://github.com/users/EndPositive/packages?repo_name=slipstream).

## Documentation

slipstream's documentation is available at [endpositive.github.io/slipstream](https://endpositive.github.io/slipstream/).

# Acknowledgements

David Fifield's DNSTT and Turbo Tunnel concept has been a massive source of inspiration.
Although slipstream inherits no code, this work could not have been possible without his ideas.

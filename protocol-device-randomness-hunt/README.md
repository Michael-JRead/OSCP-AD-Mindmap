# Predictable Randomness at Protocol & Device Scale (2026-10-23)

Round 9 is the follow-up to [round 8](../insecure-randomness-hunt/README.md). It asks where "random" values
that protect **network protocols and devices** are predictable: TCP sequence numbers, DNS query IDs, ICE/STUN
credentials, wallet keys, smart-home network keys and installer-generated passwords. Six hunters each had an
independent skeptic.

All work was local: generator code compiled into in-process harnesses, resolvers measured against our own
logging DNS server on loopback, and keys generated in our own processes. The wallet track had extra rules: no
blockchain or address data was touched, no seed-search tools were written, and determinism was shown only on
our own locally generated outputs.

> **Disclosure status:** 15 confirmed vulnerabilities (2 High, 4 Medium / Medium-High, 9 Low / Low-Medium /
> Low-Moderate),
> all **unpatched**. Details are embargoed and go to each project privately first, so affected projects are
> not named here.

## Results (aggregate)

| Track | Confirmed | Class |
|---|---|---|
| Embedded TCP/IP stacks (NUMBER:JACK / Amnesia:33 re-check, 15 stacks at current heads) | 3 (1 Medium, 2 Low) | default TCP ISNs that are a global counter or a seeded LCG, which is an **incomplete fix** of a 2021 report in one case; clock-derived DNS IDs |
| DNS stub resolvers & forwarders (25+ targets, 1–3k queries each, 7 spoof variants) | 2 (1 Medium, 1 Low) | forwarders that pass the client's transaction ID straight to the upstream, one of them an **incomplete fix** of a 2026 CVE |
| WebRTC / P2P (30+ projects) | 3 (Low / Low-Moderate) | ICE credentials, STUN IDs, SRTP keys or SCTP tags from non-CSPRNGs on some platforms; one stack accepts unauthenticated ICE check responses |
| Wallet key generation (≈80 libraries across JS, React Native, Dart, Python, Go, Rust, Java and Swift) | 1 (**High**, opt-in mode) | a key-generation CLI mode drawing private keys from a 32-bit-seeded Mersenne Twister |
| Smart-home / IoT keys | 5 (1 **High**, 1 Medium-High, 1 Medium, 1 Low-Medium, 1 Low) | a constant "entropy source" left in a vendor platform port; a Zigbee network key derived from the device MAC; a "cryptographic" RNG that is an unseeded LCG on some chip families; `Math.random` network keys |
| Install-time generators (60+ installers, charts and operators) | 1 (Low) | an installer encryption key taken from bash `$RANDOM` |

## Publishable negatives (no embargo needed)

- **Mainstream wallet libraries are clean.** Every default key and mnemonic path we traced uses a CSPRNG, and
  the React Native shims fail closed or fall back only in dev builds:
  - JS: bip39, @scure/bip39, ethers 6, viem, web3.js, @ethereumjs/wallet, bitcoinjs-lib/bip32/ecpair,
    @solana/web3.js and kit, tronweb, cosmjs, polkadot (its insecure fallback was removed in 13.5.9), algosdk,
    near, xrpl, stellar, ton.
  - Dart: the main pub.dev wallet packages.
  - Native ecosystems: the mainstream Python, Go, Rust and Java/Kotlin libraries.

  The 2023-era Milk Sad / Randstorm failure modes are not present in current mainstream libraries.
- **Mainstream DNS resolvers are fine off-path.** These have strong TXIDs plus random ports: glibc, the
  uClibc-ng CVE-2022-30295 fix (effective), Zig std, Go's pure-Go resolver, dnspython, JDK JNDI, dnsjava and
  hickory (Deno). c-ares uses CSPRNG IDs but documents its shared-port default.
- **Embedded stacks:** Zephyr, CycloneTCP, the FreeRTOS+TCP core and ESP-IDF's RFC 6528 hook are clean. Several
  others document that the integrator must supply an RNG. The risk sits in the defaults of the reference ports.
- **Smart-home hubs:** these generate network keys with a CSPRNG: Zigbee2MQTT and zigbee-herdsman,
  zigpy/bellows/ZNP/deCONZ/ZHA, and Z-Wave JS (S0, and S2 via a CTR_DRBG).
- **Installers:** we read the actual generator in each of these and found a CSPRNG with adequate length:
  - Self-hosted apps: mailcow, Nextcloud AIO, Jitsi, BigBlueButton, Discourse, Mastodon, Synapse, Sentry
    self-hosted, Supabase, Appwrite, Coolify, Plausible, Chatwoot, GitLab Omnibus, Pi-hole, Zulip.
  - VPN installers: the common ones.
  - Platform tooling: the Proxmox community scripts, YunoHost, Umbrel, TrueNAS apps, Bitnami helpers, Grafana
    chart, Rancher bootstrap, Argo CD.
  - Kubernetes operators: CloudNativePG, Zalando, Percona, MongoDB community and Strimzi.

## Takeaways
1. **Incomplete fixes again.** Two of the confirmed issues are partial fixes of earlier public reports. One
   randomized only the starting value of a counter; one replaced a single bad ID value but kept forwarding all
   the others. Re-test old reports against current code.
2. **The weak point is reference ports and fallbacks, not core libraries.** Core APIs are mostly fine. The
   problems are a platform port with a "TBD" entropy function, a fallback RNG used on some operating systems,
   and chip families where a "secure" RNG is an unseeded LCG.
3. **Device identifiers are not secrets.** MAC addresses, chip IDs and boot-constant CPU IDs are public or
   guessable. Keys must come from a hardware RNG or a properly seeded CSPRNG, not from identifiers.
4. **Defensive checks for your own fleet:** confirm RFC 6528 ISNs are enabled on embedded TCP builds. Confirm
   DNS forwarders assign their own upstream transaction IDs. Re-key smart-home networks whose keys were created
   on first boot by firmware you have not verified.

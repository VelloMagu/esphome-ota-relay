# ESPHome OTA Relay

<p>
  <a href="https://www.home-assistant.io/integrations/esphome/">
    <img src="https://brands.home-assistant.io/homeassistant/logo.png" alt="Home Assistant" height="48">
  </a>
  &nbsp;&nbsp;
  <a href="https://esphome.io/components/ota/esphome/">
    <img src="https://brands.home-assistant.io/esphome/logo.png" alt="ESPHome" height="48">
  </a>
</p>

Home Assistant add-on. It accepts a firmware image that was compiled on another computer and flashes an ESPHome device on the Home Assistant LAN. Device addresses and noise keys come from the [ESPHome integration](https://www.home-assistant.io/integrations/esphome/). The upload uses the [ESPHome OTA](https://esphome.io/components/ota/esphome/) protocol.

## Install

1. In Home Assistant, open Settings, Add-ons, Add-on store, then the menu, Repositories.
2. Add `https://github.com/VelloMagu/esphome-ota-relay`.
3. Install **ESPHome OTA Relay**.
4. Set a long random token in the add-on options and start the add-on.

The add-on uses the host network and listens on the configured port, `8096` unless you change it.

## API

Send `Authorization: Bearer <token>` on every request.

- `GET /v1/devices` returns each device `name`, `host`, and `online`. It does not return encryption keys.
- `POST /v1/devices/<name>/firmware` uploads one `firmware.ota.bin` as multipart field `firmware`, or as `application/octet-stream`.
- `GET /v1/jobs/<id>` returns `state`, `percent`, and the log tail.

ESP-IDF builds produce `.esphome/build/<name>/build/firmware.ota.bin`. Send that file. `firmware.factory.bin` is for serial flashing and is rejected.

A device is matched by its ESPHome name. The noise key and LAN address come from the ESPHome entries already stored by Home Assistant. A device that is not in Home Assistant can be listed in the add-on options with `name`, `host`, and `encryption_key`.

## Versions

Releases use semantic versions. The add-on version in `esphome_ota_relay/config.yaml` matches the git tag, starting at `0.1.0`. Notes are in `esphome_ota_relay/CHANGELOG.md`.

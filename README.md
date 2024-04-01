# Darkmode

## API

GET `https://darkmode.datasektionen.se/` - returns the current darkmode status as either `true` or `false` with the `Content-Type` header set to `application/json`.

## Env variables

| Name     | Description                                                                                                                                                               |
|----------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| PORT     | The port to listen for connections on                                                                                                                                     |
| DARKMODE | Either `true` or `false`. Defaults to `true`                                                                                                                              |
| WEBHOOKS | A list of urls separated by commas. A GET request will be sent to each of these with the header `X-Darkmode-Event: updated` when the darkmode status (might have) changed |

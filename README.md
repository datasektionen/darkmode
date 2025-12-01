# Darkmode

## API

GET `https://darkmode.datasektionen.se/` - returns the current darkmode status as either `true` or `false` with the `Content-Type` header set to `application/json`.

## Env variables

| Name                 | Description                                                                                                                                                               |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PORT`               | The port to listen for connections on                                                                                                                                     |
| `WEBHOOKS`           | A list of urls separated by commas. A GET request will be sent to each of these with the header `X-Darkmode-Event: updated` when the darkmode status (might have) changed |
| `OIDC_PROVIDOR`      | The url to oidc provider                                                                                                                                                  |
| `OIDC_CLIENT_ID`     | Client id at oidc provide                                                                                                                                                 |
| `OIDC_CLIENT_SECRET` | Secret used for connecting to oidc                                                                                                                                        |
| `OIDC_REDIRECT_URL`  | Url to redirecet back to after successful login                                                                                                                           |
| `DATABASE_URL`       | Connection settings for connecting to database. Format: postgres://username>:pasword@host:port/database                                                                   |


## Other systems

Darkmode depends on sso and hive. The system name in Hive is `darkmode` and it checks the permission `switch`.

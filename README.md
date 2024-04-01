# Darkmode

## API

GET `https://darkmode.datasektionen.se/` - returns the current darkmode status as either `true` or `false` with the `Content-Type` header set to `application/json`.

## Env variables

| Name                 | Description                                                                                                                                                               |
|----------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `PORT`               | The port to listen for connections on                                                                                                                                     |
| `WEBHOOKS`           | A list of urls separated by commas. A GET request will be sent to each of these with the header `X-Darkmode-Event: updated` when the darkmode status (might have) changed |
| `LOGIN_FRONTEND_URL` | Origin at which the browser can reach the login system's frontend                                                                                                         |
| `LOGIN_API_URL`      | Origin at which the backend can reach the login system's api                                                                                                              |
| `LOGIN_API_KEY`      | API key for login                                                                                                                                                         |
| `PLS_URL`            | Origin to pls                                                                                                                                                             |
| `REDIS_URL`          | Where to connect to redis. Example: `redis://:password@hostname:6379`                                                                                                     |

## Other systems

Darkmode depends on login and pls. The system name in pls is `darkmode` and it checks the permission `switch`.

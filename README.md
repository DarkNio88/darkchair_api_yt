# darkchair_api_yt

Tiny Node helper around `yt-dlp` to fetch metadata and stream audio to stdout.

Usage

 - Install `yt-dlp` on the host (binary must be on PATH).
 - Optionally provide cookies via `YTDLP_COOKIES` env or a `cookies.txt` in the project root.

Example

```js
const yt = require('./darkchair_api_yt');

yt.isAvailable().then(console.log);

yt.getInfo('https://www.youtube.com/watch?v=...').then(info => console.log(info.title));

const { stream, proc } = yt.stream('https://www.youtube.com/watch?v=...');
stream.pipe(process.stdout); // example: pipe raw audio to stdout
```

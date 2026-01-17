# DarkChair_API_YouTube

Tiny Node helper around `yt-dlp` to fetch metadata and stream audio to stdout.

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/Y8Y31SFJ81)

Usage

 - Install `yt-dlp` on the host (binary must be on PATH).
 - Optionally provide cookies via `YTDLP_COOKIES` env or a `cookies.txt` in the project root.
 - This module always uses `cookies.txt` from the main project folder (the parent directory of this module).
	 Place an exported `cookies.txt` there to allow access to restricted videos.
 - Alternatively you can enable browser cookie extraction by setting `YTDLP_COOKIES_FROM_BROWSER` (but the module prioritizes the project `cookies.txt`).
	 Example: `YTDLP_COOKIES_FROM_BROWSER=chrome node index.js`

Example

```js
const yt = require('darkchair_api_yt');

yt.isAvailable().then(console.log);

yt.getInfo('https://www.youtube.com/watch?v=...').then(info => console.log(info.title));

const { stream, proc } = yt.stream('https://www.youtube.com/watch?v=...');
stream.pipe(process.stdout); // example: pipe raw audio to stdout
```

# proxies
Builds a large proxy list by gathering proxies from multiple sources 🌐

## Install

```bash
GOPROXY=direct go install github.com/ogpourya/proxies@latest
````

## Run

```bash
proxies
```

## Output

* Saves deduplicated, shuffled proxies to `proxies.txt` in current folder
* Lines look like:

```
http://1.2.3.4:8080
socks5://8.8.8.8:1080
https://example.com:443
```

## Notes

* Fails silently on bad sources
* Adds protocol if missing
* Adds default port if missing (80/http, 443/https, 1080/socks)

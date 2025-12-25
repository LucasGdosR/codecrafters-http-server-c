# HTTP 1.1 From Scratch

This is my take on CodeCrafters' ["Build Your Own HTTP Server"](https://app.codecrafters.io/r/glorious-mallard-480161). Currently 14/14 stages complete, waiting for the next extension.

## Functionalities

- Accept concurrent TCP connections;
- Connections take multiple requests;
- Endpoints capturing path parameters, request bodies, servicing files, and creating files;
- Supports "Connection: close" header;
- Supports gzip compression;

## Highlights

- Single arena per thread for the entirety of the memory needs (reset per request, destroyed on disconnect);
- Destructive parsing of the request extracting method, path, headers, and body with zero copy;
- Zero copy response, allocating it in the same order of the response;
- gzip compression using `zlib.h`;

**Note**: Head over to [codecrafters.io](https://app.codecrafters.io/r/glorious-mallard-480161) to try the challenge.

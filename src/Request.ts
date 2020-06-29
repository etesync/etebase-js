interface Response {
  type: string;
  status: number;
  ok: boolean;
  statusText: string;
  body: Uint8Array;
}

export default async function request(url: string, options: RequestInit = {}): Promise<Response> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(options.method?.toUpperCase() ?? "GET", url, true);
    xhr.responseType = "arraybuffer";

    if (options.headers) {
      for (const x of Object.keys(options.headers)) {
        xhr.setRequestHeader(x, options.headers[x].toString());
      }
    }

    xhr.onload = () => {
      const body = xhr.response;

      resolve({
        type: "default",
        status: xhr.status,
        statusText: xhr.statusText,
        ok: xhr.status >= 200 && xhr.status < 300,
        body,
      });
    };

    xhr.onerror = () => {
      setTimeout(() => reject(new TypeError("Network request failed")), 0);
    };

    xhr.ontimeout = () => {
      setTimeout(() => reject(new TypeError("Network request failed")), 0);
    };

    xhr.onabort = () => {
      setTimeout(() => reject(new DOMException("Aborted", "AbortError")), 0);
    };

    xhr.send(options.body);
  });
}


# SwiftHTTP

[![Go Reference](https://pkg.go.dev/badge/github.com/SyNdicateFoundation/swifthttp.svg)](https://pkg.go.dev/github.com/SyNdicateFoundation/swifthttp)
[![Go Report Card](https://goreportcard.com/badge/github.com/SyNdicateFoundation/swifthttp)](https://goreportcard.com/report/github.com/SyNdicateFoundation/swifthttp)

**SwiftHTTP** is a powerful and flexible, high-performance HTTP client library for Go, engineered for speed, efficiency, and advanced customization. Designed by the SyNdicate Foundation, it provides a low-level interface for crafting and executing HTTP requests with precision, supporting modern protocols like HTTP/2, HTTP/3, and the legacy SPDY/3.1.

The library is built to handle millions of fast requests, offering features like connection pooling, IP spoofing, and deep customization of TLS handshakes using `uTLS` to mimic various browser fingerprints.

## 🚀 Features

-   **High Performance:** Optimized for scenarios requiring massive volumes of fast, concurrent requests.
-   **Multi-Version Protocol Support:** Full client support for `HTTP/1.1`, `HTTP/2.0`, `HTTP/3.0`, and `SPDY/3.1`.
-   **Advanced TLS Customization:** Integrates with `uTLS` to allow fine-grained control over the TLS `ClientHello`, enabling emulation of different browsers and JA3 fingerprints.
-   **LegitAgent Integration:** Seamlessly works with `legitagent` to generate realistic browser profiles, including headers, header order, and TLS signatures.
-   **IP Spoofing:** Built-in utilities to add common IP-spoofing headers (`X-Forwarded-For`, `CF-Connecting-IP`, etc.) for testing and specialized use cases.
-   **Proxy Support:** Flexible proxy integration through the `signproxy` interface.
-   **Fluent Configuration:** Utilizes a clean, fluent API with functional options for configuring clients and crafting requests.
-   **Efficient Connection Management:** Manages persistent sessions to reuse connections and reduce latency.

## ⚙️ Installation

To add SwiftHTTP to your Go project, run the following command:

```sh
go get github.com/SyNdicateFoundation/swifthttp
```

Here's a basic example of how to create a client and make a simple GET request.

```go
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/url"

	"github.com/SyNdicateFoundation/swifthttp"
)

func main() {
	// 1. Create a new default HTTP/1.1 client
	client := swifthttp.NewHttpClient()

	// 2. Parse the target URL
	targetURL, err := url.Parse("https://httpbin.org/get")
	if err != nil {
		log.Fatalf("Failed to parse URL: %v", err)
	}

	// 3. Create a persistent session to the target host
	session, err := client.CreateSession(context.Background(), targetURL)
	if err != nil {
		log.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	// 4. Create a new GET request
	httpRequest := swifthttp.NewRequest(
		swifthttp.WithSetHeader("Accept", "application/json"),
	)

	// 5. Execute the request
	resp, err := session.Request(context.Background(), httpRequest)
	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// 6. Process the response
	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read body: %v", err)
	}
	fmt.Println("Response Body:", string(body))
}
```

## 📖 Advanced Usage

### Client Configuration

SwiftHTTP's client is configured using functional options, allowing you to chain together the settings you need.

#### Setting Timeouts

Configure dial and request timeouts for more resilient networking.

```go
timeoutConfig := swifthttp.HttpTimeout{
    Dial:    5 * time.Second,
    Request: 10 * time.Second,
}

client := swifthttp.NewHttpClient(
    swifthttp.WithTimeout(timeoutConfig),
)
```

#### Using HTTP/2.0

To enable HTTP/2, simply specify the version during client creation.

```go
client := swifthttp.NewHttpClient(
    swifthttp.WithVersion(swifthttp.HttpVersion2_0),
)
```

#### Custom TLS Fingerprints with LegitAgent

Mimic a real browser's TLS `ClientHello` and headers by using `legitagent`.

```go
// Initialize a generator for realistic browser profiles
agentGenerator := legitagent.NewGenerator()

client := swifthttp.NewHttpClient(
    swifthttp.WithVersion(swifthttp.HttpVersion2_0),
    swifthttp.WithAgentGenerator(agentGenerator), // Applies JA3, headers, etc.
)
```

#### Enabling IP Spoofing Headers

Add a suite of common proxy headers to your requests.

```go
client := swifthttp.NewHttpClient(
    // Adds headers like X-Forwarded-For, CF-Connecting-IP, etc.
    // A new random IP is used for each session.
    swifthttp.WithIpSpoofer(true, false), // perSessionIp=true, useIpv6=false
)
```

### Building Requests

Requests are also built using a clean, fluent API.

#### POST Request with Body

```go
jsonData := []byte(`{"key":"value"}`)

postRequest := swifthttp.NewRequest(
    swifthttp.WithMethod(swifthttp.RequestTypePost),
    swifthttp.WithBody(jsonData, "application/json"),
    swifthttp.WithCustomPath("/post"),
)
```

#### Adding Multiple Values for a Header

Use `WithAddHeader` to append values to the same header key.

```go
requestWithMultiHeaders := swifthttp.NewRequest(
    swifthttp.WithAddHeader("X-Custom", "value1"),
    swifthttp.WithAddHeader("X-Custom", "value2"),
)
```

### Fire-and-Forget Requests

For scenarios where you don't need to process the response, use the `Fire` method. This sends the request and immediately returns without waiting for a reply, which is highly efficient for certain high-load tasks.

```go
err := session.Fire(context.Background(), httpRequest)
if err != nil {
    // Handle error related to sending the request
}
```

## Architecture Overview

SwiftHTTP is designed around three main components:

1.  **Client (`*Client`)**: The factory for creating sessions. It holds the global configuration, such as timeouts, proxy settings, and protocol version. It is safe for concurrent use.

2.  **Session (`HttpSession`)**: Represents a persistent connection (or set of streams) to a specific host. It is created from a `Client`. Sessions handle the specifics of the chosen protocol (`HTTP/1.1`, `H2`, etc.) and are responsible for connection reuse. **Sessions are generally not safe for concurrent use.** For concurrent requests to the same host, create multiple sessions or synchronize access.

3.  **Request (`*HttpRequest`)**: A lightweight struct representing an HTTP request to be sent. It is configured with functional options to set the method, body, headers, and more.

This separation allows for efficient resource management, as a single `Client` can manage multiple `Session` objects, each maintaining a long-lived connection to a different service.

## 🤝 Contributing

The SyNdicate Foundation welcomes contributors of all backgrounds. Trust is key to our success, and we invite anyone who earns our trust to join the development team. Our projects adhere to high ethical standards, and we believe in helping each other grow.

If you encounter an issue or have a feature request, please [open an issue](https://github.com/SyNdicateFoundation/swifthttp/issues) on GitHub.

## 📜 License

This project is licensed under the terms of the SyNdicate Foundation. Please see the license file for more details.
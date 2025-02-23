[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://en.wikipedia.org/wiki/MIT_License)
[![Documentation](https://img.shields.io/badge/Documentation-GoDoc-green.svg)](https://godoc.org/github.com/gford1000-go/packer)

# Packer

Packer provides a mechanism to securely serialise an `Item` comprising a key and a map of attribute names to values.

The `AES-GCM` encryption key used to encrypt attribute values is itself encrypted using an `EnvelopeKeyProvider` so that
it can be added to the serialised `Item` data, allowing later decryption provided that the `EnvelopeKeyProvider` can be retrieved.

On deserialisation, the `Item` contents are returned as an `EncryptedItem`, with the attribute values remaining encrypted until 
needed.  

```go
func main() {
    // TODO...
}
```

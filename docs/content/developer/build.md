---
title: "Building and Customizing Trojan-Go"
draft: false
weight: 10
---

Building requires a Go version higher than 1.26. Please verify your compiler version before building. It is recommended to use snap to install and update Go.

Compilation is straightforward. You can use the Makefile preset steps to compile:

```shell
make
make install #install systemd service, etc. (optional)
```

Or use Go directly to compile:

```shell
go build -tags "full" #build the full version
```

You can specify the target OS and architecture for cross-compilation by setting the GOOS and GOARCH environment variables, for example

```shell
GOOS=windows GOARCH=386 go build -tags "full" #windows x86
GOOS=linux GOARCH=arm64 go build -tags "full" #linux arm64
```

You can use release.sh for batch cross-compilation across multiple platforms; this script is used to build the release versions.

Most modules in Trojan-Go are pluggable. You can find the import declarations for each module in the build folder. If you do not need certain features or want to reduce the size of the executable, you can customize modules using build tags, for example

```shell
go build -tags "full" #build all modules
go build -tags "client" -trimpath -ldflags="-s -w -buildid=" #client-only, with symbol table stripped to reduce size
go build -tags "server mysql" #server and mysql support only
```

Using the full tag is equivalent to

```shell
go build -tags "api client server forward nat other"
```

# AutoVHost - Apache Dynamic Virtual Host Module

> **Note**: This is legacy code preserved for historical/archeological purposes. It is not suitable for production use.

## Overview

AutoVHost is an Apache HTTP Server module for dynamic, automatic virtual host resolution. It automatically maps incoming HTTP requests to the correct document root and configuration based on the requested hostname, eliminating the need for explicit VirtualHost configuration in Apache.

This module was developed by **Tibanne Co., Ltd.** for shared hosting environments where multiple domains could be served from a single Apache instance with automatic directory mapping and per-virtual-host configuration management.

## Technologies

- **Language**: C (C99 standard)
- **Build System**: GNU Autotools (Autoconf, Automake, Libtool)
- **Target**: Apache 2.x (with APR - Apache Portable Runtime)
- **Platform**: Linux/POSIX

## Components

### Core Module: `mod_autovhost.c`

The main Apache module providing:

- **Host Scanning**: Validates and normalizes hostnames, implements intelligent domain fallback logic
- **Path Resolution**: Tests filesystem paths using pattern `/prefix/x/xy/host/vhost/` with symlink support
- **Request Translation**: Apache hook that intercepts requests, determines document root, and loads per-vhost configuration
- **Request Logging**: Collects detailed request/response information and sends via Unix sockets to logging daemons

### Utility Daemons

| Daemon | Purpose |
|--------|---------|
| `write_daemon.c` | Receives log data via Unix socket, writes to timestamped log files |
| `transmit_daemon.c` | Receives log data, buffers and forwards to remote TCP server |

### Configuration Tools

| File | Purpose |
|------|---------|
| `gen_conf.php` | PHP utility to generate binary `.config` files for virtual hosts |
| `read_socket.php` | Test utility to receive and decode log packets |

## Architecture

```
Request Flow:
┌─────────────────────────────────────────────────────────────┐
│ HTTP Request arrives at Apache                              │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
     ┌───────────────────────────────────┐
     │ mod_autovhost_translate() hook    │
     │ (APR_HOOK_FIRST priority)         │
     └────────────┬──────────────────────┘
                  │
                  ▼
     ┌───────────────────────────────────┐
     │ scan_host() - Hostname Lookup:    │
     │ • Validate hostname               │
     │ • Test vhost directories          │
     │ • Progressive domain fallback     │
     │ • Symlink resolution (aliases)    │
     └────────────┬──────────────────────┘
                  │
                  ▼
     ┌───────────────────────────────────┐
     │ Load *.config binary file         │
     │ Set document root                 │
     │ Inject PHP directives dynamically │
     │ Set security limits (open_basedir)│
     └────────────┬──────────────────────┘
                  │
                  ▼
     ┌───────────────────────────────────┐
     │ Apache continues processing       │
     └───────────────────────────────────┘
```

### Virtual Host Directory Structure

```
/prefix/
  ├── e/
  │   ├── ex/
  │   │   ├── example.com/
  │   │   │   ├── www/          (document root)
  │   │   │   ├── mail/
  │   │   │   ├── sessions/
  │   │   │   └── example.com_www.config
```

The first two characters of the hostname are used for filesystem sharding.

## Features

### Security
- Strict hostname character whitelist (a-z, 0-9, . - _)
- PHP `open_basedir` confinement per vhost
- Per-vhost session storage isolation
- Symlink depth limiting (max 5 levels)

### Performance
- Filesystem sharding prevents large directories
- Circular buffers for efficient memory management in daemons
- Unix domain sockets for fast inter-process logging
- Binary config format for compact storage
- Lazy daemon spawning

### Domain Resolution
- Progressive fallback: specific vhost → www → _default
- Symlink-based domain aliasing
- Subdomain routing via symlink targets

## Building

Using Autotools:
```bash
./genconf.sh
./configure
make
make install
```

Quick install (requires APXS):
```bash
./quick_install.sh
```

## Historical Notes

### Why This Was Created

In the early 2000s, Apache 1.3 required a full restart to reload configuration, and even with Apache 2.x, many hosting providers only reloaded their httpd configuration at specific intervals (often hourly or daily). This meant customers had to wait before their newly provisioned websites would work.

AutoVHost solved this by eliminating the need for Apache configuration changes entirely. The system only needed to create the directory structure on disk, and the new virtual host was immediately available. This allowed Tibanne's **KalyHost** brand to offer web hosting that was available instantly upon signup - a significant competitive advantage at the time.

### Technical Notes

- Uses Apache private APIs (`#define CORE_PRIVATE`) for direct config manipulation
- Contains colorful code comments reflecting its production battle-testing
- Last updated for Apache 2.4+ compatibility
- Discontinued in 2015

## License

MIT License - See [COPYING](COPYING) for details.

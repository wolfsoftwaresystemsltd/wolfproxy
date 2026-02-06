# WolfProxy

[![Support me on Patreon](https://img.shields.io/badge/Patreon-Support%20Me-F96854?style=for-the-badge&logo=patreon&logoColor=white)](https://www.patreon.com/15362110/join)

A high-performance Rust-based reverse proxy server that reads and uses nginx configuration files directly.

**(C) 2025 Wolf Software Systems Ltd - http://wolf.uk.com**

## Features

- **Drop-in nginx replacement**: Reads nginx sites-enabled configuration directly
- **Automatic SSL/TLS**: Automatically picks up SSL certificates from nginx config (Let's Encrypt, etc.)
- **Load Balancing**: Full upstream support with multiple algorithms:
  - Round Robin
  - Weighted Round Robin
  - IP Hash (sticky sessions)
  - Least Connections
  - Random
- **Health Checking**: Automatic backend health monitoring with configurable thresholds
- **SNI Support**: Proper Server Name Indication for multiple SSL domains
- **HTTP/1.1 & HTTP/2**: Full protocol support
- **Monitoring Dashboard**: Built-in web interface to monitor upstream servers and traffic (port 5001)

## Quick Install

Install WolfProxy with a single command:

```bash
curl -sL https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | sudo bash
```

Or using wget:

```bash
wget -qO- https://raw.githubusercontent.com/wolfsoftwaresystemsltd/wolfproxy/main/setup.sh | sudo bash
```

### What the Installer Does

The one-line installer performs the following steps automatically:

1. **Detects your package manager** (apt, dnf, yum, pacman, or zypper)
2. **Installs build dependencies:**
   - **Debian/Ubuntu (apt):** `build-essential pkg-config libssl-dev git curl`
   - **RHEL/Fedora (dnf/yum):** `gcc gcc-c++ make pkg-config openssl-devel git curl`
   - **Arch (pacman):** `base-devel openssl git curl`
   - **openSUSE (zypper):** `gcc gcc-c++ make pkg-config libopenssl-devel git curl`
3. **Installs Rust** via rustup if not already present
4. **Clones the repository** to `/opt/wolfproxy` (or updates if already installed)
5. **Builds WolfProxy** in release mode
6. **Creates the systemd service** (`/etc/systemd/system/wolfproxy.service`)
7. **Creates default configuration** (`/opt/wolfproxy/wolfproxy.toml`)

### After Installation

```bash
# Stop nginx first (WolfProxy replaces nginx)
sudo systemctl stop nginx && sudo systemctl disable nginx

# Start WolfProxy
sudo systemctl start wolfproxy

# Enable on boot
sudo systemctl enable wolfproxy

# View logs
journalctl -u wolfproxy -f
```

### Installation Paths

| Item | Path |
|------|------|
| Binary | `/opt/wolfproxy/target/release/wolfproxy` |
| Configuration | `/opt/wolfproxy/wolfproxy.toml` |
| Service | `/etc/systemd/system/wolfproxy.service` |

For manual installation, see [Installation](#installation) below.

## Supported nginx Directives

### Server Block
- `listen` - Port and SSL configuration
- `server_name` - Virtual host names
- `root` - Document root
- `index` - Index files
- `error_page` - Custom error pages
- `ssl_certificate` / `ssl_certificate_key` - SSL certificates
- `include` - Include other config files
- `gzip` - Compression (header support)

### Location Block
- `location` - Path matching (prefix, exact `=`, regex `~`, case-insensitive `~*`, priority `^~`)
- `proxy_pass` - Reverse proxy to backend or upstream
- `proxy_set_header` - Set headers for backend
- `proxy_http_version` - HTTP version for backend
- `proxy_buffer_size` / `proxy_buffers` - Buffer configuration
- `proxy_connect_timeout` / `proxy_read_timeout` / `proxy_send_timeout` - Timeouts
- `root` / `alias` - Static file serving
- `try_files` - Try multiple files
- `return` - Return status codes or redirects
- `rewrite` - URL rewriting
- `deny` / `allow` - Access control
- `add_header` - Add response headers

### Upstream Block
- `upstream` - Define backend server groups
- `server` - Backend servers with options:
  - `weight` - Server weight
  - `max_fails` - Failure threshold
  - `fail_timeout` - Recovery timeout
  - `backup` - Backup server
  - `down` - Mark server as down
- `ip_hash` - Sticky sessions
- `least_conn` - Least connections balancing
- `wolfscale` - **WolfScale cluster mode** (writes to leader, reads load-balanced)
- `keepalive` - Connection pooling

### Conditionals
- `if ($host = ...)` - Host-based conditions
- `if ($request_method = ...)` - Method-based conditions

## Installation

### Prerequisites

- Rust 1.70+ (https://rustup.rs)
- Existing nginx configuration in `/etc/nginx/sites-enabled/`

### Build

```bash
./build.sh
```

Or manually:

```bash
cargo build --release
```

### Run

```bash
./run.sh
```

Or:

```bash
./target/release/wolfproxy
```

### Install as Service

```bash
sudo ./install_service.sh
```

This will:
1. Copy the binary to `/opt/wolfproxy/`
2. Create a systemd service
3. Optionally stop nginx and start WolfProxy

## Configuration

WolfProxy uses a simple TOML configuration file (`wolfproxy.toml`):

```toml
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443

[nginx]
config_dir = "/etc/nginx"
auto_reload = false

[monitoring]
enabled = true
port = 5001
username = "admin"
password = "admin"
```

The nginx configuration is read from:
- `{config_dir}/sites-enabled/` - Site configuration files
- `{config_dir}/conf.d/*.conf` - Additional configuration files

## Example nginx Configuration

WolfProxy will read standard nginx configuration like:

```nginx
upstream backend {
    ip_hash;
    server 10.0.10.105 max_fails=3 fail_timeout=360s;
    server 10.0.10.102 max_fails=3 fail_timeout=360s;
    server 10.0.10.103 max_fails=3 fail_timeout=360s;
}

server {
    listen 80;
    listen [::]:80;
    server_name example.com;

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
}
```

## WolfScale Integration

WolfProxy has built-in support for [WolfScale](https://github.com/wolfsoftware/wolfscale) distributed database clusters. When using the `wolfscale` directive, WolfProxy automatically routes:

- **Write requests** (POST, PUT, DELETE, PATCH) → **Leader node** only
- **Read requests** (GET, HEAD, OPTIONS) → **Load balanced** across all healthy nodes

### Example Configuration

```nginx
upstream wolfscale_cluster {
    wolfscale;  # Enable WolfScale cluster mode
    server wolftest1:8080 max_fails=3 fail_timeout=10s;
    server wolftest2:8080 max_fails=3 fail_timeout=10s;
    server wolftest3:8080 max_fails=3 fail_timeout=10s;
}

server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://wolfscale_cluster;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### How It Works

1. WolfProxy queries each node's `/status` API endpoint to determine the current leader
2. Write requests are forwarded to the leader to maintain consistency
3. Read requests are distributed across all healthy nodes for horizontal scaling
4. If the leader changes (failover), WolfProxy automatically detects and adjusts routing

### Benefits

- **Automatic failover**: No manual reconfiguration when leadership changes
- **Read scaling**: Distribute read load across all cluster nodes
- **Write consistency**: All writes go to the leader for proper replication
- **Zero downtime**: Seamless handling of leader elections

## Migration from nginx

1. **Stop nginx**: `sudo systemctl stop nginx`
2. **Install WolfProxy**: `sudo ./install_service.sh`
3. **Start WolfProxy**: `sudo systemctl start wolfproxy`
4. **Verify**: Check your sites are working
5. **Disable nginx**: `sudo systemctl disable nginx`
6. **Enable WolfProxy**: `sudo systemctl enable wolfproxy`

## Logging

Set the `RUST_LOG` environment variable to control log level:

```bash
RUST_LOG=debug ./target/release/wolfproxy
```

Levels: `trace`, `debug`, `info`, `warn`, `error`

## Monitoring Dashboard

WolfProxy includes a built-in monitoring dashboard accessible at `http://your-server:5001/`.

### Features
- **Real-time stats**: Uptime, total requests, data in/out
- **Upstream monitoring**: View all backend servers with their status (UP/DOWN)
- **Health metrics**: Active connections, request counts, failure counts per server
- **Traffic by upstream**: See request counts per upstream group
- **Load balancing info**: Shows load balancing method per upstream group
- **Auto-refresh**: Dashboard updates every 5 seconds
- **JSON API**: Available at `/stats` for programmatic access
- **Settings page**: Change username/password via web interface at `/settings`

### Configuration

```toml
[monitoring]
enabled = true       # Enable/disable the monitoring server
port = 5001          # Port for the monitoring interface
username = "admin"   # HTTP Basic Auth username
password = "admin"   # HTTP Basic Auth password
```

### Changing Credentials

You can change the monitoring credentials in two ways:

1. **Via Web Interface**: Navigate to `http://your-server:5001/settings` and use the form to update credentials
2. **Via Config File**: Edit `wolfproxy.toml` and restart the service

### Security

The monitoring dashboard is protected with HTTP Basic Authentication. **Change the default credentials** in production!

## Comparison with nginx

| Feature | nginx | WolfProxy |
|---------|-------|-----------|
| Configuration | nginx native | nginx native (reads directly) |
| Memory Usage | Low | Very Low |
| Performance | Excellent | Excellent |
| SSL/TLS | Yes | Yes (auto-detect from config) |
| HTTP/2 | Yes | Yes |
| Load Balancing | Yes | Yes |
| Built-in Monitoring | No (requires third-party) | Yes (web dashboard) |
| Lua Scripting | Yes | No |
| Module System | Yes | No (but extensible in Rust) |

## WordPress Behind WolfProxy

When running WordPress behind WolfProxy (or any reverse proxy), you may encounter issues such as:

- "Cookies are blocked or not supported by your browser" login errors
- Redirect loops
- Mixed content warnings
- Session issues

### Recommended nginx Configuration for WordPress

For WordPress sites, use this location block configuration:

```nginx
server {
    listen 443 ssl;
    server_name your-wordpress-site.com;

    ssl_certificate /etc/letsencrypt/live/your-wordpress-site.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-wordpress-site.com/privkey.pem;

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Cookie handling for WordPress
        proxy_set_header Cookie $http_cookie;
        proxy_pass_header Set-Cookie;
        proxy_cookie_path / /;
        
        # Disable buffering for better cookie handling
        proxy_buffering off;
        
        proxy_pass http://backend_servers;
    }
}
```

### WordPress wp-config.php Settings

Add these lines to your `wp-config.php` file (before "That's all, stop editing!"):

```php
/**
 * Reverse Proxy Configuration
 * Required when WordPress is behind a reverse proxy like WolfProxy
 */

// Trust the proxy's X-Forwarded-Proto header for HTTPS detection
if (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') {
    $_SERVER['HTTPS'] = 'on';
}

// Trust X-Forwarded-For for real client IP
if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $forwarded_ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
    $_SERVER['REMOTE_ADDR'] = trim($forwarded_ips[0]);
}

// Force SSL for admin (recommended)
define('FORCE_SSL_ADMIN', true);

// Optional: Set cookie domain if you have issues with subdomains
// define('COOKIE_DOMAIN', 'your-wordpress-site.com');

// Optional: Define site URL to prevent redirect loops
// define('WP_HOME', 'https://your-wordpress-site.com');
// define('WP_SITEURL', 'https://your-wordpress-site.com');
```

### Troubleshooting WordPress Cookie Issues

1. **Clear your browser cookies** for the WordPress site after making configuration changes

2. **Check that your site URL is correct** in WordPress Settings → General (Site URL and WordPress URL should both use `https://`)

3. **Verify headers are being passed** by checking your server logs or using browser developer tools to inspect request/response headers

4. **If using load balancing with multiple backends**, ensure you're using `ip_hash` for sticky sessions:
   ```nginx
   upstream backend_servers {
       ip_hash;
       server 10.0.10.101;
       server 10.0.10.102;
   }
   ```

5. **Check for redirect loops** - if WordPress and your proxy disagree about HTTP vs HTTPS, you'll get infinite redirects. The `X-Forwarded-Proto` header and `wp-config.php` settings above should fix this.

## License

MIT License - See LICENSE file

## Support

- Website: http://wolf.uk.com
- Issues: GitHub Issues

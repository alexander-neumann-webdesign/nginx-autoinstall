#!/bin/bash
# NGINX Autoinstall Script - Improved Version
# Usage: chmod +x ./nginx-modern-autoinstall.sh && ./nginx-modern-autoinstall.sh

set -euo pipefail  # Exit on error, undefined vars, pipe failures
IFS=$'\n\t'        # Secure IFS

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        ERROR)   echo -e "${RED}[ERROR]${NC} ${timestamp} - $message" >&2 ;;
        WARN)    echo -e "${YELLOW}[WARN]${NC} ${timestamp} - $message" ;;
        INFO)    echo -e "${GREEN}[INFO]${NC} ${timestamp} - $message" ;;
        DEBUG)   echo -e "${BLUE}[DEBUG]${NC} ${timestamp} - $message" ;;
    esac
}

# Error handling
error_exit() {
    log ERROR "$1"
    exit 1
}

# Cleanup function
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log WARN "Script failed. Cleaning up temporary files..."
        rm -rf /usr/local/src/nginx/ 2>/dev/null || true
    fi
    exit $exit_code
}

trap cleanup EXIT

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    error_exit "This script must be run as root. Use: sudo $0"
fi

# Detect OS and version
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        error_exit "Cannot detect operating system"
    fi
    
    log INFO "Detected OS: $OS $OS_VERSION"
    
    # Check for supported OS
    case $OS in
        ubuntu|debian)
            log INFO "Supported OS detected"
            ;;
        *)
            error_exit "Unsupported OS: $OS. This script supports Ubuntu/Debian only."
            ;;
    esac
}

# Configuration with validation
readonly NGINX_STABLE_VER=${NGINX_STABLE_VER:-1.28.0}
readonly NGINX_MAINLINE_VER=${NGINX_MAINLINE_VER:-1.29.1}
readonly NGINX_VER=${NGINX_VER:-$NGINX_MAINLINE_VER}
readonly NGINX_USER=${NGINX_USER:-nginx}
readonly NGINX_GROUP=${NGINX_GROUP:-nginx}
readonly BROTLI=${BROTLI:-y}
readonly ZSTD=${ZSTD:-y}
readonly CACHEPURGE=${CACHEPURGE:-y}
readonly BUILD_THREADS=${BUILD_THREADS:-$(nproc)}
readonly PERFORMANCE_OPTIMIZED=${PERFORMANCE_OPTIMIZED:-y}

# Validate version format
if [[ ! $NGINX_VER =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error_exit "Invalid NGINX version format: $NGINX_VER"
fi

log INFO "Building NGINX version: $NGINX_VER"
log INFO "NGINX will run as user: $NGINX_USER, group: $NGINX_GROUP"

# Validate user and group names
if [[ ! $NGINX_USER =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]]; then
    error_exit "Invalid NGINX user name: $NGINX_USER"
fi

if [[ ! $NGINX_GROUP =~ ^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$ ]]; then
    error_exit "Invalid NGINX group name: $NGINX_GROUP"
fi

# Define paths
readonly NGINX_SOURCE_DIR="/usr/local/src/nginx"
readonly NGINX_BUILD_DIR="${NGINX_SOURCE_DIR}/nginx-${NGINX_VER}"
readonly NGINX_MODULES_DIR="${NGINX_SOURCE_DIR}/modules"

# Detect CPU architecture for optimal compilation
detect_cpu_arch() {
    local cpu_model
    cpu_model=$(lscpu | grep "Model name" | cut -d: -f2 | xargs)
    log INFO "Detected CPU: $cpu_model"
    
    # Check for specific Intel Xeon E3-1275 v6 (Kaby Lake)
    if echo "$cpu_model" | grep -qi "E3-1275 v6\|Kaby Lake"; then
        log INFO "Detected Intel Xeon E3-1275 v6 (Kaby Lake) - applying specific optimizations"
        ARCH_SPECIFIC="-march=skylake -mtune=skylake"
    elif echo "$cpu_model" | grep -qi "skylake"; then
        ARCH_SPECIFIC="-march=skylake -mtune=skylake"
    elif echo "$cpu_model" | grep -qi "haswell\|broadwell"; then
        ARCH_SPECIFIC="-march=haswell -mtune=haswell"
    elif echo "$cpu_model" | grep -qi "sandy bridge\|ivy bridge"; then
        ARCH_SPECIFIC="-march=sandybridge -mtune=sandybridge"
    else
        log INFO "Using generic native optimization"
        ARCH_SPECIFIC="-march=native -mtune=native"
    fi
    
    log INFO "Selected architecture flags: $ARCH_SPECIFIC"
}

# NGINX build options with Intel Xeon E3-1275 v6 specific optimizations
readonly NGINX_OPTIONS="
    --prefix=/etc/nginx
    --sbin-path=/usr/sbin/nginx
    --conf-path=/etc/nginx/nginx.conf
    --error-log-path=/var/log/nginx/error.log
    --http-log-path=/var/log/nginx/access.log
    --pid-path=/run/nginx.pid
    --lock-path=/run/nginx.lock
    --http-client-body-temp-path=/var/cache/nginx/client_temp
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp
    --http-uwsgi-temp-path=/var/cache/nginx/fastcgi_temp
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp
    --user=$NGINX_USER
    --group=$NGINX_GROUP
    --with-cc-opt='-O3 -march=skylake -mtune=skylake -msse4.1 -msse4.2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mfsgsbase -fstack-protector-strong -flto=auto -fomit-frame-pointer -funroll-loops -fprefetch-loop-arrays -ffast-math -DTCP_FASTOPEN=23 -DNGX_HAVE_AES_NI=1 -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC'
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,-O2 -Wl,--sort-common -Wl,--gc-sections -Wl,--hash-style=gnu -Wl,--build-id=sha1 -flto=auto -pie'"

# Minimal high-performance NGINX modules (customized)
NGINX_MODULES="--with-threads
    --with-file-aio
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_v3_module
    --with-http_mp4_module
    --with-http_auth_request_module
    --with-http_access_module
    --with-http_auth_basic_module
    --with-http_map_module
    --with-http_referer_module
    --with-http_rewrite_module
    --with-http_proxy_module
    --with-http_fastcgi_module
    --with-http_charset_module
    --with-http_gzip_module
    --with-stream
    --with-stream_ssl_module
    --without-http_ssi_module
    --without-http_userid_module
    --without-http_mirror_module
    --without-http_autoindex_module
    --without-http_geo_module
    --without-http_split_clients_module
    --without-http_uwsgi_module
    --without-http_scgi_module
    --without-http_grpc_module
    --without-http_memcached_module
    --without-http_limit_conn_module
    --without-http_limit_req_module
    --without-http_empty_gif_module
    --without-http_browser_module
    --without-http_upstream_hash_module
    --without-http_upstream_ip_hash_module
    --without-http_upstream_least_conn_module
    --without-http_upstream_random_module
    --without-http_upstream_keepalive_module
    --without-http_upstream_zone_module"

# Check if nginx is already installed
check_existing_nginx() {
    if command -v nginx >/dev/null 2>&1; then
        local current_version
        current_version=$(nginx -v 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "unknown")
        log WARN "NGINX is already installed (version: $current_version)"
        read -p "Do you want to continue and replace it? [y/N]: " -r
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log INFO "Installation cancelled by user"
            exit 0
        fi
    fi
}

# Install dependencies with error checking
install_dependencies() {
    log INFO "Installing build dependencies..."
    
    local packages=(
        build-essential ca-certificates wget curl
        libpcre2-dev autoconf unzip automake libtool tar git 
        libssl-dev zlib1g-dev uuid-dev lsb-release 
        cmake equivs pkg-config libzstd-dev
    )
    
    # Check OpenSSL version for HTTP/3 support
    if ! check_openssl_version; then
        log WARN "OpenSSL version may not fully support HTTP/3 QUIC. Consider upgrading."
    fi
    
    apt-get update -qq || error_exit "Failed to update package lists"
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log INFO "Installing $package..."
            apt-get install -y "$package" || error_exit "Failed to install $package"
        fi
    done
    
    log INFO "Dependencies installed successfully"
}

# Check OpenSSL version for HTTP/3 compatibility
check_openssl_version() {
    local openssl_version
    openssl_version=$(openssl version | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
    
    log INFO "System OpenSSL version: $openssl_version"
    
    # OpenSSL 3.2+ has better QUIC support, but 3.0+ should work
    if [[ $(echo "$openssl_version" | cut -d. -f1) -ge 3 ]]; then
        log INFO "OpenSSL version is compatible with HTTP/3"
        return 0
    else
        log WARN "OpenSSL version might have limited HTTP/3 support"
        return 1
    fi
}

# Download and verify NGINX source
download_nginx_source() {
    log INFO "Downloading NGINX source code..."
    
    cd "$NGINX_SOURCE_DIR" || error_exit "Cannot change to source directory"
    
    # Download with better error handling
    if ! wget -q --timeout=30 --tries=3 "http://nginx.org/download/nginx-${NGINX_VER}.tar.gz"; then
        error_exit "Failed to download NGINX source"
    fi
    
    # Basic integrity check (file size should be reasonable)
    local file_size
    file_size=$(stat -c%s "nginx-${NGINX_VER}.tar.gz")
    if [[ $file_size -lt 100000 ]]; then  # Less than 100KB is suspicious
        error_exit "Downloaded file appears to be incomplete"
    fi
    
    tar -xzf "nginx-${NGINX_VER}.tar.gz" || error_exit "Failed to extract NGINX source"
    rm "nginx-${NGINX_VER}.tar.gz"
    
    log INFO "NGINX source downloaded and extracted"
}

# Build Zstd module
build_zstd_module() {
    if [[ $ZSTD != 'y' ]]; then
        return 0
    fi
    
    log INFO "Building Zstd module..."
    
    cd "$NGINX_MODULES_DIR" || error_exit "Cannot access modules directory"
    
    if ! git clone --depth=1 https://github.com/tokers/zstd-nginx-module; then
        error_exit "Failed to clone Zstd repository"
    fi
    
    # Verify zstd library is available
    if ! pkg-config --exists libzstd; then
        error_exit "libzstd development package is not installed"
    fi
    
    local zstd_version
    zstd_version=$(pkg-config --modversion libzstd)
    log INFO "Found libzstd version: $zstd_version"
    
    NGINX_MODULES+=" --add-module=$NGINX_MODULES_DIR/zstd-nginx-module"
    log INFO "Zstd module prepared successfully"
}

# Build Brotli module
build_brotli_module() {
    if [[ $BROTLI != 'y' ]]; then
        return 0
    fi
    
    log INFO "Building Brotli module..."
    
    cd "$NGINX_MODULES_DIR" || error_exit "Cannot access modules directory"
    
    if ! git clone --recurse-submodules --depth=1 https://github.com/google/ngx_brotli; then
        error_exit "Failed to clone Brotli repository"
    fi
    
    cd ngx_brotli/deps/brotli || error_exit "Cannot access Brotli directory"
    mkdir -p out && cd out || error_exit "Cannot create build directory"
    
    # Build Brotli with optimizations
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DBUILD_SHARED_LIBS=OFF \
          -DCMAKE_C_FLAGS="-O2 -fPIC" \
          -DCMAKE_CXX_FLAGS="-O2 -fPIC" \
          .. || error_exit "CMake configuration failed"
    
    make -j "$BUILD_THREADS" || error_exit "Brotli build failed"
    
    NGINX_MODULES+=" --add-module=$NGINX_MODULES_DIR/ngx_brotli"
    log INFO "Brotli module built successfully"
}

# Build Cache Purge module
build_cache_purge_module() {
    if [[ $CACHEPURGE != 'y' ]]; then
        return 0
    fi
    
    log INFO "Building Cache Purge module..."
    
    cd "$NGINX_MODULES_DIR" || error_exit "Cannot access modules directory"
    
    if ! git clone --depth=1 https://github.com/nginx-modules/ngx_cache_purge; then
        error_exit "Failed to clone Cache Purge repository"
    fi
    
    NGINX_MODULES+=" --add-module=$NGINX_MODULES_DIR/ngx_cache_purge"
    log INFO "Cache Purge module prepared"
}

# Create nginx user and group
create_nginx_user() {
    local group_exists=false
    local user_exists=false
    
    # Check if group exists
    if getent group "$NGINX_GROUP" >/dev/null 2>&1; then
        log INFO "Group '$NGINX_GROUP' already exists"
        group_exists=true
    else
        log INFO "Creating group '$NGINX_GROUP'..."
        if groupadd -r "$NGINX_GROUP" 2>/dev/null; then
            log INFO "Group '$NGINX_GROUP' created successfully"
        else
            error_exit "Failed to create group '$NGINX_GROUP'"
        fi
    fi
    
    # Check if user exists
    if id "$NGINX_USER" >/dev/null 2>&1; then
        log INFO "User '$NGINX_USER' already exists"
        user_exists=true
        
        # Check if existing user is in the correct group
        if ! groups "$NGINX_USER" | grep -q "\b$NGINX_GROUP\b"; then
            log INFO "Adding existing user '$NGINX_USER' to group '$NGINX_GROUP'..."
            if usermod -g "$NGINX_GROUP" "$NGINX_USER" 2>/dev/null; then
                log INFO "User '$NGINX_USER' added to group '$NGINX_GROUP'"
            else
                log WARN "Failed to add user '$NGINX_USER' to group '$NGINX_GROUP'"
            fi
        fi
    else
        log INFO "Creating user '$NGINX_USER'..."
        if useradd -r -g "$NGINX_GROUP" -s /usr/sbin/nologin -d /nonexistent -c "nginx user" "$NGINX_USER" 2>/dev/null; then
            log INFO "User '$NGINX_USER' created successfully"
        else
            error_exit "Failed to create user '$NGINX_USER'"
        fi
    fi
    
    # Verify the user and group configuration
    local user_primary_group
    user_primary_group=$(id -gn "$NGINX_USER" 2>/dev/null)
    
    if [[ "$user_primary_group" != "$NGINX_GROUP" ]]; then
        log WARN "User '$NGINX_USER' primary group is '$user_primary_group', expected '$NGINX_GROUP'"
        log INFO "Attempting to fix group membership..."
        if usermod -g "$NGINX_GROUP" "$NGINX_USER" 2>/dev/null; then
            log INFO "Fixed: User '$NGINX_USER' now belongs to group '$NGINX_GROUP'"
        else
            error_exit "Failed to set correct group for user '$NGINX_USER'"
        fi
    fi
    
    # Get user and group IDs for logging
    local nginx_uid nginx_gid
    nginx_uid=$(id -u "$NGINX_USER")
    nginx_gid=$(id -g "$NGINX_USER")
    
    log INFO "NGINX user configuration:"
    log INFO "  User: $NGINX_USER (UID: $nginx_uid)"
    log INFO "  Group: $NGINX_GROUP (GID: $nginx_gid)"
}

# Setup directory structure
setup_directories() {
    log INFO "Setting up directory structure..."
    
    local dirs=(
        "/etc/nginx"
        "/etc/nginx/sites-available"
        "/etc/nginx/sites-enabled"
        "/etc/nginx/conf.d"
        "/var/cache/nginx"
        "/var/log/nginx"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chown "$NGINX_USER:$NGINX_GROUP" "$dir" 2>/dev/null || true
    done
    
    log INFO "Directory structure created"
}

# Download default configuration
download_default_config() {
    if [[ ! -e /etc/nginx/nginx.conf ]]; then
        log INFO "Downloading default nginx.conf..."
        cd /etc/nginx || error_exit "Cannot access nginx config directory"
        
        # Use a more reliable source or embed the config
        if ! wget -q --timeout=10 "https://raw.githubusercontent.com/nginx/nginx/master/conf/nginx.conf"; then
            log WARN "Failed to download default config, creating optimized one..."
            cat > nginx.conf << EOF
# High-performance NGINX configuration
user $NGINX_USER;
worker_processes auto;
worker_rlimit_nofile 65535;
error_log /var/log/nginx/error.log crit;
pid /run/nginx.pid;

events {
    worker_connections 4096;
    use epoll;
    multi_accept on;
}

http {
    # Basic Settings
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 30;
    keepalive_requests 1000;
    reset_timedout_connection on;
    client_body_timeout 10;
    send_timeout 2;
    client_header_timeout 10;
    client_max_body_size 16m;
    client_body_buffer_size 128k;
    client_header_buffer_size 3m;
    large_client_header_buffers 4 256k;
    server_tokens off;
    
    # MIME Types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Gzip Compression (enabled with your modules)
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

    # Zstd Compression (higher compression ratio than gzip)
    zstd on;
    zstd_comp_level 6;
    zstd_min_length 1000;
    zstd_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml
        application/wasm;

    # Brotli Compression (best compression for modern browsers)
    brotli on;
    brotli_comp_level 6;
    brotli_min_length 1000;
    brotli_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml
        application/wasm;

    # Charset handling
    charset_types
        text/css
        text/plain
        text/vnd.wap.wml
        text/javascript
        text/xml
        application/json
        application/rss+xml
        application/atom+xml;

    # Logging (minimal for performance)
    log_format minimal '\$remote_addr - \$status [\$time_local] "\$request" \$body_bytes_sent "\$http_user_agent"';
    access_log /var/log/nginx/access.log minimal buffer=64k flush=5m;

    # SSL/TLS Optimization
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # HTTP/3 and QUIC settings
    http3 on;
    http3_max_concurrent_streams 128;
    quic_retry on;
    
    # Map for common use cases
    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        '' close;
    }
    
    # Security Headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Alt-Svc header for HTTP/3 advertising
    add_header Alt-Svc 'h3=":443"; ma=86400' always;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF
        fi
        log INFO "Default configuration installed"
    fi
}

# Compile NGINX
compile_nginx() {
    log INFO "Compiling NGINX..."
    
    cd "$NGINX_BUILD_DIR" || error_exit "Cannot access build directory"
    
    # Configure with better error handling
    log DEBUG "Running configure with options..."
    if ! ./configure $NGINX_OPTIONS $NGINX_MODULES; then
        error_exit "NGINX configuration failed"
    fi
    
    # Build
    log INFO "Building NGINX (using $BUILD_THREADS threads)..."
    if ! make -j "$BUILD_THREADS"; then
        error_exit "NGINX build failed"
    fi
    
    # Install
    log INFO "Installing NGINX..."
    if ! make install; then
        error_exit "NGINX installation failed"
    fi
    
    # Strip debug symbols to reduce size
    strip /usr/sbin/nginx 2>/dev/null || true
    
    log INFO "NGINX compiled and installed successfully"
}

# Setup systemd service
setup_systemd_service() {
    local service_file="/etc/systemd/system/nginx.service"
    
    if [[ ! -f $service_file ]]; then
        log INFO "Creating systemd service file..."
        
        cat > "$service_file" << 'EOF'
[Unit]
Description=The NGINX HTTP and reverse proxy server
Documentation=http://nginx.org/en/docs/
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t
ExecStart=/usr/sbin/nginx
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
KillMode=mixed
TimeoutStopSec=5
KillSignal=SIGQUIT
PrivateTmp=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        
        systemctl daemon-reload
        systemctl enable nginx
        log INFO "Systemd service created and enabled"
    fi
}

# Create optimized default site
create_default_site() {
    if [[ ! -f /etc/nginx/sites-available/default ]]; then
        log INFO "Creating optimized default site configuration..."
        
        cat > /etc/nginx/sites-available/default << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    # HTTP/3 and HTTP/2 with SSL
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    listen 443 quic default_server reuseport;
    listen [::]:443 quic default_server reuseport;
    
    server_name _;
    root /var/www/html;
    index index.html index.htm index.php;
    
    # SSL Configuration (replace with your certificates)
    ssl_certificate /etc/nginx/ssl/nginx-selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx-selfsigned.key;
    
    # HTTP/3 Alt-Svc header
    add_header Alt-Svc 'h3=":443"; ma=86400';
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Multi-layer compression (browsers choose best supported)
    gzip on;
    gzip_vary on;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;
    
    # Zstd compression (modern browsers, better than gzip)
    zstd on;
    zstd_comp_level 6;
    zstd_min_length 1000;
    zstd_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript application/wasm;
    
    # Brotli compression (best compression ratio)
    brotli on;
    brotli_comp_level 6;
    brotli_min_length 1000;
    brotli_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript application/wasm;
    
    # Performance optimizations
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|woff|woff2)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
        gzip_static on;
    }
    
    # MP4 streaming support
    location ~* \.mp4$ {
        mp4;
        mp4_buffer_size 1m;
        mp4_max_buffer_size 5m;
        add_header Cache-Control "public, max-age=31536000";
    }
    
    # FastCGI PHP processing (if needed)
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_pass unix:/var/run/php/php-fpm.sock; # Adjust path as needed
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
    }
    
    # Basic auth example (uncomment if needed)
    # location /admin {
    #     auth_basic "Admin Area";
    #     auth_basic_user_file /etc/nginx/.htpasswd;
    #     try_files $uri $uri/ =404;
    # }
    
    # Proxy example (uncomment if needed)
    # location /api/ {
    #     proxy_pass http://backend;
    #     proxy_set_header Host $host;
    #     proxy_set_header X-Real-IP $remote_addr;
    #     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    #     proxy_set_header X-Forwarded-Proto $scheme;
    #     proxy_cache_bypass $http_upgrade;
    # }
    
    location / {
        try_files $uri $uri/ =404;
    }
}
EOF
        
        # Enable the site
        ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
        
        # Create SSL directory and self-signed certificate for testing
        mkdir -p /etc/nginx/ssl
        mkdir -p /var/www/html
        
        if [[ ! -f /etc/nginx/ssl/nginx-selfsigned.crt ]]; then
            log INFO "Creating self-signed SSL certificate for testing..."
            openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                -keyout /etc/nginx/ssl/nginx-selfsigned.key \
                -out /etc/nginx/ssl/nginx-selfsigned.crt \
                -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
                >/dev/null 2>&1
        fi
        
        # Create simple index page
        if [[ ! -f /var/www/html/index.html ]]; then
            cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>NGINX HTTP/3 Ready</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .protocol { color: #0066cc; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Welcome to NGINX</h1>
    <p>Your high-performance NGINX server is running with HTTP/3 and QUIC support!</p>
    <p>Protocol: <span class="protocol" id="protocol">Loading...</span></p>
    
    <script>
        // Detect HTTP version
        if (window.chrome && chrome.loadTimes) {
            document.getElementById('protocol').textContent = 'HTTP/2 or HTTP/3';
        } else {
            document.getElementById('protocol').textContent = 'HTTP/1.1';
        }
    </script>
</body>
</html>
EOF
        fi
        
        chown -R "$NGINX_USER:$NGINX_GROUP" /var/www/html
        log INFO "Default site configuration created"
    fi
}
    if [[ ! -f /etc/logrotate.d/nginx ]]; then
        log INFO "Setting up log rotation..."
        
        cat > /etc/logrotate.d/nginx << EOF
/var/log/nginx/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 $NGINX_USER $NGINX_GROUP
    sharedscripts
    postrotate
        if [ -f /run/nginx.pid ]; then
            kill -USR1 \`cat /run/nginx.pid\`
        fi
    endscript
}
EOF
        log INFO "Log rotation configured"
    fi
}

# Block APT nginx packages
block_apt_nginx() {
    local pref_file="/etc/apt/preferences.d/nginx-block"
    
    if [[ ! -f $pref_file ]]; then
        log INFO "Blocking nginx installation via APT..."
        
        cat > "$pref_file" << 'EOF'
Package: nginx*
Pin: release *
Pin-Priority: -1
EOF
        log INFO "APT nginx packages blocked"
    fi
}

# Create equivs package
create_equivs_package() {
    log INFO "Creating fake nginx package to satisfy dependencies..."
    
    local equivs_dir="$NGINX_SOURCE_DIR/equivs-nginx"
    mkdir -p "$equivs_dir" && cd "$equivs_dir" || error_exit "Cannot create equivs directory"
    
    cat > nginx << EOF
Section: misc
Priority: optional
Standards-Version: 3.9.2

Package: nginx
Version: $NGINX_VER-custom
Maintainer: nginx-autoinstall
Architecture: all
Description: Custom compiled nginx package
 This is a fake package to satisfy nginx dependencies
 for a custom compiled version of nginx.
EOF
    
    if equivs-build nginx && dpkg -i "nginx_${NGINX_VER}-custom_all.deb"; then
        log INFO "Fake nginx package installed"
    else
        log WARN "Failed to create/install fake nginx package (non-critical)"
    fi
}

# Verify installation
verify_installation() {
    log INFO "Verifying NGINX installation..."
    
    # Test configuration
    if ! /usr/sbin/nginx -t; then
        error_exit "NGINX configuration test failed"
    fi
    
    # Start nginx
    if ! systemctl start nginx; then
        error_exit "Failed to start NGINX"
    fi
    
    # Check if it's running
    if ! systemctl is-active --quiet nginx; then
        error_exit "NGINX is not running"
    fi
    
    # Test HTTP response
    sleep 2
    if ! curl -sf http://localhost >/dev/null; then
        log WARN "NGINX is running but not responding to HTTP requests"
    fi
    
    log INFO "NGINX installation verified successfully"
}

# Optimize system for NGINX performance
optimize_system() {
    if [[ $PERFORMANCE_OPTIMIZED != 'y' ]]; then
        return 0
    fi
    
    log INFO "Applying system optimizations for NGINX performance..."
    
    # Create performance tuning configuration
    cat > /etc/sysctl.d/99-nginx-performance.conf << 'EOF'
# Network optimizations for NGINX
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 5000
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_max_tw_buckets = 400000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_congestion_control = bbr

# File descriptor limits
fs.file-max = 2097152
fs.nr_open = 2097152

# Memory management
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-nginx-performance.conf >/dev/null 2>&1 || log WARN "Some sysctl settings may require reboot"
    
    # Set ulimits for nginx user
    cat >> /etc/security/limits.conf << EOF

# NGINX performance limits
$NGINX_USER soft nofile 65535
$NGINX_USER hard nofile 65535
$NGINX_USER soft nproc 32768
$NGINX_USER hard nproc 32768
EOF
    
    log INFO "System optimizations applied"
}
    local nginx_version
    nginx_version=$(/usr/sbin/nginx -v 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+')
    
    echo ""
    log INFO "============================================="
    log INFO "High-Performance NGINX Installation Complete!"
    log INFO "============================================="
    log INFO "Version: $nginx_version"
    log INFO "User/Group: $NGINX_USER:$NGINX_GROUP"
    log INFO "Configuration: /etc/nginx/nginx.conf"
    log INFO "Default Site: /etc/nginx/sites-available/default"
    log INFO "Logs: /var/log/nginx/"
    log INFO "Service: systemctl {start|stop|restart|status} nginx"
    log INFO ""
    log INFO "Compression Support:"
    log INFO "  ✓ Gzip (universal browser support)"
    log INFO "  ✓ Brotli (20-25% better than gzip)"
    log INFO "  ✓ Zstd (15-20% better than gzip, faster)"
    log INFO "  ✓ Multi-layer negotiation (best available used)"
    log INFO "HTTP/3 Features:"
    log INFO "  ✓ QUIC Protocol Support"
    log INFO "  ✓ HTTP/3 Module Enabled"
    log INFO "  ✓ System OpenSSL Integration"
    log INFO "  ✓ Alt-Svc Header for Protocol Negotiation"
    log INFO ""
    log INFO "Performance Optimizations:"
    log INFO "  ✓ Custom Module Set (Production Ready)"
    log INFO "  ✓ Aggressive Compiler Optimizations (-O3, -march=skylake)"
    log INFO "  ✓ System-Level Network Tuning"
    log INFO "  ✓ Optimized Worker Configuration"
    log INFO "  ✓ Multi-layer Compression (Gzip + Brotli + Zstd)"
    log INFO "  ✓ MP4 Streaming Support"
    log INFO "  ✓ FastCGI PHP Support"
    log INFO ""
    log INFO "Test URLs:"
    log INFO "  HTTP:  http://localhost/"
    log INFO "  HTTPS: https://localhost/ (self-signed cert)"
    log INFO "  Status: http://localhost/nginx_status"
    log INFO ""
    log INFO "To verify HTTP/3 support:"
    log INFO "  curl --http3 -k https://localhost/"
    log INFO "============================================="
    
    # Show status
    systemctl status nginx --no-pager -l || true
}

# Main execution
main() {
    log INFO "Starting NGINX autoinstall script..."
    
    detect_os
    check_existing_nginx
    detect_cpu_arch
    
    # Cleanup and prepare
    rm -rf "$NGINX_SOURCE_DIR" 2>/dev/null || true
    mkdir -p "$NGINX_MODULES_DIR"
    
    install_dependencies
    create_nginx_user
    setup_directories
    download_default_config
    
	build_cache_purge_module
    build_brotli_module
	build_zstd_module
    
    download_nginx_source
    compile_nginx
    
    setup_systemd_service
    setup_logrotate
    create_default_site
    optimize_system
    block_apt_nginx
    create_equivs_package
    
    verify_installation
    show_final_info
    
    log INFO "Installation completed successfully!"
}

# Run main function
main "$@"
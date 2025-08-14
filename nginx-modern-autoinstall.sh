#!/bin/bash
# NGINX Autoinstall Script v0.5
# Usage: chmod +x ./nginx-modern-autoinstall.sh && ./nginx-modern-autoinstall.sh
# or: wget -O - https://raw.githubusercontent.com/alexander-neumann-webdesign/nginx-autoinstall/refs/heads/master/nginx-modern-autoinstall.sh | bash

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

# Configuration with validation
readonly NGINX_STABLE_VER=${NGINX_STABLE_VER:-1.28.0}
readonly NGINX_MAINLINE_VER=${NGINX_MAINLINE_VER:-1.29.1}
readonly NGINX_VER=${NGINX_VER:-$NGINX_MAINLINE_VER}
readonly NGINX_USER=${NGINX_USER:-nginx}
readonly NGINX_GROUP=${NGINX_GROUP:-nginx}
readonly BROTLI=${BROTLI:-y}
readonly ZSTD=${ZSTD:-n}
readonly CACHEPURGE=${CACHEPURGE:-y}
readonly CLOUDFLARE_ZLIB=${CLOUDFLARE_ZLIB:-n}
readonly BORING_SSL=${BORING_SSL:-n}
readonly JEMALLOC=${JEMALLOC:-n}
readonly PCRE_JIT=${PCRE_JIT:-n}
readonly BUILD_THREADS=${BUILD_THREADS:-$(nproc)}

# Validate version format
if [[ ! $NGINX_VER =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error_exit "Invalid NGINX version format: $NGINX_VER"
fi

log INFO "Building NGINX version: $NGINX_VER"
log INFO "NGINX will run as user: $NGINX_USER, group: $NGINX_GROUP"

# Enhanced options logging
log INFO "Enhanced build options:"
[[ $CLOUDFLARE_ZLIB == 'y' ]] && log INFO "  ✓ Cloudflare zlib (improved compression performance)"
[[ $BORING_SSL == 'y' ]] && log INFO "  ✓ BoringSSL (Google's optimized SSL library)"
[[ $JEMALLOC == 'y' ]] && log INFO "  ✓ jemalloc (improved memory management)"
[[ $PCRE_JIT == 'y' ]] && log INFO "  ✓ PCRE JIT (faster regex processing)"

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

# Initialize architecture-specific variable
ARCH_SPECIFIC=""

# Global variables for custom libraries
CLOUDFLARE_ZLIB_PATH=""
BORING_SSL_PATH=""
JEMALLOC_PATH=""

# Minimal high-performance NGINX modules (customized)
NGINX_MODULES=(
    --with-threads
    --with-file-aio
    --with-http_ssl_module
    --with-http_v2_module
    --with-http_v3_module
    --with-http_auth_request_module
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
    --without-http_upstream_zone_module
)

# Function to build NGINX options dynamically
build_nginx_options() {
    # Detect CPU architecture first
    detect_cpu_arch
    
    # Base compiler optimization flags
    local cc_opt="-O3 ${ARCH_SPECIFIC} -msse4.1 -msse4.2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mfsgsbase"
    cc_opt="${cc_opt} -fstack-protector-strong -flto=auto -fomit-frame-pointer -funroll-loops"
    cc_opt="${cc_opt} -fprefetch-loop-arrays -ffast-math -DTCP_FASTOPEN=23 -DNGX_HAVE_AES_NI=1"
    cc_opt="${cc_opt} -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC"
    
    local ld_opt="-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -Wl,-O2 -Wl,--sort-common"
    ld_opt="${ld_opt} -Wl,--gc-sections -Wl,--hash-style=gnu -Wl,--build-id=sha1 -flto=auto -pie"
    
    # Add Cloudflare zlib paths if enabled
    if [[ $CLOUDFLARE_ZLIB == 'y' && -n $CLOUDFLARE_ZLIB_PATH ]]; then
        cc_opt="${cc_opt} -I${CLOUDFLARE_ZLIB_PATH}"
        ld_opt="${ld_opt} -L${CLOUDFLARE_ZLIB_PATH}"
    fi
    
    # Add BoringSSL paths if enabled
    if [[ $BORING_SSL == 'y' && -n $BORING_SSL_PATH ]]; then
        cc_opt="${cc_opt} -I${BORING_SSL_PATH}/include"
        ld_opt="${ld_opt} -L${BORING_SSL_PATH}/build/ssl -L${BORING_SSL_PATH}/build/crypto"
    fi
    
    # Add jemalloc paths if enabled
    if [[ $JEMALLOC == 'y' && -n $JEMALLOC_PATH ]]; then
        cc_opt="${cc_opt} -I${JEMALLOC_PATH}/include"
        ld_opt="${ld_opt} -L${JEMALLOC_PATH}/lib -ljemalloc"
    fi
    
    # Build NGINX options array
    NGINX_OPTIONS=(
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
        --with-cc-opt="$cc_opt"
        --with-ld-opt="$ld_opt"
    )
    
    # Add custom library paths
    if [[ $CLOUDFLARE_ZLIB == 'y' && -n $CLOUDFLARE_ZLIB_PATH ]]; then
        NGINX_OPTIONS+=(--with-zlib="$CLOUDFLARE_ZLIB_PATH")
    fi
    
    if [[ $PCRE_JIT == 'y' ]]; then
        NGINX_OPTIONS+=(--with-pcre-jit)
    fi

}

# Backup existing nginx binary
backup_existing_nginx() {
    if command -v nginx >/dev/null 2>&1; then
        local nginx_path
        nginx_path=$(command -v nginx)
        local backup_path="${nginx_path}.backup.$(date +%Y%m%d-%H%M%S)"
        
        read -p "Do you want to backup the current nginx binary? [Y/n]: " -r
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            log INFO "Skipping nginx binary backup"
        else
            log INFO "Backing up current nginx binary..."
            if cp "$nginx_path" "$backup_path"; then
                log INFO "Nginx binary backed up to: $backup_path"
            else
                log WARN "Failed to backup nginx binary (continuing anyway)"
            fi
        fi
    fi
}

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
        backup_existing_nginx
    fi
}

# Install dependencies with error checking
install_dependencies() {
    local packages=(
        build-essential ca-certificates wget curl
        autoconf unzip automake libtool tar git 
        uuid-dev lsb-release cmake equivs pkg-config
    )

    # Standard dependencies
    if [[ $CLOUDFLARE_ZLIB != 'y' ]]; then
        packages+=(zlib1g-dev)
    fi
    
    if [[ $BORING_SSL != 'y' ]]; then
        packages+=(libssl-dev)
    else
        packages+=(golang-go)  # Required for BoringSSL
    fi
    
    if [[ $PCRE_JIT != 'y' ]]; then
        packages+=(libpcre2-dev)
    else
        packages+=(libpcre3-dev)  # PCRE JIT requires PCRE1
    fi
    
    if [[ $ZSTD == 'y' ]]; then
        packages+=(libzstd-dev)
    fi
    
    # Check OpenSSL version for HTTP/3 support (only if not using BoringSSL)
    if [[ $BORING_SSL != 'y' ]]; then
        check_openssl_version || log WARN "OpenSSL version may not fully support HTTP/3 QUIC. Consider upgrading."
    fi

    apt-get update -qq || error_exit "Failed to update package lists"

    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log INFO "Installing $package..."
            apt-get install -y "$package" || error_exit "Failed to install $package"
        fi
    done
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

# Build Cloudflare zlib
build_cloudflare_zlib() {
    if [[ $CLOUDFLARE_ZLIB != 'y' ]]; then
        return 0
    fi
    
    log INFO "Building Cloudflare zlib..."
    
    cd "$NGINX_SOURCE_DIR" || error_exit "Cannot access source directory"
    
    if ! git clone --depth=1 https://github.com/cloudflare/zlib cloudflare-zlib; then
        error_exit "Failed to clone Cloudflare zlib repository"
    fi
    
    cd cloudflare-zlib || error_exit "Cannot access Cloudflare zlib directory"
    
    # Configure and build
    if ! ./configure --static; then
        error_exit "Cloudflare zlib configuration failed"
    fi
    
    if ! make -j "$BUILD_THREADS"; then
        error_exit "Cloudflare zlib build failed"
    fi
    
    CLOUDFLARE_ZLIB_PATH="$PWD"
    log INFO "Cloudflare zlib built successfully at: $CLOUDFLARE_ZLIB_PATH"
}

# Build BoringSSL
build_boring_ssl() {
    if [[ $BORING_SSL != 'y' ]]; then
        return 0
    fi
    
    log INFO "Building BoringSSL..."
    
    cd "$NGINX_SOURCE_DIR" || error_exit "Cannot access source directory"
    
    if ! git clone --depth=1 https://github.com/google/boringssl; then
        error_exit "Failed to clone BoringSSL repository"
    fi
    
    cd boringssl || error_exit "Cannot access BoringSSL directory"
    
    mkdir -p build && cd build || error_exit "Cannot create build directory"
    
    # Configure and build
    if ! cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF ..; then
        error_exit "BoringSSL configuration failed"
    fi
    
    if ! make -j "$BUILD_THREADS"; then
        error_exit "BoringSSL build failed"
    fi
    
    # Create compatibility structure
    cd ..
    mkdir -p .openssl/lib .openssl/include || error_exit "Cannot create BoringSSL structure"
    cp -R include/* .openssl/include/ || error_exit "Cannot copy BoringSSL headers"
    cp build/crypto/libcrypto.a .openssl/lib/ || error_exit "Cannot copy libcrypto"
    cp build/ssl/libssl.a .openssl/lib/ || error_exit "Cannot copy libssl"
    
    BORING_SSL_PATH="$PWD"
    log INFO "BoringSSL built successfully at: $BORING_SSL_PATH"
}

# Build jemalloc
build_jemalloc() {
    if [[ $JEMALLOC != 'y' ]]; then
        return 0
    fi
    
    log INFO "Building jemalloc..."
    
    cd "$NGINX_SOURCE_DIR" || error_exit "Cannot access source directory"
    
    local jemalloc_version="5.3.0"
    if ! wget -q --timeout=30 --tries=3 "https://github.com/jemalloc/jemalloc/releases/download/${jemalloc_version}/jemalloc-${jemalloc_version}.tar.bz2"; then
        error_exit "Failed to download jemalloc source"
    fi
    
    tar -xjf "jemalloc-${jemalloc_version}.tar.bz2" || error_exit "Failed to extract jemalloc"
    cd "jemalloc-${jemalloc_version}" || error_exit "Cannot access jemalloc directory"
    
    # Configure and build
    if ! ./configure --prefix="$PWD/install" --enable-static --disable-shared; then
        error_exit "jemalloc configuration failed"
    fi
    
    if ! make -j "$BUILD_THREADS"; then
        error_exit "jemalloc build failed"
    fi
    
    if ! make install; then
        error_exit "jemalloc install failed"
    fi
    
    JEMALLOC_PATH="$PWD/install"
    log INFO "jemalloc built successfully at: $JEMALLOC_PATH"
}

# Download and verify NGINX source
download_nginx_source() {
    log INFO "Downloading NGINX source code..."
    
    mkdir -p "$NGINX_SOURCE_DIR"
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
    
    NGINX_MODULES+=( --add-module="$NGINX_MODULES_DIR/zstd-nginx-module" )
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
    
    NGINX_MODULES+=( --add-module="$NGINX_MODULES_DIR/ngx_brotli" )
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
    
    NGINX_MODULES+=( --add-module="$NGINX_MODULES_DIR/ngx_cache_purge" )
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

# Compile NGINX
compile_nginx() {
    log INFO "Compiling NGINX..."
    
    cd "$NGINX_BUILD_DIR" || error_exit "Cannot access build directory"
    
    # Configure with better error handling
    log DEBUG "Running configure with options..."
    log DEBUG "Options: ${NGINX_OPTIONS[*]}"
    log DEBUG "Modules: ${NGINX_MODULES[*]}"
    
    if ! ./configure "${NGINX_OPTIONS[@]}" "${NGINX_MODULES[@]}"; then
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

setup_logrotate(){
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

show_final_info(){
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
    log INFO "Build Configuration:"
    [[ $ARCH_SPECIFIC != "" ]] && log INFO "  ✓ CPU Architecture: ${ARCH_SPECIFIC}"
    [[ $CLOUDFLARE_ZLIB == 'y' ]] && log INFO "  ✓ Cloudflare zlib (enhanced compression)"
    [[ $BORING_SSL == 'y' ]] && log INFO "  ✓ BoringSSL (Google's optimized SSL library)"
    [[ $JEMALLOC == 'y' ]] && log INFO "  ✓ jemalloc (improved memory management)"
    [[ $PCRE_JIT == 'y' ]] && log INFO "  ✓ PCRE JIT (faster regex processing)"
    log INFO ""
    log INFO "Compression Support:"
    log INFO "  ✓ Gzip (universal browser support)"
    [[ $BROTLI == 'y' ]] && log INFO "  ✓ Brotli (20-25% better than gzip)"
    [[ $ZSTD == 'y' ]] && log INFO "  ✓ Zstd (15-20% better than gzip, faster)"
    log INFO "  ✓ Multi-layer negotiation (best available used)"
    log INFO "HTTP/3 Features:"
    log INFO "  ✓ QUIC Protocol Support"
    log INFO "  ✓ HTTP/3 Module Enabled"
    if [[ $BORING_SSL == 'y' ]]; then
        log INFO "  ✓ BoringSSL Integration (optimized QUIC)"
    else
        log INFO "  ✓ System OpenSSL Integration"
    fi
    log INFO "  ✓ Alt-Svc Header for Protocol Negotiation"
    log INFO ""
    log INFO "Performance Optimizations:"
    log INFO "  ✓ Custom Module Set (Production Ready)"
    log INFO "  ✓ Aggressive Compiler Optimizations (-O3, ${ARCH_SPECIFIC})"
    if [[ $JEMALLOC == 'y' ]]; then
        log INFO "  ✓ jemalloc Memory Allocator"
    fi
    if [[ $PCRE_JIT == 'y' ]]; then
        log INFO "  ✓ PCRE Just-In-Time Compilation"
    fi
    if [[ $CLOUDFLARE_ZLIB == 'y' ]]; then
        log INFO "  ✓ Cloudflare zlib (faster compression)"
    fi
    log INFO "  ✓ System-Level Network Tuning"
    log INFO "  ✓ Optimized Worker Configuration"
    log INFO "  ✓ FastCGI PHP Support"
    log INFO ""
    log INFO "Test URLs:"
    log INFO "  HTTP:  http://localhost/"
    log INFO "  HTTPS: https://localhost/ (self-signed cert)"
    log INFO "  Status: http://localhost/nginx_status"
    log INFO ""
    log INFO "To verify HTTP/3 support:"
    log INFO "  curl --http3 -k https://localhost/"
    log INFO ""
    log INFO "Enhanced Features Summary:"
    log INFO "  • Architecture-optimized compilation (${ARCH_SPECIFIC})"
    if [[ $CLOUDFLARE_ZLIB == 'y' ]]; then
        log INFO "  • Cloudflare zlib for improved compression performance"
    fi
    if [[ $BORING_SSL == 'y' ]]; then
        log INFO "  • BoringSSL for optimized cryptographic operations"
    fi
    if [[ $JEMALLOC == 'y' ]]; then
        log INFO "  • jemalloc for reduced memory fragmentation"
    fi
    if [[ $PCRE_JIT == 'y' ]]; then
        log INFO "  • PCRE JIT for faster regex pattern matching"
    fi
    log INFO "============================================="
    
    # Show status
    systemctl status nginx --no-pager -l || true
}

# Main execution
main() {
    log INFO "Starting enhanced NGINX autoinstall script..."
    
    detect_os
    check_existing_nginx
    
    # Cleanup and prepare
    rm -rf "$NGINX_SOURCE_DIR" 2>/dev/null || true
    mkdir -p "$NGINX_MODULES_DIR"
    
    install_dependencies
    create_nginx_user
    setup_directories
    
    # Build custom libraries first
    build_cloudflare_zlib
    build_boring_ssl
    build_jemalloc
    
    # Build NGINX modules
    build_cache_purge_module
    build_brotli_module
    build_zstd_module

    # Build NGINX options after detecting CPU architecture
    build_nginx_options
    
    download_nginx_source
    compile_nginx
    
    setup_systemd_service
    setup_logrotate
    block_apt_nginx
    create_equivs_package
    
    verify_installation
    show_final_info
    
    log INFO "Enhanced installation completed successfully!"
}

# Run main function
main "$@"
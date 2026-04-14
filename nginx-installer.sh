#!/bin/bash

# =============================================================================
# NGINX HIGH PERFORMANCE AUTO INSTALLER v1.1.0
# =============================================================================
#
# DESCRIPTION:
# Compiles a bleeding-edge Nginx binary optimized for maximum throughput and 
# lowest latency. Replaces the stock OS binary while preserving configurations.
# specifically tuned for high-traffic WordPress/PHP environments.
#
# CORE STACK:
# - Nginx Mainline: Latest upstream release (supports native 103 Early Hints).
# - QuicTLS (OpenSSL 3.3 Fork): Full HTTP/3 (QUIC) & 0-RTT support.
# - PCRE2 with JIT for faster regex processing.
# - Async I/O: Thread Pools + File AIO enabled for non-blocking disk access.
#
# OPTIMIZATIONS:
# - Compiler: GCC -O3 + -march=native (AVX/AVX2/AVX-512 tuning).
# - Linker: Link Time Optimization (LTO) enabled for whole-program analysis.
# - Crypto: NASM (Netwide Assembler) for accelerated SSL/TLS handshakes.
# - Memory: Linked against Jemalloc (Facebook's allocator) to prevent leaks.
#
# COMPRESSION:
# - Brotli: Google's next-gen compression (High compression, low CPU).
# - Zstd: Facebook's real-time compression (Extremely fast).
# - Cloudflare Zlib: Optimized fork of Zlib (Up to 2x faster Gzip).
#
# COMPATIBILITY:
# - HTTP 103 Early Hints: Supported (Native in Nginx Mainline 1.29+).
# - OS Support: Debian / Ubuntu LTS versions.
#
# -----------------------------------------------------------------------------
# USAGE:
# 1. Save file:        nano nginx-installer.sh
# 2. Make executable:  chmod +x nginx-installer.sh
# 3. Run as root:      ./nginx-installer.sh
#
# -----------------------------------------------------------------------------
# ROLLBACK (If needed):
# 1. Restore binary:   cp /usr/sbin/nginx.backup /usr/sbin/nginx
# 2. Restart service:  systemctl restart nginx
# =============================================================================

set -e

# --- 1. SYSTEM CHECKS ---
if [[ $EUID -ne 0 ]]; then
    echo -e "\033[0;31m[ERROR] This script must be run as root.\033[0m"
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
        echo -e "\033[0;31m[ERROR] This script is optimized for Debian or Ubuntu only.\033[0m"
        echo "Detected OS: $ID"
        exit 1
    fi
else
    echo -e "\033[0;31m[ERROR] Cannot detect OS. /etc/os-release missing.\033[0m"
    exit 1
fi

# --- CONFIGURATION ---
ENABLE_CF_ZLIB="y"       # Enable Cloudflare Optimized Zlib
ENABLE_PCRE_CUSTOM="y"   # Enable PCRE2 with JIT
ENABLE_HEADERS_MORE="n"  # Enable Headers More Module

# Versions (Nginx version is auto-detected)
OPENSSL_BRANCH="openssl-3.3" 
PCRE2_VER="10.45"

# Paths
NGINX_PATH="/etc/nginx"
SBIN_PATH="/usr/sbin/nginx"
CONF_PATH="/etc/nginx/nginx.conf"
LOG_PATH="/var/log/nginx"
CACHE_PATH="/var/cache/nginx"
PID_PATH="/run/nginx/nginx.pid"
LOCK_PATH="/run/nginx/nginx.lock"

# Build Environment
BUILD_ROOT="/tmp/nginx-hpc-build"
NGINX_USER="nginx"
NGINX_GROUP="nginx"

# --- VISUALS ---
R='\033[0;31m'
G='\033[0;32m'
C='\033[0;36m'
Y='\033[1;33m'
NC='\033[0m'

info() { echo -e "${C}[INFO]${NC} $1"; }
success() { echo -e "${G}[OK]${NC} $1"; }
warn() { echo -e "${Y}[WARN]${NC} $1"; }
fail() { echo -e "${R}[ERROR]${NC} $1"; tput cnorm; exit 1; }

# Spinner Animation
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    tput civis
    echo -n "    Processing "
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
    echo ""
    tput cnorm
}

# Error Trap
handle_error() {
    tput cnorm
    echo ""
    echo -e "${R}!!! BUILD FAILED !!!${NC}"
    echo "Command failed: $BASH_COMMAND"
    echo "Working Dir: $(pwd)"
    if [ -f "$BUILD_ROOT/build.log" ]; then
         echo -e "${Y}--- LAST 20 LINES OF LOG ---${NC}"
         tail -n 20 "$BUILD_ROOT/build.log"
         echo -e "${Y}--------------------------${NC}"
         echo "Full log: $BUILD_ROOT/build.log"
    fi
    exit 1
}
trap 'handle_error' ERR

# --- PRE-FLIGHT ---
rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT"

#clear
echo -e "${G}===================================================${NC}"
echo -e "${G}   NGINX HPC AUTO INSTALLER v1.0.3${NC}"
echo -e "${G}===================================================${NC}"

# 1. INSTALL DEPENDENCIES
info "Installing build dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential git cmake curl gnupg2 ca-certificates \
    lsb-release unzip linux-headers-$(uname -r) equivs libpcre2-dev zlib1g-dev \
    libgd-dev uuid-dev libjemalloc-dev libzstd-dev libxml2-dev libxslt-dev \
    nasm binutils > /dev/null

success "Dependencies installed."
echo -e "   - GCC:    $(gcc --version | head -n1 | awk '{print $3}')"
echo -e "   - NASM:   $(nasm -v | awk '{print $3}')"

# Check for Gold Linker
if ld.gold -v &>/dev/null; then
    LINKER_FLAG="-fuse-ld=gold"
    echo -e "   - Linker: GNU Gold (Optimized)"
else
    LINKER_FLAG=""
    echo -e "   - Linker: GNU Standard (BFD) - Fallback"
fi

# 2. DOWNLOAD SOURCES
cd "$BUILD_ROOT"
info "Downloading Modules & Sources..."

# OpenSSL
echo -n "   - Fetching OpenSSL ($OPENSSL_BRANCH)... "
git clone --depth 1 -b "$OPENSSL_BRANCH" https://github.com/quictls/openssl.git > /dev/null 2>&1
cd openssl && echo "Ref: $(git rev-parse --short HEAD)" && cd ..

# Brotli
echo -n "   - Fetching Brotli (Google)... "
git clone --recurse-submodules -j$(nproc) https://github.com/google/ngx_brotli > /dev/null 2>&1
cd ngx_brotli && echo "Ref: $(git rev-parse --short HEAD)" && cd ..

# Zstd
echo -n "   - Fetching Zstd (Tokers)... "
git clone --depth 1 https://github.com/tokers/zstd-nginx-module.git > /dev/null 2>&1
cd zstd-nginx-module && echo "Ref: $(git rev-parse --short HEAD)" && cd ..

# Cache Purge
echo -n "   - Fetching Cache Purge... "
git clone --depth 1 https://github.com/nginx-modules/ngx_cache_purge.git > /dev/null 2>&1
cd ngx_cache_purge && echo "Ref: $(git rev-parse --short HEAD)" && cd ..

# Cloudflare Zlib
if [ "$ENABLE_CF_ZLIB" == "y" ]; then
    echo -n "   - Fetching Cloudflare Zlib... "
    git clone --depth 1 https://github.com/cloudflare/zlib.git > /dev/null 2>&1
    mv zlib zlib-cf
    cd zlib-cf
    echo -n "Ref: $(git rev-parse --short HEAD) ... "
    ./configure > /dev/null 2>&1
    echo "Configured."
    cd ..
    CF_ZLIB_OPT="--with-zlib=../zlib-cf"
fi

# PCRE2
if [ "$ENABLE_PCRE_CUSTOM" == "y" ]; then
    echo -n "   - Fetching PCRE2 ($PCRE2_VER)... "
    wget -q "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-${PCRE2_VER}/pcre2-${PCRE2_VER}.tar.gz"
    tar -zxf pcre2-${PCRE2_VER}.tar.gz
    echo "Extracted."
    PCRE_OPT="--with-pcre=../pcre2-${PCRE2_VER} --with-pcre-jit"
fi

# Headers More
EXTRA_MODULES=""
if [ "$ENABLE_HEADERS_MORE" == "y" ]; then
    echo -n "   - Fetching Headers More... "
    git clone --depth 1 https://github.com/openresty/headers-more-nginx-module.git > /dev/null 2>&1
    cd headers-more-nginx-module && echo "Ref: $(git rev-parse --short HEAD)" && cd ..
    EXTRA_MODULES="$EXTRA_MODULES --add-module=../headers-more-nginx-module"
fi

# 3. DETECT NGINX VERSION
info "Checking for latest Nginx version..."

# Scrape the raw file listing to find the latest 1.x.x version
# This ensures we get the bleeding-edge mainline release
LATEST_VER=$(curl -s http://nginx.org/download/ | grep -oP 'nginx-1\.\d+\.\d+' | sort -uV | tail -n 1 | sed 's/nginx-//')

if [ -z "$LATEST_VER" ]; then
    warn "Auto-detection failed."
    read -p "Enter Nginx version manually (e.g. 1.29.4): " NGINX_VER
else
    echo -e "   - Latest Available: ${G}$LATEST_VER${NC}"
    read -t 5 -p "   - Press ENTER to build $LATEST_VER, or type a custom version: " USER_INPUT || true
    echo ""
    if [ -z "$USER_INPUT" ]; then
        NGINX_VER=$LATEST_VER
    else
        NGINX_VER=$USER_INPUT
    fi
fi

if [ -z "$NGINX_VER" ]; then fail "No version specified."; fi

info "Downloading Nginx $NGINX_VER..."
wget -q --spider "http://nginx.org/download/nginx-${NGINX_VER}.tar.gz" || fail "Version $NGINX_VER not found on nginx.org!"
wget -q "http://nginx.org/download/nginx-${NGINX_VER}.tar.gz"

tar -zxf "nginx-${NGINX_VER}.tar.gz" || fail "Tar extraction failed."
if [ ! -d "nginx-${NGINX_VER}" ]; then fail "Directory nginx-${NGINX_VER} not found."; fi

cd "nginx-${NGINX_VER}"

# 4. CONFIGURE & COMPILE
info "Configuring build options..."

# --- MODULES CONFIGURATION ---
# Enabled Modules (Split for readability)
ENABLE_MODULES=" \
    --with-threads \
    --with-file-aio \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-http_v3_module \
"

# LEAN MODE: Explicitly disabled modules
DISABLE_MODULES=" \
    --without-http_autoindex_module \
    --without-http_ssi_module \
    --without-http_scgi_module \
    --without-http_uwsgi_module \
    --without-http_geo_module \
    --without-http_split_clients_module \
    --without-http_memcached_module \
    --without-http_empty_gif_module \
    --without-http_browser_module \
    --without-http_userid_module \
    --without-http_grpc_module \
    --without-http_mirror_module \
    --without-http_limit_conn_module \
    --without-http_limit_req_module \
    --without-http_upstream_hash_module \
    --without-http_upstream_ip_hash_module \
    --without-http_upstream_least_conn_module \
    --without-http_upstream_random_module \
    --without-http_upstream_zone_module \
"

# OPTIMIZATION FLAGS
# -O3: Aggressive optimization
# -march=native: Tune for this CPU
# -flto: Link Time Optimization
# -fuse-ld=gold: Fast linker (if available)
OPT_FLAGS="-O3 -march=native -fPIC -D_FORTIFY_SOURCE=2 -fstack-protector-strong -Wformat -Werror=format-security -Wno-deprecated-declarations -DTCP_FASTOPEN=23 -flto"
LD_FLAGS="-Wl,-z,relro -Wl,-z,now -ljemalloc $LINKER_FLAG -flto"

./configure \
    --prefix=$NGINX_PATH \
    --sbin-path=$SBIN_PATH \
    --conf-path=$CONF_PATH \
    --http-log-path=$LOG_PATH/access.log \
    --error-log-path=$LOG_PATH/error.log \
    --pid-path=$PID_PATH \
    --lock-path=$LOCK_PATH \
    --http-client-body-temp-path=$CACHE_PATH/body \
    --http-proxy-temp-path=$CACHE_PATH/proxy \
    --http-fastcgi-temp-path=$CACHE_PATH/fastcgi \
    --http-uwsgi-temp-path=$CACHE_PATH/uwsgi \
    --http-scgi-temp-path=$CACHE_PATH/scgi \
    --user=$NGINX_USER \
    --group=$NGINX_GROUP \
    $ENABLE_MODULES \
    --add-module=../ngx_brotli \
    --add-module=../zstd-nginx-module \
    --add-module=../ngx_cache_purge \
    $EXTRA_MODULES \
    --with-openssl=../openssl \
    --with-openssl-opt="enable-ktls enable-ec_nistp_64_gcc_128 -march=native -madx -mbmi -mbmi2 -O3 -fno-plt" \
    $PCRE_OPT \
    $CF_ZLIB_OPT \
    $DISABLE_MODULES \
    --with-cc-opt="$OPT_FLAGS" --with-ld-opt="$LD_FLAGS" > "$BUILD_ROOT/build.log" 2>&1

success "Configuration complete."

info "Compiling Nginx (This will take time)..."
make -j$(nproc) >> "$BUILD_ROOT/build.log" 2>&1 &
show_spinner $!
success "Compilation complete."

# 5. INSTALL
info "Installing binaries..."
mkdir -p "$BUILD_ROOT/install_temp/$CACHE_PATH"
make install DESTDIR="$BUILD_ROOT/install_temp" >> "$BUILD_ROOT/build.log" 2>&1
info "Stripping debug symbols..."

NEW_BIN="$BUILD_ROOT/install_temp$SBIN_PATH"
strip -s "$NEW_BIN"

# Ensure basic config exists for testing
if [ ! -f "$CONF_PATH" ]; then
    mkdir -p "$(dirname $CONF_PATH)"
    echo "events {} http {}" > "$CONF_PATH"
fi

info "Testing new binary..."
echo "---------------------------------------------------"
if ! "$NEW_BIN" -t -c "$CONF_PATH"; then
    echo "---------------------------------------------------"
    fail "Config test failed. Aborting installation."
fi
echo "---------------------------------------------------"

info "Swapping binaries..."
if [ -f "$SBIN_PATH" ]; then 
    cp "$SBIN_PATH" "$SBIN_PATH.backup.$(nginx -v 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' || echo "unknown").$(date +%Y%m%d-%H%M%S)";
    mv "$SBIN_PATH" "$SBIN_PATH.backup";
fi
cp "$NEW_BIN" "$SBIN_PATH"
chmod 755 "$SBIN_PATH"

# Safe copy of defaults (no overwrite)
cp -rn "$BUILD_ROOT/install_temp/etc"/* /etc/ 2>/dev/null || true
cp -rn "$BUILD_ROOT/install_temp/usr/share" /usr/ 2>/dev/null || true

# 6. SYSTEM CONFIG
if ! id "$NGINX_USER" &>/dev/null; then 
    useradd --no-create-home --shell /bin/false --system --user-group "$NGINX_USER"
fi
mkdir -p $LOG_PATH $CACHE_PATH
chown -R $NGINX_USER:$NGINX_GROUP $LOG_PATH $CACHE_PATH

info "Updating Systemd Unit..."
cat > /lib/systemd/system/nginx.service <<EOF
[Unit]
Description=The NGINX HTTP and reverse proxy server
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
PIDFile=$PID_PATH
RuntimeDirectory=nginx
RuntimeDirectoryMode=0755
ExecStartPre=$SBIN_PATH -t
ExecStart=$SBIN_PATH
ExecReload=$SBIN_PATH -s reload
ExecStop=/bin/kill -s QUIT \$MAINPID
PrivateTmp=true
LimitNOFILE=65535
Restart=on-failure
RestartSec=5s
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable nginx

# Log Rotation
if [ ! -f /etc/logrotate.d/nginx ]; then
    cat > /etc/logrotate.d/nginx <<EOF
$LOG_PATH/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 $NGINX_USER root
    sharedscripts
    postrotate
        if [ -f $PID_PATH ]; then
            kill -USR1 \`cat $PID_PATH\`
        fi
    endscript
}
EOF
fi

# APT Pinning
if [ ! -f /etc/apt/preferences.d/nginx-block ]; then
cat > /etc/apt/preferences.d/nginx-block <<EOF
Package: nginx*
Pin: release *
Pin-Priority: -1
EOF
fi

# equivs
if ! dpkg -s nginx 2>/dev/null | grep -q "custom"; then
    info "Registering dummy package..."
    cd "$BUILD_ROOT"
    cat > nginx-dummy.control <<EOF
Section: misc
Priority: optional
Standards-Version: 3.9.2
Package: nginx
Provides: nginx-full, nginx-common, nginx-core, nginx-light, nginx-extras, httpd
Version: 9.9.9-custom
Architecture: all
Maintainer: root <root@localhost>
Description: Custom HPC Nginx
EOF
    equivs-build nginx-dummy.control > /dev/null
    dpkg -i nginx_*.deb > /dev/null
fi

# 7. FINISH
info "Restarting Nginx..."
if systemctl is-active --quiet nginx; then
    systemctl restart nginx
else
    systemctl start nginx
fi

echo -e "${G}===================================================${NC}"
echo -e "${G}   SUCCESS! Nginx is live.${NC}"
echo -e "   - Version: $($SBIN_PATH -v 2>&1 | tr '\n' ' ')"
echo -e "${G}===================================================${NC}"
rm -rf "$BUILD_ROOT"
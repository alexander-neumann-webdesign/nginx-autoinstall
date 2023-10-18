#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo -e "Sorry, you need to run this as root"
	exit 1
fi

# Define versions
NGINX_STABLE_VER=${NGINX_STABLE_VER:-1.24.0}
NGINX_MAINLINE_VER=${NGINX_MAINLINE_VER:-1.25.2}

# Choose between NGINX_STABLE_VER and NGINX_MAINLINE_VER
NGINX_VER=$NGINX_MAINLINE_VER

# Add modules
BROTLI=${BROTLI:-y}
CACHEPURGE=${CACHEPURGE:-y}

# Define options
NGINX_OPTIONS=${NGINX_OPTIONS:-"
	--prefix=/etc/nginx \
	--sbin-path=/usr/sbin/nginx \
	--conf-path=/etc/nginx/nginx.conf \
	--error-log-path=/var/log/nginx/error.log \
	--http-log-path=/var/log/nginx/access.log \
	--pid-path=/var/run/nginx.pid \
	--lock-path=/var/run/nginx.lock \
	--http-client-body-temp-path=/var/cache/nginx/client_temp \
	--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
	--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
	--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
	--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
	--user=nginx \
	--group=nginx \
	--with-cc-opt=-Wno-deprecated-declarations \
	--with-cc-opt=-Wno-ignored-qualifiers"}

# Define modules
NGINX_MODULES=${NGINX_MODULES:-"--with-threads \
	--with-file-aio \
	--with-http_ssl_module \
	--with-http_v2_module \
	--with-http_mp4_module \
	--with-http_auth_request_module \
	--without-http_mirror_module \
	--without-http_ssi_module \
	--without-http_userid_module \
	--without-http_autoindex_module \
	--without-http_geo_module \
	--without-http_split_clients_module \
	--without-http_uwsgi_module \
	--without-http_scgi_module \
	--without-http_grpc_module \
	--without-http_memcached_module \
	--without-http_empty_gif_module"}


# Cleanup
rm -r /usr/local/src/nginx/ >>/dev/null 2>&1
mkdir -p /usr/local/src/nginx/modules

# Dependencies
apt-get update
apt-get install -y build-essential ca-certificates wget curl libpcre3 libpcre3-dev autoconf unzip automake libtool tar git libssl-dev zlib1g-dev uuid-dev lsb-release libxml2-dev libxslt1-dev cmake

#Brotli
if [[ $BROTLI == 'y' ]]; then
	echo "building module: ngx_brotli ..."
	
	# cd /usr/local/src/nginx/modules || exit 1
	# git clone https://github.com/google/ngx_brotli
	# cd ngx_brotli || exit 1
	# git submodule update --init

	cd /usr/local/src/nginx/modules || exit 1
	git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli
	
	mkdir ngx_brotli/deps/brotli/out
	cd ngx_brotli/deps/brotli/out
	
	cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_CXX_FLAGS="-Ofast -m64 -march=native -mtune=native -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections" -DCMAKE_INSTALL_PREFIX=./installed ..
	cmake --build . --config Release --target brotlienc
	
	export CFLAGS="-m64 -march=native -mtune=native -Ofast -flto -funroll-loops -ffunction-sections -fdata-sections -Wl,--gc-sections"
	export LDFLAGS="-m64 -Wl,-s -Wl,-Bsymbolic -Wl,--gc-sections"
	
	NGINX_MODULES=$(
		echo "$NGINX_MODULES"
		echo "--add-module=/usr/local/src/nginx/modules/ngx_brotli"
	)
fi

# Cache Purge
if [[ $CACHEPURGE == 'y' ]]; then
	echo "building module: ngx_cache_purge ..."

	cd /usr/local/src/nginx/modules || exit 1
	git clone --depth 1 https://github.com/nginx-modules/ngx_cache_purge

	NGINX_MODULES=$(
		echo "$NGINX_MODULES"
		echo "--add-module=/usr/local/src/nginx/modules/ngx_cache_purge"
	)
fi

# Download and extract of Nginx source code
cd /usr/local/src/nginx/ || exit 1
wget -qO- http://nginx.org/download/nginx-${NGINX_VER}.tar.gz | tar zxf -
cd nginx-${NGINX_VER} || exit 1

# Download default nginx.conf if it doesnt exist
if [[ ! -e /etc/nginx/nginx.conf ]]; then
	mkdir -p /etc/nginx
	cd /etc/nginx || exit 1
	wget https://raw.githubusercontent.com/alexander-neumann-webdesignnginx-autoinstall/master/conf/nginx.conf
fi

# compile nginx
cd /usr/local/src/nginx/nginx-${NGINX_VER} || exit 1
./configure $NGINX_OPTIONS $NGINX_MODULES
make -j "$(nproc)"
make install

# remove debugging symbols
strip -s /usr/sbin/nginx

# Nginx installation from source does not add an init script for systemd and logrotate

# Using the official systemd script and logrotate conf from nginx.org
if [[ ! -e /lib/systemd/system/nginx.service ]]; then
	cd /lib/systemd/system/ || exit 1
	wget https://raw.githubusercontent.com/alexander-neumann-webdesign/nginx-autoinstall/master/conf/nginx.service
	# Enable nginx start at boot
	systemctl enable nginx
fi

if [[ ! -e /etc/logrotate.d/nginx ]]; then
	cd /etc/logrotate.d/ || exit 1
	wget https://raw.githubusercontent.com/alexander-neumann-webdesign/nginx-autoinstall/master/conf/nginx-logrotate -O nginx
fi

# Nginx's cache directory is not created by default
if [[ ! -d /var/cache/nginx ]]; then
	mkdir -p /var/cache/nginx
fi

# We add the sites-* folders as some use them.
if [[ ! -d /etc/nginx/sites-available ]]; then
	mkdir -p /etc/nginx/sites-available
fi
if [[ ! -d /etc/nginx/sites-enabled ]]; then
	mkdir -p /etc/nginx/sites-enabled
fi
if [[ ! -d /etc/nginx/conf.d ]]; then
	mkdir -p /etc/nginx/conf.d
fi

# Restart Nginx
systemctl restart nginx

# Block Nginx from being installed via APT
if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]; then
	cd /etc/apt/preferences.d/ || exit 1
	echo -e 'Package: nginx*\nPin: release *\nPin-Priority: -1' >nginx-block
fi

# Resolve apt dependencies
if [[ $(lsb_release -si) == "Debian" ]] || [[ $(lsb_release -si) == "Ubuntu" ]]; then
	apt-get install equivs
	cd /usr/local/src/nginx/
	mkdir equivs && cd equivs
	echo -e 'Section: misc\nPriority: optional\nStandards-Version: 3.9.2\n\nPackage: nginx\nVersion: ${NGINX_VER}\nMaintainer: alexanderneumann\nArchitecture: all\nDescription: Fake package for nginx to avoid dependencies' > nginx-dummy.ctl
fi

# We're done !
echo "Installation done."
exit
;;
FROM nginx:stable

ARG CONTAINER_GID
ARG CONTAINER_UID
ARG CONTAINER_USER
ARG CONTAINER_GROUP

RUN groupadd -g ${CONTAINER_GID} ${CONTAINER_GROUP} && \
    useradd -u ${CONTAINER_UID} -g ${CONTAINER_GID} ${CONTAINER_USER}
    
RUN apt update \
&& apt-get -y install wget build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev libgd-dev libxml2 libxml2-dev uuid-dev \
&& cd /var/opt/ \
&& wget http://nginx.org/download/nginx-1.24.0.tar.gz \
&& tar -zxvf nginx-1.24.0.tar.gz \
&& wget https://github.com/evanmiller/mod_zip/archive/refs/tags/1.3.0.tar.gz \
&& tar -xvf 1.3.0.tar.gz \
&& cd nginx-1.24.0 \
&& ./configure --prefix=/var/www/html --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --http-log-path=/var/log/nginx/access.log --error-log-path=/var/log/nginx/error.log --with-pcre  --lock-path=/var/lock/nginx.lock --pid-path=/var/run/nginx.pid --with-compat --with-file-aio --with-threads --with-http_addition_module --with-http_auth_request_module --with-http_dav_module --with-http_flv_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_random_index_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-mail --with-mail_ssl_module --with-stream --with-stream_realip_module --with-stream_ssl_module --with-stream_ssl_preread_module --add-module=/var/opt/mod_zip-1.3.0 \
&& make \
&& make install

COPY ./etc/ /etc/nginx/
COPY ./certs/*.key /etc/ssl/private/
COPY ./certs/*.crt /etc/ssl/certs/

RUN envsubst < /etc/nginx/nginx.conf.template > /etc/nginx/nginx.conf

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["nginx"]

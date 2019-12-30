# echo 'hxp{FLAG}' > flag.txt && docker build -t file_magician . && docker run -ti -p 8000:80 file_magician
FROM debian:buster

RUN apt-get update && \
    apt-get install -y \
        nginx \
        php-fpm \
        php-sqlite3 \
    && rm -rf /var/lib/apt/lists/

RUN rm -rf /var/www/html/*
COPY docker-stuff/default /etc/nginx/sites-enabled/default
COPY docker-stuff/www.conf /etc/php/7.3/fpm/pool.d/www.conf

#  # Permission
#  7 rwx
#  6 rw-
#  5 r-x
#  4 r--
#  3 -wx
#  2 -w-
#  1 --x
#  0 ---

COPY flag.txt /flag.txt
RUN chown root:root /flag.txt && \
    mv flag.txt flag_$(< /dev/urandom tr -dc a-zA-Z0-9 | head -c 16).txt && \
    chmod 444 /flag_*.txt

COPY index.php /var/www/html/
RUN chown -R root:root /var/www && \
    find /var/www -type d -exec chmod 555 {} \; && \
    find /var/www -type f -exec chmod 444 {} \;  && \
    mkdir /var/www/html/files && \
    chmod 703 /var/www/html/files

RUN ln -sf /dev/stdout /var/log/nginx/access.log && \
    ln -sf /dev/stderr /var/log/nginx/error.log

USER www-data
RUN (find --version && id --version && sed --version && grep --version) > /dev/null
RUN ! find / -writable -or -user $(id -un) -or -group $(id -Gn|sed -e 's/ / -or -group  /g') 2> /dev/null | grep -Ev -m 1 '^(/dev/|/run/|/proc/|/sys/|/tmp|/var/tmp|/var/lock|/var/lib/php/sessions|/var/log/nginx/error.log|/var/log/nginx/access.log|/var/www/html/files)'
USER root

EXPOSE 80
CMD while true; do find /var/www/html/files/ -maxdepth 1 -mindepth 1 -type d -mmin +15 -exec rm -rf -- {} \; ; sleep 1m; done & \
    /etc/init.d/php7.3-fpm start && \
    nginx -g 'daemon off;'
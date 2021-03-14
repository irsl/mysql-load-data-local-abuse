FROM debian:buster

RUN apt-get update && apt-get install -y build-essential cpanminus libdbd-mysql-perl && \
    cpanm --notest install Digest::SHA1 && \
	cpanm install DBIx::MyServer && \
	apt-get remove -y build-essential cpanminus && \
	apt-get autoremove -y && \
	rm -rf /var/lib/apt/lists/* 
ADD rogue-mysql-server.pl /usr/local/bin

ENTRYPOINT ["/usr/local/bin/rouge-mysql-server.pl"]

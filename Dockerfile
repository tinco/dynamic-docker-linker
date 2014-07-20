FROM phusion/passenger-ruby21
MAINTAINER Tinco Andringa "mail@tinco.nl"
RUN curl -s https://get.docker.io/ubuntu/ | sudo sh && apt-get install iptables && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
ADD dynamic-docker-linker.rb /sbin/
RUN chmod a+x /sbin/dynamic-docker-linker.rb
ENTRYPOINT dynamic-docker-linker.rb $0
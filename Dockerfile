FROM centos:7

LABEL maintainer "Security Onion Solutions, LLC"
LABEL version="Wazuh Manager"
LABEL description="Wazuh Manager running in Docker container for use with Security Onion"

RUN yum update -y

# Install pre-reqs
RUN yum install -y initscripts
RUN yum install -y expect
RUN yum install -y logrotate
RUN yum install -y openssl

# Creating ossec user as uid:gid 943:943
RUN groupadd -g 945 ossec
RUN useradd -u 945 -g 945 -d /var/ossec -s /sbin/nologin ossec

# Add Wazuh repo
ADD config/repos.bash /repos.bash
RUN chmod +x /repos.bash
RUN /repos.bash

# Download wazuh-manager pkg
#RUN rpm -i https://packages.wazuh.com/yum/el/7/x86_64/wazuh-manager-2.0.1-1.el7.x86_64.rpm

# Install wazuh-manager
RUN yum install -y wazuh-manager

# Install nodejs and wazuh-api 
RUN curl -sL https://rpm.nodesource.com/setup_6.x | bash -
RUN yum install -y nodejs 
#RUN rpm -i https://packages.wazuh.com/yum/el/7/x86_64/wazuh-api-2.0.1-1.el7.x86_64.rpm
RUN yum install -y wazuh-api

# Add OSSEC config
ADD config/securityonion_rules.xml /var/ossec/ruleset/rules/securityonion_rules.xml
ADD config/ossec.conf /var/ossec/etc/ossec.conf

# Adding first run script.
ADD config/data_dirs.env /data_dirs.env
ADD config/init.bash /init.bash

# Sync calls are due to https://github.com/docker/docker/issues/9547
RUN chmod 755 /init.bash &&\
    sync && /init.bash &&\
    sync && rm /init.bash

# Adding entrypoint
ADD config/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh

RUN yum clean all

ENTRYPOINT ["/entrypoint.sh"]

FROM armdocker.rnd.ericsson.se/proj-ldc/common_base_os_release/sles:BASE_IMAGE_VERSION

MAINTAINER VM VNFM

COPY . /tmp/localrepo/
COPY code/* /opt/ericsson/eric-vnflcm-migration/scripts/

RUN (echo [SLES-OS]; echo name=SLES-OS; echo baseurl=https://arm.rnd.ki.sw.ericsson.se/artifactory/proj-ldc-repo-rpm-local/common_base_os/sles/BASE_IMAGE_VERSION?ssl_verify=no; echo enabled=1; echo gpgcheck=0) > /etc/zypp/repos.d/COMMON_BASE_OS_SLES_REPO.repo \
    && (echo [LocalRepo]; echo name=Local Repository; echo baseurl=file:///tmp/localrepo/; echo enabled=1; echo gpgcheck=0) > /etc/zypp/repos.d/localrepo.repo \
    && (echo [ADPBuildEnv]; echo name=ADPBuildEnv; echo baseurl=https://arm.sero.gic.ericsson.se/artifactory/proj-ldc-repo-rpm-local/adp-dev/adp-build-env/BASE_IMAGE_VERSION?ssl_verify=no; echo enabled=1; echo gpgcheck=0) > /etc/zypp/repos.d/ADPBuildEnv.repo \
    && zypper install -y libxslt1 python3 rsyslog aaa_base-extras openssh cronie shadow curl wget iputils unzip python3-requests python3-pycurl python3-PyYAML postgresql postgresql-server postgresql-contrib python3-paramiko python3-pycryptodome python3-rpm python3-Jinja2 python3-psycopg2 libcap-progs \
    && setcap cap_net_raw,cap_net_admin+p /usr/bin/ping \
    && zypper rm -y libcap-progs \
    && (echo [3ppRepo]; echo name=3ppRepo; echo baseurl=https://arm.sero.gic.ericsson.se/artifactory/proj-suse-repos-rpm-local/SLE15/SLE-15-SP4-Module-Basesystem/?ssl_verify=no; echo enabled=1; echo gpgcheck=0) > /etc/zypp/repos.d/3ppRepo.repo \
    && zypper in -r 3ppRepo -y python3-PrettyTable python3-pexpect \
    && (echo [ADPBuildEnv]; echo name=ADPBuildEnv; echo baseurl=https://arm.sero.gic.ericsson.se/artifactory/proj-ldc-repo-rpm-local/adp-dev/adp-build-env/BASE_IMAGE_VERSION?ssl_verify=no; echo enabled=1; echo gpgcheck=0) > /etc/zypp/repos.d/ADPBuildEnv.repo && zypper in -r ADPBuildEnv -y vim gcc && zypper rr ADPBuildEnv \
    && chmod -R 755 /opt/ericsson \
    && rm -rf /tmp/localrepo/ \
    && groupadd eric-vm-vnfm-migration -g 261482 \
    && useradd -G eric-vm-vnfm-migration eric-vm-vnfm-migration -u 261482 -d /home/eric-vm-vnfm-migration \
    && chage -E -1 -M -1 eric-vm-vnfm-migration \
    && mkdir -p /home/eric-vm-vnfm-migration \
    && chmod 777 /opt/ericsson/eric-vnflcm-migration/scripts/entrypoint.sh \
    && ln -f -s /usr/bin/python3.6 /usr/bin/python \
    && echo "All operations completed."

ENTRYPOINT exec  /bin/sh /opt/ericsson/eric-vnflcm-migration/scripts/entrypoint.sh

USER eric-vm-vnfm-migration

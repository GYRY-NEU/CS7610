FROM centos:8

RUN yum -y update &&\
    yum -y install dnf-plugins-core python39-pip make cmake gcc gcc-c++ git &&\
    dnf config-manager --set-enabled powertools &&\
    yum config-manager --set-enabled powertools &&\
    dnf -y install glibc-static &&\
    yum -y install libstdc++-static &&\
    pip3 install conan

RUN conan profile new default --detect &&\
    sed -i 's/compiler.libcxx=libstdc++/compiler.libcxx=libstdc++11/g' /root/.conan/profiles/default

ADD . /final

RUN cd /final && \
    make release

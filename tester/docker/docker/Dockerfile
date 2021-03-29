FROM ubuntu:18.04 

MAINTAINER Clemens Schiffer <clemens.schiffer@v2c2.at>

USER root 
RUN apt-get update; apt-get upgrade -y; 
RUN apt-get -y install  git build-essential g++-7 cmake gcc-7 libicu-dev build-essential libzip-dev libxerces-c-dev libssl-dev xsdcxx libasio-dev
RUN apt-get -y install unzip htop net-tools network-manager vim iputils-ping  tmux wget 
RUN apt-get -y install maven lib32z1 lib32ncurses5 bzip2

# build dir
RUN mkdir -p /var/build 
WORKDIR /var/build

RUN git clone https://github.com/modelica/DCPLib.git /var/build/DCPLib

RUN cd /var/build/DCPLib && mkdir -p build && cd build && \
	cmake .. && \
	cmake --build . --target install

RUN wget https://github.com/CLIUtils/CLI11/releases/download/v1.9.1/CLI11.hpp
RUN cp /var/build/CLI11.hpp /usr/local/include/ 
RUN git clone https://github.com/modelica/DCPTester.git /var/build/DCPTester
WORKDIR /var/build/DCPTester
RUN chmod +x build.sh
RUN ./build.sh

WORKDIR /var/build/DCPTester/tester/SlaveUnderTest
RUN mkdir build 
RUN cd build && cmake .. && cmake --build .

RUN git clone https://github.com/modelica/DCPTestGenerator.git /var/build/TestGenerator
WORKDIR /var/build/TestGenerator
RUN mvn verify



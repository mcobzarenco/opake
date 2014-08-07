FROM ubuntu:14.04

MAINTAINER Marius Cobzarenco <marius@reinfer.io>

RUN mkdir /src
WORKDIR /src

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    apt-get install -y python-dev python-pip && \
    apt-get install -y automake build-essential libtool git && \
    apt-get install -y libffi-dev

# Install node, coffeescript and bower
RUN apt-add-repository -y ppa:chris-lea/node.js && \
    apt-get update && \
    apt-get install -y nodejs
RUN npm install -g coffee-script
RUN npm install -g bower

# Install libsodium from source
RUN git clone https://github.com/jedisct1/libsodium.git
RUN cd libsodium && ./autogen.sh && ./configure && make && make install

# Install pynacl from source
RUN git clone https://github.com/pyca/pynacl.git
RUN cd pynacl && python setup.py install

# Install disturbe
RUN pip install bottle jsonschema gunicorn redis riak
RUN ldconfig
RUN mkdir disturbe
ADD . /src/disturbe
RUN rm -rf disturbe/static/components
RUN cd disturbe && bower --allow-root install
RUN cd disturbe/static && coffee -c disturbe.coffee

VOLUME ["/src/disturbe"]
WORKDIR /src/disturbe

ENTRYPOINT ["./disturbe-app.py"]

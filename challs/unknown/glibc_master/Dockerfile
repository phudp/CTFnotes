FROM debian:bookworm
# RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list
RUN apt-get update && apt-get -y upgrade
RUN apt-get install -y xinetd
RUN useradd -u 1000 -m pwn
CMD ["/usr/sbin/xinetd", "-dontfork"]

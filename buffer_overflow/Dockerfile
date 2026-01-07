FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    gdb \
    python3 \
    python3-pip \
    git \
    vim \
    nano \
    curl \
    wget \
    sudo \
    net-tools \
    iptables \
    tar \
    gzip \
    build-essential \
    libc6-dev \
    libssl-dev \
    libffi-dev \
    procps \
    netcat \
    socat \
    strace \
    ltrace \
    checksec \
    binutils \
    file \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash user && \
    echo "user:user" | chpasswd && \
    echo "root:root" | chpasswd

RUN pip3 install --upgrade pip && \
    pip3 install \
    pwntools

WORKDIR /opt
RUN git clone https://github.com/pwndbg/pwndbg && \
    cd pwndbg && \
    ./setup.sh

RUN echo "source /opt/pwndbg/gdbinit.py" >> /root/.gdbinit && \
    echo "set disassembly-flavor intel" >> /root/.gdbinit && \
    echo "set follow-fork-mode child" >> /root/.gdbinit && \
    cp /root/.gdbinit /home/user/.gdbinit && \
    chown user:user /home/user/.gdbinit

RUN mkdir -p /challenge

COPY sysadmin.c /challenge/sysadmin.c

WORKDIR /challenge
RUN gcc -fno-stack-protector -no-pie -z execstack -g -O0 -o sysadmin sysadmin.c

RUN chown root:root sysadmin && \
    chmod u+s sysadmin && \
    chown user:user /challenge -R

RUN echo "alias gdb='gdb -q'" >> /home/user/.bashrc && \
    echo "alias ll='ls -la'" >> /home/user/.bashrc && \
    echo "export TERM=xterm-256color" >> /home/user/.bashrc

RUN cat > /usr/local/bin/start_challenge << 'EOF'
#!/bin/bash
clear
echo "===================================================="
echo "     System Administration Console Challenge       "
echo "===================================================="
echo ""
echo "Binary: ./sysadmin (SUID root)"
echo "Source: sysadmin.c"
echo ""
echo "Available tools:"
echo "  gdb ./sysadmin          - Debug with pwndbg"
echo "  checksec ./sysadmin     - Check security"
echo "  python3                 - Python with pwntools"
echo ""
echo "Current directory: /challenge"
echo "===================================================="
cd /challenge
exec /bin/bash
EOF

RUN chmod +x /usr/local/bin/start_challenge

USER user
WORKDIR /challenge

CMD ["/bin/bash", "-c", "start_challenge"]

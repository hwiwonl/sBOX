#!/bin/bash

##
## Check the os and distributions
##
function get_distro() {
    if [[ -f /etc/os-release ]]
      then
        # On Linux systems
        source /etc/os-release
        dist=$ID
        ver=$VERSION_ID
    else
        # On systems other than Linux (e.g. Mac or FreeBSD)
        dist='etc'
    fi
}

PID=$$

function exe() {
    $@ && echo -e "\e[32m@@SUCCESS [$@]\e[0m" || (echo -e "\e[31m@@FAIL [$@]\e[0m" ; kill -9 $PID)
}

get_distro
F_KERNEL="/var/log/sbx_kernel_check"
F_KERNUP="/var/log/sbx_kernel_upgrade"
F_BCC="/var/log/sbx_bcc_check"

function ubuntu_setup() {
    echo -e "\033[43;31mUbuntu" $ver"\033[0m"
    ## Check kernel version
    regex='([0-9]+)\.([0-9]+)'
    [[ $(uname -r) =~ $regex ]]
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}

    [[ $(echo $ver) =~ $regex ]]
    main=${BASH_REMATCH[1]}

    # echo $major.$minor
    if [ $major -ge '4' -a $minor -ge '2' ]; then
        if [ $main -eq '21' ]; then
            echo "Hello 21.xx"
            apt install -y bison build-essential cmake flex git libedit-dev libllvm11 llvm-11-dev libclang-11-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils python3-yaml
            apt install -y arping netperf iperf
            apt install -y luajit luajit-5.1-dev
        elif [ $main -eq '20' ]; then
            echo "Hello 20.xx"
            exe apt update
            ## Install LLVM & Dependencies
            echo -e "\033[43;31mInstall LLVM & Dependencies\033[0m"
            exe apt install -y bison build-essential cmake flex git libedit-dev libllvm7 llvm-7-dev libclang-7-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils python3-yaml
            exe apt install -y luajit libluajit-5.1-dev
            
            ## Build bcc
            echo -e "\033[43;31mBuild bcc\033[0m"
            exe wget https://github.com/iovisor/bcc/releases/download/v0.22.0/bcc-src-with-submodule.tar.gz
            exe tar xvfz bcc-src-with-submodule.tar.gz
            exe rm -rf bcc-src-with-submodule.tar.gz
            exe mkdir bcc/build
            exe cd bcc/build
            exe cmake ..
            exe make
            exe make install
            exe cmake -DPYTHON_CMD=python3 .. # build python3 binding
            exe cd src/python/
            exe make
            exe make install
            # popd
            ## FLAG denoting that this system is ready for SBX
            exe touch $F_BCC
            # /usr/lib/systemd/system/sbx.service
            
        elif [ $main -eq '18' ]; then
            echo "Hello 18.xx"
            exe apt update

            if [ $major -ge '5' -a $minor -ge '2' ]; then
                ## FLAG denoting that the current kernel version supports BCC
                if [ -f $F_KERNUP ]; then
                    exe rm -rf $F_KERNUP
                    exe touch $F_KERNEL
                    echo "Current kernel version now supports BCC"
                else
                    echo "Current kernel version already supports BCC"
                    exe touch $F_KERNEL
                fi

                ## Install LLVM & Dependencies
                echo -e "\033[43;31mInstall LLVM & Dependencies\033[0m"
                export DEBIAN_FRONTEND=noninteractive
                exe apt install -y bison build-essential cmake flex git libedit-dev libllvm6.0 llvm-6.0-dev libclang-6.0-dev python3 zlib1g-dev libelf-dev libfl-dev python3-distutils python3-yaml
                exe apt install -y arping netperf iperf
                exe apt install -y luajit luajit-5.1-dev

                ## Build bcc
                echo -e "\033[43;31mBuild bcc\033[0m"
                exe update-alternatives --install /usr/bin/python python /usr/bin/python3 10
                exe wget https://github.com/iovisor/bcc/releases/download/v0.22.0/bcc-src-with-submodule.tar.gz
                exe tar xvfz bcc-src-with-submodule.tar.gz
                exe rm -rf bcc-src-with-submodule.tar.gz
                exe mkdir bcc/build
                exe cd bcc/build
                exe cmake ..
                exe make
                exe make install
                exe cmake -DPYTHON_CMD=python3 .. # build python3 binding
                exe cd src/python/
                exe make
                exe make install
                # popd
                ## FLAG denoting that this system is ready for SBX
                exe touch $F_BCC
            else
                echo -e "\033[43;31mUpgrade kernel...\033[0m"
                ## Kernel update
                exe apt install -y linux-image-5.4.0-97-generic
                exe apt install -y linux-headers-5.4.0-97-generic
                ## FLAG denoting that the current kernel version supports BCC
                exe touch $F_KERNUP
                sleep 3 && reboot &
                exit 100
            fi

        elif [ $main -eq '16' ]; then
            echo "Hello 16.xx"
            
        elif [ $main -eq '14' ]; then
            echo "Hello 14.xx"
            VER=trusty
            echo "deb http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main
            deb-src http://llvm.org/apt/$VER/ llvm-toolchain-$VER-3.7 main" | \
                sudo tee /etc/apt/sources.list.d/llvm.list            
            wget -O - http://llvm.org/apt/llvm-snapshot.gpg.key --no-check-certificate | sudo apt-key add -
            apt-get update
            
        else
            echo "Other versions"
        fi
    fi

}

function centos_setup() {
    echo -e "\033[43;31mCentOS" $ver"\033[0m"
    ## Check kernel version
    regex='([0-9]+)\.([0-9]+)'
    [[ $(uname -r) =~ $regex ]]
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}

    if [ $ver == '7' ]
        then
            echo "Hello CentOS 7"
            if [ $major -ge '4' -a $minor -ge '2' ]; then
                ## FLAG denoting that the current kernel version supports BCC
                if [ -f $F_KERNUP ]; then
                    exe rm -rf $F_KERNUP
                    exe touch $F_KERNEL
                    echo "Current kernel version now supports BCC"
                else
                    echo "Current kernel version already supports BCC"
                    touch $F_KERNEL
                fi

                ## Update repo manager
                exe yum -y update
                exe yum install yum-plugin-fastestmirror
                exe rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org

                ## Install LLVM
                echo -e "\033[43;31mInstall LLVM\033[0m"
                exe yum install -y centos-release-scl yum-utils
                exe yum-config-manager --enable rhel-server-rhscl-7-rpms
                # exe yum install -y devtoolset-7 llvm-toolset-7 llvm-toolset-7-llvm-devel llvm-toolset-7-llvm-static llvm-toolset-7-clang-devel
                # source scl_source enable devtoolset-7 llvm-toolset-7
                exe yum install -y devtoolset-7.0 llvm-toolset-7.0 llvm-toolset-7.0-llvm-devel llvm-toolset-7.0-llvm-static llvm-toolset-7.0-clang-devel
                source scl_source enable devtoolset-7.0 llvm-toolset-7.0
                # exe scl enable llvm-toolset-7.0 bash 

                ## Install dependencies
                echo -e "\033[43;31mInstall Dependencies\033[0m"
                exe yum install -y python3 python3-yaml wget git cmake gcc gcc-c++
                exe yum install -y elfutils-libelf-devel cmake3 bison flex ncurses-devel
                # exe yum install -y luajit luajit-devel  # for Lua support 
            else
                echo -e "\033[43;31mUpgrade kernel...\033[0m"
                ## Download the latest kernel
                exe yum install -y https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
                exe yum -y --enablerepo=elrepo-kernel install kernel-ml kernel-ml-devel
                exe grub2-set-default 0
                ## FLAG denoting that the current kernel version supports BCC
                exe touch $F_KERNUP
                sleep 3 && reboot &
                exit 100
            fi
    elif [ $ver == '8' ]
        then
            echo "Hello CentOS 8"
            ## FLAG denoting that the current kernel version supports BCC
            echo "Current kernel version already supports BCC"
            exe touch $F_KERNEL

            dnf -y update
            stat=$?
            if [ $stat -ne 0 ]
                then
                    ## Update packages
                    exe sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
                    exe sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
                    exe rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-*
                    exe dnf -y update --allowerasing --nogpgcheck
            fi

            exe dnf install centos-release-stream -y
            exe dnf swap centos-{linux,stream}-repos -y
            exe dnf distro-sync -y

            ## Upgrade kernel
            # yum install -y https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm
            # dnf install -y https://www.elrepo.org/elrepo-release-8.0-2.el8.elrepo.noarch.rpm
            # dnf -y --enablerepo=elrepo-kernel install kernel-ml

            ## Install LLVM
            echo -e "\033[43;31mInstall LLVM\033[0m"
            ## TODO : encapsulate development tools
            # exe dnf -y group install "Development Tools"
            dnf -y group install "Development Tools"
            # yum install -y scl-utils-build.x86_64
            exe dnf -y install clang clang-devel llvm-toolset llvm-devel llvm-static 

            ## Install dependencies
            echo -e "\033[43;31mInstall Dependencies\033[0m"
            exe yum install -y python3 python3-yaml wget git cmake gcc gcc-c++
            alternatives --set python /usr/bin/python3
            exe yum install -y elfutils-libelf-devel cmake3 git bison flex ncurses-devel
            exe yum install -y https://forensics.cert.org/cert-forensics-tools-release-el8.rpm
            exe dnf --enablerepo=forensics install -y luajit luajit-devel
    else
        echo "Not supported version" $dist $ver
    fi

    ## Download bcc
    echo -e "\033[43;31mBuild bcc\033[0m"
    exe wget https://github.com/iovisor/bcc/releases/download/v0.22.0/bcc-src-with-submodule.tar.gz
    exe tar xvfz bcc-src-with-submodule.tar.gz
    exe rm -rf bcc-src-with-submodule.tar.gz
    exe mkdir bcc/build 
    exe cd bcc/build
    exe cmake -DENABLE_LLVM_SHARED=1 ..
    exe make -j$(nproc)
    exe make install
    exe cmake -DENABLE_LLVM_SHARED=1 -DPYTHON_CMD=python3 ..
    exe cd src/python
    exe make
    exe make install
    ## FLAG denoting that this system is ready for SBX
    exe touch $F_BCC
}

function almalinux_setup() {
    echo -e "\033[43;31;1mAlmaLinux" $ver"\033[0m"
    ## Check kernel version
    regex='([0-9]+)\.([0-9]+)'
    [[ $(uname -r) =~ $regex ]]
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}

    echo "Current kernel version" $major.$minor "already supports BCC"
    exe touch $F_KERNEL

    ## Update repositories
    dnf -y update
    stat=$?
    if [ $stat -ne 0 ]
        then
            ## Update packages
            exe sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*
            exe sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*
            exe rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-*
            exe dnf -y update --allowerasing --nogpgcheck
    fi

    # exe dnf install centos-release-stream -y
    # exe dnf swap centos-{linux,stream}-repos -y
    # exe dnf distro-sync -y

    ## Install LLVM
    echo -e "\033[43;31mInstall LLVM\033[0m"
    ## TODO : encapsulate development tools
    # exe dnf -y group install "Development Tools"
    dnf -y group install "Development Tools"
    # yum install -y scl-utils-build.x86_64
    exe dnf -y install clang clang-devel llvm-toolset llvm-devel llvm-static 

    ## Install dependencies
    echo -e "\033[43;31mInstall Dependencies\033[0m"
    exe yum install -y python3 python3-yaml wget git cmake gcc gcc-c++
    alternatives --set python /usr/bin/python3
    exe yum install -y elfutils-libelf-devel cmake3 git bison flex ncurses-devel
    exe yum install -y https://forensics.cert.org/cert-forensics-tools-release-el8.rpm
    exe dnf --enablerepo=forensics install -y luajit luajit-devel

    ## Download bcc
    echo -e "\033[43;31mBuild bcc\033[0m"
    exe wget https://github.com/iovisor/bcc/releases/download/v0.22.0/bcc-src-with-submodule.tar.gz
    exe tar xvfz bcc-src-with-submodule.tar.gz
    exe rm -rf bcc-src-with-submodule.tar.gz
    exe mkdir bcc/build 
    exe cd bcc/build
    exe cmake -DENABLE_LLVM_SHARED=1 ..
    exe make -j$(nproc)
    exe make install
    exe cmake -DENABLE_LLVM_SHARED=1 -DPYTHON_CMD=python3 ..
    exe cd src/python
    exe make
    exe make install
    ## FLAG denoting that this system is ready for SBX
    exe touch $F_BCC
}

function debian_setup() {
    echo -e "\033[43;31mDebian" $ver"\033[0m"
}

if [ $dist == 'ubuntu' ]
  then
    ubuntu_setup
elif [ $dist == 'debian' ]
  then    
    debian_setup
elif [ $dist == 'centos' ] && [ $ver == '7' ] || [ $ver == '8' ]
  then
    centos_setup
elif [ $dist == 'almalinux' ]
  then
    almalinux_setup
else
    echo "Not supported OS" $dist $ver
fi

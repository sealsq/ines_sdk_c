#!/bin/bash -e

#=======================================
#SEAL SQ 2024
#INeS SDK
#IoT / Tools / Provisioning / Firmware Team
#=======================================

#SPDX-License-Identifier: Apache-2.0*/

FIRST_CONFIG_FILE=.firstconfig.txt

Help()
{
   # Display Help
   echo "This script allow you to run instalation and working Zero Touch Provisioning demo"
   echo
   echo "options:"
   echo "-i     First instalation, this will install cmake and Python requierements"
   echo "-w     Force compilation of wolfssl Library"
   echo "-b     This will force the building of library Ines SDK"
   echo "-h     Print this Help."
}

install()
{
   sudo apt-get update
   sudo apt-get --yes --force-yes install cmake
   sudo apt-get --yes --force-yes install python3
}

submoduleInit()
{   
   source config.cfg
   git submodule init
   git submodule update
}

checkoutWolfssl()
{   
   source config.cfg
   pushd "extlibs/libwolfssl/wolfssl/"
   echo "----------| Checkout to WOLFSSL VERSION : ${WOLFSSL_TAG} |----------"
   git checkout ${WOLFSSL_TAG}   
   popd
}

addVaulticToWolfssl()
{   
   source config.cfg
   pushd "extlibs/libwolfssl/wolfssl/"
   echo "----------| Copy Vault-IC requierements to WOLFSSL stack |----------"
   cp -r ../patchwolfsslvaultic/wolfssl/* .
   popd
}

firstInstall()
{
   install
   addVaulticToWolfssl
   echo done, remove this file if you want to do first setup again > ${FIRST_CONFIG_FILE}
}

buildapp()
{
   echo "---INeS SDK : Build LIB START---"
   CMAKE_OPTS="-DVAULTIC_PRODUCT=${VAULTIC_PRODUCT}"
   
   CMAKE_OPTS+=" -DWOLFSSL_USER_SETTINGS=yes -DWOLFSSL_EXAMPLES=no -DWOLFSSL_CRYPT_TESTS=no"
   
   if([ ! -z ${COMPILATION_MODE} ] ); then 
    CMAKE_OPTS+=" -DCOMPILATION_MODE=${COMPILATION_MODE}"
   fi

   if([ ! -z ${INTERFACE} ] ); then 
    CMAKE_OPTS+=" -DVAULTIC_COMM=${INTERFACE}"
   fi

    CMAKE_OPTS+=" -DWITH_WOLFSSL=${CMAKE_BINARY_DIR}/lib/sealsq_inesSDK/extlibs/libwolfssl/wolfssl"

   echo "Running CMAKE"
   rm -rf build/
   mkdir build
   cd build/
   cmake ${CMAKE_OPTS} ..
   echo "Cleaning"
   make clean
   echo "Building"
   make all

   if [ -f "./zeroTouchProvisioning_app" ];then
      echo "Zero Touch Provisioning App in C build";
   else
      exit
   fi
}


############################################################
############################################################
# Main program                                             #
############################################################
############################################################
############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts ":hbiwv" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      i) # Install Prerequities
		 echo "Install Requierment"
         install
         exit;;
      b) # force build
         buildapp
         exit;;
      v) # Install Prerequities
		 echo "Vault-IC with Wolfssl config"
         addVaulticToWolfssl
         exit;;
      \?) # Invalid option
         echo "Error: Invalid option"
         Help
         exit;;
   esac
done

source config.cfg

if [ -e ${FIRST_CONFIG_FILE} ]
then
    echo "First config Already done"
else
    echo "Do first config"
    firstInstall
fi


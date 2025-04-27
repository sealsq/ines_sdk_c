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
   submoduleInit
   checkoutWolfssl
   addVaulticToWolfssl
   echo done, remove this file if you want to do first setup again > ${FIRST_CONFIG_FILE}
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


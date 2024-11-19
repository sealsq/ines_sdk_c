# Nous voulons un cmake "récent" pour utiliser les dernières fonctionnalités
cmake_minimum_required(VERSION 3.0)

# Notre projet est étiqueté libhello
project(libini)

# Crée des variables avec les fichiers à compiler
set(SRCS
    ini.c
    )
    
set(HEADERS
    ini.h
    )
source_group( include FILES ${HEADERS} )
source_group( src FILES ${SRCS} )
    
add_library(ini ${SRCS} ${HEADERS})

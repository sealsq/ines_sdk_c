# Nous voulons un cmake "récent" pour utiliser les dernières fonctionnalités
cmake_minimum_required(VERSION 3.0)

# Notre projet est étiqueté libhello
project(libjson)

# Crée des variables avec les fichiers à compiler
set(SRCS
    json.c
    )
    
set(HEADERS
    json.h
    )
source_group( include FILES ${HEADERS} )
source_group( src FILES ${SRCS} )
    
add_library(json ${SRCS} ${HEADERS})

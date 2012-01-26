SAGA X.509 Context Adaptor
==========================

The X.509 adaptor implements the SAGA context API for X.509 
certificates. It is required by several other adaptors, 
including the Globus and gLite adaptors. 

Setup
-----

(Please refer to the INSTALL file for more details)

Assuming the required SAGA C++ Core libraries are installed and the environment 
variable $SAGA_LOCATION is set accordingly, the Condor adaptor can be installed
by typing:

    ./configure
    make
    make install 

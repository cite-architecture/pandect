#/bin/bash
export LIBCPTL_PATH=/Users/gweaver/DISTRO/cptl-power/src/
export LIBXML2_PATH=/usr/local/opt/libxml2/lib/python2.7/site-packages
export PYTHONPATH=$LIBXML2_PATH:$LIBCPTL_PATH:$PYTHONPATH
python ./src/pandect/browser.py
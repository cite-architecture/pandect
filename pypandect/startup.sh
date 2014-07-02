#/bin/bash
export LIBCPTL_PATH=/path/to/DISTRO/cptl-power/src/
export PYTHONPATH=$LIBCPTL_PATH:$PYTHONPATH
python2 ./src/pandect/browser.py
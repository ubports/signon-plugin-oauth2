include( common-vars.pri )
include( common-project-config.pri )

TEMPLATE  = subdirs
CONFIG   += ordered
SUBDIRS   = src tests

include( common-installs-config.pri )

#include( doc/doc.pri )

# End of File

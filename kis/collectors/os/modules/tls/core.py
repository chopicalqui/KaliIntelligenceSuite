# -*- coding: utf-8 -*-
"""
implements all base functionality for TLS collectors
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2018 Lukas Reiter

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
__version__ = 0.1

from collectors.os.modules.core import BaseCollector
from collectors.os.modules.core import BaseHydra
from collectors.os.modules.core import BaseNmap
from collectors.os.modules.core import ServiceDescriptorBase


class TlsServiceDescriptor(ServiceDescriptorBase):
    """
    This class describes how an TLS service looks like
    """

    def __init__(self):
        super().__init__()


class BaseTlsCollector(BaseCollector):
    """
    This is the base class for all TLS collectors
    """

    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TlsServiceDescriptor(),
                         **kwargs)


class BaseTlsHydra(BaseHydra):
    """
    This class implements basic functionality for TLS collectors that use Hydra.
    """
    def __init__(self, priority, timeout, **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TlsServiceDescriptor(),
                         **kwargs)


class BaseTlsNmap(BaseNmap):
    """
    This class implements basic functionality for TLS collectors that use Hydra.
    """
    def __init__(self, priority,
                 timeout,
                 **kwargs):
        super().__init__(priority=priority,
                         timeout=timeout,
                         service_descriptors=TlsServiceDescriptor(),
                         **kwargs)


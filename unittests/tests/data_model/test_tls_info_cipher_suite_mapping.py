#!/usr/bin/python3
"""
this file implements unittests for the data model
"""

__author__ = "Lukas Reiter"
__license__ = "GPL v3.0"
__copyright__ = """Copyright 2022 Lukas Reiter

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

from database.model import KeyExchangeAlgorithm
from database.model import TlsInfoCipherSuiteMapping
from unittests.tests.core import BaseDataModelTestCase


class TestTlsInfoCipherSuiteMapping(BaseDataModelTestCase):
    """
    Test data model for TlsInfoCipherSuiteMapping
    """

    def __init__(self, test_name: str):
        super().__init__(test_name, TlsInfoCipherSuiteMapping)

    def test_unique_constraint(self):
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            tls_info = self.create_tls_info(session=session)
            cipher_suite = self.query_cipher_suite(session=session)
            self._test_unique_constraint(session=session,
                                         tls_info=tls_info,
                                         cipher_suite=cipher_suite,
                                         order=1,
                                         prefered=False,
                                         kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)

    def test_not_null_constraint(self):
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            tls_info = self.create_tls_info(session=session)
            cipher_suite = self.query_cipher_suite(session=session)
            self._test_not_null_constraint(session=session,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           prefered=False,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           order=1,
                                           prefered=False,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           prefered=False,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           prefered=False)
            self._test_not_null_constraint(session=session,
                                           tls_info=tls_info,
                                           cipher_suite=cipher_suite,
                                           order=1,
                                           kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)

    def test_check_constraint(self):
        pass

    def test_success(self):
        self.init_db(load_cipher_suites=True)
        with self._engine.session_scope() as session:
            tls_info = self.create_tls_info(session=session)
            cipher_suite = self.query_cipher_suite(session=session)
            self._test_success(session=session,
                               tls_info=tls_info,
                               cipher_suite=cipher_suite,
                               order=1,
                               prefered=False,
                               kex_algorithm_details=KeyExchangeAlgorithm.ecdh_x25519)

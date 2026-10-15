// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uasc

import (
	"bytes"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uapolicy"
)

func (s *SecureChannel) verifyRemoteCertificate(der []byte) error {
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil {
		return ua.StatusBadCertificateInvalid
	}
	leaf := append([]byte(nil), cert.Raw...)
	if err := s.cfg.VerifyServerCertificate(append([]byte(nil), leaf...), ""); err != nil {
		return err
	}
	s.verifiedRemoteCertificateMu.Lock()
	s.verifiedRemoteCertificate = leaf
	s.verifiedRemoteCertificateMu.Unlock()
	return nil
}

// VerifySessionCertificate binds the CreateSession certificate to the authenticated
// OPN leaf and validates its ApplicationURI before credentials are sent.
func (s *SecureChannel) VerifySessionCertificate(der []byte, applicationURI string) error {
	if s.cfg.VerifyServerCertificate == nil || s.cfg.SecurityMode == ua.MessageSecurityModeNone {
		return nil
	}
	cert, err := uapolicy.ParseCertificate(der)
	if err != nil {
		return ua.StatusBadCertificateInvalid
	}
	s.verifiedRemoteCertificateMu.RLock()
	same := len(s.verifiedRemoteCertificate) > 0 && bytes.Equal(s.verifiedRemoteCertificate, cert.Raw)
	s.verifiedRemoteCertificateMu.RUnlock()
	if !same {
		return ua.StatusBadCertificateInvalid
	}
	if applicationURI == "" {
		return ua.StatusBadCertificateURIInvalid
	}
	return s.cfg.VerifyServerCertificate(append([]byte(nil), cert.Raw...), applicationURI)
}

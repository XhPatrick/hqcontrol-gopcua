// Copyright 2018-2020 opcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package opcua

import "github.com/gopcua/opcua/ua"

func serverApplicationURI(endpoints []*ua.EndpointDescription, mode ua.MessageSecurityMode, policy string) (string, error) {
	var uri string
	for _, ep := range endpoints {
		if ep == nil || ep.SecurityMode != mode || ep.SecurityPolicyURI != policy {
			continue
		}
		if ep.Server == nil || ep.Server.ApplicationURI == "" {
			return "", ua.StatusBadCertificateURIInvalid
		}
		if uri != "" && uri != ep.Server.ApplicationURI {
			return "", ua.StatusBadCertificateURIInvalid
		}
		uri = ep.Server.ApplicationURI
	}
	if uri == "" {
		return "", ua.StatusBadCertificateURIInvalid
	}
	return uri, nil
}

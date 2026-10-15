# Authenticated server certificate validation

This fork starts from gopcua v0.9.1, commit
`79bc0dc8971d5d4e5dcab6e182f5ecca4278b0a8`. The upstream MIT license is retained.

`opcua.VerifyServerCertificate` adds an optional validation callback after the
SDK authenticates each signed OpenSecureChannel response, including renewal.
The SDK binds the CreateSession certificate to that authenticated channel leaf
and validates the matching endpoint ApplicationURI before ActivateSession.
Session signature verification errors are returned instead of being discarded.

The callback receives the actual leaf DER and an empty URI during channel
validation, then the server ApplicationURI during session validation. It must
validate application trust, certificate lifetime, host identity and URI as
required by its consumer. A nil callback retains the upstream trust behavior;
it does not enable certificate validation automatically. SecurityMode None
has no authenticated certificate contract.

This hook does not implement a CA trust store, revocation retrieval or automatic
certificate acceptance. HQControl uses explicit administrator trust of one leaf
certificate and standard Go X.509 verification. Tests cover actual signed
channels, pre-activation rejection and renewal.

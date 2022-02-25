package crypto11

import (
	"crypto"
	"crypto/x509"
	"github.com/miekg/pkcs11"
	"github.com/pkg/errors"
)

// Takes a handles to the private half of a keypair, locates the public half with the matching CKA_ID and CKA_LABEL
// values and constructs a keypair object from them both.
func (c *Context) makeKeyPairByLabel(session *pkcs11Session, privHandle *pkcs11.ObjectHandle) (signer Signer, certificate *x509.Certificate, err error) {
	attributes := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, 0),
	}
	if attributes, err = session.ctx.GetAttributeValue(session.handle, *privHandle, attributes); err != nil {
		return nil, nil, err
	}

	label := attributes[0].Value
	keyType := bytesToUlong(attributes[1].Value)

	var pubHandle *pkcs11.ObjectHandle

	// Find the public half which has a matching CKA_LABEL
	pubHandle, err = findKey(session, nil, label, uintPtr(pkcs11.CKO_PUBLIC_KEY), &keyType)
	if err != nil {
		return nil, nil, err
	}

	resultPkcs11PrivateKey := pkcs11PrivateKey{
		pkcs11Object: pkcs11Object{
			handle:  *privHandle,
			context: c,
		},
	}

	var pub crypto.PublicKey
	if pub == nil && pubHandle == nil {
		// We can't return a Signer if we don't have private and public key. Treat it as an error.
		return nil, nil, errNoPublicHalf
	}

	switch keyType {
	case pkcs11.CKK_DSA:
		result := &pkcs11PrivateKeyDSA{pkcs11PrivateKey: resultPkcs11PrivateKey}
		if pubHandle != nil {
			if pub, err = exportDSAPublicKey(session, *pubHandle); err != nil {
				return nil, nil, err
			}
			result.pkcs11PrivateKey.pubKeyHandle = *pubHandle
		}

		result.pkcs11PrivateKey.pubKey = pub
		return result, certificate, nil

	case pkcs11.CKK_RSA:
		result := &pkcs11PrivateKeyRSA{pkcs11PrivateKey: resultPkcs11PrivateKey}
		if pubHandle != nil {
			if pub, err = exportRSAPublicKey(session, *pubHandle); err != nil {
				return nil, nil, err
			}
			result.pkcs11PrivateKey.pubKeyHandle = *pubHandle
		}

		result.pkcs11PrivateKey.pubKey = pub
		return result, certificate, nil

	case pkcs11.CKK_ECDSA:
		result := &pkcs11PrivateKeyECDSA{pkcs11PrivateKey: resultPkcs11PrivateKey}
		if pubHandle != nil {
			if pub, err = exportECDSAPublicKey(session, *pubHandle); err != nil {
				return nil, nil, err
			}
			result.pkcs11PrivateKey.pubKeyHandle = *pubHandle
		}

		result.pkcs11PrivateKey.pubKey = pub
		return result, certificate, nil

	default:
		return nil, nil, errors.Errorf("unsupported key type: %X", keyType)
	}
}

// FindKeyPair retrieves a previously created asymmetric key pair, or nil if it cannot be found.
//
// At least one of id and label must be specified.
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
// because we cannot implement crypto.Signer without the public key.
func (c *Context) FindKeyPairByLabel(label []byte) (Signer, error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	result, err := c.FindKeyPairsByLabel(label)
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		return nil, nil
	}

	return result[0], nil
}

// FindKeyPairs retrieves all matching asymmetric key pairs, or a nil slice if none can be found.
//
// At least one of id and label must be specified.
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
// because we cannot implement crypto.Signer without the public key.
func (c *Context) FindKeyPairsByLabel(label []byte) (signer []Signer, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	if label == nil {
		return nil, errors.New("id and label cannot both be nil")
	}

	attributes := NewAttributeSet()
	err = attributes.Set(CkaLabel, label)
	if err != nil {
		return nil, err
	}

	return c.FindKeyPairsByLabelWithAttributes(attributes)
}


// FindKeyPairsWithAttributes retrieves previously created asymmetric key pairs, or nil if none can be found.
// The given attributes are matched against the private half only. Then the public half with a matching CKA_ID
// and CKA_LABEL values is found.
//
// Only private keys that have a non-empty CKA_ID will be found, as this is required to locate the matching public key.
// If the private key is found, but the public key with a corresponding CKA_ID is not, the key is not returned
// because we cannot implement crypto.Signer without the public key.
func (c *Context) FindKeyPairsByLabelWithAttributes(attributes AttributeSet) (signer []Signer, err error) {
	if c.closed.Get() {
		return nil, errClosed
	}

	var keys []Signer

	if _, ok := attributes[CkaClass]; ok {
		return nil, errors.Errorf("keypair attribute set must not contain CkaClass")
	}

	err = c.withSession(func(session *pkcs11Session) error {
		// Add the private key class to the template to find the private half
		privAttributes := attributes.Copy()
		err = privAttributes.Set(CkaClass, pkcs11.CKO_PRIVATE_KEY)
		if err != nil {
			return err
		}

		privHandles, err := findKeysWithAttributes(session, privAttributes.ToSlice())
		if err != nil {
			return err
		}

		for _, privHandle := range privHandles {
			k, _, err := c.makeKeyPairByLabel(session, &privHandle)

			if err == errNoCkaId || err == errNoPublicHalf {
				continue
			}
			if err != nil {
				return err
			}

			keys = append(keys, k)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return keys, nil
}
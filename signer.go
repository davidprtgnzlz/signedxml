package signedxml

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

var signingAlgorithms map[x509.SignatureAlgorithm]cryptoHash

func init() {
	signingAlgorithms = map[x509.SignatureAlgorithm]cryptoHash{
		// MD2 not supported
		// x509.MD2WithRSA: cryptoHash{algorithm: "rsa", hash: crypto.MD2},
		x509.MD5WithRSA:    {algorithm: "rsa", hash: crypto.MD5},
		x509.SHA1WithRSA:   {algorithm: "rsa", hash: crypto.SHA1},
		x509.SHA256WithRSA: {algorithm: "rsa", hash: crypto.SHA256},
		x509.SHA384WithRSA: {algorithm: "rsa", hash: crypto.SHA384},
		x509.SHA512WithRSA: {algorithm: "rsa", hash: crypto.SHA512},
		// DSA not supported
		// x509.DSAWithSHA1:  cryptoHash{algorithm: "dsa", hash: crypto.SHA1},
		// x509.DSAWithSHA256:cryptoHash{algorithm: "dsa", hash: crypto.SHA256},
		// Golang ECDSA support is lacking, can't seem to load private keys
		// x509.ECDSAWithSHA1:   cryptoHash{algorithm: "ecdsa", hash: crypto.SHA1},
		// x509.ECDSAWithSHA256: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA256},
		// x509.ECDSAWithSHA384: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA384},
		// x509.ECDSAWithSHA512: cryptoHash{algorithm: "ecdsa", hash: crypto.SHA512},
	}
}

type cryptoHash struct {
	algorithm string
	hash      crypto.Hash
}

// Signer provides options for signing an XML document
type Signer struct {
	localOps bool
	signatureData
	privateKey interface{}
}

// NewSigner returns a *Signer for the XML provided
func NewSigner(xml string) (*Signer, error) {
	doc, err := parseXML(xml)
	if err != nil {
		return nil, err
	}
	return NewSignerFromDoc(doc)
}

// NewSignerFromDoc returns a *Signer for the Document provided
func NewSignerFromDoc(doc *etree.Document) (*Signer, error) {
	s := &Signer{localOps: false, signatureData: signatureData{xml: doc}}
	return s, nil
}

// Sign populates the XML digest and signature based on the parameters present and privateKey given
func (s *Signer) Sign(privateKey interface{}) (string, error) {
	s.privateKey = privateKey

	if s.signature == nil {
		if err := s.parseEnvelopedSignature(); err != nil {
			return "", err
		}
	}
	if err := s.parseSignedInfo(); err != nil {
		return "", err
	}
	if err := s.parseSigAlgorithm(); err != nil {
		return "", err
	}
	if err := s.parseCanonAlgorithm(); err != nil {
		return "", err
	}
	if err := s.setDigest(); err != nil {
		return "", err
	}
	if err := s.setSignature(); err != nil {
		return "", err
	}

	xml, err := s.xml.WriteToString()
	if err != nil {
		return "", err
	}
	return xml, nil
}

// SetReferenceIDAttribute set the referenceIDAttribute
func (s *Signer) SetReferenceIDAttribute(refIDAttribute string) {
	s.signatureData.refIDAttribute = refIDAttribute
}

// SetLocalOps set the local variable localOps to modify the behavior of the
// library to work with specific tags and not with the entire document
func (s *Signer) SetLocalOps(localOps bool) {
	s.localOps = localOps
}

func (s *Signer) setDigest() (err error) {
	var nss map[string]string
	if s.localOps {
		nss = make(map[string]string)
		FindAllNamespaces(&s.xml.Copy().Element, nss)
	}

	references := s.signedInfo.FindElements("./Reference")
	for _, ref := range references {
		var doc *etree.Document
		if s.localOps {
			doc, err = s.getReferencedXML(ref, s.xml.Copy())
			if err != nil {
				return err
			}
			if doc.Root().SelectAttr("xmlns:"+doc.Root().Space) == nil {
				doc.Root().CreateAttr("xmlns:"+doc.Root().Space, nss[doc.Root().Space])
			}

			// FIX: la canonicalización se debe realizar con el método Transform ÚNICAMENTE sobre el tag al cual se
			// le ha de calcular el/la Digest.
			// En la librería original, se hace siempre sobre el documento completo, con lo que el resultado de la
			// canonicalización es distinta al que se obtendría de hacer únicamente sobre el tag en cuestión
			//			==> Ver estandar
		} else {
			doc = s.xml.Copy()
		}

		transforms := ref.SelectElement("Transforms")
		if transforms != nil {
			for _, transform := range transforms.SelectElements("Transform") {
				if s.localOps {
					nnss := make(map[string]struct{})
					FindAllNeededNamespaces(&doc.Element, transform, false, nnss)
					for k := range nnss {
						if doc.Root().SelectAttr("xmlns:"+k) == nil {
							doc.Root().CreateAttr("xmlns:"+k, nss[k])
						}
					}
				}

				doc, err = processTransform(transform, doc)
				if err != nil {
					return err
				}
			}
		}

		if !s.localOps {
			doc, err = s.getReferencedXML(ref, doc)
			if err != nil {
				return err
			}
		}

		calculatedValue, err := calculateHash(ref, doc)
		if err != nil {
			return err
		}

		digestValueElement := ref.SelectElement("DigestValue")
		if digestValueElement == nil {
			return errors.New("signedxml: unable to find DigestValue")
		}
		digestValueElement.SetText(calculatedValue)
	}
	return nil
}

func (s *Signer) setSignature() (err error) {
	var canonSignedInfo string
	var signedInfoElement *etree.Element
	canonMethodDocAsString := ""
	if s.localOps {
		nss := make(map[string]string)
		nnss := make(map[string]struct{})
		FindAllNamespaces(&s.xml.Copy().Element, nss)

		signedInfoElement = s.signedInfo.Copy()
		canonMethodElement := signedInfoElement.FindElement("./CanonicalizationMethod").Copy()
		FindAllNeededNamespaces(signedInfoElement, canonMethodElement, false, nnss)

		for k := range nnss {
			if signedInfoElement.SelectAttr("xmlns:"+k) == nil {
				signedInfoElement.CreateAttr("xmlns:"+k, nss[k])
			}
		}

		if canonMethodElement != nil {
			tDoc := etree.NewDocument()
			tDoc.SetRoot(canonMethodElement)
			canonMethodDocAsString, err = tDoc.WriteToString()
			if err != nil {
				return fmt.Errorf("signedxml: it has been impossible to obtain the CanonicalizationMethod element")
			}
		}
	} else {
		signedInfoElement = s.signedInfo
	}

	canonSignedInfo, err = s.canonAlgorithm.ProcessElement(signedInfoElement, canonMethodDocAsString)
	if err != nil {
		return err
	}

	var hashed, signature []byte
	//var h1, h2 *big.Int
	signingAlgorithm, ok := signingAlgorithms[s.sigAlgorithm]
	if !ok {
		return errors.New("signedxml: unsupported algorithm")
	}

	hasher := signingAlgorithm.hash.New()
	hasher.Write([]byte(canonSignedInfo))
	hashed = hasher.Sum(nil)

	switch signingAlgorithm.algorithm {
	case "rsa":
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.privateKey.(*rsa.PrivateKey), signingAlgorithm.hash, hashed)
		/*
			case "dsa":
				h1, h2, err = dsa.Sign(rand.Reader, s.privateKey.(*dsa.PrivateKey), hashed)
			case "ecdsa":
				h1, h2, err = ecdsa.Sign(rand.Reader, s.privateKey.(*ecdsa.PrivateKey), hashed)
		*/
	}
	if err != nil {
		return err
	}

	// DSA and ECDSA has not been validated
	/*
		if signature == nil && h1 != nil && h2 != nil {
			signature = append(h1.Bytes(), h2.Bytes()...)
		}
	*/

	b64 := base64.StdEncoding.EncodeToString(signature)
	sigValueElement := s.signature.SelectElement("SignatureValue")
	sigValueElement.SetText(b64)

	return nil
}

func FindAllNamespaces(node *etree.Element, nss map[string]string) {
	for _, attr := range node.Attr {
		if attr.Space == "xmlns" {
			nss[attr.Key] = attr.Value
		}
	}
	for i := 0; i < len(node.Child); i++ {
		child := node.Child[i]
		switch child := child.(type) {
		case *etree.Element:
			FindAllNamespaces(child, nss)
		}
	}
}

func FindAllNeededNamespaces(node *etree.Element, canonOrTransMethod *etree.Element, deepSearch bool, nnss map[string]struct{}) {
	if nnss == nil {
		nnss = make(map[string]struct{})
	}

	if node.Space != "" {
		nnss[node.Space] = struct{}{}
	}

	if canonOrTransMethod != nil {
		methodDoc := etree.NewDocument()
		methodDoc.SetRoot(canonOrTransMethod.Copy())
		prefixList := FindPrefixList(methodDoc)
		for _, k := range prefixList {
			nnss[k] = struct{}{}
		}
	}

	if deepSearch {
		findAllNeededNamespaces(node, nnss)
	}
}

func findAllNeededNamespaces(node *etree.Element, nnss map[string]struct{}) {
	if nnss == nil {
		nnss = make(map[string]struct{})
	}

	if node.Space != "" {
		nnss[node.Space] = struct{}{}
	}

	for i := 0; i < len(node.Child); i++ {
		child := node.Child[i]
		switch child := child.(type) {
		case *etree.Element:
			findAllNeededNamespaces(child, nnss)
		}
	}
}

func FindPrefixList(canonOrTransformMethod *etree.Document) (result []string) {
	if canonOrTransformMethod == nil {
		return []string{}
	}

	inclNSNode := canonOrTransformMethod.Root().SelectElement("InclusiveNamespaces")
	if inclNSNode != nil {
		prefixList := inclNSNode.SelectAttrValue("PrefixList", "")
		if prefixList != "" {
			result = strings.Split(prefixList, " ")
		}
	}

	return
}

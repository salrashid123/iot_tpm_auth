package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	"github.com/google/go-tpm-tools/client"

	"github.com/google/go-tpm/tpm2"
)

const (
	emptyPassword   = ""
	defaultPassword = ""
)

var (
	tpmPath       = flag.String("tpm-path", "/dev/tpm0", "Path to the TPM device (character device or a Unix socket).")
	primaryHandle = flag.String("primaryHandle", "primary.bin", "Handle to the primary")
	keyHandle     = flag.String("keyHandle", "key.bin", "Handle to the privateKey")
	flush         = flag.String("flush", "all", "Flush existing handles")
	x509certFile  = flag.String("x509certFile", "x509cert.pem", "x509 certificate ")
	cn            = flag.String("cn", "OURServiceAccountName@PROJECT_ID.iam.gserviceaccount.com", "Common Name for the certificate ")
	handleNames   = map[string][]tpm2.HandleType{
		"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
		"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
		"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
		"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
	}

	defaultKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagRestricted | tpm2.FlagDecrypt,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits: 2048,
		},
	}

	rsaKeyParams = tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagSign,
		AuthPolicy: []byte{},
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA, // note, the signer uses RSAPSS
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
)

func main() {

	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open TPM %s: %v", *tpmPath, err)
		os.Exit(1)
	}
	defer func() {
		if err := rwc.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "can't close TPM %s: %v", *tpmPath, err)
			os.Exit(1)
		}
	}()

	totalHandles := 0
	for _, handleType := range handleNames[*flush] {
		handles, err := client.Handles(rwc, handleType)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error getting handles", *tpmPath, err)
			os.Exit(1)
		}
		for _, handle := range handles {
			if err = tpm2.FlushContext(rwc, handle); err != nil {
				fmt.Fprintf(os.Stderr, "Error flushing handle 0x%x: %v\n", handle, err)
				os.Exit(1)
			}
			fmt.Printf("Handle 0x%x flushed\n", handle)
			totalHandles++
		}
	}

	pcrList := []int{0}
	pcrSelection := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: pcrList}

	pkh, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, pcrSelection, emptyPassword, emptyPassword, defaultKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating Primary %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, pkh)

	pkhBytes, err := tpm2.ContextSave(rwc, pkh)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for pkh %v\n", err)
		os.Exit(1)
	}

	// err = tpm2.FlushContext(rwc, pkh)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
	// 	os.Exit(1)
	// }
	err = ioutil.WriteFile(*primaryHandle, pkhBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for pkh%v\n", err)
		os.Exit(1)
	}

	// pkh, err = tpm2.ContextLoad(rwc, pkhBytes)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "ContextLoad failed for pkh %v\n", err)
	// 	os.Exit(1)
	// }

	privInternal, pubArea, _, _, _, err := tpm2.CreateKey(rwc, pkh, pcrSelection, defaultPassword, defaultPassword, rsaKeyParams)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  CreateKey %v\n", err)
		os.Exit(1)
	}
	newHandle, _, err := tpm2.Load(rwc, pkh, defaultPassword, pubArea, privInternal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error  loading hash key %v\n", err)
		os.Exit(1)
	}
	defer tpm2.FlushContext(rwc, newHandle)

	ekhBytes, err := tpm2.ContextSave(rwc, newHandle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for ekh %v\n", err)
		os.Exit(1)
	}
	err = ioutil.WriteFile(*keyHandle, ekhBytes, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ContextSave failed for ekh%v\n", err)
		os.Exit(1)
	}

	// pHandle := tpmutil.Handle(0x81010002)
	// err = tpm2.EvictControl(rwc, defaultPassword, tpm2.HandleOwner, newHandle, pHandle)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error  persisting hash key  %v\n", err)
	// 	os.Exit(1)
	// }
	// defer tpm2.FlushContext(rwc, pHandle)

	fmt.Printf("======= Key persisted ========\n")
	fmt.Printf("======= Creating x509 Certificate ========\n")

	// https://raw.githubusercontent.com/salrashid123/signer/master/certgen/certgen.go

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate serial number: %s", err)
		os.Exit(1)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         *cn,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		DNSNames:  []string{*cn},
		KeyUsage:  x509.KeyUsageDigitalSignature,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	kk, err := client.NewCachedKey(rwc, tpm2.HandleEndorsement, rsaKeyParams, newHandle)
	s, err := kk.GetSigner()
	if err != nil {
		fmt.Fprintf(os.Stderr, "can't getSigner %q: %v", tpmPath, err)
		os.Exit(1)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, kk.PublicKey(), s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create certificate: %s\n", err)
		os.Exit(1)
	}
	certOut, err := os.Create(*x509certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open %s for writing: %s", *x509certFile, err)
		os.Exit(1)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write data to %s: %s", *x509certFile, err)
		os.Exit(1)
	}
	if err := certOut.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "Error closing %s  %s", *x509certFile, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *x509certFile)

}

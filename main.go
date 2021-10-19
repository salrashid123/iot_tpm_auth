package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	jwt "github.com/golang-jwt/jwt"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	saltpm "github.com/salrashid123/signer/tpm"
	//salpem "github.com/salrashid123/signer/pem"
)

var (
	mqttHost = "mqtt.googleapis.com"
	mqttPort = "8883"
)

func main() {
	projectID := flag.String("projectID", "", "ProjectID")
	region := flag.String("region", "us-central1", "Region")
	registryID := flag.String("registryID", "myregistry", "RegistryID")
	deviceID := flag.String("deviceID", "", "DeviceID")
	certsCA := flag.String("certsCA", "roots.pem", "CA Certificate (https://pki.google.com/roots.pem)")
	flag.Parse()

	if *projectID == "" || *deviceID == "" {
		fmt.Printf("ProjectID and deviceID must be set")
		return
	}

	// comment this section if using raw PEMkey
	// r, err := salpem.NewPEMCrypto(&salpem.PEM{
	// 	PrivatePEMFile: "ca_scratchpad/certs/iot1-rsa.key",
	// })
	// if err != nil {
	// 	fmt.Printf("Error loading PEM %v", err)
	// 	return
	// }

	// uncomment if using TPM
	r, err := saltpm.NewTPMCrypto(&saltpm.TPM{
		TpmDevice: "/dev/tpm0",
		//TpmHandle: 0x81010002,
		TpmHandleFile: "key.bin",
	})
	if err != nil {
		fmt.Printf("Error loading TPM %v", err)
		return
	}

	// https://cloud.google.com/iot/docs/concepts/device-security#authentication
	// "The connection is closed when the JWT expires (after accounting for the allowed clock drift)."
	claims := jwt.StandardClaims{
		Audience:  *projectID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(300 * time.Second).Unix(),
	}

	SigningMethodRS256 = &SigningMethodRSA{"RS256", crypto.SHA256}

	jwt.RegisterSigningMethod("RS256", func() jwt.SigningMethod {
		return SigningMethodRS256
	})

	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)

	p := r.Public()
	pubKey, ok := p.(*rsa.PublicKey)
	if !ok {
		fmt.Printf("Error reading key %v", err)
		return
	}
	derEncoded, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		fmt.Printf("Error MarshalPKIXPublicKey %v", err)
		return
	}

	hasher := sha256.New()
	hasher.Write(derEncoded)
	id := hex.EncodeToString(hasher.Sum(nil))

	token.Header["kid"] = id

	rcc, err := token.SignedString(&r)
	if err != nil {
		fmt.Printf("Error Signing %v", err)
		return
	}

	fmt.Printf("SignedJWT: %s\n", rcc)

	/// ************

	rra, err := jwt.Parse(rcc, func(token *jwt.Token) (interface{}, error) {
		return r.Public(), nil
	})
	if err != nil {
		fmt.Printf("     Error parsing JWT %v", err)
		return
	}
	fmt.Printf("%v\n", rra.Valid)

	// if rra.Valid {
	// 	os.Exit(1)
	// }
	// ************
	// iotcore,mqtt
	//mqtt.DEBUG = log.New(os.Stdout, "[DEBUG] ", 0)

	certpool := x509.NewCertPool()
	pemCerts, err := ioutil.ReadFile(*certsCA)
	if err != nil {
		fmt.Printf("     Error loading cacerts %v", err)
		return
	}

	certpool.AppendCertsFromPEM(pemCerts)
	config := &tls.Config{
		RootCAs:            certpool,
		ClientAuth:         tls.NoClientCert,
		ClientCAs:          nil,
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{},
		MinVersion:         tls.VersionTLS12,
	}

	clientID := fmt.Sprintf("projects/%s/locations/%s/registries/%s/devices/%s",
		*projectID,
		*region,
		*registryID,
		*deviceID,
	)

	opts := mqtt.NewClientOptions()
	broker := fmt.Sprintf("ssl://%v:%v", mqttHost, mqttPort)

	opts.AddBroker(broker)
	opts.SetClientID(clientID).SetTLSConfig(config)

	// opts.SetCredentialsProvider(func() (username string, password string) {
	// 	return "unused", rcc
	// })
	opts.SetUsername("unused") // username cannot be null see https://cloud.google.com/iot/docs/concepts/device-security#authentication
	opts.SetPassword(rcc)

	onConn := func(client mqtt.Client) {
		fmt.Printf("connected\n")
	}
	opts.SetOnConnectHandler(onConn)

	// Incoming
	opts.SetDefaultPublishHandler(func(client mqtt.Client, msg mqtt.Message) {
		fmt.Printf("[handler] Topic: %v\n", msg.Topic())
		fmt.Printf("[handler] Payload: %v\n", msg.Payload())
	})

	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		fmt.Printf("     Error with mqtt client %v", err)
		return
	}

	topic := struct {
		config   string
		events   string
		commands string
		state    string
	}{
		config:   fmt.Sprintf("/devices/%v/config", deviceID),
		events:   fmt.Sprintf("/devices/%v/events", deviceID),
		commands: fmt.Sprintf("/devices/%v/commands/#", deviceID),
		state:    fmt.Sprintf("/devices/%v/state", deviceID),
	}

	fmt.Println("[main] Creating Subscription")

	go client.Subscribe(topic.commands, 0, func(client mqtt.Client, msg mqtt.Message) {
		fmt.Printf("* [%s] %s\n", msg.Topic(), string(msg.Payload()))
	})

	go client.Subscribe(topic.events, 0, func(client mqtt.Client, msg mqtt.Message) {
		fmt.Printf("* [%s] %s\n", msg.Topic(), string(msg.Payload()))
	})

	fmt.Printf("[main] Publishing Message\n")
	t := client.Publish(
		topic.events,
		0,
		false,
		"some message")

	go func() {
		<-t.Done()
		if t.Error() != nil {
			fmt.Printf("%v", t.Error())
		}
	}()
	t.WaitTimeout(5 * time.Second)

	time.Sleep(10 * time.Second)

	fmt.Println("[main] MQTT Client Disconnecting")

	client.Disconnect(250)

}

type SigningMethodRSA struct {
	Name string
	Hash crypto.Hash
}

var (
	SigningMethodRS256 *SigningMethodRSA
)

func (m *SigningMethodRSA) Alg() string {
	return m.Name
}

func (m *SigningMethodRSA) Verify(signingString, signature string, key interface{}) error {
	var err error

	var sig []byte
	if sig, err = jwt.DecodeSegment(signature); err != nil {
		return err
	}

	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return jwt.ErrInvalidKeyType
	}

	h := sha256.New()
	h.Write([]byte(signingString))
	digest := h.Sum(nil)

	return rsa.VerifyPKCS1v15(rsaKey, m.Hash, digest, sig)

}

func (m *SigningMethodRSA) Sign(signingString string, key interface{}) (string, error) {

	k, ok := key.(crypto.Signer)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}
	h := sha256.New()
	h.Write([]byte(signingString))
	digest := h.Sum(nil)
	s, err := k.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return "", err
	}
	return jwt.EncodeSegment(s), nil
}

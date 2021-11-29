package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	jwt "github.com/golang-jwt/jwt"

	mqtt "github.com/eclipse/paho.mqtt.golang"

	tpmjwt "github.com/salrashid123/golang-jwt-tpm"
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

	ctx := context.Background()
	var keyctx interface{}

	// https://cloud.google.com/iot/docs/concepts/device-security#authentication
	// "The connection is closed when the JWT expires (after accounting for the allowed clock drift)."
	claims := jwt.StandardClaims{
		Audience:  *projectID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(300 * time.Second).Unix(),
	}

	tpmjwt.SigningMethodTPMRS256.Override()
	token := jwt.NewWithClaims(tpmjwt.SigningMethodTPMRS256, claims)

	config := &tpmjwt.TPMConfig{
		TPMDevice:     "/dev/tpm0",
		KeyHandleFile: "key.bin",
		//KeyTemplate:   tpmjwt.AttestationKeyParametersRSA256,
		KeyTemplate: tpmjwt.UnrestrictedKeyParametersRSA256,
	}

	keyctx, err := tpmjwt.NewTPMContext(ctx, config)
	if err != nil {
		fmt.Printf("Unable to initialize tpmJWT: %v", err)
		return
	}

	token.Header["kid"] = config.GetKeyID()
	tokenString, err := token.SignedString(keyctx)
	if err != nil {
		fmt.Printf("Error signing %v", err)
		return
	}
	fmt.Printf("TOKEN: %s\n", tokenString)

	token.Header["kid"] = config.GetKeyID()

	rcc, err := token.SignedString(keyctx)
	if err != nil {
		fmt.Printf("Error Signing %v", err)
		return
	}

	fmt.Printf("SignedJWT: %s\n", rcc)

	/// ************

	keyFunc, err := tpmjwt.TPMVerfiyKeyfunc(ctx, config)
	if err != nil {
		fmt.Printf("could not get keyFunc: %v", err)
		return
	}

	vtoken, err := jwt.Parse(tokenString, keyFunc)
	if err != nil {
		fmt.Printf("Error verifying token %v", err)
		return
	}

	if vtoken.Valid {
		fmt.Printf("     verified with TPM PublicKey")
	}

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
	tlsconfig := &tls.Config{
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
	opts.SetClientID(clientID).SetTLSConfig(tlsconfig)

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
		config:   fmt.Sprintf("/devices/%s/config", *deviceID),
		events:   fmt.Sprintf("/devices/%s/events", *deviceID),
		commands: fmt.Sprintf("/devices/%s/commands/#", *deviceID),
		state:    fmt.Sprintf("/devices/%s/state", *deviceID),
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

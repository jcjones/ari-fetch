// https://datatracker.ietf.org/doc/draft-ietf-acme-ari/05/
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log/slog"
	"net/http"
)

var (
	acmeURL = flag.String("acme", "https://acme-v02.api.letsencrypt.org/directory", "acme server")
	verbose = flag.Bool("v", false, "verbose")

	authorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
)

type ARIDirectory struct {
	RenewalInfo string
}

type ARIWindow struct {
	Start string
	End   string
}

type ARIResponse struct {
	ExplanationURL  string
	SuggestedWindow ARIWindow
}

func findARIEndpoint() (string, error) {
	resp, err := http.Get(*acmeURL)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)

	var dir ARIDirectory
	err = json.Unmarshal(buf.Bytes(), &dir)
	if err != nil {
		return "", err
	}

	slog.Debug("HTTP ACME Directory GET completed", "URL", *acmeURL, "response status", resp.StatusCode, "dict", dir)
	return dir.RenewalInfo, nil
}

func getAKIString(ext []byte) (string, error) {
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(ext, &seq)
	if err != nil {
		return "", fmt.Errorf("Error unmarshaling %s", err)
	} else if len(rest) != 0 {
		return "", fmt.Errorf("x509: trailing data after X.509 extension")
	}

	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return "", asn1.StructuralError{Msg: "bad AKI sequence"}
	}

	var aki asn1.RawValue
	rest, err = asn1.Unmarshal(seq.Bytes, &aki)
	if err != nil {
		return "", fmt.Errorf("Error unmarshaling %s", err)
	}

	b64 := base64.RawURLEncoding.EncodeToString(aki.Bytes)
	slog.Debug("Authority Key Identifier", "hex", hex.EncodeToString(aki.Bytes), "base64", b64)

	return b64, nil
}

func getSerialString(endEntity *x509.Certificate) (string, error) {
	val, err := asn1.Marshal(endEntity.SerialNumber)
	if err != nil {
		return "", err
	}

	var serialRaw asn1.RawValue
	rest, err := asn1.Unmarshal(val, &serialRaw)
	if err != nil {
		return "", fmt.Errorf("Error unmarshaling %s", err)
	} else if len(rest) != 0 {
		return "", fmt.Errorf("x509: trailing data after X.509 extension")
	}

	b64 := base64.RawURLEncoding.EncodeToString(serialRaw.Bytes)
	slog.Debug("Serial Number", "hex", hex.EncodeToString(serialRaw.Bytes), "base64", b64)
	return b64, nil
}

func processFile(ariBaseURL string, certPath string) error {
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("Error reading file: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	endEntity, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v\n", err)
	}

	akiString := ""
	for _, ext := range endEntity.Extensions {
		if ext.Id.Equal(authorityKeyIdentifier) {
			akiString, err = getAKIString(ext.Value)
			if err != nil {
				return err
			}
		}
	}

	if akiString == "" {
		return fmt.Errorf("Couldn't obtain the AKI string")
	}

	serialString, err := getSerialString(endEntity)

	ariUrl := fmt.Sprintf("%s/%s.%s", ariBaseURL, akiString, serialString)
	slog.Info("ARI Request", "InputPEM", certPath, "renewalInfoURL", ariUrl)

	resp, err := http.Get(ariUrl)
	if err != nil {
		return err
	}

	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	io.Copy(buf, resp.Body)

	// Unmarshal and remarshal is silly but we want to pretty print it.
	var ariResp ARIResponse
	err = json.Unmarshal(buf.Bytes(), &ariResp)
	if err != nil {
		return err
	}

	prettyIndent, _ := json.MarshalIndent(ariResp, "", "    ")
	fmt.Print(string(prettyIndent) + "\n")
	return nil
}

func main() {
	flag.Parse()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if flag.NArg() == 0 {
		slog.Error("must provide at least one PEM certificate to process")
		return
	}

	ariBaseUrl, err := findARIEndpoint()
	if err != nil {
		slog.Error("Couldn't find ARI endpoint", "URL", acmeURL, "error", err.Error())
		return
	}

	for _, certPath := range flag.Args() {
		err := processFile(ariBaseUrl, certPath)
		if err != nil {
			slog.Error("Error processing file", "error", err.Error())
			return
		}
	}
}

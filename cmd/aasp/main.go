// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Package main implements a server for attestation agent service.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"strings"

	"encoding/base64"
	"encoding/json"
	"encoding/pem"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/attest"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/common"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/keyprovider"
	"github.com/Microsoft/confidential-sidecar-containers/pkg/skr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
)

type AzureInformation struct {
	// Endpoint of the certificate cache service from which
	// the certificate chain endorsing hardware attestations
	// can be retrieved. This is optinal only when the container
	// will expose attest/maa and key/release APIs.
	CertCache attest.CertCache `json:"certcache,omitempty"`

	// Identifier of the managed identity to be used
	// for authenticating with AKV MHSM. This is optional and
	// useful only when the container group has been assigned
	// more than one managed identity.
	Identity common.Identity `json:"identity,omitempty"`
}

var (
	EncodedUvmInformation common.UvmInformation
)

var azure_info AzureInformation
var defaultCertCacheEndpoint = "americas.test.acccache.azure.net"

type DecryptConfig struct {
	Parameters map[string][]string
}

type EncryptConfig struct {
	Parameters map[string][]string
	Dc         DecryptConfig
}

type KeyWrapParams struct {
	Ec       EncryptConfig `json:"ec,omitempty"`
	Optsdata string        `json:"optsdata,omitempty"`
}

type KeyUnwrapParams struct {
	Dc         DecryptConfig `json:"dc,omitempty"`
	Annotation string        `json:"annotation"`
}

type AnnotationPacket struct {
	Kid              string `json:"kid"`
	WrappedData      []byte `json:"wrapped_data"`
	Iv               []byte `json:"iv,omitempty"`
	WrapType         string `json:"wrap_type,omitempty"`
	KmsEndpoint      string `json:"kms_endpoint,omitempty"`
	AttesterEndpoint string `json:"attester_endpoint,omitempty"`
}

type RSAKeyInfo struct {
	PublicKeyPath    string `json:"public_key_path"`
	KmsEndpoint      string `json:"kms_endpoint"`
	AttesterEndpoint string `json:"attester_endpoint"`
}

type keyProviderInput struct {
	// Operation is either "keywrap" or "keyunwrap"
	// attestation-agent can only handle the case of "keyunwrap"
	Op string `json:"op"`
	// For attestation-agent, keywrapparams should be empty.
	KeyWrapParams   KeyWrapParams   `json:"keywrapparams,omitempty"`
	KeyUnwrapParams KeyUnwrapParams `json:"keyunwrapparams,omitempty"`
}

type KeyUnwrapResults struct {
	OptsData []byte `json:"optsdata"`
}

type KeyWrapResults struct {
	Annotation []byte `json:"annotation"`
}

type KeyProviderProtocolOutput struct {
	// KeyWrapResult encodes the results to key wrap if operation is to wrap
	KeyWrapResults KeyWrapResults `json:"keywrapresults,omitempty"`
	// KeyUnwrapResult encodes the result to key unwrap if operation is to unwrap
	KeyUnwrapResults KeyUnwrapResults `json:"keyunwrapresults,omitempty"`
}

// server is used to implement helloworld.GreeterServer.
type server struct {
	keyprovider.UnimplementedKeyProviderServiceServer
}

func (s *server) SayHello(ctx context.Context, in *keyprovider.HelloRequest) (*keyprovider.HelloReply, error) {
	akv := skr.AKV{
		Endpoint:   "accmhsm.managedhsm.azure.net",
		APIVersion: "api-version=7.3-preview",
		//BearerToken: bearerToken,
	}

	maa := attest.MAA{
		Endpoint:   "sharedeus2.eus2.test.attest.azure.net",
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := skr.KeyBlob{
		KID:       "golangversionupdatetest",
		Authority: maa,
		AKV:       akv,
	}

	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
	// it is not presented as fine-grained init-time claims in the MAA token, which would
	// introduce larger MAA tokens that MHSM would accept
	//keyBytes, err := skr.SecureKeyRelease("", azure_info.CertCache, azure_info.Identity, skrKeyBlob)
	keyBytes, err := skr.SecureKeyRelease1(azure_info.CertCache, azure_info.Identity, skrKeyBlob, EncodedUvmInformation)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "SKR failed: %v", err)
	}

	jwkJSONBytes, err := json.Marshal(keyBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SKR failed: %v", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(jwkJSONBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Released key is invalid: %v", err)
	}

	x, _ := base64.StdEncoding.DecodeString("Id0Q1zXKiOpf3VwvWsxIc4jOr/NHfK5/MerMoz62NN3kFN6quGqSGtzMQVDC+Bqr/g+nMFMl+9V2hCv6n5U15L4c9rlh6OEEqic81y5SDBAzBT1gKa/VZTxZJVZOhOzKSPLqLJzUDVIehuK1+j38MfpG4EfYeG5+17TEwoP/0AKxIp6HXnF3pfWc6BoTrqrCR/eD5nDQKpnuPPhRwJpz/Xwy7hIigQ1/D74U2CUoyornf0hoV3+YdjB2+jKz/V0Od1xnzxl1Okvyuw7Phil/mfsL+oFOc+rfaubjVkNMfhmf5Ju8yFk016PI0T71r7N0GC92YGgD6tKQ1IEqbAuDMjG2RCD1S50KfjeYgCvSIo2QKja8tqyof6Am20XIB/zUr0gNz62f+8zEGCEkqja9hHpN8ZlsXWGAFSd35tHZxlG1WkpRJ7T5OZ8lkt7FUOG+sV8NrbCcbSYrFfYVPiQtPss7T++Z8Hoyx7za+9mD+OpuLBc0Mz77qegBrDrfVVB0")

	var plaintext []byte
	if privkey, ok := key.(*rsa.PrivateKey); ok {
		plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, x, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Unwrapping failed: %v", err)
		}
	} else {
		return nil, status.Errorf(codes.Internal, "Released key is not a RSA private key: %v", err)
	}

	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
		KeyUnwrapResults: KeyUnwrapResults{OptsData: plaintext},
	})

	// return &keyprovider.KeyProviderKeyWrapProtocolOutput{
	// 	KeyProviderKeyWrapProtocolOutput: protocolBytes,
	// }, nil

	return &keyprovider.HelloReply{Message: "Hello " + in.GetName() + " " + string(protocolBytes)}, nil
}

func Test() {
	akv := skr.AKV{
		Endpoint:   "accmhsm.managedhsm.azure.net",
		APIVersion: "api-version=7.3-preview",
		//BearerToken: bearerToken,
	}

	maa := attest.MAA{
		Endpoint:   "sharedeus2.eus2.test.attest.azure.net",
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := skr.KeyBlob{
		KID:       "golangversionupdatetest",
		Authority: maa,
		AKV:       akv,
	}

	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
	// it is not presented as fine-grained init-time claims in the MAA token, which would
	// introduce larger MAA tokens that MHSM would accept
	//keyBytes, err := skr.SecureKeyRelease("", azure_info.CertCache, azure_info.Identity, skrKeyBlob)
	fmt.Println("about to enter secure key release func")
	keyBytes, err := skr.SecureKeyRelease1(azure_info.CertCache, azure_info.Identity, skrKeyBlob, EncodedUvmInformation)

	if err != nil {
		fmt.Printf("SKR failed: %v\n", err)
	} else {
		fmt.Println("SKR ok")
	}

	jwkJSONBytes, err := json.Marshal(keyBytes)
	if err != nil {
		fmt.Printf("SKR marshall failed: %v\n", err)
	} else {
		fmt.Println("SKR marshall ok")
	}

	key, err := x509.ParsePKCS8PrivateKey(jwkJSONBytes)
	if err != nil {
		fmt.Printf("Released key is invalid: %v\n", err)
	} else {
		fmt.Println("Released key is ok")
	}

	fmt.Println("Released key is ok")

	x, _ := base64.StdEncoding.DecodeString("Id0Q1zXKiOpf3VwvWsxIc4jOr/NHfK5/MerMoz62NN3kFN6quGqSGtzMQVDC+Bqr/g+nMFMl+9V2hCv6n5U15L4c9rlh6OEEqic81y5SDBAzBT1gKa/VZTxZJVZOhOzKSPLqLJzUDVIehuK1+j38MfpG4EfYeG5+17TEwoP/0AKxIp6HXnF3pfWc6BoTrqrCR/eD5nDQKpnuPPhRwJpz/Xwy7hIigQ1/D74U2CUoyornf0hoV3+YdjB2+jKz/V0Od1xnzxl1Okvyuw7Phil/mfsL+oFOc+rfaubjVkNMfhmf5Ju8yFk016PI0T71r7N0GC92YGgD6tKQ1IEqbAuDMjG2RCD1S50KfjeYgCvSIo2QKja8tqyof6Am20XIB/zUr0gNz62f+8zEGCEkqja9hHpN8ZlsXWGAFSd35tHZxlG1WkpRJ7T5OZ8lkt7FUOG+sV8NrbCcbSYrFfYVPiQtPss7T++Z8Hoyx7za+9mD+OpuLBc0Mz77qegBrDrfVVB0")

	var plaintext []byte
	if privkey, ok := key.(*rsa.PrivateKey); ok {
		plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, x, nil)
		if err != nil {
			fmt.Printf("Unwrapping failed: %v\n", err)
		}
		fmt.Println("Unwrapping ok.")
	} else {
		fmt.Printf("Released key is not a RSA private key: %v", err)
	}

	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
		KeyUnwrapResults: KeyUnwrapResults{OptsData: plaintext},
	})

	fmt.Println("released protocol bytes: ", protocolBytes)

}

// Convert federated token stored in a file into access token for a resource
// Borrowed from https://github.com/Azure/azure-workload-identity/blob/c155ecee0d9fa681c15ead4bbdce729fd8c99da1/pkg/proxy/proxy.go#L195
// See tutorial at: https://learn.microsoft.com/en-us/azure/aks/learn/tutorial-kubernetes-workload-identity

func getAccessTokenFromFederatedToken(ctx context.Context, federatedTokenFile, clientID, tenantID, resource string) (string, error) {
	cred := confidential.NewCredFromAssertionCallback(func(context.Context, confidential.AssertionRequestOptions) (string, error) {
		token, err := os.ReadFile(federatedTokenFile)
		return string(token), err
	})

	confidentialClient, err := confidential.New(clientID, cred,
		confidential.WithAuthority(fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", tenantID)))
	if err != nil {
		return "", fmt.Errorf("failed to create confidential client: %v", err)
	}

	result, err := confidentialClient.AcquireTokenByCredential(ctx, []string{resource + "/.default"})
	if err != nil {
		return "", fmt.Errorf("failed to acquire access token: %v", err)
	}
	return result.AccessToken, nil
}

func directWrap(optsdata []byte, key_path string) ([]byte, error) {
	_, kid := path.Split(key_path)
	var annotation AnnotationPacket
	annotation.Kid = kid
	annotation.Iv = []byte("")
	annotation.WrapType = "rsa_3072"

	var keyInfo RSAKeyInfo
	path := key_path + "-info.json"
	keyInfoBytes, e := os.ReadFile(path)
	if e != nil {
		return nil, fmt.Errorf("Failed to read key info file %v", path)
	}

	err := json.Unmarshal(keyInfoBytes, &keyInfo)
	if err != nil {
		return nil, fmt.Errorf("Invalid RSA key info file %v", path)
	}
	log.Printf("%v", keyInfo)

	annotation.AttesterEndpoint = keyInfo.AttesterEndpoint
	annotation.KmsEndpoint = keyInfo.KmsEndpoint
	fmt.Printf("%+v\n", keyInfo)
	pubpem, err := os.ReadFile(keyInfo.PublicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read public key file %v", keyInfo.PublicKeyPath)
	}
	block, _ := pem.Decode([]byte(pubpem))
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Invalid public key in %v, error: %v", path, err)
	}

	var ciphertext []byte
	if pubkey, ok := key.(*rsa.PublicKey); ok {
		ciphertext, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubkey, optsdata, nil)
		if err != nil {
			return nil, fmt.Errorf("Failed to encrypt with the public key %v", err)
		}
	} else {
		return nil, fmt.Errorf("Invalid public RSA key in %v", path)
	}

	annotation.WrappedData = ciphertext
	fmt.Println(string(ciphertext))
	annotationBytes, _ := json.Marshal(annotation)
	fmt.Println(string(annotationBytes))
	return annotationBytes, nil
}

func (s *server) WrapKey(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
	var input keyProviderInput
	str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
	err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed key provider input: %v. Error: %v", str, err.Error())
	}
	log.Printf("Key provider input: %v", input)

	var ec = input.KeyWrapParams.Ec
	if len(ec.Parameters["attestation-agent"]) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "attestation-agent must be specified in the encryption config parameters: %v", ec)
	}
	aaKid, _ := base64.StdEncoding.DecodeString(ec.Parameters["attestation-agent"][0])
	tokens := strings.Split(string(aaKid), ":")

	if len(tokens) < 2 {
		return nil, status.Errorf(codes.InvalidArgument, "Key id is not provided in the request")
	}

	aa := tokens[0]
	kid := tokens[1]
	if aa != "aasp" && aa != "aaa" {
		return nil, status.Errorf(codes.InvalidArgument, "Unexpected attestation agent %v specified. Perhaps you send the request to a wrong endpoint?", aa)
	}
	log.Printf("Attestation agent: %v, kid: %v", aa, kid)

	optsdata, err := base64.StdEncoding.DecodeString(input.KeyWrapParams.Optsdata)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Optsdata is not base64 encoding: %v", err)
	}

	annotationBytes, e := directWrap(optsdata, kid)
	if e != nil {
		return nil, status.Errorf(codes.Internal, "%v", e)
	}

	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
		KeyWrapResults: KeyWrapResults{Annotation: annotationBytes},
	})

	return &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolBytes,
	}, nil
}

func (s *server) UnWrapKey(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
	var input keyProviderInput
	str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
	err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed key provider input: %v. Error: %v", str, err.Error())
	}
	log.Printf("Key provider input: %v", input)

	var dc = input.KeyUnwrapParams.Dc
	if len(dc.Parameters["attestation-agent"]) == 0 {
		return nil, status.Errorf(codes.InvalidArgument, "attestation-agent must be specified in decryption config parameters: %v", str)
	}
	aa, _ := base64.StdEncoding.DecodeString(dc.Parameters["attestation-agent"][0])
	log.Printf("Attestation agent name: %v", string(aa))

	if string(aa) != "aasp" && string(aa) != "aaa" {
		return nil, status.Errorf(codes.InvalidArgument, "Unexpected attestation agent %v specified. Perhaps you send the request to a wrong endpoint?", string(aa))
	}

	var annotationBytes []byte
	annotationBytes, err = base64.StdEncoding.DecodeString(input.KeyUnwrapParams.Annotation)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Annotation is not a base64 encoding: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Decoded annotation: %v", string(annotationBytes))

	var annotation AnnotationPacket
	err = json.Unmarshal(annotationBytes, &annotation)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Ill-formed annotation packet: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
	}
	log.Printf("Annotation packet: %v", annotation)

	// bearerToken := ""

	// // Note: obtaining access token through federated token file is AKS specific
	// clientID := os.Getenv("AZURE_CLIENT_ID")
	// tenantID := os.Getenv("AZURE_TENANT_ID")
	// tokenFile := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	// if clientID != "" && tenantID != "" && tokenFile != "" {
	// 	bearerToken, err = getAccessTokenFromFederatedToken(c, tokenFile, clientID, tenantID, "https://managedhsm.azure.net")
	// 	if err != nil {
	// 		return nil, status.Errorf(codes.Internal, "Failed to obtain access token to MHSM: %v", err)
	// 	}
	// }
	mhsm := skr.AKV{
		Endpoint:   annotation.KmsEndpoint,
		APIVersion: "api-version=7.3-preview",
	}

	maa := attest.MAA{
		Endpoint:   annotation.AttesterEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-01",
	}

	skrKeyBlob := skr.KeyBlob{
		KID:       annotation.Kid,
		Authority: maa,
		AKV:       mhsm,
	}

	azuredata, err := json.Marshal(azure_info)
	if err != nil {
		fmt.Println("errdsuauhdksa")
	}
	fmt.Printf("azure_info %s\n", string(azuredata))

	skrdata, err := json.Marshal(skrKeyBlob)
	if err != nil {
		fmt.Println("errdsuauhdksa1")
	}
	fmt.Printf("skrKeyBlob %s\n", string(skrdata))

	uvmin, err := json.Marshal(EncodedUvmInformation)
	if err != nil {
		fmt.Println("errdsuauhdksa2")
	}
	fmt.Printf("skrKeyBlob %s\n", string(uvmin))

	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
	// it is not presented as fine-grained init-time claims in the MAA token, which would
	// introduce larger MAA tokens that MHSM would accept
	//keyBytes, err := skr.SecureKeyRelease("", azure_info.CertCache, azure_info.Identity, skrKeyBlob)
	//keyBytes, err := skr.SecureKeyReleaseOld(azure_info.CertCache, azure_info.Identity, skrKeyBlob, EncodedUvmInformation)
	keyBytes, err := skr.SecureKeyReleaseOld("", azure_info.CertCache, azure_info.Identity, skrKeyBlob)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SKR failed: %v", err)
	} else {
		fmt.Println("SKR failed")
	}

	jwkJSONBytes, err := json.Marshal(keyBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "SKR failed: %v", err)
	} else {
		fmt.Println("SKR marshall failed")
	}

	key, err := x509.ParsePKCS8PrivateKey(jwkJSONBytes)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Released key is invalid: %v", err)
	} else {
		fmt.Println("release key is valid")
	}

	var out *keyprovider.KeyProviderKeyWrapProtocolOutput = nil
	var plaintext []byte
	if privkey, ok := key.(*rsa.PrivateKey); ok {
		plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, annotation.WrappedData, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Unwrapping failed: %v", err)
		} else {
			fmt.Println("unwrapping ok ")
		}
	} else {
		return nil, status.Errorf(codes.Internal, "Released key is not a RSA private key: %v", err)
	}

	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
		KeyUnwrapResults: KeyUnwrapResults{OptsData: plaintext},
	})

	return &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: protocolBytes,
	}, nil

	return out, nil
}

// func (s *server) UnWrapKey1(c context.Context, grpcInput *keyprovider.KeyProviderKeyWrapProtocolInput) (*keyprovider.KeyProviderKeyWrapProtocolOutput, error) {
// 	// var input keyProviderInput
// 	// str := string(grpcInput.KeyProviderKeyWrapProtocolInput)
// 	// err := json.Unmarshal(grpcInput.KeyProviderKeyWrapProtocolInput, &input)
// 	// if err != nil {
// 	// 	return nil, status.Errorf(codes.InvalidArgument, "Ill-formed key provider input: %v. Error: %v", str, err.Error())
// 	// }
// 	// log.Printf("Key provider input: %v", input)

// 	// var dc = input.KeyUnwrapParams.Dc
// 	// if len(dc.Parameters["attestation-agent"]) == 0 {
// 	// 	return nil, status.Errorf(codes.InvalidArgument, "attestation-agent must be specified in decryption config parameters: %v", str)
// 	// }
// 	// aa, _ := base64.StdEncoding.DecodeString(dc.Parameters["attestation-agent"][0])
// 	// log.Printf("Attestation agent name: %v", string(aa))

// 	// if string(aa) != "aasp" && string(aa) != "aaa" {
// 	// 	return nil, status.Errorf(codes.InvalidArgument, "Unexpected attestation agent %v specified. Perhaps you send the request to a wrong endpoint?", string(aa))
// 	// }

// 	// var annotationBytes []byte
// 	// annotationBytes, err = base64.StdEncoding.DecodeString(input.KeyUnwrapParams.Annotation)
// 	// if err != nil {
// 	// 	return nil, status.Errorf(codes.InvalidArgument, "Annotation is not a base64 encoding: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
// 	// }
// 	// log.Printf("Decoded annotation: %v", string(annotationBytes))

// 	// var annotation AnnotationPacket
// 	// err = json.Unmarshal(annotationBytes, &annotation)
// 	// if err != nil {
// 	// 	return nil, status.Errorf(codes.InvalidArgument, "Ill-formed annotation packet: %v. Error: %v", input.KeyUnwrapParams.Annotation, err.Error())
// 	// }
// 	// log.Printf("Annotation packet: %v", annotation)

// 	// // bearerToken := ""

// 	// // // Note: obtaining access token through federated token file is AKS specific
// 	// // clientID := os.Getenv("AZURE_CLIENT_ID")
// 	// // tenantID := os.Getenv("AZURE_TENANT_ID")
// 	// // tokenFile := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
// 	// // if clientID != "" && tenantID != "" && tokenFile != "" {
// 	// // 	bearerToken, err = getAccessTokenFromFederatedToken(c, tokenFile, clientID, tenantID, "https://managedhsm.azure.net")
// 	// // 	if err != nil {
// 	// // 		return nil, status.Errorf(codes.Internal, "Failed to obtain access token to MHSM: %v", err)
// 	// // 	}
// 	// // }
// 	mhsm := skr.AKV{
// 		Endpoint:   "accmhsm.managedhsm.azure.net",
// 		APIVersion: "api-version=7.3-preview",
// 	}

// 	maa := attest.MAA{
// 		Endpoint:   "sharedeus2.eus2.attest.azure.net",
// 		TEEType:    "SevSnpVM",
// 		APIVersion: "api-version=2020-10-01",
// 	}

// 	skrKeyBlob := skr.KeyBlob{
// 		KID:       "testkey000",
// 		Authority: maa,
// 		AKV:       mhsm,
// 	}

// 	azuredata, err := json.Marshal(azure_info)
// 	if err != nil {
// 		fmt.Println("errdsuauhdksa")
// 	}
// 	fmt.Printf("azure_info %s\n", string(azuredata))

// 	skrdata, err := json.Marshal(skrKeyBlob)
// 	if err != nil {
// 		fmt.Println("errdsuauhdksa1")
// 	}
// 	fmt.Printf("skrKeyBlob %s\n", string(skrdata))

// 	uvmin, err := json.Marshal(EncodedUvmInformation)
// 	if err != nil {
// 		fmt.Println("errdsuauhdksa2")
// 	}
// 	fmt.Printf("skrKeyBlob %s\n", string(uvmin))

// 	// MHSM has limit on the request size. We do not pass the EncodedSecurityPolicy here so
// 	// it is not presented as fine-grained init-time claims in the MAA token, which would
// 	// introduce larger MAA tokens that MHSM would accept
// 	//keyBytes, err := skr.SecureKeyRelease("", azure_info.CertCache, azure_info.Identity, skrKeyBlob)
// 	//keyBytes, err := skr.SecureKeyReleaseOld(azure_info.CertCache, azure_info.Identity, skrKeyBlob, EncodedUvmInformation)
// 	keyBytes, err := skr.SecureKeyReleaseOld("", azure_info.CertCache, azure_info.Identity, skrKeyBlob)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "SKR failed: %v", err)
// 	} else {
// 		fmt.Println("SKR failed")
// 	}

// 	jwkJSONBytes, err := json.Marshal(keyBytes)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "SKR failed: %v", err)
// 	} else {
// 		fmt.Println("SKR marshall failed")
// 	}

// 	key, err := x509.ParsePKCS8PrivateKey(jwkJSONBytes)
// 	if err != nil {
// 		return nil, status.Errorf(codes.Internal, "Released key is invalid: %v", err)
// 	} else {
// 		fmt.Println("release key is valid")
// 	}

// 	var out *keyprovider.KeyProviderKeyWrapProtocolOutput = nil
// 	var plaintext []byte
// 	if privkey, ok := key.(*rsa.PrivateKey); ok {
// 		plaintext, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, privkey, annotation.WrappedData, nil)
// 		if err != nil {
// 			return nil, status.Errorf(codes.Internal, "Unwrapping failed: %v", err)
// 		} else {
// 			fmt.Println("unwrapping ok ")
// 		}
// 	} else {
// 		return nil, status.Errorf(codes.Internal, "Released key is not a RSA private key: %v", err)
// 	}

// 	protocolBytes, _ := json.Marshal(KeyProviderProtocolOutput{
// 		KeyUnwrapResults: KeyUnwrapResults{OptsData: plaintext},
// 	})

// 	return &keyprovider.KeyProviderKeyWrapProtocolOutput{
// 		KeyProviderKeyWrapProtocolOutput: protocolBytes,
// 	}, nil

// 	return out, nil
// }

func (s *server) GetReport(c context.Context, in *keyprovider.KeyProviderGetReportInput) (*keyprovider.KeyProviderGetReportOutput, error) {
	reportDataStr := in.GetReportDataHexString()
	log.Printf("Received report data: %v", reportDataStr)

	if _, err := os.Stat("/dev/sev"); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "SEV guest driver is missing: %v", err)
	}

	cmd := exec.Command("/bin/get-snp-report", reportDataStr)
	reportOutput, err := cmd.Output()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed to generate attestation report: %v", err)
	}

	return &keyprovider.KeyProviderGetReportOutput{
		ReportHexString: string(reportOutput),
	}, nil
}

func main() {
	port := flag.String("keyprovider_sock", "127.0.0.1:50000", "Port on which the key provider to listen")
	flag.String("getresource_sock", "127.0.0.1:50001", "Port on which the resource provider to listen. Ignored")
	infile := flag.String("infile", "", "The file with its content to be wrapped")
	key_path := flag.String("keypath", "", "The path to the wrapping key")
	outfile := flag.String("outfile", "", "The file to save the wrapped data")
	flag.Parse()

	//var er error
	// bearerToken := ""
	// clientID := "fbaeca1c-6341-48c4-9891-84249bf346a1"
	// tenantID := "72f988bf-86f1-41af-91ab-2d7cd011db47"
	// tokenFile := "/var/run/secrets/azure/tokens/azure-identity-token"
	// if tenantID != "" && tokenFile != "" {
	// 	bearerToken, er = getAccessTokenFromFederatedToken(context.TODO(), tokenFile, clientID, tenantID, "https://managedhsm.azure.net")
	// 	if er != nil {
	// 		log.Fatalf("Failed to get access token %v", er)
	// 	}
	// }
	// log.Printf("bearerToken: %v", bearerToken)

	if *infile != "" {
		bytes, err := os.ReadFile(*infile)
		if err != nil {
			log.Fatalf("Can't read input file %v", *infile)
		}
		if *key_path == "" {
			log.Fatalf("The key path is not specified for wrapping")
		}
		if *outfile == "" {
			log.Fatalf("The output file is not specified")
		}

		if _, err := os.Stat(*key_path + "-info.json"); err != nil {
			log.Fatalf("The wrapping key info is not found")
		}

		annotationBytes, e := directWrap(bytes, *key_path)
		if e != nil {
			log.Fatalf("%v", e)
		}

		outstr := base64.StdEncoding.EncodeToString(annotationBytes)
		if err := os.WriteFile(*outfile, []byte(outstr), 0644); err != nil {
			log.Fatalf("Failed to save the wrapped data to %v", *outfile)
		}
		log.Printf("Success! The wrapped data is saved to %v", *outfile)
		return
	}

	lis, err := net.Listen("tcp", *port)
	if err != nil {
		log.Fatalf("failed to listen on port %v: %v", *port, err)
	}
	log.Printf("Listening on port %v", *port)

	certCacheEndpoint := os.Getenv("CertCacheEndpoint")
	if certCacheEndpoint == "" {
		certCacheEndpoint = defaultCertCacheEndpoint
	}

	// Temporary solution until we get the cert chain from the host
	azure_info.CertCache = attest.CertCache{
		AMD:        false,
		Endpoint:   certCacheEndpoint,
		TEEType:    "SevSnpVM",
		APIVersion: "api-version=2020-10-15-preview",
	}
	azure_info.Identity.ClientId = os.Getenv("AZURE_CLIENT_ID")
	if azure_info.Identity.ClientId == "" {
		log.Printf("Warning: Env AZURE_CLIENT_ID is not set")
	}

	EncodedUvmInformation, _ = common.GetUvmInfomation()
	fmt.Println("EncodedSecurityPolicy")
	fmt.Println(EncodedUvmInformation.EncodedSecurityPolicy)
	fmt.Println("EncodedUvmReferenceInfo")
	fmt.Println(EncodedUvmInformation.EncodedUvmReferenceInfo)

	s := grpc.NewServer()
	keyprovider.RegisterKeyProviderServiceServer(s, &server{})
	reflection.Register(s)
	fmt.Println("about to enter Test func")
	Test()
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to start GRPC server: %v", err)
	}
}

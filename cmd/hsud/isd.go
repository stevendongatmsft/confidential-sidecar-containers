package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os/exec"
)

func main() {

	cmd := exec.Command("/mnt/c/Users/stevendong/go/src/github.com/microsoft/confidential-sidecar-containers/tools/get-snp-report/bin/get-fake-snp-report", "a", "b")
	fmt.Println()
	x, _ := cmd.Output()
	// privateWrappingKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// // construct the key blob
	// jwkSetBytes, _ := common.GenerateJWKSet(privateWrappingKey)

	// fmt.Println(len(jwkSetBytes))
	hexString := hex.EncodeToString(x)

	// Convert the hex string to bytes
	decodedBytes, err := hex.DecodeString(hexString)
	if err != nil {
		fmt.Println("dame")
	}

	base64String := base64.StdEncoding.EncodeToString(decodedBytes)
	fmt.Println(base64String)
	// Convert the bytes to a string
	fmt.Println(string(decodedBytes))
	runtimeDataBytes, err := base64.StdEncoding.DecodeString("hellotest")
	fmt.Println(len(runtimeDataBytes))
}

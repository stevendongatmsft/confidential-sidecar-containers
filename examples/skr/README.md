# Attestation and Secure Key Release Sidecar Example

In our confidential container group example, we will deploy the skr sidecar along with a set of test containers that exercise and test the REST API.
- **skr sidecar.** The sidecar’s entry point is /skr.sh which uses the SkrSideCarArgs environment variable to pass the certificate cache endpoint information.
- **attest/raw test.** The sidecar’s entry point is /tests/attest_client.sh which uses the AttestClientRuntimeData environment variable to pass a blob whose sha-256 digest will be encoded in the raw attestation report as report_data.
- **attest/maa test.** The sidecar’s entry point is /tests/attest_client.sh which uses two environment variables: (i) AttestClientMAAEndpoint passes the Microsoft Azure Attestation endpoint which will author the attestation token, (ii) AttestClientRuntimeData passes a blob whose sha-256 digest will be encoded in the attestation token as runtime claim.
- **key/release test.** The sidecar’s entry point is /tests/skr_client.sh which uses the three environment variables: (i) SkrClientKID passes the key identifier of the key to be released from the key vault, (ii) SkrClientAKVEndpoint passes the key vault endpoint from which the key will be released, and (iii) SkrClientMAAEndpoint passes the Microsoft Azure Attestation endpoint shall author the attestation token required for releasing the secret. The MAA endpoint shall be the same as the one specified in the SKR policy during the key import to the key vault.

## Preparation

### Managed identity
The user needs to generate a user-assigned managed idenity which will be attached to the container group so that the containers can have the right access permissions to Azure services and resources. More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

### Policy generation
Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group. There is an az tool available for generating policies. See [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples) for installing Azure `confcom` CLI extension.  

The ARM template can be used directly to generate a security policy. The following command generates a security policy and automatically injects it into the template. Make sure `--debug-mode` option is included so that the generated policy allows shelling into container to see the released key in this example. NOTE: the current image used in the ARM template is built upon commit id a82b530. 

    `az confcom acipolicygen -a aci-skr-arm-template.json --debug-mode`

The ARM template file includes three entries: (i) skr sidecar container which whitelists the /skr.sh as entry point command and the environment variable SkrSideCarArgs used by the script, (ii) attest_client container which whitelists the /tests/attest_client.sh as entry point command and a set of environment variables used by the script and whose names begin with AttestClient, and  (iii) skr_client container which whitelists the /tests/skr_client.sh as entry point command and a set of environment variables used by the script and whose names begin with SkrClient. 
Please note that:
- The skr sidecar must be allowed to execute as elevated because it needs access to the PSP which is mounted as a device at /dev/sev. 
- The policy includes one entry for both attestation tests, as both tests use the same entry point and a superset of environment variables whitelisted by the AttestClient regular expression.

### Import key
The user needs to instantiate an Azure Key Vault resource that supports storing keys in an HSM: a [Premium vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) or an [MHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview). For the former, the user needs to assign 
the *Key Vault Crypto Officer* and *Key Vault Crypto User* roles to the user-assigned managed identity and for the latter, the user needs to assign *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys to the user-assigned managed identity.

Once the key vault resource is ready, the user can import `RSA-HSM` or `oct-HSM` keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` after updating the `importkeyconfig.json` with the required information as discussed in the tools' readme file. For instance, the hostdata claim value needs to be set to the hash digest of the security policy, which can be obtained by executing the following command:

`go run <parent_dir>/tools/securitypolicydigest/main.go -p <base64-std-encoded-string-of-security-policy>`

And the AAD token with permission to AKV/mHSM can be obtained with the following command: 

`az account get-access-token --resource https://managedhsm.azure.net` 

Once the `importkeyconfig.json` is updated, execute the following command:

`cd <parent_dir>/tools/importkey`

`go run main.go -c <parent_dir>/examples/skr/importkeyconfig.json

### Deployment
The `aci-arm-template.json` provides an ARM template which can be parametrized using the security policy obtained above, the registry name (and credentials if private), the user-assigned managed identity, and the URIs to the endpoints required by the sidecar and test containers, discussed above.


Let us see an example of running SKR containers on confidential ACI. In this example, the MAA endpoint used is sharedeus2.eus2.test.attest.azure.net. The used managed HSM instance endpoint is accmhsm.managedhsm.azure.net.  

Update the ARM template with a managed identity that has the following role based access: 

*Key Vault Crypto Officer* and *Key Vault Crypto User* roles if using AKV
*Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys. 

insert picture 

Update the following on the ARM template. If you are using a private image, you should also update the following with a managed identity that has access to the private container registry. In our case, you do not need this section because we are using a public image. 

"imageRegistryCredentials": [
          {
            "server": "parmaregistry.azurecr.io",
            "identity": ""
          }
],

this belongs to encfs 
You should also have the Reader and Storage Blob Reader/Contributor roles to the storage container on which the encrypted model image has been uploaded. 



Run the following command to generate the security policy and make sure you include the `--deubg-mode` option so that the policy allows users to shell into the container. 

    1az confcom acipolicygen -a aci-arm-template.json --debug-mode`


Key import: 

git clone git@github.com:microsoft/confidential-sidecar-containers.git and in the tools folder, there are two tools that allow users to obtain the security hash of the generated policy and importing key into the key vault.


Copy the value of the generated `ccePolicy` poicy from the ARM template and obtain the security hash of the policy by running: 

    `go run tools/securitypolicydigest/main.go -p ccePolicyValue`

At the end of the command output, you should see something similar to the following: 

inittimeData sha-256 digest **aaa4e****cc09d**

Obtain the AAD token with the following command 

    `az account get-access-token --resource https://managedhsm.azure.net`

Fill in the keyimportconfig.json file with the above information. See the following as an example: 

```
{
    "key": {
        "kid": "doc-sample-key-release",  **<- This is the key name you will import your key into mHSM. SkrClientKID on ARM template.**
        "authority": {
            "endpoint": "sharedeus2.eus2.test.attest.azure.net" **<- MAA endpoint. SkrClientMAAEndpoint on ARM template**
        },
        "mhsm": {
            "endpoint": "accmhsm.managedhsm.azure.net", **<- mHSM endpoint. SkrClientAKVEndpoint on ARM template**
            "api_version": "api-version=7.3-preview",
            "bearer_token": "eyJ***6qlA" **<- AAD token obtained above**
        }
    },
    "claims": [
        [
            {
                "claim": "x-ms-sevsnpvm-hostdata",
                "equals": "aaa4e****cc09d" **<- Security hash obtained above** 
            },
            {
                "claim": "x-ms-compliance-status",
                "equals": "azure-compliant-uvm"
            },
            {
                "claim": "x-ms-sevsnpvm-is-debuggable",
                "equals": "false"
            }
        ]
    ]
}
```

Import the key into mHSM with the following command. I'm using a fake encryption key here because I just want to see the key gets released. 

go run /tools/importkey/main.go -c keyimportconfig.json -kh encryptionKey

Upon successful import completion, you should see something similar to the following: 

[34 71 33 117 113 25 191 84 199 236 137 166 201 103 83 20 203 233 66 236 121 110 223 2 122 99 106 20 22 212 49 224]
https://accmhsm.managedhsm.azure.net/keys/doc-sample-key-release/8659****0cdff08
{"version":"0.2","anyOf":[{"authority":"https://sharedeus2.eus2.test.attest.azure.net","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"}]}]}

Deployment: 

Make sure the ccePolicy is not blank and deploy confidential ACI in your preferred way. I'm deploying using Azure portal. To verify the key has been successful released, shell into the `skr-sidecar-container` container and see the log.txt and you should see the following log message: 

level=debug msg=Releasing key blob: {doc-sample-key-release}

Alternatively, you can shell into the container `test-skr-client-hsm-skr` and the released key is in keyrelease.out. 
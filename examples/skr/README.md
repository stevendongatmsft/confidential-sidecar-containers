# Attestation and Secure Key Release Sidecar Example

## Table of Contents
- [Managed identity](#managed-identity)
- [Policy generation](#policy-generation)
- [Import key](#import-key)
- [Deployment](#deployment)
- [Step by step example](#step-by-step-example)

In our confidential container group example, we will deploy the skr sidecar along with a set of test containers that exercise and test the REST API.
- **skr sidecar.** The sidecar’s entry point is /skr.sh which uses the SkrSideCarArgs environment variable to pass the certificate cache endpoint information.
- **attest/raw test.** The sidecar’s entry point is /tests/attest_client.sh which uses the AttestClientRuntimeData environment variable to pass a blob whose sha-256 digest will be encoded in the raw attestation report as report_data.
- **attest/maa test.** The sidecar’s entry point is /tests/attest_client.sh which uses two environment variables: (i) AttestClientMAAEndpoint passes the Microsoft Azure Attestation endpoint which will author the attestation token, (ii) AttestClientRuntimeData passes a blob whose sha-256 digest will be encoded in the attestation token as runtime claim.
- **key/release test.** The sidecar’s entry point is /tests/skr_client.sh which uses the three environment variables: (i) SkrClientKID passes the key identifier of the key to be released from the key vault, (ii) SkrClientAKVEndpoint passes the key vault endpoint from which the key will be released, and (iii) SkrClientMAAEndpoint passes the Microsoft Azure Attestation endpoint shall author the attestation token required for releasing the secret. The MAA endpoint shall be the same as the one specified in the SKR policy during the key import to the key vault.


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

### Step by step example 
Here is an example of running skr sidecar on confidential ACI. In this example, the MAA endpoint is `sharedeus2.eus2.test.attest.azure.net`. The managed HSM instance is `accmhsm.managedhsm.azure.net`.  

We are using the following ARM template for this sample: 
```
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "containerGroupName": {
      "defaultValue": "aciSKRSidecarTest",
      "type": "String",
      "metadata": {
        "description": "Secure Key Release Sidecar Example"
      }
    }
  },
  "resources": [
    {
      "type": "Microsoft.ContainerInstance/containerGroups",
      "apiVersion": "2022-10-01-preview",
      "name": "[parameters('containerGroupName')]",
      "location": "[resourceGroup().location]",
      "identity": {
        "type": "UserAssigned",
        "userAssignedIdentities": {
          "/subscriptions/***/resourceGroups/resourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myIdentity": {}
        }
      },
      "properties": {
        "containers": [
          {
            "name": "skr-sidecar-container",
            "properties": {
              "command": [
                "/skr.sh"
              ],
              "image": "mcr.microsoft.com/aci/skr:main_20230216.1",
              "resources": {
                "requests": {
                  "cpu": 1,
                  "memoryInGB": 2
                }
              },
              "ports": [
                {
                  "port": 8080
                }
              ]
            }
          },
          {
            "name": "test-skr-client-container",
            "properties": {
              "command": [
                "/tests/skr_client.sh"
              ],
              "environmentVariables": [
                {
                  "name": "SkrClientMAAEndpoint",
                  "value": "sharedeus2.eus2.test.attest.azure.net"
                },
                {
                  "name": "SkrClientAKVEndpoint",
                  "value": "accmhsm.managedhsm.azure.net"
                },
                {
                  "name": "SkrClientKID",
                  "value": "doc-sample-key-release"
                }
              ],
              "image": "mcr.microsoft.com/aci/skr:main_20230216.1",
              "resources": {
                "requests": {
                  "cpu": 0.5,
                  "memoryInGB": 1
                }
              }
            }
          },
          {
            "name": "test-attest-client-container",
            "properties": {
              "command": [
                "/tests/attest_client.sh"
              ],
              "environmentVariables": [
                {
                  "name": "AttestClientRuntimeData",
                  "value": "eyJrZXlzIjpbeyJlIjoiQVFBQiIsImtleV9vcHMiOlsiZW5jcnlwdCJdLCJraWQiOiJOdmhmdXEyY0NJT0FCOFhSNFhpOVByME5QXzlDZU16V1FHdFdfSEFMel93Iiwia3R5IjoiUlNBIiwibiI6InY5NjVTUm15cDh6Ykc1ZU5GdURDbW1pU2VhSHB1akcyYkNfa2VMU3V6dkRNTE8xV3lyVUp2ZWFhNWJ6TW9PMHBBNDZwWGttYnFIaXNvelZ6cGlORExDbzZkM3o0VHJHTWVGUGYyQVBJTXUtUlNyek41NnF2SFZ5SXI1Y2FXZkhXay1GTVJEd0FlZnlOWVJIa2RZWWtnbUZLNDRoaFVkdGxDQUtFdjVVUXBGWmp2aDRpSTlqVkJkR1lNeUJhS1FMaGpJNVdJaC1RRzZaYTVzU3VPQ0ZNbm11eXV2TjVEZmxwTEZ6NTk1U3MtRW9CSVktTmlsNmxDdHZjR2dSLUlialVZSEFPczVhamFtVHpnZU84a3gzVkNFOUhjeUtteVVac2l5aUY2SURScDJCcHkzTkhUakl6N3Rta3BUSHg3dEhuUnRsZkUyRlV2MEI2aV9RWWxfWkE1USJ9XX0="
                }
              ],
              "image": "mcr.microsoft.com/aci/skr:main_20230216.1",
              "resources": {
                "requests": {
                  "cpu": 0.5,
                  "memoryInGB": 1
                }
              }
            }
          },
          {
            "name": "test-attest-maa-client-container",
            "properties": {
              "command": [
                "/tests/attest_client.sh"
              ],
              "environmentVariables": [
                {
                  "name": "AttestClientMAAEndpoint",
                  "value": "sharedeus2.eus2.test.attest.azure.net"
                },
                {
                  "name": "AttestClientRuntimeData",
                  "value": "eyJrZXlzIjpbeyJlIjoiQVFBQiIsImtleV9vcHMiOlsiZW5jcnlwdCJdLCJraWQiOiJOdmhmdXEyY0NJT0FCOFhSNFhpOVByME5QXzlDZU16V1FHdFdfSEFMel93Iiwia3R5IjoiUlNBIiwibiI6InY5NjVTUm15cDh6Ykc1ZU5GdURDbW1pU2VhSHB1akcyYkNfa2VMU3V6dkRNTE8xV3lyVUp2ZWFhNWJ6TW9PMHBBNDZwWGttYnFIaXNvelZ6cGlORExDbzZkM3o0VHJHTWVGUGYyQVBJTXUtUlNyek41NnF2SFZ5SXI1Y2FXZkhXay1GTVJEd0FlZnlOWVJIa2RZWWtnbUZLNDRoaFVkdGxDQUtFdjVVUXBGWmp2aDRpSTlqVkJkR1lNeUJhS1FMaGpJNVdJaC1RRzZaYTVzU3VPQ0ZNbm11eXV2TjVEZmxwTEZ6NTk1U3MtRW9CSVktTmlsNmxDdHZjR2dSLUlialVZSEFPczVhamFtVHpnZU84a3gzVkNFOUhjeUtteVVac2l5aUY2SURScDJCcHkzTkhUakl6N3Rta3BUSHg3dEhuUnRsZkUyRlV2MEI2aV9RWWxfWkE1USJ9XX0="
                }
              ],
              "image": "mcr.microsoft.com/aci/skr:main_20230216.1",
              "resources": {
                "requests": {
                  "cpu": 1,
                  "memoryInGB": 1
                }
              }
            }
          }
        ],
        "imageRegistryCredentials": [
          {
            "server": "sampleprivateregistry.azurecr.io",
            "identity": ""
          }
        ],
        "osType": "Linux",
        "ipAddress": {
          "type": "Public",
          "ports": [
            {
              "protocol": "tcp",
              "port": 8080
            }
          ]
        },
        "sku": "confidential",
        "confidentialComputeProperties": {
          "ccePolicy": "<base64-std-encoded-string-of-policy>"
        }
      }
    }
  ],
  "outputs": {
    "containerIPv4Address": {
      "type": "String",
      "value": "[reference(resourceId('Microsoft.ContainerInstance/containerGroups/', parameters('containerGroupName'))).ipAddress.ip]"
    }
  }
}
```

**Preparation**: 

Update the following ARM template managed identity portion that has the correct role based access. The managed identity needs *Key Vault Crypto Officer* and *Key Vault Crypto User* roles if using AKV. *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys if using managed HSM. Follow [Managed identity](#managed-identity) for detailed instruction. 

```
"identity": {
        "type": "UserAssigned",
        "userAssignedIdentities": {
          "/subscriptions/***/resourceGroups/resourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myIdentity": {}
        }
},
```

Update the managed identity in imageRegistryCredentials on the ARM template in order to access the private container registry. In our case, you do not need this section because we are using a public image. 

```
"imageRegistryCredentials": [
          {
            "server": "sampleprivateregistry.azurecr.io",
            "identity": ""
          }
],
```

**Generate security policy**: 

Run the following command to generate the security policy and make sure you include the `--deubg-mode` option so that the policy allows users to shell into the container. 

    az confcom acipolicygen -a aci-arm-template.json --debug-mode


**Key import**: 

    git clone git@github.com:microsoft/confidential-sidecar-containers.git

Use the tools in this repository to obtain the security hash of the generated policy and to import key into the AKV/mHSM. Copy the value of the generated `ccePolicy` from the ARM template. At the root of the clone repo, obtain the security hash of the policy by running: 

    go run tools/securitypolicydigest/main.go -p ccePolicyValue

At the end of the command output, you should see something similar to the following: 

    inittimeData sha-256 digest **aaa4e****cc09d**

Obtain the AAD token: 

    az account get-access-token --resource https://managedhsm.azure.net

Fill in the keyimportconfig.json file with the above information. See the following as an example: 

```
{
    "key": {
        "kid": "doc-sample-key-release",  <- This is the key name you will import your key into mHSM. SkrClientKID on ARM template.
        "authority": {
            "endpoint": "sharedeus2.eus2.test.attest.azure.net" <- MAA endpoint. SkrClientMAAEndpoint on ARM template
        },
        "mhsm": {
            "endpoint": "accmhsm.managedhsm.azure.net", <- mHSM endpoint. SkrClientAKVEndpoint on ARM template
            "api_version": "api-version=7.3-preview",
            "bearer_token": "eyJ***6qlA" <- AAD token obtained above
        }
    },
    "claims": [
        [
            {
                "claim": "x-ms-sevsnpvm-hostdata",
                "equals": "aaa4e****cc09d" <- Security hash obtained above
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

```
[34 71 33 117 113 25 191 84 199 236 137 166 201 103 83 20 203 233 66 236 121 110 223 2 122 99 106 20 22 212 49 224]
https://accmhsm.managedhsm.azure.net/keys/doc-sample-key-release/8659****0cdff08
{"version":"0.2","anyOf":[{"authority":"https://sharedeus2.eus2.test.attest.azure.net","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"}]}]}
```

In this case, I use the following command to verify my key has been successfully imported: 

	az account set --subscription "my subscription"
    az keyvault key list --hsm-name accmhsm -o table 

**Deployment**: 

Deploy and verify the key has been successful released, shell into the `skr-sidecar-container` container and see the log.txt and you should see the following log message: 

```
level=debug msg=Releasing key blob: {doc-sample-key-release}
```

Alternatively, you can shell into the container `test-skr-client-hsm-skr` and the released key is in keyrelease.out. 
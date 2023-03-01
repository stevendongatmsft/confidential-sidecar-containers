# Encrypted filesystem container example

## Table of Contents
  - [Managed identity](#managed-identity)
  - [Security policy generation](#security-policy-generation)
  - [Import encryption key](#import-encryption-key)
  - [Encrypted filesystem](#encrypted-filesystem)
  - [Testing](#testing)
  - [Deployment](#deployment)
  - [Step by step example](#step-by-step-example)

### Managed identity
The user needs to generate a user-assigned managed idenity which will be attached to the container group so that the containers can have the right access permissions to Azure services and resources. More information about creating identities can be found [here.](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/)

### Security policy generation
Deploying a confidential container group requires generating a security policy that restricts what containers can run within the container group. There is an az tool available for generating policies. See [here](https://github.com/Azure/azure-cli-extensions/tree/main/src/confcom/azext_confcom#microsoft-azure-cli-confcom-extension-examples) for installing Azure `confcom` CLI extension.  

The ARM template can be used directly to generate a security policy. The following command generates a security policy and automatically injects it into the template. 

```az confcom acipolicygen -a aci-arm-template.json```

The ARM template file file includes two entries: (i) encrypted filesystem sidecar container which whitelists the /encfs.sh as entry point command and the environment variable *EncfsSideCarArgs* used by the script, and (ii) an application container which whitelists a while loop command as entry point command. NOTE: the current image used in the ARM template is built upon commit id a82b530. 

### Import encryption key
The user needs to instantiate an Azure Key Vault resource that supports storing keys in an HSM: a [Premium vault](https://learn.microsoft.com/en-us/azure/key-vault/general/overview) or an [MHSM resource](https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview). For the former, the user needs to assign 
the *Key Vault Crypto Officer* and *Key Vault Crypto User* roles to the user-assigned managed identity and for the latter, the user needs to assign *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys to the user-assigned managed identity.

Once the key vault resource is ready, the user can import `RSA-HSM` or `oct-HSM` keys into it using the `importkey` tool placed under `<parent_repo_dir>/tools/importkey` after updating the `importkeyconfig.json` with the required information as discussed in the tools' readme file. For instance, the hostdata claim value needs to be set to the hash digest of the security policy, which can be obtained by executing the following command:

`go run <parent_dir>/tools/securitypolicydigest/main.go -p <base64-std-encoded-string-of-security-policy>`

And the AAD token with permission to AKV/mHSM can be obtained with the following command:

`az account get-access-token --resource https://managedhsm.azure.net`

Once the `importkeyconfig.json` is updated, execute the following command:

`cd <parent_dir>/tools/importkey`

`go run main.go -c <parent_dir>/examples/encfs/importkeyconfig.json -kh <hexstring encoding oct-HSM key> -out`

`go run main.go -c <parent_dir>/examples/encfs/importkeyconfig.json -kp private-key.pem -out`

`go run main.go -c <parent_dir>/examples/encfs/importkeyconfig.json -out`

For `RSA-HSM` keys, the `importkey` (if prompted using the `-out` flag) derives an octet key from the RSA private key. Note that it is safe
to use the private RSA key as entropy for a symmetric key as logn as the RSA key pair is not used for any other cryptographic operation.

### Encrypted filesystem
The user needs to instantiate an [Azure storage container](https://docs.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-blobs-upload) onto which the encrypted filesystem will be uploaded. The roles *Reader* and *Storage Blob Reader* roles need to be assigned to the user-assigned managed identity.

The script `generatefs/generatefs.sh` creates `encfs.img` with the contents of the `generatefs/filesystem` directory. You may need to adjust the size of the image in the script, as it isn't calculated automatically. 

The script expects a symmetric key stored in binary format `keyfile.bin` previously created during key import phase. If not passed, the script will generate a new one and the user will need to follow the import key instructions.

```
[!] Generating keyfile...
1+0 records in
1+0 records out
32 bytes copied, 0.00142031 s, 22.5 kB/s
keyfile exists
Key in hex string format
b'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'
[!] Creating encrypted image...
Key slot 0 created.
Command successful.
[!] Formatting as ext4...
mke2fs 1.45.5 (07-Jan-2020)
Creating filesystem with 12288 4k blocks and 12288 inodes

Allocating group tables: done
Writing inode tables: done
Creating journal (1024 blocks): done
Writing superblocks and filesystem accounting information: done

[!] Mounting...
[!] Copying contents to encrypted device...
lost+found  test.txt
[!] Closing device...
```

The user needs to upload the blob to the previously generated storage container 

```azcopy copy --blob-type=PageBlob ./generatefs/encfs.img 'https://<storage-container-uri>.blob.core.windows.net/private-container/encfs.img?<SAS_token_to_container_with_write_create_read_permissions>```

## Testing
In our confidential container group example, we will deploy the encrypted filesystem sidecar along with a simple container that runs indefinitely. The simple container will have access to the remote filesystem mounted by the sidecar container.

### Deployment
The `aci-arm-template.json` provides an ACI ARM template which can be parametrized using the security policy obtained above, the registry name (and credentials if private), the user-assigned managed identity, and the encrypted filesystem sidecar's *EncfsSideCarArgs* set to the base64-std-encoded-string of the sidecar's runtime attribute specified in the `encfs-sidecar-args.json` 

Once the deployment completes, the user can shell into the applicaiton container and execute the following commands:

```
# ls /mnt/remote/share/
lost+found  test.txt

/ # cat /mnt/remote/share/test.txt 
This is a file inside the filesystem.
```

Alternatively, the whitelisted command in test-encfs-container outputs the following log, which users are able to see under the Logs tab.
```
This is a file inside the filesystem.
This is a file inside the filesystem.

```

### Step by step example 

Here is an example of running encfs sidecar on confidential ACI. In this example, the MAA endpoint is `sharedeus2.eus2.test.attest.azure.net`. The managed HSM instance is `accmhsm.managedhsm.azure.net`.  

We are using the following ARM template for this sample: 

```
{
  "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "containerGroupName": {
      "type": "string",
      "defaultValue": "encfs-sample",
      "metadata": {
        "description": "Encrypted filesystem sidecar example"
      }
    }
  },
  "resources": [
    {
      "name": "[parameters('containerGroupName')]",
      "type": "Microsoft.ContainerInstance/containerGroups",
      "apiVersion": "2022-10-01-preview",
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
            "name": "encrypted-filesystem-sidecar-container",
            "properties": {
              "command": [
                "/encfs.sh"
              ],
              "environmentVariables": [
                {
                  "name": "EncfsSideCarArgs",
                  "value": "ewogICAgImF6dXJlX2ZpbGVzeXN0ZW1zIjogWwogICAgICAgIHsKICAgICAgICAgICAgIm1vdW50X3BvaW50IjogIi9tbnQvcmVtb3RlL3NoYXJlIiwKICAgICAgICAgICAgImF6dXJlX3VybCI6ICJodHRwczovL3Nkb25nbWxpbmZlcmVuY2VkZW1vLmJsb2IuY29yZS53aW5kb3dzLm5ldC9wcml2YXRlLWNvbnRhaW5lci9tb2RlbHMuaW1nIiwKICAgICAgICAgICAgImF6dXJlX3VybF9wcml2YXRlIjogdHJ1ZSwKICAgICAgICAgICAgImtleSI6IHsKICAgICAgICAgICAgICAgICJraWQiOiAiZW5jZnMtZG9jLXNhbXBsZS1rZXkxIiwKICAgICAgICAgICAgICAgICJhdXRob3JpdHkiOiB7CiAgICAgICAgICAgICAgICAgICAgImVuZHBvaW50IjogInNoYXJlZGV1czIuZXVzMi50ZXN0LmF0dGVzdC5henVyZS5uZXQiCiAgICAgICAgICAgICAgICB9LAogICAgICAgICAgICAgICAgImFrdiI6IHsKICAgICAgICAgICAgICAgICAgICAiZW5kcG9pbnQiOiAiYWNjbWhzbS5tYW5hZ2VkaHNtLmF6dXJlLm5ldCIKICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgfQogICAgICAgIH0KICAgIF0KfQ=="
                }
              ],
              "image": "mcr.microsoft.com/aci/encfs:main_20230216.1",
              "resources": {
                "requests": {
                  "cpu": 1,
                  "memoryInGb": 2
                }
              },
              "volumeMounts": [
                {
                  "name": "remotemounts",
                  "mountPath": "/mnt/remote"
                }
              ]
            }
          },
          {
            "name": "test-encfs-container",
            "properties": {
              "command": [
                "/bin/sh",
                "-c",
                "while true; do cat /mnt/remote/share/test.txt | /usr/bin/head -n 20; sleep 1; done"
              ],
              "image": "docker.io/alpine:3.17.1",
              "resources": {
                "requests": {
                  "cpu": 0.5,
                  "memoryInGb": 1
                }
              },
              "volumeMounts": [
                {
                  "name": "remotemounts",
                  "mountPath": "/mnt/remote"
                }
              ],
              "ports": [
                {
                  "port": 8000
                }
              ]
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
              "port": 8000
            }
          ]
        },
        "sku": "confidential",
        "confidentialComputeProperties": {
          "ccePolicy": ""
        },
        "volumes": [
          {
            "name": "remotemounts",
            "emptyDir": {}
          }
        ]
      }
    }
  ],
  "outputs": {
    "containerIPv4Address": {
      "type": "string",
      "value": "[reference(resourceId('Microsoft.ContainerInstance/containerGroups/', parameters('containerGroupName'))).ipAddress.ip]"
    }
  }
}
```

**Preparation**: 

Please follow [Encrypted filesystem](#encrypted-filesystem) to generate and upload the encrypted file system to container storage as a page blob. Once done, update the following ARM template managed identity portion that has the correct role based access. The managed identity needs *Key Vault Crypto Officer* and *Key Vault Crypto User* roles if using AKV. *Managed HSM Crypto Officer* and *Managed HSM Crypto User* roles for /keys if using managed HSM. Follow [Managed identity](#managed-identity) for detailed instruction. The same identity should also have the Reader and Storage Blob Reader/Contributor roles to the storage container on which the encrypted model image has been uploaded. 

"identity": {
        "type": "UserAssigned",
        "userAssignedIdentities": {
          "/subscriptions/***/resourceGroups/resourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/myIdentity": {}
        }
},


Update the managed identity in the imageRegistryCredentials on the ARM template in order to access the private container registry. In our case, you do not need this section because we are using a public image. 

"imageRegistryCredentials": [
          {
            "server": "sampleprivateregistry.azurecr.io",
            "identity": ""
          }
],

**Encfs sidecar argument**: 

```
{
    "azure_filesystems": [
        {
            "mount_point": "/mnt/remote/share4", <- User indicates the mount_point where the remote file system should be mounted 
            "azure_url": "https://sdongmlinferencedemo.blob.core.windows.net/private-container/models.img", <- azure blob storage url for generated encryption file system
            "azure_url_private": true,
            "key": {
                "kid": "encfs-doc-sample-key", <- Imported encrytion key name in mHSM
                "authority": {
                    "endpoint": "sharedeus2.eus2.test.attest.azure.net" <- MAA endpoint 
                },
                "akv": {
                    "endpoint": "accmhsm.managedhsm.azure.net" <- mHSM endpoint 
                }
            }
        }
    ]
}
```
The value of `EncfsSideCarArgs` env var on the ARM template should be the base64 encoding of the encfs sidecar argument above. 

**Generate security policy**: 

Run the following command to generate the security policy and include the `--deubg-mode` option so that the security policy allows users to shell into the container for debugging purposes. 

    az confcom acipolicygen -a aci-arm-template.json --debug-mode


**Key import**: 

    git clone git@github.com:microsoft/confidential-sidecar-containers.git 

Use the tools in this repository to obtain the security hash of the generated policy and to import key into the AKV/mHSM. Copy the value of the generated `ccePolicy` from the ARM template and obtain the security hash of the policy by running: 

    go run tools/securitypolicydigest/main.go -p ccePolicyValue

At the end of the command output, you should see something similar to the following: 

    inittimeData sha-256 digest **aaa4e****cc09d**

Obtain the AAD token: 

    az account get-access-token --resource https://managedhsm.azure.net

Fill in the keyimportconfig.json file with all the information. See the following as an example:

```
{
    "key": {
        "kid": "doc-sample-key-release",  <- This is the key name you will import your key into mHSM. 
        "authority": {
            "endpoint": "sharedeus2.eus2.test.attest.azure.net" <- MAA endpoint. 
        },
        "mhsm": {
            "endpoint": "accmhsm.managedhsm.azure.net", <- mHSM endpoint.
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

Import the key into mHSM with the following command. The value of the -kh flag should be the encryption key you obtained during file system generation. 

    go run /tools/importkey/main.go -c keyimportconfig.json -kh encryptionKey

Upon successful import completion, you should see something similar to the following: 

[34 71 33 117 113 25 191 84 199 236 137 166 201 103 83 20 203 233 66 236 121 110 223 2 122 99 106 20 22 212 49 224]
https://accmhsm.managedhsm.azure.net/keys/doc-sample-key-release/8659****0cdff08
{"version":"0.2","anyOf":[{"authority":"https://sharedeus2.eus2.test.attest.azure.net","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"aaa7***7cc09d"},{"claim":"x-ms-compliance-status","equals":"azure-compliant-uvm"},{"claim":"x-ms-sevsnpvm-is-debuggable","equals":"false"}]}]}

In this case, I use the following command to verify my key has been successfully imported: 

	  az account set --subscription "my subscription"
    az keyvault key list --hsm-name accmhsm -o table 

**Deployment**: 

Start deployment and verify file system mounting. See [Deployment](#deployment) for detail.
# State

As mentioned in the {doc}`configuration guide </usage/config>`, Certwrangler adheres to the [XDG Base Directory Specification](https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html) and as such its state for the [local state manager](#certwrangler.state_managers.local.LocalStateManager) plugin will save to `${XDG_DATA_HOME}/certwrangler` or `~/.local/share/certwrangler` if `${XDG_DATA_HOME}` is not set.

## Encryption and state management

Certwrangler supports state encryption at rest. To configure encrypted state, generate a new encryption key with `certwrangler state generate-key`:


```
$ certwrangler state generate-key
        Key: qAcfMUXN4ubbTJQAt5JLq6aR3Qy0bP7AAaAmqN9UXFQ=
Fingerprint: c068fcf6b22b
```

Then take this new key and place it in your certwrangler config under the state manager config:

```
state:
  encryption_keys:
    - qAcfMUXN4ubbTJQAt5JLq6aR3Qy0bP7AAaAmqN9UXFQ=
```

You can verify that the key is loaded by running `certwrangler state fingerprint` to print the fingerprint of the active key.

Multiple encryption keys can be specified under `encryption_keys`, the "active" key is always the top-most key defined in the list. Additional keys will be tried if decryption fails with the active key, but only the active key will be used for encryption operations.

Once this is done, stop Certwrangler if it's still running. Run `certwrangler state encrypt` to encrypt the state with the current active key:

```
$ certwrangler state encrypt
Encrypting account 'default'...
Encrypting cert 'testlinode.com'...
```

You can get a list of all the entities in certwrangler's state by running `certwrangler state list`. This will also print orphaned entities, which are entities that are in the state but not referenced by your config. You can filter for orphaned entities by passing the `--orphaned` flag:

```
$ certwrangler state list --orphaned
{
    "accounts": {
        "test_account1": {
            "encrypted": true,
            "encryption_metadata": {
                "Fingerprint": "6eb7f4614625"
            },
            "orphaned": true,
            "path": "/home/<username>/.local/share/certwrangler/accounts/test_account1.json"
        }
    },
    "certs": {}
}
```

You can remove entities from the state with `certwrangler state delete` like so:

```
$ certwrangler state delete account test_account1
Deleting the following account from the state:
{
    "test_account1": {
        "encrypted": true,
        "encryption_metadata": {
            "Fingerprint": "6eb7f4614625"
        },
        "orphaned": true,
        "path": "/home/<username>/.local/share/certwrangler/accounts/test_account1.json"
    }
}
Continue? Only 'yes' will be accepted: yes
Deleted state for account 'test_account1'.
```

To remove encryption, first stop Certwrangler, then run `certwrangler state decrypt`:

```
$ certwrangler state decrypt
Decrypting account 'default'...
Decrypting cert 'testlinode.com'...

```

Once done, you can remove the encryption keys definition from your config and restart Certwrangler.

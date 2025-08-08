# Custom Domains for Internet Computer

An automated SSL certificate management system that enables registration of custom domains for Internet Computer (IC) canisters using ACME protocol and Let's Encrypt.

## Features
- **Certificate Lifecycle Management**
  - Obtains SSL certificate for custom domains via ACME protocol and Let's Encrypt
  - Automatically renews certificates before expiration 
  - Allows seamless updates of domain-to-canister mappings
  - Allows domain deletion with certificate revocation
- **DNS-01 Challenge Support**: Uses Cloudflare DNS API for peforming ACME challenge
- **Internet Computer Integration**: Seamlessly integrates with IC for storing/retrieving certificates on canister
- **Domain Validation**: 
  - Validates domain ownership through DNS records
  - Validates canister ownership via asset file `./well-known/ic-domains`
- **RESTful API**: Convenient HTTP API for domain registration, status checking, validation, etc.
- **Worker System**: Allows to spawn multiple background workers for certificate operations
- **Encrypted Storage**: Securely stores certificate and private key via encryption in canister

##  Architecture
### Components
- **Backend API** (`backend/`): HTTP REST API server for domain management
- **Canister Client** (`canister_client/`): Client library for IC canister communication
- **Canister Backend** (`canister/`): IC canister for distributed certificate storage
- **Base Library** (`base/`): Shared types, traits, and utilities
- **Worker System**: Background processing for certificate lifecycle tasks

### Task Types
- **Issue**: Initial certificate issuance for new domains
- **Renew**: Automatic certificate renewal before expiration
- **Update**: Update canister mapping for existing domains
- **Delete**: Certificate revocation and cleanup

## Example usage

### Canister Setup
Deploy the storage canister:
```bash
$ cd canister/canister_backend
$ dfx deploy
```

### Run the Service
```bash
# Start the API server and worker
$ cargo run --example custom_domains_example
```

### Important API Endpoints
#### Register Domain
```bash
POST /v1/domains
Content-Type: application/json
{
  "domain": "example.com"
}
```

#### Check Domain Status
```bash
GET /v1/domains/example.com
```
#### Validate Domain Configuration
```bash
GET /v1/domains/example.com/validate
```

### Response Format

```json
{
  "status": "success",
  "code": 200,
  "message": "Domain registration request accepted",
  "data": {
    "domain": "example.com",
    "canister_id": "rdmx6-jaaaa-aaaaa-aaadq-cai",
    "status": "processing"
  }
}
```

## Domain Validation
The system validates domains through multiple checks:
1. **DNS Configuration**: Verifies required CNAME and TXT records
2. **Canister Ownership**: Confirms domain is listed in canister's file `/.well-known/ic-domains`
3. **No Conflicting Records**: Ensures no existing ACME challenge records

## Security
- Certificates and private keys are stored encrypted in the storage canister
- Secure communication with the storage canister with authorization
- Domain and canister ownership are verified before issuing certificate
- Certificate revocation on deletion
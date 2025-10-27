# Custom Domains for Internet Computer

An automated SSL certificate management system enabling registration of custom domains for canisters on the Internet Computer (IC) using the ACME protocol and Let's Encrypt.

![Architecture Diagram](./CustomDomains.svg)

## Features
- **Automated Certificate Lifecycle**
  - Issue, renew, and revoke SSL certificates for custom domains
  - Update domain-to-canister mappings
  - Automatic renewal before expiration
- **DNS-01 Challenge Support**
  - Uses Cloudflare DNS API for ACME challenges
- **Internet Computer Integration**
  - Certificates and mappings stored in a canister (key-value store)
  - Canister acts as a task queue for workers
- **Domain Validation**
  - DNS record checks (CNAME, TXT)
  - Canister ownership via asset file `/.well-known/ic-domains`
  - No conflicting ACME challenge records
- **RESTful API**
  - HTTP endpoints for registration, status, validation, and management
- **Worker System**
  - Multiple background workers for certificate operations
- **Encrypted Storage**
  - Certificates and private keys are encrypted in the canister
- **Rate Limiting**
  - Configurable rate limiting for API endpoints
- **OpenAPI Documentation**
  - Swagger UI for API exploration and testing

## Architecture
### Components
- **Backend API** (`backend/`): Axum-based HTTP REST API server for domain management
- **Base Library** (`base/`):
  - Worker system: Fetches and executes certificate lifecycle tasks from the canister
  - Utilities: Domain validation, encryption, error handling
- **Canister Backend** (`canister/canister_backend/`):
  - Key-value store for domains, certificates, and tasks
  - Metrics
- **Canister API** (`canister/api/`):
  - Shared types and API definitions for canister communication
- **Canister Client** (`canister_client/`):
  - Library for backend/workers to interact with the canister
- **Examples** (`examples/`):
  - Example server startup and configuration (`custom_domains_example.rs`)
- **Tests** (`tests/`):
  - End-to-end and canister integration tests

### Task Types
- **Issue**: Initial certificate issuance for new domains
- **Renew**: Automatic certificate renewal before expiration
- **Update**: Update canister mapping for existing domains
- **Delete**: Certificate revocation and cleanup

## Usage
### Canister Setup
Deploy the storage canister to mainnet or locally:
```bash
$ cd canister/canister_backend
$ dfx deploy canister_backend --mode=reinstall --network=playground
```

### Environment Variables
Set required environment variables:
```bash
$ export CANISTER_ID=...
$ export CLOUDFLARE_API_TOKEN=...
```

### Run the Service
Start the API server and a worker:
```bash
$ cargo run --example custom_domains_example --features openapi
```

### API Documentation
Open Swagger UI to explore and test API endpoints:
```
http://127.0.0.1:3000/swagger-ui
```

## API Endpoints (Examples)
### Register a New Domain
```http
POST /v1/domains
Content-Type: application/json
{
  "domain": "example.com"
}
```

### Check Domain Status
```http
GET /v1/domains/example.com
```

### Validate Domain Eligibility
```http
GET /v1/domains/example.com/validate
```

### Response Format
```json
{
  "status": "success",
  "message": "Domain registration request accepted and may take a few minutes to process",
  "data": {
    "domain": "example.org",
    "canister_id": "laqa6-raaaa-aaaam-aehzq-cai"
  }
}
```

## Domain Validation
Domains are validated through:
1. **DNS Configuration**: Required CNAME and TXT records
2. **Canister Ownership**: Domain listed in `/.well-known/ic-domains` asset file
3. **No Conflicting Records**: No existing ACME challenge records

## Security
- Certificates and private keys encrypted in the canister
- Secure canister communication with authorization
- Ownership checks before issuing or deleting certificates
- Configurable rate limiting for API endpoints
- Certificate revocation on domain deletion/renewals

## Project Structure
```
custom-domains/
├── backend/              # Axum REST API server
├── base/                 # Worker system, validation, encryption
├── canister/
│   ├── api/              # Canister API
│   └── canister_backend/ # Canister implementation
├── canister_client/      # Canister communication library
├── examples/             # Example of the system startup
├── tests/                # E2E and canister tests
├── CustomDomains.svg     # Architecture diagram
```

## Contributing

External code contributions are currently not being accepted to this repository.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for more details.

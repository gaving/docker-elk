# Docker with Elasticsearch + SG

ES bundled with SG and functionality enabled:-

- JWT
- Audit

## Run

- `docker-compose up`
- `docker-compose exec -T elasticsearch bin/init_sg.sh`

## Log in

- `http://localhost:5601/` w/ admin/admin

## Requests

Include token in requests to ES e.g.

- `http :9200/_searchguard/authinfo "X-Auth-Token: <token>"`

or use basic auth:-

- `http --auth readall:readall :9200/_searchguard/authinfo`

## Load data

- `gzip -d -c contrib/accounts.json.gz | http :9200/bank/account/_bulk\?pretty "X-Auth-Token: <token>"`

## Query data

```json
echo '{
  "_source": {
    "includes": ["email"]
  },
  "query": {
    "match": {
      "firstname": "Dale"
    }
  }
}' | http --auth readall:readall :9200/bank/_search
```

- View auditlog index in Kibana to view `COMPLIANCE_DOC_READ` events (data viewed) and `AUTHENTICATED` events (queries ran)

## References

### Set up JWT key

#### Generate key

- `ssh-keygen -t rsa -b 4096 -m PEM -f contrib/jwtRS256.key # (don't add passphrase)`
- `openssl rsa -in contrib/jwtRS256.key -pubout -outform PEM -out contrib/jwtRS256.key.pub`
- `cat contrib/jwtRS256.key`
- `cat contrib/jwtRS256.key.pub`

#### Generate token

- Download https://github.com/mattroberts297/jsonwebtokencli
- Generate token with the following:-

```json
jwt --encode --algorithm 'RS256' --private-key-file './jwtRS256.key' '{
  "sub": "admin",
  "name": "Gavin Gilmour",
  "iat": 1516239022,
  "roles": "admin"
}'
```

### Config changes

#### elasticsearch.yml

```bash
searchguard.enterprise_modules_enabled: true

searchguard.ssl.transport.keystore_filepath: sg/node-0-keystore.jks
searchguard.ssl.transport.truststore_filepath: sg/truststore.jks
searchguard.ssl.transport.enforce_hostname_verification: false

searchguard.restapi.roles_enabled: ["sg_all_access"]

searchguard.authcz.admin_dn:
  - "CN=kirk,OU=client,O=client,l=tEst,C=De"

searchguard.audit.type: internal_elasticsearch
searchguard.audit.config.index: auditlog
searchguard.audit.config.disabled_rest_categories: NONE
searchguard.audit.config.disabled_transport_categories: NONE
searchguard.audit.ignore_users:
  - kibanaserver
  - admin

searchguard.compliance.history.read.watched_fields:
  - bank,*
```

#### sg_config.yml

```bash
searchguard:
  dynamic:
    http:
      xff:
        enabled: false
    authc:
      jwt_auth_domain:
        enabled: true
        order: 0
        http_authenticator:
          type: jwt
          challenge: false
          config:
            signing_key: |-
              -----BEGIN PUBLIC KEY-----
              <contents of public key generated above>
              -----END PUBLIC KEY-----
            jwt_header: "X-Auth-Token"
            jwt_url_parameter: null
            subject_key: "sub"
            roles_key: "roles"
        authentication_backend:
          type: noop
```

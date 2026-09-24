# JSON Web Tokens

Not JWT.

## Usage

Create a signer and factory, then use the factory to issue and parse tokens:

```go
signer, err := signers.NewHS256([]byte("secret"))
if err != nil {
	return err
}
factory := jsonwt.NewFactory("key-id", signer)

token, err := factory.Token(time.Hour, claims)
if err != nil {
	return err
}
encoded := token.String()

token, err = factory.Parse(encoded)
if err != nil {
	return err
}
return token.Claim(&claims)
```

`Factory.Parse` decodes the token and verifies its algorithm, key ID,
signature, and lifetime. `Decode` is available for callers that explicitly
need unverified token data.

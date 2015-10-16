# jwt
This library is a scala implementation of the JSON Web Token (JWT) [specification](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

If you are not familiar with JWTs, then I suggest you check out [this](https://developer.atlassian.com/static/connect/docs/latest/concepts/understanding-jwt.html) article.
# Goal
This project aims to abstract away from the raw strings and json often seen in JWT implementations. We instead leverage types for a stricter and more robust implementation.
# Usage
Creating headers and claims 
---------------------------
This library contains implementations of all the registered claims and headers laid out in the JWT specification 
```scala
// The Algorithm object contains various valid encryption methods, per the JWT specification.
// Creating an alg header.
Alg(Algorithm.HS256)

// Creating an iss claim.
Iss("readme")
```
Creating a decoded JWT
----------------------
```scala
val jwt = new DecodedJwt(Seq(Alg(Algorithm.HS256), Typ("JWT")), Seq(Iss("readme")))

// Extracting values from a jwt is simple, just provide the field type
jwt.getHeader[Typ]  // Returns Some(Typ("JWT"))
jwt.getClaim[Iss]   // Returns Some(Iss("readme"))
jwt.getClaim[Sub]   // Returns None
```
Encrypting and signing a decoded JWT
------------------------------------
```scala
// Create a jwt
val jwt = new DecodedJwt(Seq(Alg(Algorithm.HS256), Typ("JWT")), Seq(Iss("readme")))

// Returns the encoded and signed jwt using the algorithm from the alg header, and the secret provided.
jwt.encodedAndSigned("secret")
```
Validating an encoded JWT
-------------------------
The below will attempt to validate a JWT.

Note that the alg header should not be in the required headers, as all JWTs require it already.
```scala
DecodedJwt.validateEncodedJwt(
  jwt,              // An encoded jwt as a string
  "secret",         // The secret to validate the signature against
  Algorithm.HS256,  // The algorithm we require
  Set(Typ),         // The set of headers we require (excluding alg)
  Set(Iss)          // The set of claims we require
)
```
Returns a DecodedJwt wrapped in Success on success, otherwise Failure.

Per the JWT specification, you can mark fields as ignored during validation. See this [test](https://github.com/iain-logan/jwt/blob/master/src/test/scala/io/igl/jwt/JwtSpec.scala?#L80) for an example.
Private headers and claims
--------------------------
A JWT library would be pretty underwhelming if you couldn't use headers and claims outwith those outlined in the JWT specification.

Here is how to make a custom claim, Uid.
```scala
// I use a Long for uids, so we use that as the value type
case class Uid(value: Long) extends ClaimValue {

  // A reference to the field object
  override val field: ClaimField = Uid
  
  // A json representation of our value
  override val jsValue: JsValue = JsNumber(value)
}

object Uid extends ClaimField {

  // A function that attempts to construct our claim from a json value
  override def attemptApply(value: JsValue): Option[ClaimValue] =
    value.asOpt[Long].map(apply)
  
  // The field name  
  override val name: String = "uid"
}
```
New fields created like this can be used in exactly the same manner as the registered fields already implemented in this library.
# License
This software is licensed under the MIT license, see [LICENSE](https://github.com/iain-logan/jwt/blob/master/LICENSE).

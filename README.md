# This pacakge is deprecated as of 2018-06-16
I've let this project become neglected over the last few years.
I simply don't have the time required to address pull requests and issues, let alone create bug fixes and implement new features.
Instead of letting it rot over time, I've decided to officially deprecate this library.

A note to anyone still interested in contributing to this library. I'd be very happy for it to be forked and continued under a new maintainer, please do feel free to do so. I'll be leaving the project here as public, there's no sense in removing it.

All the best,
Iain

# jwt [![Build Status](https://travis-ci.org/iain-logan/jwt.svg?branch=master)](https://travis-ci.org/iain-logan/jwt)
This library is a Scala implementation of the JSON Web Token (JWT) [specification](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

If you are not familiar with JWTs, then I suggest you check out [this](https://developer.atlassian.com/static/connect/docs/latest/concepts/understanding-jwt.html) article.
# Goal
This project aims to abstract away from the raw strings and json often seen in JWT implementations. We instead leverage types for a stricter and more robust implementation.
# Getting it
Simply add the following to your build.sbt file:

`libraryDependencies += "io.igl" %% "jwt" % "1.2.2"`

# Usage
Creating headers and claims 
---------------------------
This library contains implementations of all the registered claims and headers laid out in the JWT specification.
```scala
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

Should we want to validate a JWT similar to the above example, we would do the following.

```scala
DecodedJwt.validateEncodedJwt(
  jwt,                       // An encoded jwt as a string
  "secret",                  // The key to validate the signature against
  Algorithm.HS256,           // The algorithm we require
  Set(Typ),                  // The set of headers we require (excluding alg)
  Set(Iss),                  // The set of claims we require
  iss = Some(Iss("readme"))  // The iss claim to require (similar optional arguments exist for all registered claims)
)
```
Returns a `DecodedJwt` wrapped in `Success` on success, otherwise `Failure`.

Note that the alg header should not be in the required headers, as it is required by all JWTs already.

Per the JWT specification, you can mark fields as ignored during validation. See this [test](https://github.com/iain-logan/jwt/blob/master/src/test/scala/io/igl/jwt/JwtSpec.scala?#L160) for examples.

Private headers and claims
--------------------------
A JWT library would be pretty underwhelming if you couldn't use headers and claims outwith those outlined in the JWT specification.

Here is how to make a custom claim, uid.
```scala
// I use a Long for uids, so we use that as the value type
case class Uid(value: Long) extends ClaimValue {

  // A reference to the field object
  override val field: ClaimField = Uid
  
  // A json representation of our value
  override val jsValue: JsValue = JsNumber(value)
}

object Uid extends (Long => Uid) with ClaimField {

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

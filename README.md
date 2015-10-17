# jwt [![Build Status](https://travis-ci.org/iain-logan/jwt.svg?branch=master)](https://travis-ci.org/iain-logan/jwt)
This library is a Scala implementation of the JSON Web Token (JWT) [specification](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html).

If you are not familiar with JWTs, then I suggest you check out [this](https://developer.atlassian.com/static/connect/docs/latest/concepts/understanding-jwt.html) article.
# Goal
This project aims to abstract away from the raw strings and json often seen in JWT implementations. We instead leverage types for a stricter and more robust implementation.
# Getting it
Currently this project is not published externally, so local publishing is required. This will change soon.
- Clone the repository
  - `git clone https://github.com/iain-logan/jwt.git`
- Launch `sbt` in the project and publish locally
  - `cd jwt`
  - `sbt` (If using activator do `activator shell` instead)
  - `publish-local` (If using activator do `publishLocal` instead)
- Add the following line to your build.sbt
  - `libraryDependencies ++= Seq("io.igl" %% "jwt" % "1.1.1")`
- Now import into your project
  - `import io.igl.jwt._`

# Usage
Creating headers and claims 
---------------------------
This library contains implementations of all the registered claims and headers laid out in the JWT specification.
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
Returns a `DecodedJwt` wrapped in `Success` on success, otherwise `Failure`.

This will only validate a JWT in the sense that its signature is valid, no attempts are made to reject tokens that have expired due to the exp claim etc.

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

You will need to add `play-json` as a dependency to your project when using private fields. Do this by adding the below line to your build.sbt
file.

```
libraryDependencies ++= Seq("com.typesafe.play" %% "play-json" % "2.4.0")
```
# License
This software is licensed under the MIT license, see [LICENSE](https://github.com/iain-logan/jwt/blob/master/LICENSE).

package io.igl.jwt

import scala.util.Success

class JwtSpec extends UnitSpec {

  val secret = "secret"

  "A DecodedJwt" should "give the correct result when encrypted" in {
    val jwt = new DecodedJwt(Seq(Alg(Algorithm.HS256), Typ("JWT")), Seq(Sub("123456789")))
    val correctEncoding =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894"
    jwt.encodedAndSigned(secret) should be (correctEncoding)
  }

  it should "be equivalent to the same DecodedJwt after it has been encoded and decoded, given the same " +
    "secret was used and that the headers and claims previously set are demanded when decoding" in {
    val algorithm = Algorithm.HS256
    val requiredHeaders = Set[HeaderField](Typ)
    val requiredClaims  = Set[ClaimField](Sub)
    val headers = Seq[HeaderValue](Typ("JWT"), Alg(algorithm))
    val claims  = Seq[ClaimValue](Sub("1234567890"))

    val beforeJwt = new DecodedJwt(headers, claims)
    val afterJwt = DecodedJwt.validateEncodedJwt(
      beforeJwt.encodedAndSigned(secret),
      secret,
      algorithm,
      requiredHeaders,
      requiredClaims)

    afterJwt should be (Success(beforeJwt))
  }

  it should "use the last occurrence of a header/claim when multiple headers/claims of the same type are provided" in {
    val lastTyp = Typ("JWT")
    val lastSub = Sub("12345")
    new DecodedJwt(List(Typ("ASD"), lastTyp), Nil).getHeader[Typ] should be (Some(lastTyp))
    new DecodedJwt(Nil, Seq(Sub("asdf"), lastSub)).getClaim[Sub] should be (Some(lastSub))
  }

  it should "always have an algorithm header, even when one is not provided, in which case it should be set to \"none\"" in {
    new DecodedJwt(Nil, Nil).getHeader[Alg] should be (Some(Alg(Algorithm.NONE)))
    new DecodedJwt(Seq(Alg(Algorithm.HS256)), Nil).getHeader[Alg] should be (Some(Alg(Algorithm.HS256)))
  }

  it should "give correct results when asked for various headers" in {
    val typ = Typ("JWT")
    val alg = Alg(Algorithm.HS256)
    val jwt = new DecodedJwt(Seq(typ, alg), Nil)

    jwt.getHeader[Typ] should be (Some(typ))
    jwt.getHeader[Alg] should be (Some(alg))
    jwt.getHeader[Cty.type] should be (None)
  }

  it should "give correct results when asked for various claims" in {
    val sub = Sub("foo")
    val iss = Iss("bar")
    val jwt = new DecodedJwt(Nil, Seq(sub, iss))

    jwt.getClaim[Sub] should be (Some(sub))
    jwt.getClaim[Iss] should be (Some(iss))
    jwt.getClaim[Exp] should be (None)
  }

  it should "not be created from an encoded jwt where the required headers contains the algorithm field" in {
    DecodedJwt.validateEncodedJwt("", secret, Algorithm.NONE, Set(Alg), Set()).isFailure should be (true)
  }

  it should "not be created from an encoded jwt with fields we don't recognise as being either required or ignored" in {
    val jwt = new DecodedJwt(Seq(Alg(Algorithm.HS256), Typ("JWT")), Seq(Iss("hindley")))
    val encoded = jwt.encodedAndSigned(secret)
    DecodedJwt.validateEncodedJwt(encoded, secret, Algorithm.HS256, Set(), Set(Iss)).isFailure should be (true)
    DecodedJwt.validateEncodedJwt(encoded, secret, Algorithm.HS256, Set(Typ), Set()).isFailure should be (true)
  }

  it should "be able to be created from an encoded jwt where we are ignoring some fields" in {
    val jwt = new DecodedJwt(Seq(Alg(Algorithm.HS256), Typ("JWT")), Seq(Iss("hindley")))
    val jwtIgnoringIss = new DecodedJwt(Seq(jwt.getHeader[Alg].get, jwt.getHeader[Typ].get), Nil)
    val jwtIgnoringTyp = new DecodedJwt(Seq(jwt.getHeader[Alg].get), Seq(jwt.getClaim[Iss].get))
    val encoded = jwt.encodedAndSigned(secret)
    DecodedJwt.validateEncodedJwt(encoded, secret, Algorithm.HS256, Set(Typ), Set(), Set(), Set(Iss.name)) should be (Success(jwtIgnoringIss))
    DecodedJwt.validateEncodedJwt(encoded, secret, Algorithm.HS256, Set(), Set(Iss), Set(Typ.name)) should be (Success(jwtIgnoringTyp))

  }

}

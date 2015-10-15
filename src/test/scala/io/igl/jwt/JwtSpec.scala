package io.igl.jwt

import scala.util.Success

class JwtSpec extends UnitSpec {

  val secret = "secret"

  "A DecodedJwt" should "give the correct result when encrypted" in {
    val jwt = new DecodedJwt(Alg(Algorithm.HS256), Typ("JWT"))(Sub("123456789"))
    jwt.encodedAndSigned(secret) should be ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkifQ.qHdut1UR4-2FSAvh7U3YdeRR5r5boVqjIGQ16Ztp894")
  }

  it should "be equivalent to the same DecodedJwt after it has been encoded and decoded, given the same " +
    "secret was used and that the headers and claims previously set are demanded when decoding" in {
      val algorithm = Algorithm.HS256
      val requiredHeaders = List[HeaderField](Typ)
      val requiredClaims  = List[ClaimField](Sub)
      val headers = List[HeaderValue](Typ("JWT"), Alg(algorithm))
      val claims  = List[ClaimValue](Sub("1234567890"))
      val jwt = new DecodedJwt(headers:_*)(claims:_*)
      DecodedJwt.validateEncodedJwt(jwt.encodedAndSigned(secret), secret, algorithm)(requiredHeaders:_*)(requiredClaims:_*) should be (Success(jwt))
    }

  it should "use the last occurrence of a header/claim when multiple headers/claims of the same type are provided" in {
    val lastTyp = Typ("JWT")
    val lastSub = Sub("12345")
    new DecodedJwt(Typ("ASD"), lastTyp)().getHeader[Typ] should be (Some(lastTyp))
    new DecodedJwt()(Sub("asdf"), lastSub).getClaim[Sub] should be (Some(lastSub))
  }

  it should "always have an algorithm header, even when one is not provided, in which case it should be set to \"none\"" in {
    new DecodedJwt()().getHeader[Alg] should be (Some(Alg(Algorithm.NONE)))
    new DecodedJwt(Alg(Algorithm.HS256))().getHeader[Alg] should be (Some(Alg(Algorithm.HS256)))
  }

  it should "give correct results when asked for various headers" in {
    val typ = Typ("JWT")
    val alg = Alg(Algorithm.HS256)
    val jwt = new DecodedJwt(typ, alg)()

    // The jwt has both these headers, so should return them
    jwt.getHeader[Typ] should be (Some(typ))
    jwt.getHeader[Alg] should be (Some(alg))
    // This header does not exist in our jwt, so should not be found
    jwt.getHeader[Cty.type] should be (None)
  }

  it should "give correct results when asked for various claims" in {
    val sub = Sub("foo")
    val iss = Iss("bar")
    val jwt = new DecodedJwt()(sub, iss)

    // The jwt has both these claims, so should return them
    jwt.getClaim[Sub] should be (Some(sub))
    jwt.getClaim[Iss] should be (Some(iss))
    // This claim does not exist in our jwt, so should not be found
    jwt.getClaim[Exp] should be (None)
  }
}

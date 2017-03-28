package io.igl.jwt

import io.igl.jwt.Algorithm.{HS384, HS512}
import org.apache.commons.codec.binary.Base64
import play.api.libs.json.{JsNumber, JsValue}

import scala.util.Success

class JwtSpec extends UnitSpec {

  val secret = "secret"

  def now: Long = System.currentTimeMillis / 1000

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

  it should "not be created if a different secret is used when decoding an encoded jwt" in {
    val algorithm = Algorithm.HS256
    val requiredHeaders = Set[HeaderField](Typ)
    val requiredClaims  = Set[ClaimField](Sub)
    val headers = Seq[HeaderValue](Typ("JWT"), Alg(algorithm))
    val claims  = Seq[ClaimValue](Sub("1234567890"))

    val jwt = new DecodedJwt(headers, claims)

    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret + secret,
      algorithm,
      requiredHeaders,
      requiredClaims).isFailure should be (true)
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

  it should "support the none algorithm" in {
    val alg = Alg(Algorithm.NONE)
    val jwt = new DecodedJwt(Seq(Typ("JWT")), Seq(Iss("foo")))
    val encoded = jwt.encodedAndSigned(secret)

    encoded should be ("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJmb28ifQ.")

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(Typ),
      Set(Iss)
    ) should be (Success(jwt))
  }

  it should "support the HS256 algorithm" in {
    val alg = Alg(Algorithm.HS256)
    val jwt = new DecodedJwt(Seq(alg, Typ("JWT")), Seq(Iss("foo")))
    val encoded = jwt.encodedAndSigned(secret)

    encoded should be ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.G1XNxLIxhWF4FFTI3TqZ6XIDorxNnx5J6kHe0jTb70s")

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(Typ),
      Set(Iss)
    ) should be (Success(jwt))
  }

  it should "support the HS384 algorithm" in {
    val alg = Alg(Algorithm.HS384)
    val jwt = new DecodedJwt(Seq(alg, Typ("JWT")), Seq(Iss("foo")))
    val encoded = jwt.encodedAndSigned(secret)

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(Typ),
      Set(Iss)
    ) should be (Success(jwt))
  }

  it should "support the HS512 algorithm" in {
    val alg = Alg(Algorithm.HS512)
    val jwt = new DecodedJwt(Seq(alg, Typ("JWT")), Seq(Iss("foo")))
    val encoded = jwt.encodedAndSigned(secret)

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(Typ),
      Set(Iss)
    ) should be (Success(jwt))
  }
  it should "support the RS256 algorithm" in {
    
    val privateKeyEncoded = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDuDcbzv9sFtiWK\nuoAsKYkak1Tjw7ZmRjmZs1W9RiroJy5PAZOTDbC/VlKptKFd4FGqpVvWuV2Ert24\nVYwpAdBZR5evI705MX/iQY2kAJ0IchoRJ2INPbvYgkbknxTPjwfMKIxpF5supYKi\nbFf8qg4V2DhioaZ+EN4zkBDgcBP85ZOssTu+KADtVmEMo/agERs3UWWwum2tbsw4\nJS0FCdi7B6jHYdisqNXQ8OQEjmhlO7PtBEN7mqcgWOrlampRU1+4hOQNM2BisXGd\nLlayG+BgDrDdOX3G3CKL1RrDriBEUfM/X6Rb3E6tpR5mXbH0179qOdhzbhKlT3r0\nemm2uAIJAgMBAAECggEBAJZy2Jk2WKrsah+aLOU8Pu0vzgfAqidLHJ46C+b6UKW2\nFXtTKLxYe6sBWG7uvMlCuvpZVYiIUEVJ6tDUKCfGgLHcIE5NDQr3cLZC7cyHorcy\nvay3si1iJbT46OsWayWeZLQvsEW+6JF7gus6BAWoSAygQUp8lWe5K2V1GGVwEAHU\nseQ7nDnbZyqF4Cx3otzHfjG9KU5R0N2rzIN0FLkLKz+j9YHIDDX0lCsYFY/yWn+c\nlKs+f1q93XPAbzn+bFegDROg6fUVHZQJlpGIo51+jg3/xco0omrNKgwOy1a4NxUa\nt8aAa2fQb1VVo/kPBw4ERY6qMURHML3E6D7NLEbFxN0CgYEA/ukucb4RfY+E4yWx\naEiHsow7Sj1g4PIFMGtL4wA7kfjOOzZ1dDCuKfkziwyWxbtzFvWKfHhT6qsb6opM\nK2V6FGWuKl6ts3caviqs4vw7DLYpU2+vqiJqNt4mySljiIJhmNeYV9I5hCEklU4w\n80rYBF+69bsxiYGWJ51xhNCEz18CgYEA7xIoXkLRRsCfk/pFB54pbzyr5BY0kCQN\n9AqBEG6buoAYZ0UAgTMyNFWA9SlwP/BBhN58ZoetwWk9/yK7woPck/rq9q+F40ES\nzN4vagSrUqylv3eGGiGIiwXOj6w0ttaqBF/UMUw03z5NtZwm7ybUTRxcCf7PvgKE\nWbB8aWI475cCgYB/9Yms6x5YiyzH4Wn20UHc7OvuTnVNNfBI5/OGFd3RXrYXnzTC\niJVE2KV5DW65/2i8g7Fq3fQx/oba62Vk+2GWz5voBPLo/cbc4ws6PideMCr6iTwD\nCZeLx2Rs4mvmYJyhXshIfW0F2KVGlaOY3V8mgu+U3sz1G6nGZRBQ/WNNvQKBgQC6\nNpN48GSfzpO9qFeyWlB90200CNPCXkL8Dl5/VRg5iWL4tTdya1U0jFEZJMDJHLN7\n8exF1HLTzsy6eOx0006xeOUhZpBL9bjWGE4oLyDfEZk87LVojywS1WASapjYvZXK\nOHZIO8qHBLl0tv9gkgcVVPyf0Hkx0DYUwjH1x8r/WwKBgBuPK/vT59jO1f6xLltN\nP9KWR9weoJYL2Rv+a+JWWBmUtey/A3lbonrTSkRkYfGT06mV4ANOQAmvgBO9PHVX\nG/RH5e8g0uWi3iaa61kA6aFPzrhAsWUa65uEBsBX5dllGowiFdku2asr16DRibQd\nZWj0r6T/5FqNrsl+WjMxRjWU\n\n"
    val alg = Alg(Algorithm.RS256)
    val privateKey = Base64.decodeBase64(privateKeyEncoded)
    val jwt=  new DecodedJwt(Seq(alg, Typ("JWT")), Seq(Iss("foo")))
    val encoded = jwt.encodedAndSigned(privateKey)

    DecodedJwt.validateEncodedJwtWithEncodedSecret(
      encoded,
      privateKey,
      alg.value,
      Set(Typ),
      Set(Iss)
    ) should be (Success(jwt))
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

  it should "not be created from an encoded jwt where the algorithms do not match" in {
    val typ = Typ("JWT")
    val iss = Iss("hindley")
    val jwt = new DecodedJwt(Seq(Alg(Algorithm.HS256), typ), Seq(iss))
    val encoded = jwt.encodedAndSigned(secret)
    DecodedJwt.validateEncodedJwt(encoded, secret, Algorithm.NONE, Set(typ.field), Set(iss.field)).isFailure should be (true)
  }

  it should "support all registered headers" in {
    val typ = Typ("JWT")
    val alg = Alg(Algorithm.HS256)
    val cty = Cty
    val headers = Seq(typ, alg, cty)

    val jwt = new DecodedJwt(headers, Seq())
    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret,
      alg.value,
      Set(Typ, Cty),
      Set()) should be (Success(jwt))
  }

  it should "support all registered claims" in {
    val alg = Alg(Algorithm.HS256)
    val iss = Iss("hindley")
    val sub = Sub("123456789")
    val audSingle = Aud("users")
    val audMany = Aud(Seq("admin", "users"))
    val exp = Exp(now + 100)
    val nbf = Nbf(now - 100)
    val iat = Iat(1234567890L)
    val jti = Jti("asdf1234")
    val claimsA = Seq[ClaimValue](iss, sub, audSingle, exp, nbf, iat, jti)

    val jwtA = new DecodedJwt(Seq(alg), claimsA)
    DecodedJwt.validateEncodedJwt(
      jwtA.encodedAndSigned(secret),
      secret,
      alg.value,
      Set(),
      claimsA.map(_.field).toSet) should be (Success(jwtA))
    val claimsB = Seq[ClaimValue](iss, sub, audMany, exp, nbf, iat, jti)
    val jwtB = new DecodedJwt(Seq(alg), claimsB)
    DecodedJwt.validateEncodedJwt(
      jwtB.encodedAndSigned(secret),
      secret,
      alg.value,
      Set(),
      claimsB.map(_.field).toSet) should be (Success(jwtB))
  }

  it should "not be created from an expired jwt" in {
    val jwt = new DecodedJwt(Seq(), Seq(Exp(now - 100)))

    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret,
      Algorithm.NONE,
      Set(),
      Set(Exp)
    ).isFailure should be (true)
  }

  it should "be able to ignore the exp claim" in {
    val jwt = new DecodedJwt(Seq(Typ("JWT")), Seq(Exp(now - 100)))

    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret,
      Algorithm.NONE,
      Set(Typ),
      Set(),
      Set(),
      Set(Exp.name)
    ) should be (Success(new DecodedJwt(Seq(Typ("JWT")), Seq())))
  }

  it should "not be created from a not yet valid jwt" in {
    val jwt = new DecodedJwt(Seq(), Seq(Nbf(now + 100)))

    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret,
      Algorithm.NONE,
      Set(),
      Set(Nbf)
    ).isFailure should be (true)
  }

  it should "be able to ignore the nbf claim" in {
    val jwt = new DecodedJwt(Seq(Typ("JWT")), Seq(Nbf(now + 100)))

    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret,
      Algorithm.NONE,
      Set(Typ),
      Set(),
      Set(),
      Set(Nbf.name)
    ) should be (Success(new DecodedJwt(Seq(Typ("JWT")), Seq())))
  }

  it should "support the private scope claim" in {

    val alg = Alg(Algorithm.HS256)
    val scope = Scope("https://www.googleapis.com/auth/devstorage.read_write")
    val jwt = new DecodedJwt(Seq(alg), Seq(scope))

    jwt.getClaim[Scope] should be (Some(scope))

    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret,
      alg.value,
      Set(),
      Set(Scope)) should be (Success(jwt))
  }


  it should "support private unregistered fields" in {

    object Uid extends ClaimField {
      override def attemptApply(value: JsValue): Option[ClaimValue] =
        value.asOpt[Long].map(apply)

      override val name: String = "uid"
    }

    case class Uid(value: Long) extends ClaimValue {
      override val field: ClaimField = Uid
      override val jsValue: JsValue = JsNumber(value)
    }

    val alg = Alg(Algorithm.HS256)
    val uid = Uid(123456789L)
    val jwt = new DecodedJwt(Seq(alg), Seq(uid))

    jwt.getClaim[Uid] should be (Some(uid))

    DecodedJwt.validateEncodedJwt(
      jwt.encodedAndSigned(secret),
      secret,
      alg.value,
      Set(),
      Set(Uid)) should be (Success(jwt))
  }

  it should "check if a specific iss claim is required when creating from an encoded jwt" in {
    val alg = Alg(Algorithm.HS256)
    val iss = Iss("jeff")
    val jwt = new DecodedJwt(Seq(alg), Seq(iss))
    val encoded = jwt.encodedAndSigned(secret)

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Iss),
      iss = Some(iss)
    ) should be (Success(jwt))

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Iss),
      iss = Some(Iss(iss.value + "a"))
    ).isFailure should be (true)
  }

  it should "check if a specific aud claim is required when creating from an encoded jwt" in {
    val alg = Alg(Algorithm.HS256)
    val aud = Aud("jeff")
    val jwt = new DecodedJwt(Seq(alg), Seq(aud))
    val encoded = jwt.encodedAndSigned(secret)

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Aud),
      aud = Some(aud)
    ) should be (Success(jwt))

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Aud),
      aud = Some(Aud(aud.value.left + "a"))
    ).isFailure should be (true)
  }

  it should "check if a specific iat claim is required when creating from an encoded jwt" in {
    val alg = Alg(Algorithm.HS256)
    val iat = Iat(1234567890L)
    val jwt = new DecodedJwt(Seq(alg), Seq(iat))
    val encoded = jwt.encodedAndSigned(secret)

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Iat),
      iat = Some(iat)
    ) should be (Success(jwt))

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Iat),
      iat = Some(Iat(iat.value + 1))
    ).isFailure should be (true)
  }

  it should "check if a specific sub claim is required when creating from an encoded jwt" in {
    val alg = Alg(Algorithm.HS256)
    val sub = Sub("jeff")
    val jwt = new DecodedJwt(Seq(alg), Seq(sub))
    val encoded = jwt.encodedAndSigned(secret)

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Sub),
      sub = Some(sub)
    ) should be (Success(jwt))

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Sub),
      sub = Some(Sub(sub.value + "a"))
    ).isFailure should be (true)
  }

  it should "check if a specific jti claim is required when creating from an encoded jwt" in {
    val alg = Alg(Algorithm.HS256)
    val jti = Jti("asdf")
    val jwt = new DecodedJwt(Seq(alg), Seq(jti))
    val encoded = jwt.encodedAndSigned(secret)

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Jti),
      jti = Some(jti)
    ) should be (Success(jwt))

    DecodedJwt.validateEncodedJwt(
      encoded,
      secret,
      alg.value,
      Set(),
      Set(Jti),
      jti = Some(Jti(jti.value + "a"))
    ).isFailure should be (true)
  }

  it should "support Base64 Encoded Secret" in {
    val decoder = new Base64(true)
    val alg = Alg(Algorithm.HS256)
    val jwt = new DecodedJwt(Seq(alg, Typ("JWT")), Seq(Iss("foo")))
    val decodedSecret : Array[Byte] = decoder.decode(secret)
    val encoded = jwt.encodedAndSigned(decodedSecret)

   encoded should be ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJmb28ifQ.M-3mD1aZMseTJW_lnV2_YKuMXcMKIBVevaSYLU4P3zE")

    DecodedJwt.validateEncodedJwtWithEncodedSecret(
      encoded,
      decodedSecret,
      alg.value,
      Set(Typ),
      Set(Iss)
    ) should be (Success(jwt))
  }
}

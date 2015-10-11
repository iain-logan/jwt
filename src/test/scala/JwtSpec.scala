import _root_.io.igl.jwt._

import scala.util.Success

class JwtSpec extends UnitSpec {

  val secret = "secret"

  "A DecodedJwt" should "give the correct result when encrypted" in {
    val jwt = DecodedJwt(List(Typ("JWT")), List(Sub("1234567890")), Algorithm.HS256)
    jwt.encodedAndSigned(secret) should be ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I")
  }

  it should "be equivalent to the same DecodedJwt after it has been encoded and decoded, given the same " +
    "secret was used and that the headers and claims previously set are demanded when decoding" in {
      val algorithm = Algorithm.HS256
      val requiredHeaders = List[Header](Typ)
      val requiredClaims  = List[Claim](Sub)
      val headers = List[HeaderValue](Typ("JWT"))
      val claims  = List[ClaimValue](Sub("1234567890"))
      val jwt = DecodedJwt(headers, claims, algorithm)
      DecodedJwt.validateEncodedJwt(jwt.encodedAndSigned(secret), requiredHeaders, requiredClaims, secret, algorithm) should be (Success(jwt))
    }
}

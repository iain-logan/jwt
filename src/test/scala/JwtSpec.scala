import _root_.io.igl.jwt._

class JwtSpec extends UnitSpec {

  val secret = "secret"

  "A DecodedJwt" should "give the correct result when encrypted" in {
    val jwt = DecodedJwt(Set(Alg(Algorithm.HS256), Typ("JWT")), Set(Sub("1234567890")))
    jwt.encodedAndSigned(secret) should be ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Rq8IxqeX7eA6GgYxlcHdPFVRNFFZc5rEI3MQTZZbK3I")
  }

  it should "be equivalent to the same DecodedJwt after it has been encoded and decoded, given the same " +
    "secret was used and that the headers and claims previously set are demanded when decoding" in {
      val algorithm = Algorithm.HS256
      val requiredHeaders = Set[Header](Alg, Typ)
      val requiredClaims  = Set[Claim](Sub)
      val headers = Set[HeaderValue](Alg(algorithm), Typ("JWT"))
      val claims  = Set[ClaimValue](Sub("1234567890"))
      val jwt = DecodedJwt(headers, claims)
      System.out.println(DecodedJwt.validateEncodedJwt(jwt.encodedAndSigned(secret), requiredHeaders, requiredClaims, secret, algorithm))
      DecodedJwt.validateEncodedJwt(jwt.encodedAndSigned(secret), requiredHeaders, requiredClaims, secret, algorithm) should be (jwt)
    }
}
